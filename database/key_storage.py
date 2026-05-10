# =============================================================
# SQLite Key Storage — Pure Python
# Stores ECC key pairs, DH session keys, and message history
# No third-party libraries — uses Python's built-in sqlite3
# =============================================================

import sqlite3
import os
import base64
import hashlib
import time
from datetime import datetime

# Database file location
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'chat_keys.db')


# ─────────────────────────────────────────────
# DATABASE MANAGER
# ─────────────────────────────────────────────

class KeyStorage:
    """
    Manages persistent storage of:
    - ECC key pairs per user
    - DH session keys per session
    - AES session keys
    - Message history with timing data
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = os.path.abspath(db_path)
        self._init_database()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_database(self):
        """Create all tables if they don't exist"""
        with self._connect() as conn:
            cursor = conn.cursor()

            # ── ECC Key Pairs ──
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecc_keys (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT NOT NULL UNIQUE,
                    private_key TEXT NOT NULL,
                    public_key  TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                )
            """)

            # ── DH Session Keys ──
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dh_sessions (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id      TEXT NOT NULL UNIQUE,
                    username        TEXT NOT NULL,
                    peer_username   TEXT NOT NULL,
                    dh_public_key   TEXT NOT NULL,
                    derived_key     TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                )
            """)

            # ── AES Session Keys ──
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS aes_sessions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL UNIQUE,
                    username    TEXT NOT NULL,
                    aes_key     TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                )
            """)

            # ── Message History ──
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS message_history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id      TEXT NOT NULL,
                    sender          TEXT NOT NULL,
                    message_hash    TEXT NOT NULL,
                    aes_enc_time    REAL,
                    aes_dec_time    REAL,
                    ecc_enc_time    REAL,
                    ecc_dec_time    REAL,
                    sent_at         TEXT NOT NULL
                )
            """)

            conn.commit()
        print(f"[DB] Database ready at: {self.db_path}")


    # ─────────────────────────────────────────
    # ECC KEY OPERATIONS
    # ─────────────────────────────────────────

    def save_ecc_keypair(self, username: str, private_key: int, public_key: tuple):
        """Save ECC key pair for a user"""
        priv_b64 = base64.b64encode(private_key.to_bytes(32, 'big')).decode()
        pub_bytes = public_key[0].to_bytes(32, 'big') + public_key[1].to_bytes(32, 'big')
        pub_b64 = base64.b64encode(pub_bytes).decode()

        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ecc_keys
                (username, private_key, public_key, created_at)
                VALUES (?, ?, ?, ?)
            """, (username, priv_b64, pub_b64, _now()))
            conn.commit()
        print(f"[DB] ECC keys saved for: {username}")

    def load_ecc_keypair(self, username: str):
        """
        Load ECC key pair for a user.
        Returns: (private_key_int, public_key_tuple) or None
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT private_key, public_key FROM ecc_keys WHERE username = ?",
                (username,)
            ).fetchone()

        if not row:
            return None

        priv = int.from_bytes(base64.b64decode(row[0]), 'big')
        pub_bytes = base64.b64decode(row[1])
        pub = (
            int.from_bytes(pub_bytes[:32], 'big'),
            int.from_bytes(pub_bytes[32:], 'big')
        )
        return priv, pub

    def ecc_keypair_exists(self, username: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM ecc_keys WHERE username = ?", (username,)
            ).fetchone()
        return row is not None


    # ─────────────────────────────────────────
    # DH SESSION KEY OPERATIONS
    # ─────────────────────────────────────────

    def save_dh_session(self, session_id: str, username: str,
                        peer_username: str, dh_public_key: int,
                        derived_key: bytes):
        """Save a DH session key"""
        pub_b64 = base64.b64encode(dh_public_key.to_bytes(256, 'big')).decode()
        key_b64 = base64.b64encode(derived_key).decode()

        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO dh_sessions
                (session_id, username, peer_username, dh_public_key, derived_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, username, peer_username, pub_b64, key_b64, _now()))
            conn.commit()
        print(f"[DB] DH session saved: {session_id}")

    def load_dh_session(self, session_id: str):
        """
        Load a DH session.
        Returns: dict with session data or None
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM dh_sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()

        if not row:
            return None

        return {
            'session_id':    row[1],
            'username':      row[2],
            'peer_username': row[3],
            'dh_public_key': int.from_bytes(base64.b64decode(row[4]), 'big'),
            'derived_key':   base64.b64decode(row[5]),
            'created_at':    row[6],
        }


    # ─────────────────────────────────────────
    # AES SESSION KEY OPERATIONS
    # ─────────────────────────────────────────

    def save_aes_session(self, session_id: str, username: str, aes_key: bytes):
        """Save an AES session key"""
        key_b64 = base64.b64encode(aes_key).decode()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO aes_sessions
                (session_id, username, aes_key, created_at)
                VALUES (?, ?, ?, ?)
            """, (session_id, username, key_b64, _now()))
            conn.commit()
        print(f"[DB] AES session saved: {session_id}")

    def load_aes_session(self, session_id: str) -> bytes:
        """Load an AES session key. Returns key bytes or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT aes_key FROM aes_sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()
        return base64.b64decode(row[0]) if row else None


    # ─────────────────────────────────────────
    # MESSAGE HISTORY OPERATIONS
    # ─────────────────────────────────────────

    def save_message(self, session_id: str, sender: str,
                     message: str, timing: dict):
        """
        Save a message record with timing data.
        Message content is stored as a hash only (privacy).
        """
        msg_hash = hashlib.sha256(message.encode()).hexdigest()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO message_history
                (session_id, sender, message_hash,
                 aes_enc_time, aes_dec_time,
                 ecc_enc_time, ecc_dec_time, sent_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, sender, msg_hash,
                timing.get('aes_enc', 0), timing.get('aes_dec', 0),
                timing.get('ecc_enc', 0), timing.get('ecc_dec', 0),
                _now()
            ))
            conn.commit()

    def get_session_stats(self, session_id: str) -> dict:
        """Get timing statistics for a session"""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT aes_enc_time, aes_dec_time,
                       ecc_enc_time, ecc_dec_time
                FROM message_history
                WHERE session_id = ?
            """, (session_id,)).fetchall()

        if not rows:
            return {}

        count = len(rows)
        avg_aes = sum(r[0] + r[1] for r in rows) / count
        avg_ecc = sum(r[2] + r[3] for r in rows) / count

        return {
            'message_count': count,
            'avg_aes_total_ms': round(avg_aes, 4),
            'avg_ecc_total_ms': round(avg_ecc, 4),
            'faster_algorithm': 'AES' if avg_aes < avg_ecc else 'ECC',
        }

    def get_all_sessions(self) -> list:
        """Get a summary of all sessions"""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT session_id, username, peer_username, created_at
                FROM dh_sessions ORDER BY created_at DESC
            """).fetchall()
        return [{'session_id': r[0], 'username': r[1],
                 'peer': r[2], 'created_at': r[3]} for r in rows]


    # ─────────────────────────────────────────
    # UTILITY
    # ─────────────────────────────────────────

    def clear_all(self):
        """Wipe all stored keys — use with caution"""
        with self._connect() as conn:
            conn.execute("DELETE FROM ecc_keys")
            conn.execute("DELETE FROM dh_sessions")
            conn.execute("DELETE FROM aes_sessions")
            conn.execute("DELETE FROM message_history")
            conn.commit()
        print("[DB] All keys cleared.")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from crypto.ecc import generate_ecc_keypair
    from crypto.dh import DiffieHellman
    from crypto.aes import generate_aes_key

    print("=== SQLite Key Storage Test ===\n")

    db = KeyStorage()

    # Test ECC key storage
    priv, pub = generate_ecc_keypair()
    db.save_ecc_keypair("alice", priv, pub)
    loaded = db.load_ecc_keypair("alice")
    assert loaded[0] == priv
    print(f"ECC keypair save/load: PASSED ✓")

    # Test DH session storage
    alice = DiffieHellman()
    bob   = DiffieHellman()
    derived = alice.compute_shared_secret(bob.public_key)
    db.save_dh_session("session_001", "alice", "bob", alice.public_key, derived)
    session = db.load_dh_session("session_001")
    assert session['derived_key'] == derived
    print(f"DH session save/load:  PASSED ✓")

    # Test AES session storage
    aes_key = generate_aes_key()
    db.save_aes_session("session_001", "alice", aes_key)
    loaded_key = db.load_aes_session("session_001")
    assert loaded_key == aes_key
    print(f"AES session save/load: PASSED ✓")

    # Test message history
    timing = {'aes_enc': 0.62, 'aes_dec': 1.1, 'ecc_enc': 28.5, 'ecc_dec': 14.2}
    db.save_message("session_001", "alice", "Hello Bob!", timing)
    db.save_message("session_001", "alice", "How are you?", timing)
    stats = db.get_session_stats("session_001")
    print(f"Message history stats: PASSED ✓")
    print(f"  Messages: {stats['message_count']}")
    print(f"  Avg AES:  {stats['avg_aes_total_ms']} ms")
    print(f"  Avg ECC:  {stats['avg_ecc_total_ms']} ms")
    print(f"  Faster:   {stats['faster_algorithm']}")

    db.clear_all()
    print(f"\nDatabase cleared. All tests PASSED ✓")