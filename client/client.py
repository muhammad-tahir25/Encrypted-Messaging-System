# =============================================================
# Chat Client — Networking + Encryption Logic
# Handles server connection, AES + ECC encrypt/decrypt,
# and exposes callbacks for the GUI layer
# =============================================================

import socket
import threading
import json
import base64
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.aes import aes_encrypt, aes_decrypt, generate_aes_key
from crypto.ecc import (
    generate_ecc_keypair, ecc_encrypt, ecc_decrypt,
    point_to_bytes, bytes_to_point,
    private_key_to_bytes, bytes_to_private_key
)
from crypto.dh import DiffieHellman, public_key_to_bytes, bytes_to_public_key
from database.key_storage import KeyStorage

HOST = '127.0.0.1'
PORT = 55555


# ─────────────────────────────────────────────
# CHAT CLIENT CLASS
# ─────────────────────────────────────────────

class ChatClient:
    def __init__(self, username: str):
        self.username = username
        self.conn     = None
        self.running  = False
        self.session_id = None

        # ── Key Storage (SQLite) ──
        self.db = KeyStorage()

        # ── ECC key pair — load from DB or generate new ──
        if self.db.ecc_keypair_exists(username):
            self.ecc_private, self.ecc_public = self.db.load_ecc_keypair(username)
            print(f"[CLIENT] Loaded ECC keys from DB for {username}")
        else:
            self.ecc_private, self.ecc_public = generate_ecc_keypair()
            self.db.save_ecc_keypair(username, self.ecc_private, self.ecc_public)
            print(f"[CLIENT] Generated and saved new ECC keys for {username}")

        # ── DH key pair ──
        self.dh = DiffieHellman()
        self.dh_shared_key = None

        # ── AES key — will be set from DH shared secret (NOT from server) ──
        # This is the key change: AES key comes from DH, not server
        self.aes_key = None

        # ── Other client's ECC public key ──
        self.peer_ecc_pub = None

        # Callbacks set by GUI
        self.on_message      = None   # fn(sender, plaintext, timing)
        self.on_system       = None   # fn(message)
        self.on_user_list    = None   # fn(users: list)
        self.on_connected    = None   # fn()
        self.on_disconnected = None   # fn()
        self.on_error        = None   # fn(error_msg)


    # ─────────────────────────────────────────
    # CONNECTION
    # ─────────────────────────────────────────

    def connect(self):
        """
        Connect to server and perform handshake.
        DH public keys are exchanged through the server.
        Each client computes the shared secret independently
        and uses it as the AES key — server never sees the AES key.
        """
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((HOST, PORT))
            self.running = True

            # Send HELLO with username + ECC public key + DH public key
            self._send({
                'type':     'hello',
                'username': self.username,
                'ecc_pub':  base64.b64encode(point_to_bytes(self.ecc_public)).decode(),
                'dh_pub':   base64.b64encode(public_key_to_bytes(self.dh.public_key)).decode()
            })

            # Wait for WELCOME or ERROR from server
            welcome = self._recv()
            if not welcome:
                if self.on_error:
                    self.on_error("No response from server.")
                return

            # ── Username already taken ──
            if welcome.get('type') == 'error':
                if self.on_error:
                    self.on_error(welcome.get('message', 'Connection error.'))
                return

            if welcome.get('type') == 'welcome':
                self.session_id = welcome.get('session_id', f"{self.username}_session")

                # ── If peers already connected, compute DH shared secret immediately ──
                # This means Client B connects after Client A —
                # server sends Client A's DH public key in the peers list
                for peer in welcome.get('peers', []):
                    peer_dh_pub = bytes_to_public_key(
                        base64.b64decode(peer['dh_pub'])
                    )
                    # Compute shared secret using peer's DH public key
                    self.dh_shared_key = self.dh.compute_shared_secret(peer_dh_pub)

                    # THIS is the key change:
                    # DH shared secret becomes the AES key
                    self.aes_key = self.dh_shared_key

                    # Save DH session to database
                    self.db.save_dh_session(
                        self.session_id, self.username, peer['username'],
                        self.dh.public_key, self.dh_shared_key
                    )
                    # Save AES session key to database
                    self.db.save_aes_session(
                        self.session_id, self.username, self.aes_key
                    )

                    # Load peer ECC public key
                    self.peer_ecc_pub = bytes_to_point(
                        base64.b64decode(peer['ecc_pub'])
                    )
                    print(f"[CLIENT] DH shared secret computed with {peer['username']}")
                    print(f"[CLIENT] AES key set from DH — server never saw this key")

            # Start listening thread
            t = threading.Thread(target=self._listen_loop, daemon=True)
            t.start()

            if self.on_connected:
                self.on_connected()

        except Exception as e:
            if self.on_error:
                self.on_error(str(e))


    def disconnect(self):
        self.running = False
        try:
            self.conn.close()
        except:
            pass
        if self.on_disconnected:
            self.on_disconnected()


    # ─────────────────────────────────────────
    # SEND MESSAGE (encrypt with BOTH AES + ECC)
    # ─────────────────────────────────────────

    def send_message(self, plaintext: str):
        """
        Encrypt plaintext with both AES-256 and ECC,
        record timing for each, and send both to server.
        AES key comes from DH shared secret.
        ECC uses peer's public key.
        """
        if not self.aes_key:
            if self.on_error:
                self.on_error("AES key not ready — waiting for peer to connect first.")
            return

        # ── AES Encryption (key came from DH shared secret) ──
        aes_cipher, aes_iv, aes_enc_time = aes_encrypt(plaintext, self.aes_key)

        # ── ECC Encryption (uses peer's ECC public key) ──
        target_pub = self.peer_ecc_pub if self.peer_ecc_pub is not None else self.ecc_public
        eph_pub, ecc_cipher, ecc_mac, ecc_enc_time = ecc_encrypt(plaintext, target_pub)

        # ── Build payload ──
        payload = {
            'type': 'message',

            # AES data
            'aes_cipher':   base64.b64encode(aes_cipher).decode(),
            'aes_iv':       base64.b64encode(aes_iv).decode(),
            'aes_enc_time': aes_enc_time,

            # ECC data
            'ecc_eph_pub':  base64.b64encode(point_to_bytes(eph_pub)).decode(),
            'ecc_cipher':   base64.b64encode(ecc_cipher).decode(),
            'ecc_mac':      base64.b64encode(ecc_mac).decode(),
            'ecc_enc_time': ecc_enc_time,

            # Sender's ECC public key so receiver can update peer key
            'sender_ecc_pub': base64.b64encode(point_to_bytes(self.ecc_public)).decode(),
            # Sender's DH public key so receiver can compute shared secret
            'sender_dh_pub':  base64.b64encode(public_key_to_bytes(self.dh.public_key)).decode(),
        }

        self._send(payload)
        return aes_enc_time, ecc_enc_time


    # ─────────────────────────────────────────
    # RECEIVE LOOP
    # ─────────────────────────────────────────

    def _listen_loop(self):
        while self.running:
            data = self._recv()
            if data is None:
                break
            self._handle_incoming(data)

        self.running = False
        if self.on_disconnected:
            self.on_disconnected()


    def _handle_incoming(self, data: dict):
        msg_type = data.get('type')

        # ── Chat message ──
        if msg_type == 'message':
            sender = data.get('sender', 'Unknown')

            # Update peer ECC public key
            if 'sender_ecc_pub' in data:
                pub_bytes = base64.b64decode(data['sender_ecc_pub'])
                self.peer_ecc_pub = bytes_to_point(pub_bytes)

            # ── Always recompute DH if sender_dh_pub present ──
            # Handles case where peer rejoined with new DH keys
            if 'sender_dh_pub' in data:
                peer_dh_pub = bytes_to_public_key(
                    base64.b64decode(data['sender_dh_pub'])
                )
                new_shared = self.dh.compute_shared_secret(peer_dh_pub)
                # Only update if key changed (peer rejoined with new keys)
                if new_shared != self.dh_shared_key:
                    self.dh_shared_key = new_shared
                    self.aes_key = self.dh_shared_key
                    if self.session_id:
                        self.db.save_dh_session(
                            self.session_id, self.username, sender,
                            self.dh.public_key, self.dh_shared_key
                        )
                        self.db.save_aes_session(
                            self.session_id, self.username, self.aes_key
                        )
                    print(f"[CLIENT] DH key updated from message — peer rejoined")

            # ── AES Decrypt (using DH-derived key) ──
            try:
                aes_cipher = base64.b64decode(data['aes_cipher'])
                aes_iv     = base64.b64decode(data['aes_iv'])
                aes_plain, aes_dec_time = aes_decrypt(aes_cipher, self.aes_key, aes_iv)
            except Exception as e:
                aes_plain, aes_dec_time = f"[AES error: {e}]", 0.0

            # ── ECC Decrypt (using own private key) ──
            try:
                eph_pub    = bytes_to_point(base64.b64decode(data['ecc_eph_pub']))
                ecc_cipher = base64.b64decode(data['ecc_cipher'])
                ecc_mac    = base64.b64decode(data['ecc_mac'])
                ecc_plain, ecc_dec_time = ecc_decrypt(
                    eph_pub, ecc_cipher, ecc_mac, self.ecc_private
                )
            except Exception:
                ecc_plain, ecc_dec_time = aes_plain, 0.0

            # Always display AES decrypted text (most reliable)
            display_text = aes_plain

            timing = {
                'aes_enc': data.get('aes_enc_time', 0),
                'aes_dec': aes_dec_time,
                'ecc_enc': data.get('ecc_enc_time', 0),
                'ecc_dec': ecc_dec_time,
            }

            # Save message record to DB
            if self.session_id:
                self.db.save_message(self.session_id, sender, display_text, timing)

            if self.on_message:
                self.on_message(sender, display_text, timing)

        # ── System message ──
        elif msg_type == 'system':
            if self.on_system:
                self.on_system(data.get('message', ''))

        # ── User list update ──
        elif msg_type == 'user_list':
            if self.on_user_list:
                self.on_user_list(data.get('users', []))

        # ── Peer key received (new client joined) ──
        # Server forwards new client's ECC + DH public keys to existing clients
        elif msg_type == 'peer_key':
            # Update peer ECC public key
            pub_bytes = base64.b64decode(data['ecc_pub'])
            self.peer_ecc_pub = bytes_to_point(pub_bytes)
            print(f"[CLIENT] Received ECC key from {data.get('username', 'peer')}")

            # ── Always recompute DH shared secret when peer key received ──
            # This handles rejoin: old key is stale, new key must replace it
            if 'dh_pub' in data:
                peer_dh_pub = bytes_to_public_key(
                    base64.b64decode(data['dh_pub'])
                )
                self.dh_shared_key = self.dh.compute_shared_secret(peer_dh_pub)
                self.aes_key = self.dh_shared_key

                peer_username = data.get('username', 'peer')
                if self.session_id:
                    self.db.save_dh_session(
                        self.session_id, self.username, peer_username,
                        self.dh.public_key, self.dh_shared_key
                    )
                    self.db.save_aes_session(
                        self.session_id, self.username, self.aes_key
                    )
                print(f"[CLIENT] DH key refreshed with {peer_username}")


    # ─────────────────────────────────────────
    # LOW-LEVEL SEND / RECV
    # ─────────────────────────────────────────

    def _send(self, data: dict):
        try:
            msg = json.dumps(data).encode('utf-8')
            length = len(msg).to_bytes(4, 'big')
            self.conn.sendall(length + msg)
        except Exception as e:
            print(f"[CLIENT] Send error: {e}")

    def _recv(self) -> dict:
        try:
            raw_len = self.conn.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = b""
            while len(data) < msg_len:
                chunk = self.conn.recv(min(4096, msg_len - len(data)))
                if not chunk:
                    return None
                data += chunk
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None


# ─────────────────────────────────────────────
# QUICK TEST (no GUI)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import time

    def on_msg(sender, plaintext, timing):
        print(f"\n[MSG] From {sender}: {plaintext}")
        print(f"  AES  → enc: {timing['aes_enc']} ms | dec: {timing['aes_dec']} ms")
        print(f"  ECC  → enc: {timing['ecc_enc']} ms | dec: {timing['ecc_dec']} ms")

    def on_sys(msg):
        print(f"[SYSTEM] {msg}")

    def on_conn():
        print("[CLIENT] Connected to server!")

    client = ChatClient("TestUser")
    client.on_message = on_msg
    client.on_system = on_sys
    client.on_connected = on_conn
    client.connect()
    time.sleep(10)