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

HOST = '127.0.0.1'
PORT = 55555


# ─────────────────────────────────────────────
# CHAT CLIENT CLASS
# ─────────────────────────────────────────────

class ChatClient:
    def __init__(self, username: str):
        self.username = username
        self.conn = None
        self.running = False

        # ECC key pair for this client
        self.ecc_private, self.ecc_public = generate_ecc_keypair()

        # AES session key (received from server after handshake)
        self.aes_key = None

        # Other client's ECC public key (for encrypting to them)
        self.peer_ecc_pub = None

        # Callbacks set by GUI
        self.on_message = None       # fn(sender, plaintext, aes_time, ecc_time)
        self.on_system  = None       # fn(message)
        self.on_user_list = None     # fn(users: list)
        self.on_connected = None     # fn()
        self.on_disconnected = None  # fn()
        self.on_error = None         # fn(error_msg)


    # ─────────────────────────────────────────
    # CONNECTION
    # ─────────────────────────────────────────

    def connect(self):
        """Connect to server and perform handshake"""
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((HOST, PORT))
            self.running = True

            # Send HELLO with username + ECC public key
            self._send({
                'type': 'hello',
                'username': self.username,
                'ecc_pub': base64.b64encode(point_to_bytes(self.ecc_public)).decode()
            })

            # Wait for WELCOME + AES key from server
            welcome = self._recv()
            if welcome and welcome.get('type') == 'welcome':
                self.aes_key = base64.b64decode(welcome['aes_key'])
                print(f"[CLIENT] Connected. AES key received.")

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
        """
        if not self.aes_key:
            if self.on_error:
                self.on_error("Not connected or AES key missing.")
            return

        # ── AES Encryption ──
        aes_cipher, aes_iv, aes_enc_time = aes_encrypt(plaintext, self.aes_key)

        # ── ECC Encryption ──
        if self.peer_ecc_pub is None:
            # Fallback: use own public key if no peer yet
            eph_pub, ecc_cipher, ecc_mac, ecc_enc_time = ecc_encrypt(plaintext, self.ecc_public)
        else:
            eph_pub, ecc_cipher, ecc_mac, ecc_enc_time = ecc_encrypt(plaintext, self.peer_ecc_pub)

        # ── Build payload ──
        payload = {
            'type': 'message',

            # AES data
            'aes_cipher': base64.b64encode(aes_cipher).decode(),
            'aes_iv':     base64.b64encode(aes_iv).decode(),
            'aes_enc_time': aes_enc_time,

            # ECC data
            'ecc_eph_pub': base64.b64encode(point_to_bytes(eph_pub)).decode(),
            'ecc_cipher':  base64.b64encode(ecc_cipher).decode(),
            'ecc_mac':     base64.b64encode(ecc_mac).decode(),
            'ecc_enc_time': ecc_enc_time,

            # Sender's ECC public key (so receiver can decrypt)
            'sender_ecc_pub': base64.b64encode(point_to_bytes(self.ecc_public)).decode(),
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

            # Update peer's ECC public key
            if 'sender_ecc_pub' in data:
                pub_bytes = base64.b64decode(data['sender_ecc_pub'])
                self.peer_ecc_pub = bytes_to_point(pub_bytes)

            # ── AES Decrypt ──
            try:
                aes_cipher = base64.b64decode(data['aes_cipher'])
                aes_iv     = base64.b64decode(data['aes_iv'])
                aes_plain, aes_dec_time = aes_decrypt(aes_cipher, self.aes_key, aes_iv)
            except Exception as e:
                aes_plain, aes_dec_time = f"[AES decrypt error: {e}]", 0.0

            # ── ECC Decrypt ──
            try:
                eph_pub    = bytes_to_point(base64.b64decode(data['ecc_eph_pub']))
                ecc_cipher = base64.b64decode(data['ecc_cipher'])
                ecc_mac    = base64.b64decode(data['ecc_mac'])
                ecc_plain, ecc_dec_time = ecc_decrypt(eph_pub, ecc_cipher, ecc_mac, self.ecc_private)
            except Exception as e:
                ecc_plain, ecc_dec_time = f"[ECC decrypt error: {e}]", 0.0

            timing = {
                'aes_enc': data.get('aes_enc_time', 0),
                'aes_dec': aes_dec_time,
                'ecc_enc': data.get('ecc_enc_time', 0),
                'ecc_dec': ecc_dec_time,
            }

            if self.on_message:
                self.on_message(sender, aes_plain, timing)

        # ── System message ──
        elif msg_type == 'system':
            if self.on_system:
                self.on_system(data.get('message', ''))

        # ── User list update ──
        elif msg_type == 'user_list':
            if self.on_user_list:
                self.on_user_list(data.get('users', []))


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