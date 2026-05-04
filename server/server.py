# =============================================================
# Multi-Client Chat Server
# Handles connections, key exchange, and message routing
# =============================================================

import socket
import threading
import json
import base64
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.ecc import generate_ecc_keypair, point_to_bytes, bytes_to_point, private_key_to_bytes, bytes_to_private_key
from crypto.aes import generate_aes_key

# ─────────────────────────────────────────────
# SERVER CONFIGURATION
# ─────────────────────────────────────────────

HOST = '127.0.0.1'
PORT = 55555


# ─────────────────────────────────────────────
# SERVER STATE
# ─────────────────────────────────────────────

clients = {}        # { conn: { 'username': str, 'ecc_pub': tuple, 'aes_key': bytes } }
clients_lock = threading.Lock()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def send_json(conn, data: dict):
    """Send a JSON message over socket"""
    try:
        msg = json.dumps(data).encode('utf-8')
        length = len(msg).to_bytes(4, 'big')
        conn.sendall(length + msg)
    except Exception as e:
        print(f"[SERVER] Send error: {e}")


def recv_json(conn) -> dict:
    """Receive a JSON message from socket"""
    try:
        raw_len = conn.recv(4)
        if not raw_len:
            return None
        msg_len = int.from_bytes(raw_len, 'big')
        data = b""
        while len(data) < msg_len:
            chunk = conn.recv(min(4096, msg_len - len(data)))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None


def get_username(conn) -> str:
    with clients_lock:
        info = clients.get(conn)
        return info['username'] if info else 'Unknown'


def broadcast_user_list():
    """Send updated user list to all connected clients"""
    with clients_lock:
        usernames = [info['username'] for info in clients.values()]
    for conn in list(clients.keys()):
        send_json(conn, {
            'type': 'user_list',
            'users': usernames
        })


def broadcast_message(sender_conn, data: dict):
    """Send a message to all clients except sender"""
    with clients_lock:
        targets = [c for c in clients if c != sender_conn]
    for conn in targets:
        send_json(conn, data)


# ─────────────────────────────────────────────
# CLIENT HANDLER
# ─────────────────────────────────────────────

def handle_client(conn, addr):
    print(f"[SERVER] New connection from {addr}")

    # ── Step 1: Receive HELLO (username + ECC public key) ──
    hello = recv_json(conn)
    if not hello or hello.get('type') != 'hello':
        print(f"[SERVER] Bad handshake from {addr}")
        conn.close()
        return

    username = hello['username']
    ecc_pub_bytes = base64.b64decode(hello['ecc_pub'])
    ecc_pub = bytes_to_point(ecc_pub_bytes)

    # ── Step 2: Generate & send a shared AES session key ──
    aes_key = generate_aes_key()

    # Store client info
    with clients_lock:
        clients[conn] = {
            'username': username,
            'ecc_pub': ecc_pub,
            'aes_key': aes_key,
            'addr': addr
        }

    # Send welcome + AES key to this client
    send_json(conn, {
        'type': 'welcome',
        'message': f'Welcome {username}! You are connected.',
        'aes_key': base64.b64encode(aes_key).decode()
    })

    print(f"[SERVER] {username} joined from {addr}")

    # Notify all clients of new user
    broadcast_user_list()
    broadcast_message(conn, {
        'type': 'system',
        'message': f'{username} has joined the chat!'
    })

    # ── Step 3: Message loop ──
    while True:
        data = recv_json(conn)
        if data is None:
            break

        msg_type = data.get('type')

        # ── Regular chat message ──
        if msg_type == 'message':
            sender = get_username(conn)
            print(f"[SERVER] Message from {sender}")

            # Forward full payload (with timing info) to all other clients
            data['sender'] = sender
            broadcast_message(conn, data)

        # ── Key exchange request (ECC public key share) ──
        elif msg_type == 'key_share':
            sender = get_username(conn)
            data['sender'] = sender
            broadcast_message(conn, data)

        # ── Ping / keep-alive ──
        elif msg_type == 'ping':
            send_json(conn, {'type': 'pong'})

    # ── Client disconnected ──
    username = get_username(conn)
    with clients_lock:
        clients.pop(conn, None)
    conn.close()

    print(f"[SERVER] {username} disconnected")
    broadcast_user_list()
    broadcast_message(None, {
        'type': 'system',
        'message': f'{username} has left the chat.'
    })


# ─────────────────────────────────────────────
# BROADCAST (allow None sender for system msgs)
# ─────────────────────────────────────────────

def broadcast_message(sender_conn, data: dict):
    """Send a message to all clients except sender"""
    with clients_lock:
        targets = [c for c in clients if c != sender_conn]
    for conn in targets:
        send_json(conn, data)


# ─────────────────────────────────────────────
# MAIN SERVER LOOP
# ─────────────────────────────────────────────

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)

    print("=" * 50)
    print(f"  Encrypted Chat Server started")
    print(f"  Listening on {HOST}:{PORT}")
    print(f"  Waiting for clients...")
    print("=" * 50)

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
            print(f"[SERVER] Active connections: {threading.active_count() - 1}")
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()