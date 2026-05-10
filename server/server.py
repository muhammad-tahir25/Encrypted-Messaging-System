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
import uuid

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.ecc import generate_ecc_keypair, point_to_bytes, bytes_to_point, private_key_to_bytes, bytes_to_private_key

# ─────────────────────────────────────────────
# SERVER CONFIGURATION
# ─────────────────────────────────────────────

HOST = '127.0.0.1'
PORT = 55555


# ─────────────────────────────────────────────
# SERVER STATE
# ─────────────────────────────────────────────

# { conn: { 'username': str, 'ecc_pub': tuple, 'dh_pub': str } }
clients = {}
clients_lock = threading.Lock()

# NOTE: Server no longer generates or sends any AES key.
# Clients now use DH to compute a shared secret independently.
# That shared secret becomes the AES key on both sides.
# Server never knows the AES key at all.


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

    # ── Step 1: Receive HELLO (username + ECC public key + DH public key) ──
    hello = recv_json(conn)
    if not hello or hello.get('type') != 'hello':
        print(f"[SERVER] Bad handshake from {addr}")
        conn.close()
        return

    username      = hello['username']
    ecc_pub_bytes = base64.b64decode(hello['ecc_pub'])
    ecc_pub       = bytes_to_point(ecc_pub_bytes)
    dh_pub_b64    = hello['dh_pub']

    # ── Check if server is full (max 2 clients) ──
    with clients_lock:
        existing_names = [info['username'] for info in clients.values()]
    if len(existing_names) >= 2:
        send_json(conn, {
            'type': 'error',
            'message': 'Server is full. Only 2 clients are allowed at a time.'
        })
        conn.close()
        print(f"[SERVER] Rejected {username} — server full ({len(existing_names)}/2 clients)")
        return

    # ── Check if username already taken ──
    if username in existing_names:
        send_json(conn, {
            'type': 'error',
            'message': f'Username "{username}" is already taken. Please choose another.'
        })
        conn.close()
        print(f"[SERVER] Rejected duplicate username: {username}")
        return

    # Store client info — no AES key stored here anymore
    with clients_lock:
        clients[conn] = {
            'username': username,
            'ecc_pub':  ecc_pub,
            'dh_pub':   dh_pub_b64,  # store DH public key
            'addr':     addr
        }

    session_id = str(uuid.uuid4())[:8] + "_" + username

    # Collect existing peers ECC + DH public keys to send to new client
    with clients_lock:
        peers = [
            {
                'username': info['username'],
                'ecc_pub':  base64.b64encode(point_to_bytes(info['ecc_pub'])).decode(),
                'dh_pub':   info['dh_pub'],  # include peer DH public key
            }
            for c, info in clients.items() if c != conn
        ]

    # ── Step 2: Send WELCOME — no AES key sent anymore ──
    # Client will compute its own AES key using DH shared secret
    send_json(conn, {
        'type':       'welcome',
        'message':    f'Welcome {username}! You are connected.',
        'session_id': session_id,
        'peers':      peers,
        # no 'aes_key' field — DH handles key agreement now
    })

    # Notify existing clients of new user ECC + DH public keys
    broadcast_message(conn, {
        'type':     'peer_key',
        'username': username,
        'ecc_pub':  base64.b64encode(point_to_bytes(ecc_pub)).decode(),
        'dh_pub':   dh_pub_b64,  # forward new client DH key to existing clients
    })

    print(f"[SERVER] {username} joined — DH public key forwarded to peers")

    # Notify all clients of updated user list + join message
    broadcast_user_list()
    broadcast_message(conn, {
        'type':    'system',
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
            data['sender'] = sender
            broadcast_message(conn, data)

        # ── Key exchange / ECC public key share ──
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
        'type':    'system',
        'message': f'{username} has left the chat.'
    })


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
    print(f"  AES keys computed by clients via DH")
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