# ⬡ Encrypted Chat

A secure, end-to-end encrypted peer-to-peer chat application built entirely from scratch in Python — **no third-party cryptography libraries**.

## Features

- **AES-256 (CBC)** — symmetric encryption implemented from scratch (S-Box, key expansion, MixColumns, PKCS#7 padding)
- **ECC / ECIES** — asymmetric encryption on the `secp256k1` curve (same as Bitcoin), with HMAC-based message authentication
- **Diffie-Hellman key exchange** — AES session key derived from DH shared secret; the server **never sees the AES key**
- **Persistent key storage** — ECC key pairs and DH sessions stored in a local SQLite database
- **PyQt5 GUI** — dark-themed chat window with real-time encryption timing displayed per message
- **Multi-client server** — TCP socket server supporting multiple concurrent users

## Project Structure

```
.
├── main.py                 # Entry point — launches the GUI
├── requirements.txt
├── client/
│   └── client.py           # Networking, handshake, encrypt/decrypt logic
├── crypto/
│   ├── aes.py              # AES-256 CBC from scratch
│   ├── dh.py               # Diffie-Hellman key exchange
│   └── ecc.py              # ECC (secp256k1) / ECIES from scratch
├── database/
│   └── key_storage.py      # SQLite key persistence
├── gui/
│   └── chat_window.py      # PyQt5 chat UI
└── server/
    └── server.py           # TCP socket server
```

## How It Works

1. **On connect**, each client sends its ECC public key and DH public key to the server.
2. The server relays these to peers; each client **independently computes the DH shared secret** and uses it as the AES key.
3. Every message is encrypted with **both AES-256 and ECC** before transmission.
4. The GUI shows per-message encryption/decryption timings for both algorithms.

## Installation

```bash
git clone https://github.com/muhammad-tahir25/encrypted-chat.git
cd encrypted-chat
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

**Start the server:**
```bash
python server/server.py
```

**Start a client (run in separate terminals):**
```bash
python main.py
```

Each client will prompt for a username. Open two terminals to test a full conversation.

## Requirements

- Python 3.8+
- PyQt5

> All cryptographic primitives (AES, ECC, DH) are implemented in pure Python for educational purposes. Do not use this in production environments.

## Security Notes

- The server acts only as a relay — it never has access to plaintext or AES keys.
- ECC keys are persisted per-username in a local SQLite database (excluded from git via `.gitignore`).
- Do not commit `*.db` files — they contain private keys.

## License

MIT
```
