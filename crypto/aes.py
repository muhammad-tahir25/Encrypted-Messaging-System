# =============================================================
# AES-256 Implementation from Scratch — Pure Python
# No third-party crypto libraries used
# =============================================================

import os
import time

# ─────────────────────────────────────────────
# AES CONSTANTS
# ─────────────────────────────────────────────

# S-Box (Substitution Box)
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Inverse S-Box
INV_S_BOX = [0] * 256
for i, v in enumerate(S_BOX):
    INV_S_BOX[v] = i

# Round constants
RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,0x97,
    0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,
]


# ─────────────────────────────────────────────
# GALOIS FIELD MULTIPLICATION (for MixColumns)
# ─────────────────────────────────────────────

def xtime(a):
    """Multiply by 2 in GF(2^8)"""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def gmul(a, b):
    """Galois Field multiplication"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


# ─────────────────────────────────────────────
# KEY EXPANSION
# ─────────────────────────────────────────────

def key_expansion(key: bytes) -> list:
    """Expand 32-byte key into 240 bytes (15 round keys for AES-256)"""
    assert len(key) == 32, "AES-256 requires a 32-byte key"
    
    Nk = 8   # 32 bytes / 4 = 8 words
    Nr = 14  # AES-256 has 14 rounds
    
    w = []
    for i in range(Nk):
        w.append(list(key[4*i : 4*i+4]))
    
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [S_BOX[b] for b in temp]
            # XOR with Rcon
            temp[0] ^= RCON[i // Nk]
        elif i % Nk == 4:
            temp = [S_BOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    
    # Convert to round keys (each is 4x4 matrix)
    round_keys = []
    for r in range(Nr + 1):
        rk = [w[4*r + c] for c in range(4)]
        round_keys.append(rk)
    return round_keys


# ─────────────────────────────────────────────
# CORE AES OPERATIONS
# ─────────────────────────────────────────────

def add_round_key(state, round_key):
    """XOR state with round key"""
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[c][r]
    return state

def sub_bytes(state):
    """Apply S-Box substitution to every byte"""
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]
    return state

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]
    return state

def shift_rows(state):
    """Cyclically shift rows"""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def mix_columns(state):
    """Mix each column using Galois Field arithmetic"""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gmul(s0,2) ^ gmul(s1,3) ^ s2        ^ s3
        state[1][c] = s0        ^ gmul(s1,2) ^ gmul(s2,3) ^ s3
        state[2][c] = s0        ^ s1         ^ gmul(s2,2) ^ gmul(s3,3)
        state[3][c] = gmul(s0,3) ^ s1        ^ s2         ^ gmul(s3,2)
    return state

def inv_mix_columns(state):
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gmul(s0,0x0e) ^ gmul(s1,0x0b) ^ gmul(s2,0x0d) ^ gmul(s3,0x09)
        state[1][c] = gmul(s0,0x09) ^ gmul(s1,0x0e) ^ gmul(s2,0x0b) ^ gmul(s3,0x0d)
        state[2][c] = gmul(s0,0x0d) ^ gmul(s1,0x09) ^ gmul(s2,0x0e) ^ gmul(s3,0x0b)
        state[3][c] = gmul(s0,0x0b) ^ gmul(s1,0x0d) ^ gmul(s2,0x09) ^ gmul(s3,0x0e)
    return state


# ─────────────────────────────────────────────
# BLOCK ENCRYPT / DECRYPT
# ─────────────────────────────────────────────

def bytes_to_state(block: bytes) -> list:
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state: list) -> bytes:
    return bytes([state[r][c] for c in range(4) for r in range(4)])

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    Nr = 14
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    return state_to_bytes(state)

def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    Nr = 14
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


# ─────────────────────────────────────────────
# PADDING (PKCS#7)
# ─────────────────────────────────────────────

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ─────────────────────────────────────────────
# AES-256 CBC MODE (with IV)
# ─────────────────────────────────────────────

def aes_encrypt(plaintext: str, key: bytes) -> tuple:
    """
    Encrypt plaintext string using AES-256 CBC.
    Returns: (ciphertext_bytes, iv, time_taken_ms)
    """
    start = time.perf_counter()

    round_keys = key_expansion(key)
    iv = os.urandom(16)
    data = pad(plaintext.encode('utf-8'))

    ciphertext = b""
    prev_block = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i+16], prev_block))
        encrypted = aes_encrypt_block(block, round_keys)
        ciphertext += encrypted
        prev_block = encrypted

    end = time.perf_counter()
    time_ms = (end - start) * 1000

    return ciphertext, iv, round(time_ms, 4)


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> tuple:
    """
    Decrypt ciphertext using AES-256 CBC.
    Returns: (plaintext_string, time_taken_ms)
    """
    start = time.perf_counter()

    round_keys = key_expansion(key)
    plaintext = b""
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_decrypt_block(block, round_keys)
        plaintext += bytes(a ^ b for a, b in zip(decrypted, prev_block))
        prev_block = block

    plaintext = unpad(plaintext).decode('utf-8')

    end = time.perf_counter()
    time_ms = (end - start) * 1000

    return plaintext, round(time_ms, 4)


# ─────────────────────────────────────────────
# KEY GENERATION
# ─────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a random 256-bit (32-byte) AES key"""
    return os.urandom(32)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    key = generate_aes_key()
    message = "Hello from AES-256!"

    print("=== AES-256 Test ===")
    print(f"Original  : {message}")

    cipher, iv, enc_time = aes_encrypt(message, key)
    print(f"Encrypted : {cipher.hex()}")
    print(f"Encrypt time: {enc_time} ms")

    decrypted, dec_time = aes_decrypt(cipher, key, iv)
    print(f"Decrypted : {decrypted}")
    print(f"Decrypt time: {dec_time} ms")
    print(f"Match: {message == decrypted} ✓")