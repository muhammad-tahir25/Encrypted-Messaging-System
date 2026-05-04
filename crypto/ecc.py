# =============================================================
# Elliptic Curve Cryptography (ECC) — Pure Python from Scratch
# Curve: secp256k1 (same curve used in Bitcoin)
# Scheme: ECIES (Elliptic Curve Integrated Encryption Scheme)
# No third-party crypto libraries used
# =============================================================

import os
import time
import hashlib
import hmac


# ─────────────────────────────────────────────
# secp256k1 CURVE PARAMETERS
# ─────────────────────────────────────────────

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (Gx, Gy)   # Generator point


# ─────────────────────────────────────────────
# MODULAR ARITHMETIC HELPERS
# ─────────────────────────────────────────────

def mod_inv(a, m):
    """Extended Euclidean Algorithm — modular inverse"""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0")
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        lm, hm = hm - lm * ratio, lm
        low, high = high - low * ratio, low
    return lm % m


# ─────────────────────────────────────────────
# ELLIPTIC CURVE POINT OPERATIONS
# ─────────────────────────────────────────────

def point_add(P1, P2):
    """Add two points on the elliptic curve"""
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2:
        if y1 != y2:
            return None  # Point at infinity
        # Point doubling
        lam = (3 * x1 * x1 + A) * mod_inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point):
    """Scalar multiplication using double-and-add"""
    result = None   # Point at infinity (identity element)
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


# ─────────────────────────────────────────────
# KEY GENERATION
# ─────────────────────────────────────────────

def generate_ecc_keypair():
    """
    Generate ECC key pair on secp256k1.
    Returns: (private_key_int, public_key_point)
    """
    private_key = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
    public_key = point_mul(private_key, G)
    return private_key, public_key


# ─────────────────────────────────────────────
# KEY DERIVATION (for symmetric encryption)
# ─────────────────────────────────────────────

def derive_key(shared_point) -> bytes:
    """Derive 32-byte symmetric key from shared EC point using SHA-256"""
    x_bytes = shared_point[0].to_bytes(32, 'big')
    return hashlib.sha256(x_bytes).digest()


# ─────────────────────────────────────────────
# SIMPLE XOR STREAM CIPHER (using derived key)
# ─────────────────────────────────────────────

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR-based stream cipher using SHA-256 key expansion.
    Used as the symmetric layer inside ECIES.
    """
    keystream = b""
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest()
        keystream += block
        counter += 1
    return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))


# ─────────────────────────────────────────────
# HMAC FOR MESSAGE AUTHENTICATION
# ─────────────────────────────────────────────

def compute_mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_mac(key: bytes, data: bytes, mac: bytes) -> bool:
    return hmac.compare_digest(compute_mac(key, data), mac)


# ─────────────────────────────────────────────
# ECIES ENCRYPT
# ─────────────────────────────────────────────

def ecc_encrypt(plaintext: str, recipient_public_key: tuple) -> tuple:
    """
    Encrypt a message using ECIES:
    1. Generate ephemeral key pair
    2. Compute shared secret via ECDH
    3. Derive symmetric key from shared secret
    4. Encrypt message with XOR stream cipher
    5. Add HMAC for integrity

    Returns: (ephemeral_public_key, ciphertext, mac, time_ms)
    """
    start = time.perf_counter()

    # Step 1: Ephemeral key pair
    eph_priv, eph_pub = generate_ecc_keypair()

    # Step 2: Shared secret (ECDH)
    shared_point = point_mul(eph_priv, recipient_public_key)
    shared_key = derive_key(shared_point)

    # Step 3: Split key → enc_key + mac_key
    enc_key = hashlib.sha256(shared_key + b"enc").digest()
    mac_key = hashlib.sha256(shared_key + b"mac").digest()

    # Step 4: Encrypt
    data = plaintext.encode('utf-8')
    ciphertext = xor_encrypt(data, enc_key)

    # Step 5: MAC
    mac = compute_mac(mac_key, ciphertext)

    end = time.perf_counter()
    time_ms = round((end - start) * 1000, 4)

    return eph_pub, ciphertext, mac, time_ms


# ─────────────────────────────────────────────
# ECIES DECRYPT
# ─────────────────────────────────────────────

def ecc_decrypt(eph_pub: tuple, ciphertext: bytes, mac: bytes,
                recipient_private_key: int) -> tuple:
    """
    Decrypt an ECIES-encrypted message.
    Returns: (plaintext_string, time_ms)
    """
    start = time.perf_counter()

    # Recompute shared secret
    shared_point = point_mul(recipient_private_key, eph_pub)
    shared_key = derive_key(shared_point)

    enc_key = hashlib.sha256(shared_key + b"enc").digest()
    mac_key = hashlib.sha256(shared_key + b"mac").digest()

    # Verify MAC
    if not verify_mac(mac_key, ciphertext, mac):
        raise ValueError("MAC verification failed — message tampered!")

    # Decrypt
    plaintext = xor_encrypt(ciphertext, enc_key).decode('utf-8')

    end = time.perf_counter()
    time_ms = round((end - start) * 1000, 4)

    return plaintext, time_ms


# ─────────────────────────────────────────────
# SERIALIZE / DESERIALIZE HELPERS
# ─────────────────────────────────────────────

def point_to_bytes(point: tuple) -> bytes:
    """Convert EC point to 64 bytes"""
    x, y = point
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def bytes_to_point(data: bytes) -> tuple:
    """Convert 64 bytes back to EC point"""
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:], 'big')
    return (x, y)

def private_key_to_bytes(priv: int) -> bytes:
    return priv.to_bytes(32, 'big')

def bytes_to_private_key(data: bytes) -> int:
    return int.from_bytes(data, 'big')


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=== ECC (secp256k1 / ECIES) Test ===")

    priv, pub = generate_ecc_keypair()
    print(f"Private key: {hex(priv)[:20]}...")
    print(f"Public key:  ({hex(pub[0])[:16]}..., {hex(pub[1])[:16]}...)")

    message = "Hello from ECC!"
    print(f"\nOriginal: {message}")

    eph_pub, cipher, mac, enc_time = ecc_encrypt(message, pub)
    print(f"Encrypted (hex): {cipher.hex()}")
    print(f"Encrypt time: {enc_time} ms")

    decrypted, dec_time = ecc_decrypt(eph_pub, cipher, mac, priv)
    print(f"Decrypted: {decrypted}")
    print(f"Decrypt time: {dec_time} ms")
    print(f"Match: {message == decrypted} ✓")