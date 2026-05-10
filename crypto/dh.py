# =============================================================
# Diffie-Hellman Key Exchange — Pure Python from Scratch
# Uses a 2048-bit safe prime for strong security
# No third-party libraries used
# =============================================================

import os
import time
import hashlib


# ─────────────────────────────────────────────
# 2048-BIT SAFE PRIME (RFC 3526 Group 14)
# This is a well-known, standardized prime used in
# real-world cryptographic protocols like TLS
# ─────────────────────────────────────────────

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)

DH_GENERATOR = 2  # Standard generator for Group 14


# ─────────────────────────────────────────────
# DIFFIE-HELLMAN CLASS
# ─────────────────────────────────────────────

class DiffieHellman:
    """
    Full Diffie-Hellman key exchange implementation.

    Usage:
        alice = DiffieHellman()
        bob   = DiffieHellman()

        # Exchange public keys
        shared_alice = alice.compute_shared_secret(bob.public_key)
        shared_bob   = bob.compute_shared_secret(alice.public_key)

        # Both shared secrets will be identical
        assert shared_alice == shared_bob
    """

    def __init__(self):
        # Generate a random 256-bit private key
        self.private_key = int.from_bytes(os.urandom(32), 'big')
        # Compute public key: g^private mod p
        self.public_key = pow(DH_GENERATOR, self.private_key, DH_PRIME)
        self._shared_secret = None
        self._derived_key = None

    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """
        Compute shared secret from other party's public key.
        Returns: 32-byte derived key (SHA-256 of shared secret)
        """
        start = time.perf_counter()

        # Shared secret: other_pub^private mod p
        shared_int = pow(other_public_key, self.private_key, DH_PRIME)

        # Convert to bytes and derive key using SHA-256
        shared_bytes = shared_int.to_bytes(256, 'big')
        derived = hashlib.sha256(shared_bytes).digest()

        self._shared_secret = shared_int
        self._derived_key = derived

        end = time.perf_counter()
        self._time_ms = round((end - start) * 1000, 4)

        return derived

    def get_derived_key(self) -> bytes:
        """Return the derived 32-byte AES-compatible key"""
        if self._derived_key is None:
            raise RuntimeError("Call compute_shared_secret() first")
        return self._derived_key

    def get_time_ms(self) -> float:
        return getattr(self, '_time_ms', 0.0)


# ─────────────────────────────────────────────
# SERIALIZATION HELPERS
# ─────────────────────────────────────────────

def public_key_to_bytes(pub: int) -> bytes:
    """Convert DH public key integer to 256 bytes"""
    return pub.to_bytes(256, 'big')

def bytes_to_public_key(data: bytes) -> int:
    """Convert 256 bytes back to DH public key integer"""
    return int.from_bytes(data, 'big')


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Diffie-Hellman Key Exchange Test ===\n")

    print("Generating Alice's key pair...")
    alice = DiffieHellman()
    print(f"Alice public key (first 32 hex): {hex(alice.public_key)[:34]}...")

    print("Generating Bob's key pair...")
    bob = DiffieHellman()
    print(f"Bob public key   (first 32 hex): {hex(bob.public_key)[:34]}...")

    print("\nExchanging public keys and computing shared secrets...")
    alice_key = alice.compute_shared_secret(bob.public_key)
    bob_key   = bob.compute_shared_secret(alice.public_key)

    print(f"\nAlice derived key : {alice_key.hex()}")
    print(f"Bob derived key   : {bob_key.hex()}")
    print(f"\nKeys match        : {alice_key == bob_key} ✓")
    print(f"DH time (Alice)   : {alice.get_time_ms()} ms")
    print(f"DH time (Bob)     : {bob.get_time_ms()} ms")
    print(f"\nDerived key length: {len(alice_key)} bytes (256-bit — AES-256 compatible)")