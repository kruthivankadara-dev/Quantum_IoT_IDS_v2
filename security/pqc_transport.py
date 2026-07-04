import oqs
import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PQCTransport:

    def __init__(self):

        self.kem_alg = "ML-KEM-512"

    # =====================================================
    # Edge creates a keypair
    # =====================================================

    def generate_keypair(self):

        receiver = oqs.KeyEncapsulation(
            self.kem_alg
        )

        public_key = receiver.generate_keypair()

        return receiver, public_key

    # =====================================================
    # IoT encapsulates
    # =====================================================

    def encapsulate(
        self,
        public_key
    ):

        start = time.perf_counter()

        sender = oqs.KeyEncapsulation(
            self.kem_alg
        )

        ciphertext, shared_secret = sender.encap_secret(
            public_key
        )

        latency = (time.perf_counter() - start) * 1000

        return ciphertext, shared_secret, latency

    # =====================================================
    # Edge decapsulates
    # =====================================================

    def decapsulate(
        self,
        receiver,
        ciphertext
    ):

        start = time.perf_counter()

        shared_secret = receiver.decap_secret(
            ciphertext
        )

        latency = (time.perf_counter() - start) * 1000

        return shared_secret, latency

    # =====================================================
    # AES-256 Key
    # =====================================================

    def derive_key(
        self,
        shared_secret
    ):

        return hashlib.sha256(
            shared_secret
        ).digest()

    # =====================================================
    # Encrypt
    # =====================================================

    def encrypt(
        self,
        key,
        plaintext
    ):

        aes = AESGCM(key)

        nonce = os.urandom(12)

        ciphertext = aes.encrypt(
            nonce,
            plaintext,
            None
        )

        return nonce, ciphertext

    # =====================================================
    # Decrypt
    # =====================================================

    def decrypt(
        self,
        key,
        nonce,
        ciphertext
    ):

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext