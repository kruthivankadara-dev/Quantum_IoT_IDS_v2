import oqs
import hashlib
import os

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

        sender = oqs.KeyEncapsulation(
            self.kem_alg
        )

        ciphertext, shared_secret = sender.encap_secret(
            public_key
        )

        return ciphertext, shared_secret

    # =====================================================
    # Edge decapsulates
    # =====================================================

    def decapsulate(
        self,
        receiver,
        ciphertext
    ):

        shared_secret = receiver.decap_secret(
            ciphertext
        )

        return shared_secret

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