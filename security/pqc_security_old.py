import oqs
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PQCSecurity:

    def __init__(self):

        self.kem_alg = "ML-KEM-512"
        self.sig_alg = "ML-DSA-65"

        print(
            f"[PQC] Initialized "
            f"KEM={self.kem_alg} "
            f"SIG={self.sig_alg}"
        )

    def secure_packet(self, packet_bytes):

        print(
            "\n[PQC] Starting Secure Packet Processing"
        )

        # =====================================
        # ML-KEM KEY EXCHANGE
        # =====================================

        server = oqs.KeyEncapsulation(
            self.kem_alg
        )

        server_pk = server.generate_keypair()

        client = oqs.KeyEncapsulation(
            self.kem_alg
        )

        ciphertext, client_secret = (
            client.encap_secret(
                server_pk
            )
        )

        server_secret = (
            server.decap_secret(
                ciphertext
            )
        )

        print(
            "[PQC] ML-KEM-512 Key Exchange Complete"
        )

        # =====================================
        # AES-256-GCM ENCRYPTION
        # =====================================

        aes_key = hashlib.sha256(
            server_secret
        ).digest()

        aes = AESGCM(aes_key)

        nonce = os.urandom(12)

        encrypted_packet = aes.encrypt(
            nonce,
            packet_bytes,
            None
        )

        print(
            "[PQC] AES-256-GCM Encryption Complete"
        )

        # =====================================
        # ML-DSA SIGNATURE
        # =====================================

        signer = oqs.Signature(
            self.sig_alg
        )

        public_key = (
            signer.generate_keypair()
        )

        signature = signer.sign(
            encrypted_packet
        )

        print(
            "[PQC] ML-DSA-65 Signature Generated"
        )

        # =====================================
        # DEBUG INFORMATION
        # =====================================

        print(
            f"[PQC] Original Packet Size = "
            f"{len(packet_bytes)} bytes"
        )

        print(
            f"[PQC] Ciphertext Size = "
            f"{len(ciphertext)} bytes"
        )

        print(
            f"[PQC] Encrypted Packet Size = "
            f"{len(encrypted_packet)} bytes"
        )

        print(
            f"[PQC] Public Key Size = "
            f"{len(public_key)} bytes"
        )

        print(
            f"[PQC] Signature Size = "
            f"{len(signature)} bytes"
        )

        print(
            "[PQC] Secure Packet Processing Complete\n"
        )

        return {

            "encrypted_packet":
            encrypted_packet,

            "signature":
            signature,

            "public_key":
            public_key,

            "nonce":
            nonce
        }