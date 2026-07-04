import json
import hashlib
import oqs


class EvidenceSecurity:
    """
    Responsible for securing the Evidence Object.

    Operations:
    -----------
    1. Canonical JSON serialization
    2. SHA-256 hashing
    3. ML-DSA-65 signing
    """

    SIGNATURE_ALGORITHM = "ML-DSA-65"

    def __init__(self):

        self.signer = oqs.Signature(
            self.SIGNATURE_ALGORITHM
        )

        self.public_key = self.signer.generate_keypair()

        self.private_key = self.signer.export_secret_key()

    def create_signed_evidence(self, evidence: dict):

        # Canonical JSON
        evidence_json = json.dumps(

            evidence,

            sort_keys=True,

            separators=(",", ":")

        )

        evidence_bytes = evidence_json.encode()

        # SHA-256
        evidence_hash = hashlib.sha256(
            evidence_bytes
        ).hexdigest()

        # ML-DSA Signature
        signature = self.signer.sign(
            evidence_bytes
        )

        return {

            "evidence": evidence,

            "evidence_hash": evidence_hash,

            "signature": signature.hex(),

            "public_key": self.public_key.hex()

        }