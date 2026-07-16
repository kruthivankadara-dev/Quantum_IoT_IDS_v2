import os
import oqs


class GatewayDSAKeys:

    SIGNATURE_ALGORITHM = "ML-DSA-65"

    BASE_DIR = os.path.dirname(__file__)

    PUBLIC_KEY_FILE = os.path.join(
        BASE_DIR,
        "gateway_dsa_public.key"
    )

    PRIVATE_KEY_FILE = os.path.join(
        BASE_DIR,
        "gateway_dsa_private.key"
    )

    @classmethod
    def initialize(cls):

        if (
            os.path.exists(cls.PUBLIC_KEY_FILE)
            and
            os.path.exists(cls.PRIVATE_KEY_FILE)
        ):

            print("[ML-DSA] Existing Gateway Signing Keys Loaded")
            return

        print("[ML-DSA] Generating Gateway Signing Keys...")

        signer = oqs.Signature(
            cls.SIGNATURE_ALGORITHM
        )

        public_key = signer.generate_keypair()

        private_key = signer.export_secret_key()

        with open(cls.PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key)

        with open(cls.PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key)

        print("[ML-DSA] Gateway Signing Keys Generated")

    @classmethod
    def load_public_key(cls):

        with open(cls.PUBLIC_KEY_FILE, "rb") as f:
            return f.read()

    @classmethod
    def load_private_key(cls):

        with open(cls.PRIVATE_KEY_FILE, "rb") as f:
            return f.read()