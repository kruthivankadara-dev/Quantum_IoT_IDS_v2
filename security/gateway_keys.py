import os
import oqs


class GatewayKeys:
    """
    Handles persistent ML-KEM-512 key generation
    for the Edge Gateway.
    """

    BASE_DIR = os.path.dirname(__file__)

    PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "gateway_public.key")
    PRIVATE_KEY_FILE = os.path.join(BASE_DIR, "gateway_private.key")

    KEM_ALGORITHM = "ML-KEM-512"

    @classmethod
    def initialize(cls):

        if (
            os.path.exists(cls.PUBLIC_KEY_FILE)
            and
            os.path.exists(cls.PRIVATE_KEY_FILE)
        ):

            print("[PQC] Existing Gateway Keys Loaded")
            return

        print("[PQC] Generating Gateway ML-KEM-512 Keypair...")

        kem = oqs.KeyEncapsulation(cls.KEM_ALGORITHM)

        public_key = kem.generate_keypair()

        private_key = kem.export_secret_key()

        with open(cls.PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key)

        with open(cls.PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key)

        print("[PQC] Gateway Keys Generated")

    @classmethod
    def load_public_key(cls):

        with open(cls.PUBLIC_KEY_FILE, "rb") as f:
            return f.read()

    @classmethod
    def load_private_key(cls):

        with open(cls.PRIVATE_KEY_FILE, "rb") as f:
            return f.read()