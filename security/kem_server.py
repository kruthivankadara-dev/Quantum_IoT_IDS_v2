import oqs
import time

from security.gateway_keys import GatewayKeys


class KEMServer:

    KEM_ALGORITHM = "ML-KEM-512"

    def __init__(self):

        self.private_key = GatewayKeys.load_private_key()

    def decapsulate(self, kem_ciphertext: bytes):

        start = time.perf_counter()

        kem = oqs.KeyEncapsulation(
            self.KEM_ALGORITHM,
            secret_key=self.private_key
        )

        shared_secret = kem.decap_secret(
            kem_ciphertext
        )

        latency = (time.perf_counter() - start) * 1000

        return shared_secret, latency