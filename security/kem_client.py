import os
import sys

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import time
import oqs

from security.gateway_keys import GatewayKeys


class KEMClient:

    KEM_ALGORITHM = "ML-KEM-512"

    def __init__(self, gateway_public_key=None):

        if gateway_public_key is None:
            gateway_public_key = GatewayKeys.load_public_key()

        self.public_key = gateway_public_key

    def encapsulate(self):

        start = time.perf_counter()

        kem = oqs.KeyEncapsulation(self.KEM_ALGORITHM)

        kem_ciphertext, shared_secret = kem.encap_secret(
            self.public_key
        )

        latency = (time.perf_counter() - start) * 1000

        return kem_ciphertext, shared_secret, latency