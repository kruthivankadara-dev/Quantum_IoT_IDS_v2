import os
import sys

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import time
import pandas as pd
import requests

from security.kem_client import KEMClient
from security.aes_session import (
    derive_session_key,
    encrypt_packet
)


EDGE_URL = "http://localhost:5001/scan"

DATASET = "dataset/CICIOT23/train/train.csv"

DEVICES = [
    "camera01",
    "doorlock01",
    "motionsensor01",
    "thermostat01",
    "smartplug01"
]

WINDOW_SIZE = 5

# Initialize PQC Client
kem_client = KEMClient()

print("\n[IOT] Loading Dataset...")

df = pd.read_csv(DATASET)

print(f"[IOT] Dataset Shape = {df.shape}")

# ==========================================
# SELECT TEST SET
# ==========================================

benign_df = df[
    df["label"] == "BenignTraffic"
].sample(
    n=30,
    random_state=42
)

attack_df = df[
    df["label"] != "BenignTraffic"
].sample(
    n=20,
    random_state=42
)

test_df = pd.concat(
    [
        benign_df,
        attack_df
    ]
).sample(
    frac=1,
    random_state=42
).reset_index(
    drop=True
)

print(f"[IOT] Total Test Packets = {len(test_df)}")

# ==========================================
# FEATURES
# ==========================================

FEATURE_COLUMNS = [
    col
    for col in test_df.columns
    if col != "label"
]

print(f"[IOT] Feature Count = {len(FEATURE_COLUMNS)}")

# ==========================================
# SEND SLIDING WINDOWS
# ==========================================

for i in range(WINDOW_SIZE - 1, len(test_df)):

    # Create sliding window
    window = (
        test_df[FEATURE_COLUMNS]
        .iloc[
            i - WINDOW_SIZE + 1 : i + 1
        ]
        .values
        .tolist()
    )

    device_id = DEVICES[
        i % len(DEVICES)
    ]

    actual_label = test_df.iloc[i]["label"]

    packet = {

        "device_id": device_id,

        "packet_window": window,

        "actual_label": actual_label

    }

    try:

        print("\n==============================")
        print("        IoT Device")
        print("==============================")

        print(f"Device : {device_id}")

        print("\nCreating Telemetry Packet...")
        print("SUCCESS")

        print("\nObtaining Edge Public Key...")

        kem_ciphertext, shared_secret, kem_time = kem_client.encapsulate()

        print("SUCCESS")

        print(f"\nML-KEM Encapsulation Time : {kem_time:.3f} ms")
        print("SUCCESS")

        session_key = derive_session_key(
            shared_secret
        )

        print("\nShared Secret Established")
        print("SUCCESS")

        nonce, ciphertext = encrypt_packet(
            packet,
            session_key
        )

        print("\nAES-256-GCM Encryption...")
        print("SUCCESS")

        print(f"\nEncrypted Packet Size : {len(ciphertext)} bytes")
        print(f"Nonce Size            : {len(nonce)} bytes")
        print(f"KEM Ciphertext Size   : {len(kem_ciphertext)} bytes")

        secure_payload = {

            "device_id": device_id,

            "kem_ciphertext": kem_ciphertext.hex(),

            "nonce": nonce.hex(),

            "ciphertext": ciphertext.hex()

        }

        print("\nSending Secure Packet...")
        print("SUCCESS")

        response = requests.post(

            EDGE_URL,

            json=secure_payload,

            timeout=10

        )

        print()

        print(
            f"[{device_id}]",
            response.json()
        )

    except requests.exceptions.ConnectionError:

        print("\n[ERROR] Edge Gateway is Offline.")
        print("Please start edge_gateway.py")
        break

    except KeyboardInterrupt:

        print("\n==============================")
        print(" IoT Simulation Stopped ")
        print("==============================")
        break

    except Exception as e:

        print("[IOT ERROR]", str(e))
        break

    time.sleep(1)

print()
print("==============================")
print(" IoT Simulation Completed ")
print("==============================")