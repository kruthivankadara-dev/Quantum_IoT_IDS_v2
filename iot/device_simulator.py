import pandas as pd
import requests
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from security.kem_client import KEMClient
from security.aes_session import derive_session_key, encrypt_packet

EDGE_URL = "http://localhost:5001/scan"
DATASET = "dataset/CICIOT23/test/test.csv"

DEVICES = [
    "camera01",
    "doorlock01",
    "motionsensor01",
    "thermostat01",
    "smartplug01"
]

WINDOW_SIZE = 10
MAX_PACKETS = 100 # Change this to test more packets

print("[IOT] Loading Test Dataset...")
df = pd.read_csv(DATASET).reset_index(drop=True)

# Only use the first MAX_PACKETS rows
df = df.sample(n=100, random_state=42).reset_index(drop=True)


FEATURE_COLUMNS = [c for c in df.columns if c != "label"]

actuals = []
predictions = []

kem_client = KEMClient()

print(f"\nTesting on {len(df)} rows...")
print(f"Window Size: {WINDOW_SIZE}\n")

for i in range(WINDOW_SIZE - 1, len(df)):

    window = df[FEATURE_COLUMNS].iloc[
        i - WINDOW_SIZE + 1:i + 1
    ].values.tolist()

    actual_label = df.iloc[i]["label"]

    packet = {
        "packet_window": window
    }

    try:
        kem_ciphertext, shared_secret, _ = kem_client.encapsulate()

        session_key = derive_session_key(shared_secret)

        nonce, ciphertext = encrypt_packet(
            packet,
            session_key
        )

        payload = {
            "device_id": DEVICES[i % len(DEVICES)],
            "status": "ACTIVE",
            "attack_count": 0,
            "kem_ciphertext": kem_ciphertext.hex(),
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "actual_label": actual_label
        }

        r = requests.post(
            EDGE_URL,
            json=payload,
            timeout=15
        )

        result = r.json()

        pred = result.get("status", "").lower()

        if actual_label == "BenignTraffic":
            actuals.append("Benign")
        else:
            actuals.append("Attack")

        if pred in [
            "temporary_isolation",
            "permanent_block",
            "reject",
            "attack"
        ]:
            predictions.append("Attack")
        else:
            predictions.append("Benign")

        print(
            f"[{i+1}/{len(df)}]",
            payload["device_id"],
            "GT:",
            actuals[-1],
            "Pred:",
            predictions[-1]
        )

    except Exception as e:
        print(f"[ERROR] Packet {i}: {e}")

