import os
import sys

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, request, jsonify

import torch
import torch.nn as nn

import numpy as np

import requests

import threading
import random
import time
import hashlib
import io
import os
import sys
import joblib
import warnings

from security.kem_server import KEMServer
from security.aes_session import (
    derive_session_key,
    decrypt_packet
)
from security.evidence_security import EvidenceSecurity


warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names"
)

sys.path.append(
    os.path.abspath(".")
)

from shared.model import CNNLSTMModel
from shared.autoencoder import AutoEncoder
from shared.config import *

from edge.device_registry import DeviceRegistry

# ===========================
# APP
# ===========================

app = Flask(__name__)

# ===========================
# PQC
# ===========================
from security.gateway_keys import GatewayKeys
registry = DeviceRegistry()
GatewayKeys.initialize()
evidence_security = EvidenceSecurity()
kem_server = KEMServer()

# ===========================
# LOAD CNN-LSTM
# ===========================

print("\n[EDGE] Loading CNN-LSTM...")

edge_model = CNNLSTMModel()

edge_model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location="cpu"
    )
)

edge_model.eval()

# ===========================
# LOAD AUTOENCODER
# ===========================

print("[EDGE] Loading Autoencoder...")

autoencoder = AutoEncoder()

autoencoder.load_state_dict(
    torch.load(
        AUTOENCODER_PATH,
        map_location="cpu"
    )
)

autoencoder.eval()

# ===========================
# LOAD SCALER
# ===========================

print("[EDGE] Loading Scaler...")

scaler = joblib.load(
    SCALER_PATH
)

CURRENT_VERSION = 1

print("[EDGE] Ready")

# ===========================
# THREAD LOCK
# ===========================

buffer_lock = threading.Lock()

# ===========================
# STREAMING STATISTICS
# Welford Algorithm
# ===========================

packet_count = 0

running_mean = np.zeros(FEATURE_COUNT)

running_m2 = np.zeros(FEATURE_COUNT)

running_min = np.full(
    FEATURE_COUNT,
    np.inf
)

running_max = np.full(
    FEATURE_COUNT,
    -np.inf
)

# ===========================
# RESERVOIR SAMPLING
# ===========================

reservoir = []

# ===========================
# CLOUD RETRY QUEUE
# ===========================

retry_queue = []

# ===========================
# LAST SUMMARY
# ===========================

last_summary_time = time.time()

# ===========================
# UPDATE STREAMING STATS
# ===========================

def update_statistics(features):

    global packet_count
    global running_mean
    global running_m2
    global running_min
    global running_max

    packet_count += 1

    delta = features - running_mean

    running_mean += delta / packet_count

    delta2 = features - running_mean

    running_m2 += delta * delta2

    running_min = np.minimum(
        running_min,
        features
    )

    running_max = np.maximum(
        running_max,
        features
    )

# ===========================
# RESERVOIR SAMPLE
# ===========================

def reservoir_sample(packet):

    global reservoir
    global packet_count

    if len(reservoir) < RESERVOIR_SIZE:

        reservoir.append(packet)

    else:

        idx = random.randint(
            0,
            packet_count - 1
        )

        if idx < RESERVOIR_SIZE:

            reservoir[idx] = packet

# ===========================
# RESET SUMMARY
# ===========================

def reset_statistics():

    global packet_count
    global running_mean
    global running_m2
    global running_min
    global running_max
    global reservoir

    packet_count = 0

    running_mean = np.zeros(
        FEATURE_COUNT
    )

    running_m2 = np.zeros(
        FEATURE_COUNT
    )

    running_min = np.full(
        FEATURE_COUNT,
        np.inf
    )

    running_max = np.full(
        FEATURE_COUNT,
        -np.inf
    )

    reservoir = []

# ===========================
# COMPUTE SUMMARY
# ===========================

def create_summary():

    global packet_count

    if packet_count == 0:

        return None

    std = np.sqrt(
        running_m2 /
        max(packet_count-1,1)
    )

    summary = {

        "type":"benign_summary",

        "packet_count":
        packet_count,

        "mean":
        running_mean.tolist(),

        "std":
        std.tolist(),

        "min":
        running_min.tolist(),

        "max":
        running_max.tolist(),

        "samples":
        reservoir
    }

    return summary

# ===========================
# SEND SUMMARY
# ===========================

def send_summary():

    global last_summary_time

    while True:

        time.sleep(5)

        now = time.time()

        with buffer_lock:

            timeout = (
                now-last_summary_time
                >= SUMMARY_INTERVAL
            )

            full = (
                packet_count
                >= MAX_BENIGN_PACKETS
            )

            if not timeout and not full:
                continue

            summary = create_summary()

            if summary is None:

                continue

            try:

                requests.post(

                    f"http://localhost:{CLOUD_PORT}/retrain",

                    json=summary,

                    timeout=10
                )

                print(
                    "[EDGE] Benign Summary Uploaded"
                )

                reset_statistics()

                last_summary_time = time.time()

            except Exception:

                retry_queue.append(
                    summary
                )

                print(
                    "[EDGE] Cloud Offline"
                )

# ===========================
# START THREAD
# ===========================

threading.Thread(

    target=send_summary,

    daemon=True

).start()

# ===========================
# SCAN API
# ===========================

@app.route(

    "/scan",

    methods=["POST"]

)
def scan():

    global CURRENT_VERSION

    data = request.json

    device_id = data.get("device_id", "unknown")

    status = data.get("status", "UNKNOWN")

    attack_count = data.get("attack_count", 0)

    print()

    print("==============================")

    print(f"[EDGE] Device : {device_id}")

    print(f"[EDGE] Status : {status}")

    print(f"[EDGE] Attack Count : {attack_count}")

    print("==============================")

    device_id = data.get("device_id","unknown_device")
    registry.update_seen(device_id)

    print("\n==================================================")
    print("TRUST LOOKUP")
    print("==================================================")

    trust_state = registry.get_trust_state(device_id)

    device = registry.get_device(device_id)

    print(f"Device ID        : {device_id}")
    print(f"Trust State      : {trust_state}")
    print(f"Previous Attacks : {device['attack_count']}")

    if registry.is_revoked(device_id):

        print("\nDecision         : Reject Immediately")

        print("Reason           : Device Permanently Revoked")

        return jsonify({

             "status":"revoked",

              "device":device_id,

              "message":"Device permanently blocked"

        }), BLOCK_RESPONSE_CODE

    print("\nDecision         : Continue to AI Engine")

    # ==========================================
    # AES-256-GCM DECRYPTION
    # ==========================================

    kem_ciphertext = bytes.fromhex(
    data["kem_ciphertext"]
    )  

    ciphertext = bytes.fromhex(
       data["ciphertext"]
    )

    nonce = bytes.fromhex(
       data["nonce"]
    )

    shared_secret = kem_server.decapsulate(kem_ciphertext)

    session_key = derive_session_key(shared_secret)

    packet = decrypt_packet(
    ciphertext=ciphertext,
    nonce=nonce,
    session_key=session_key
    )

    packet_window = packet["packet_window"]


# ===========================
# edge_gateway.py
# PART 2
# ===========================
    # ===========================
    # PREPROCESS INPUT WINDOW
    # ===========================

    packet_window = packet["packet_window"]

    scaled_packet = scaler.transform(
    packet_window
    )

    # ===========================
    # AUTOENCODER
    # ===========================

    flat_packet = np.array(
        scaled_packet
    ).reshape(-1)

    flat_packet_tensor = torch.tensor(
        flat_packet,
        dtype=torch.float32
    ).view(
        1,
        WINDOW_SIZE * FEATURE_COUNT
    )

    with torch.no_grad():

        reconstructed = autoencoder(
            flat_packet_tensor
        )

        reconstruction_error = torch.mean(

            (
                flat_packet_tensor -
                reconstructed

            ) ** 2

        ).item()

    # ===========================
    # CNN-LSTM
    # ===========================

    x = torch.tensor(

        scaled_packet,

        dtype=torch.float32

    ).view(

        1,

        WINDOW_SIZE,

        FEATURE_COUNT

    )

    with torch.no_grad():

        threat_score = edge_model(
            x
        ).item()

    print(
        f"[EDGE] Threat Score : {threat_score:.4f}"
    )

    print(
        f"[EDGE] Reconstruction Error : {reconstruction_error:.6f}"
    )

    # ===========================
    # BENIGN TRAFFIC
    # ===========================

    if (

        threat_score < THREAT_THRESHOLD

        and

        reconstruction_error < RECONSTRUCTION_THRESHOLD

    ):

        features = np.mean(

            scaled_packet,

            axis=0

        )

        with buffer_lock:

            update_statistics(
                features
            )

            reservoir_sample(
                packet_window
            )

        if PRINT_BENIGN:

            print(

                "[EDGE] Benign Packet Stored"

            )
            print("\n==================================================")
            print("SELF HEALING")
            print("==================================================")

            registry.record_clean_window(device_id)

            updated = registry.get_device(device_id)

            print(f"Trust State      : {updated['trust_state']}")
            print(f"Clean Windows    : {updated['clean_windows']}")
            print("Decision         : NORMAL COMMUNICATION")
            print(

                f"[EDGE] Buffer Count : {packet_count}"

            )

        return jsonify({

            "status":"benign",

            "score":threat_score,

            "reconstruction_error":reconstruction_error

        })

    # ===========================
    # ATTACK
    # ===========================

    print("\n==================================================")
    print("EDGE AI ENGINE")
    print("==================================================")

    print(f"CNN-LSTM Score        : {threat_score:.4f}")
    print(f"Autoencoder Error     : {reconstruction_error:.6f}")

    print("\n==================================================")
    print("CGEA")
    print("==================================================")

    print("Evidence Status       : CONFIRMED")

    print("\n==================================================")
    print("DECISION ENGINE")
    print("==================================================")

    trust_state = registry.get_trust_state(device_id)

    print(f"Previous Trust State  : {trust_state}")

    if trust_state == "TRUSTED":

       decision = "TEMPORARY_ISOLATION"

    elif trust_state == "DEGRADED":

        decision = "PERMANENT_BLOCK"

    else:

         decision = "REJECT"

    print(f"Decision              : {decision}")

    registry.apply_decision(

    device_id,

    decision,

    threat_score

  )

    status = decision


    evidence = {

    "device_id": device_id,

    "timestamp": time.time(),

    "trust_state": trust_state,

    "decision": decision,

    "threat_score": threat_score,

    "reconstruction_error": reconstruction_error,

    "attack_count": registry.get_device(device_id)["attack_count"],

    "model_version": CURRENT_VERSION
    }
    
    secured_evidence = evidence_security.create_signed_evidence(
    evidence
    )
    evidence_hash = secured_evidence["evidence_hash"]

    signature = secured_evidence["signature"]

    public_key = secured_evidence["public_key"]
    
    print("\n==================================================")
    print("EVIDENCE GENERATION")
    print("==================================================")

    print(f"Device ID             : {device_id}")
    print(f"Threat Score          : {threat_score:.4f}")

    print("\nSHA-256 Evidence Hash")

    print(evidence_hash)

    print("\nML-DSA Signature")

    print("Generated Successfully")

    attack_payload = {

    "type": "attack",

    # Required by Continual Learning
    "packet_window": packet_window,

    # Metadata
    "device_id": device_id,

    "status": status,

    "threat_score": threat_score,

    "reconstruction_error": reconstruction_error,

    "model_version": CURRENT_VERSION,

    # Blockchain Evidence
    "evidence": evidence,

    "evidence_hash": evidence_hash,

    "signature": signature,

    "public_key": public_key
}

    # ===========================
    # BLOCKCHAIN
    # ===========================

    print("\n==================================================")
    print("BLOCKCHAIN")
    print("==================================================")

    print("Status : Pending Hyperledger Fabric")

    print("TODO :")

    print("- Store Signed Evidence")

    print("- Update Trust Ledger")

    print("- Store Audit Trail")

    # ===========================
    # SEND TO CLOUD
    # ===========================

    try:

        response = requests.post(

            f"http://localhost:{CLOUD_PORT}/retrain",

            json=attack_payload,

            timeout=10

        )

        response.raise_for_status()

        print("\n==================================================")
        print("CLOUD CONTINUAL LEARNING")
        print("==================================================")
        print("[EDGE] Summary Successfully Sent")

    except requests.exceptions.ConnectionError:

        retry_queue.append(
            attack_payload
        )

        print("\n==================================================")
        print("CLOUD CONTINUAL LEARNING")
        print("==================================================")
        print("[EDGE] Cloud Offline")
        print("[EDGE] Summary Added To Retry Queue")

        print("\n==================================================")
        print("TRUST UPDATE")
        print("==================================================")

        updated = registry.get_device(device_id)

        print(f"Trust State           : {updated['trust_state']}")
        print(f"Attack Count          : {updated['attack_count']}")
        print(f"Current Decision      : {status}")

        return jsonify({

            "status": "queued",

            "evidence_hash": evidence_hash

        })

    except requests.exceptions.HTTPError as e:

        print("\n==================================================")
        print("CLOUD SERVER ERROR")
        print("==================================================")
        print(response.text)

        raise e


    # ===========================
    # MODEL UPDATE
    # ===========================

    content_type = response.headers.get(

        "Content-Type",

        ""

    )

    if "application/octet-stream" in content_type:

        package = torch.load(

            io.BytesIO(

                response.content

            ),

            map_location="cpu",

            weights_only=False

        )

        version = package["version"]

        if version > CURRENT_VERSION:

            edge_model.load_state_dict(

                package["weights"]

            )

            edge_model.eval()

            CURRENT_VERSION = version

            print("\n==================================================")
            print("MODEL UPDATE")
            print("==================================================")
            print(f"Updated Edge Model -> Version {version}")

    else:

        try:

            cloud_response = response.json()

            print("\n==================================================")
            print("CLOUD CONTINUAL LEARNING")
            print("==================================================")
            print(f"Status               : {cloud_response.get('status')}")
            print(f"Attack Buffer        : {cloud_response.get('attack', 0)}")
            print(f"Benign Buffer        : {cloud_response.get('benign', 0)}")
            print(f"Total Samples        : {cloud_response.get('total', 0)}")

        except Exception:

            pass


    print("\n==================================================")
    print("TRUST UPDATE")
    print("==================================================")

    updated = registry.get_device(device_id)

    print(f"Trust State           : {updated['trust_state']}")
    print(f"Attack Count          : {updated['attack_count']}")
    print(f"Current Decision      : {status}")

    return jsonify({

    "status": status,

    "device": device_id,

    "attack_count": registry.get_device(device_id)["attack_count"],

    "evidence_hash": evidence_hash,

    "score": threat_score,

    "reconstruction_error": reconstruction_error,

    "model_version": CURRENT_VERSION

})


# ===========================
# DEVICE APIs
# ===========================

@app.route("/devices", methods=["GET"])
def devices():
    return jsonify(registry.get_all_devices())

@app.route("/network_status", methods=["GET"])
def network_status():
    return jsonify(registry.network_statistics())

@app.route("/reset_device", methods=["POST"])
def reset_device():
    data=request.json
    device=data["device_id"]
    registry.reset_device(device)
    return jsonify({"status":"success","device":device})

# ===========================
# START SERVER
# ===========================

if __name__ == "__main__":

    print()

    print("==============================")

    print(" Edge Gateway Started ")

    print("==============================")

    app.run(

        host="0.0.0.0",

        port=EDGE_PORT,

        debug=False

    )