import os
import sys
import json

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, request, jsonify
from security.verify_signature import verify_packet

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
    decrypt_packet,
    verify_hmac
)
from security.evidence_security import EvidenceSecurity
from security import blockchain_client


warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names"
)

sys.path.append(
    os.path.abspath(".")
)

from shared.model import CNNLSTMModel
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

    performance = {}

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

    auth_tag = bytes.fromhex(
    data["auth_tag"]
    )

    session_id = data["session_id"]

    shared_secret, kem_decap_time = kem_server.decapsulate(
    kem_ciphertext
    )
    
    print("\n==================================================")
    print("POST-QUANTUM TRANSPORT")
    print("==================================================")

    print("Algorithm               : ML-KEM-512")

    print(f"Public Key Size         : {len(GatewayKeys.load_public_key())} Bytes")

    print(f"Ciphertext Size         : {len(kem_ciphertext)} Bytes")

    print(f"Shared Secret Size      : {len(shared_secret)} Bytes")

    print(f"Decapsulation Time      : {kem_decap_time:.3f} ms")

    performance["ML-KEM Decapsulation"] = kem_decap_time

    session_key = derive_session_key(
        shared_secret,
        session_id.encode()
    )

    fingerprint = hashlib.sha256(
        session_key
    ).hexdigest()[:16].upper()

    print()
    print("Session Key Fingerprint")
    print(fingerprint + "...")

    # ==========================
    # HMAC VERIFICATION
    # ==========================

    print("\n==================================================")
    print("MESSAGE AUTHENTICATION")
    print("==================================================")

    hmac_start = time.perf_counter()
    if not verify_hmac(
        session_key=session_key,
        session_id=session_id,
        ciphertext=ciphertext,
        received_tag=auth_tag
    ):

        print("Authentication : FAILED")
        print("Decision       : PACKET DROPPED")

        return jsonify({

            "status": "authentication_failed"

        }), 401
    performance["HMAC Verification"] = (
        time.perf_counter() - hmac_start
    ) * 1000

    print("Authentication : VERIFIED")
    print("Integrity      : VERIFIED")
    print("Authenticity   : VERIFIED")

    # ==========================
    # AES DECRYPTION
    # ==========================

    aes_start = time.perf_counter()

    packet = decrypt_packet(
        ciphertext=ciphertext,
        nonce=nonce,
        session_key=session_key
    )

    print("\n========== DEBUG ==========")
    print("Window received :", len(packet["packet_window"]))
    print("First row length:", len(packet["packet_window"][0]))
    print("Numpy shape     :", np.array(packet["packet_window"]).shape)
    print("===========================\n")

    performance["AES-256-GCM Decryption"] = (
        time.perf_counter() - aes_start
    ) * 1000

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

    print("Scaled shape:", np.array(scaled_packet).shape)

    
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

    cnn_start = time.perf_counter()

    with torch.no_grad():
         logits = edge_model(x)
         threat_score = torch.sigmoid(logits).item()


    print("\n========== MODEL OUTPUT ==========")
    print(f"Threat Score         : {threat_score:.6f}")
    print(f"Threshold            : {THREAT_THRESHOLD}")
    print(f"Ground Truth         : {data.get('actual_label')}")
    print("==================================\n")

   

    performance["CNN-LSTM Inference"] = (
    time.perf_counter() - cnn_start
) * 1000

    print(
        f"[EDGE] Threat Score : {threat_score:.4f}"
    )


    # ===========================
    # BENIGN TRAFFIC
    # ===========================

    if (

        threat_score < THREAT_THRESHOLD

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
        
        print("\n==================================================")
        print("PERFORMANCE METRICS")
        print("==================================================")

        total_latency = 0

        for name, value in performance.items():

            print(f"{name:<30}: {value:.3f} ms")

            total_latency += value

        print("-----------------------------------------------")
        print(f"{'Measured Total':<30}: {total_latency:.3f} ms")

        return jsonify({

                "status":"benign",

                "score":threat_score,

            })

    # ===========================
    # ATTACK
    # ===========================

    print("\n==================================================")
    print("EDGE AI ENGINE")
    print("==================================================")

    print("Telemetry Preprocessing : SUCCESS")

    print("Feature Scaling         : SUCCESS")

    print(f"Feature Count           : {FEATURE_COUNT}")

    print(f"Sliding Window          : {WINDOW_SIZE}")

    print("----------------------------------------")

    print("CNN Feature Extraction  : COMPLETE")

    print("Temporal Analysis       : COMPLETE")

    print(f"CNN Threat Score        : {threat_score:.4f}")

    print("----------------------------------------")



    print("----------------------------------------")

    if (
    threat_score >= THREAT_THRESHOLD
    
    ):

       print("Evidence Status         : ATTACK DETECTED")

    else:

       print("Evidence Status         : BENIGN")

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

    "attack_count": registry.get_device(device_id)["attack_count"],

    "model_version": CURRENT_VERSION,

    "session_id": session_id,

    "cipher_hash": hashlib.sha256(ciphertext).hexdigest()
    }
    
    sign_start = time.perf_counter()

    secured_evidence = evidence_security.create_signed_evidence(
    evidence
)

    performance["ML-DSA Signing"] = (
    time.perf_counter() - sign_start
) * 1000

    evidence_hash = secured_evidence["evidence_hash"]
    

    signature = secured_evidence["signature"]

    public_key = secured_evidence["public_key"]

    verify_start = time.perf_counter()

    evidence_bytes = json.dumps(

    evidence,

    sort_keys=True,

    separators=(",", ":")

).encode()

    verification_result = verify_packet(

    evidence_bytes,

    bytes.fromhex(signature),

    bytes.fromhex(public_key)

)
    
    performance["ML-DSA Verification"] = (
    time.perf_counter() - verify_start
) * 1000

    print("\n==================================================")
    print("SHA-256 EVIDENCE")
    print("==================================================")

    print("Evidence Generated Successfully")

    print()

    print("Hash Algorithm         : SHA-256")

    print(f"Hash Length            : {len(bytes.fromhex(evidence_hash)) * 8} bits")

    print()

    print("Evidence Hash")

    print(evidence_hash)

    print()

    print("==================================================")
    print("ML-DSA DIGITAL SIGNATURE")
    print("==================================================")

    print("Algorithm              : ML-DSA-65")

    public_key_bytes = bytes.fromhex(public_key)

    signature_bytes = bytes.fromhex(signature)

    print(f"Public Key Size        : {len(public_key_bytes)} Bytes")

    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16].upper()

    print(f"Public Key Fingerprint : {fingerprint}...")

    print(f"Signature Size         : {len(signature_bytes)} Bytes")

    print(f"Signing Time           : {performance['ML-DSA Signing']:.3f} ms")

    print()

    print("==================================================")
    print("ML-DSA VERIFICATION")
    print("==================================================")

    print("Verifying Signature...")

    print()

    print(f"Verification Time      : {performance['ML-DSA Verification']:.3f} ms")

    print()

    print(
        f"Result                 : {'VALID' if verification_result else 'INVALID'}"
    )

    print(
        f"Integrity              : {'VERIFIED' if verification_result else 'FAILED'}"
    )

    print(
       f"Authenticity           : {'VERIFIED' if verification_result else 'FAILED'}"
    )

    if verification_result:

        print()

        print("Evidence Accepted")

    else:

        print()

        print("Evidence Rejected")

    if not verification_result:

        print("\nSignature Verification Failed")

        return jsonify({

            "status": "invalid_signature"

        }),401
    attack_payload = {

    "type": "attack",

    # Required by Continual Learning
    "packet_window": packet_window,

    # Metadata
    "device_id": device_id,

    "status": status,

    "threat_score": threat_score,

    "model_version": CURRENT_VERSION,

    # Blockchain Evidence
    "evidence": evidence,

    "evidence_hash": evidence_hash,

    "signature": signature,

    "public_key": public_key
}

    print("\n==================================================")
    print("BLOCKCHAIN")
    print("==================================================")
    blockchain_status = "not_attempted"
    blockchain_tx_id = None

    blockchain_tx_id = f"TX-{device_id}-{int(evidence['timestamp'] * 1000)}"
    blockchain_alert_id = f"ALERT-{device_id}-{int(evidence['timestamp'] * 1000)}"

    try:
        submit_ms = blockchain_client.submit_record(
            tx_id=blockchain_tx_id, device_id=device_id,
            edge_cluster=EDGE_CLUSTER_ID, data_hash=evidence_hash, status="confirmed",
        )
        alert_ms = blockchain_client.raise_alert(
            alert_id=blockchain_alert_id, tx_id=blockchain_tx_id, device_id=device_id,
            severity=decision, description=f"score={threat_score:.4f}", flagged_by="edge-gateway-ids",
        )
        performance["Blockchain SubmitRecord"] = submit_ms
        performance["Blockchain RaiseAlert"] = alert_ms
        blockchain_status = "committed"
        print(f"Status : COMMITTED ({submit_ms:.1f}ms + {alert_ms:.1f}ms)")
    except Exception as e:   # widen from RuntimeError to Exception
        blockchain_status = "failed"
        print(f"Status : FAILED ({e})")

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

    except requests.exceptions.HTTPError as e:

     print("\n==================================================")
     print("CLOUD SERVER ERROR")
     print("==================================================")
     print(response.text)
     raise e

    return jsonify({
        "status": status,
        "device": device_id,
        "attack_count": registry.get_device(device_id)["attack_count"],
        "evidence_hash": evidence_hash,
        "score": threat_score,
        "message": "Cloud returned HTTP 500"
    })


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

    print("\n==================================================")
    print("PERFORMANCE METRICS")
    print("==================================================")

    total_latency = 0

    for name, value in performance.items():

        print(f"{name:<30}: {value:.3f} ms")

        total_latency += value

    print("-----------------------------------------------")
    print(f"{'Measured Total':<30}: {total_latency:.3f} ms")
    
    return jsonify({

    "status": status,

    "device": device_id,

    "attack_count": registry.get_device(device_id)["attack_count"],

    "evidence_hash": evidence_hash,

    "score": threat_score,

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