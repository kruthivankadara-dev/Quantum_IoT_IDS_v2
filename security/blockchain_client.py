import json
import os
import subprocess
import time

TEST_NETWORK_DIR = os.path.expanduser(
    "~/testingmultpeers/fabric-samples/test-network"
)
ORG_BASE = os.path.join(TEST_NETWORK_DIR, "organizations")

CHANNEL = "mychannel"
CC_NAME = "iotcc"

ORDERER_ADDR = "localhost:7050"
ORDERER_TLS_HOSTNAME = "orderer.example.com"
ORDERER_CA = os.path.join(
    ORG_BASE,
    "ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem",
)

# (address, tls root cert) — 2 peers org1, 2 peers org2, 1 peer org3
PEERS = [
    ("localhost:7051", os.path.join(
        ORG_BASE, "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/tlscacerts/tlsca.org1.example.com-cert.pem")),
    ("localhost:8051", os.path.join(
        ORG_BASE, "peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp/tlscacerts/tlsca.org1.example.com-cert.pem")),
    ("localhost:9051", os.path.join(
        ORG_BASE, "peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp/tlscacerts/tlsca.org2.example.com-cert.pem")),
    ("localhost:10051", os.path.join(
        ORG_BASE, "peerOrganizations/org2.example.com/peers/peer1.org2.example.com/msp/tlscacerts/tlsca.org2.example.com-cert.pem")),
    ("localhost:11051", os.path.join(
        ORG_BASE, "peerOrganizations/org3.example.com/peers/peer0.org3.example.com/msp/tlscacerts/tlsca.org3.example.com-cert.pem")),
]

# Fabric CLI config + identity. Equivalent to what `source envVar.sh && setGlobals 1`
# does manually in a terminal — baked in here so any caller (edge gateway, cloud
# server, a raw REPL) works without needing to export these first.
FABRIC_BIN_DIR = os.path.expanduser("~/testingmultpeers/fabric-samples/bin")
FABRIC_CFG_PATH = os.path.expanduser("~/testingmultpeers/fabric-samples/config/")

# Submitting identity: Org1 admin (matches setGlobals 1)
CORE_PEER_LOCALMSPID = "Org1MSP"
CORE_PEER_TLS_ROOTCERT_FILE = os.path.join(
    ORG_BASE,
    "peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem",
)
CORE_PEER_MSPCONFIGPATH = os.path.join(
    ORG_BASE,
    "peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp",
)
CORE_PEER_ADDRESS = "localhost:7051"


def _fabric_env():
    env = os.environ.copy()
    env["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
    env["PATH"] = FABRIC_BIN_DIR + os.pathsep + env.get("PATH", "")

    env["CORE_PEER_TLS_ENABLED"] = "true"
    env["CORE_PEER_LOCALMSPID"] = CORE_PEER_LOCALMSPID
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = CORE_PEER_TLS_ROOTCERT_FILE
    env["CORE_PEER_MSPCONFIGPATH"] = CORE_PEER_MSPCONFIGPATH
    env["CORE_PEER_ADDRESS"] = CORE_PEER_ADDRESS
    return env


def _invoke(function, args):
    cmd = [
        "peer", "chaincode", "invoke",
        "-o", ORDERER_ADDR,
        "--ordererTLSHostnameOverride", ORDERER_TLS_HOSTNAME,
        "--tls", "--cafile", ORDERER_CA,
        "-C", CHANNEL, "-n", CC_NAME,
        "--waitForEvent",
    ]
    for addr, ca in PEERS:
        cmd += ["--peerAddresses", addr, "--tlsRootCertFiles", ca]
    cmd += ["-c", json.dumps({"function": function, "Args": args})]

    start = time.perf_counter()
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, env=_fabric_env()
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    if result.returncode != 0:
        raise RuntimeError(f"{function} failed: {result.stderr.strip()}")

    return elapsed_ms


def register_device(device_id, device_type, edge_cluster, org_msp):
    return _invoke("RegisterDevice", [device_id, device_type, edge_cluster, org_msp])


def submit_record(tx_id, device_id, edge_cluster, data_hash, status):
    return _invoke("SubmitRecord", [tx_id, device_id, edge_cluster, data_hash, status])


def raise_alert(alert_id, tx_id, device_id, severity, description, flagged_by):
    return _invoke("RaiseAlert", [alert_id, tx_id, device_id, severity, description, flagged_by])