import json
import os
from datetime import datetime

from shared.config import DEVICE_REGISTRY_PATH, MAX_ATTACKS


class DeviceRegistry:

    def __init__(self):

        if not os.path.exists(DEVICE_REGISTRY_PATH):

            with open(DEVICE_REGISTRY_PATH, "w") as f:
                json.dump({}, f, indent=4)

        self.load()
        print("\n========== DEVICE REGISTRY ==========")
        print("Registry Path :", DEVICE_REGISTRY_PATH)
        print("Loaded Devices:", self.devices)
        print("=====================================\n")

    # =====================================================
    # Load / Save Registry
    # =====================================================

    def load(self):

        with open(DEVICE_REGISTRY_PATH, "r") as f:
            self.devices = json.load(f)

        # Upgrade old registry entries automatically
        for device_id in list(self.devices.keys()):
            self.register_device(device_id)

    def save(self):

        with open(DEVICE_REGISTRY_PATH, "w") as f:
            json.dump(self.devices, f, indent=4)

    # =====================================================
    # Device Registration
    # =====================================================

    def register_device(self, device_id):

        if device_id not in self.devices:

            self.devices[device_id] = {}

        device = self.devices[device_id]

        # -------------------------------------------------
        # Upgrade old registry format automatically
        # -------------------------------------------------

        if "trust_state" not in device:

            if device.get("status") == "BLOCKED":
                device["trust_state"] = "REVOKED"

            elif device.get("status") == "WARNING":
                device["trust_state"] = "DEGRADED"

            else:
                device["trust_state"] = "TRUSTED"

        if "attack_count" not in device:
            device["attack_count"] = 0

        if "clean_windows" not in device:
            device["clean_windows"] = 0

        if "last_seen" not in device:
            device["last_seen"] = ""

        if "last_attack" not in device:
            device["last_attack"] = ""

        if "threat_score" not in device:
            device["threat_score"] = 0.0

        self.save()

    # =====================================================
    # Update Last Seen
    # =====================================================

    def update_seen(self, device_id):

        self.register_device(device_id)

        self.devices[device_id]["last_seen"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self.save()

    # =====================================================
    # Trust Lookup
    # =====================================================

    def get_trust_state(self, device_id):

        self.load()

        self.register_device(device_id)

        return self.devices[device_id]["trust_state"]

    def is_revoked(self, device_id):

        self.register_device(device_id)

        return self.devices[device_id]["trust_state"] == "REVOKED"
    # =====================================================
    # Trust Update
    # Called ONLY after Decision Engine returns
    # =====================================================

    def apply_decision(self, device_id, decision, threat_score=0.0):

        self.register_device(device_id)

        device = self.devices[device_id]

        if decision == "TEMPORARY_ISOLATION":

            device["trust_state"] = "DEGRADED"

            device["attack_count"] += 1

            device["clean_windows"] = 0

            device["threat_score"] = round(threat_score, 4)

            device["last_attack"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        elif decision == "PERMANENT_BLOCK":

            device["trust_state"] = "REVOKED"

            device["attack_count"] = MAX_ATTACKS

            device["clean_windows"] = 0

            device["threat_score"] = round(threat_score, 4)

            device["last_attack"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        self.save()

    # =====================================================
    # Self-Healing
    # =====================================================

    def record_clean_window(self, device_id):

        self.register_device(device_id)

        device = self.devices[device_id]

        if device["trust_state"] == "REVOKED":
            return

        if device["trust_state"] == "DEGRADED":

            device["clean_windows"] += 1

            if device["clean_windows"] >= 10:

                device["trust_state"] = "TRUSTED"

                device["attack_count"] = 0

                device["clean_windows"] = 0

                device["threat_score"] = 0.0

        self.save()

    # =====================================================
    # Manual Reset
    # =====================================================

    def reset_device(self, device_id):

        self.register_device(device_id)

        device = self.devices[device_id]

        device["trust_state"] = "TRUSTED"

        device["attack_count"] = 0

        device["clean_windows"] = 0

        device["last_attack"] = ""

        device["threat_score"] = 0.0

        self.save()

    # =====================================================
    # Get Device Information
    # =====================================================

    def get_device(self, device_id):

         self.load()

         self.register_device(device_id)

         return self.devices[device_id]

    def get_all_devices(self):

        self.load()

        return self.devices
    
    # =====================================================
    # Network Statistics
    # =====================================================

    def network_statistics(self):

        trusted = 0
        degraded = 0
        revoked = 0

        total_attacks = 0

        for device in self.devices.values():

            total_attacks += device["attack_count"]

            if device["trust_state"] == "TRUSTED":
                trusted += 1

            elif device["trust_state"] == "DEGRADED":
                degraded += 1

            elif device["trust_state"] == "REVOKED":
                revoked += 1

        return {

            "total_devices": len(self.devices),

            "trusted": trusted,

            "degraded": degraded,

            "revoked": revoked,

            "total_attacks": total_attacks

        }
    

    # =====================================================
    # Hyperledger Fabric Placeholder
    # =====================================================

    """
    Future Integration

    Replace this local JSON registry with
    Hyperledger Fabric World State.

    Smart Contract APIs:

    getDeviceTrust(device_id)

    updateDeviceTrust(device_id)

    recordAttack(device_id)

    restoreDevice(device_id)

    """