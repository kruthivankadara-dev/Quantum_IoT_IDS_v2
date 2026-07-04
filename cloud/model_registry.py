# ==========================================
# cloud/model_registry.py
# Version 2
# ==========================================

import json
import os
import time

from shared.config import *

# ==========================================
# INITIALIZE
# ==========================================

def initialize_registry():

    if not os.path.exists(REGISTRY_PATH):

        registry = {

            "current_version":1,

            "last_updated":time.strftime(

                "%Y-%m-%d %H:%M:%S"

            )

        }

        with open(

            REGISTRY_PATH,

            "w"

        ) as f:

            json.dump(

                registry,

                f,

                indent=4

            )

# ==========================================
# LOAD
# ==========================================

def load_registry():

    initialize_registry()

    with open(

        REGISTRY_PATH,

        "r"

    ) as f:

        registry = json.load(f)

    return registry

# ==========================================
# SAVE
# ==========================================

def save_registry(registry):

    with open(

        REGISTRY_PATH,

        "w"

    ) as f:

        json.dump(

            registry,

            f,

            indent=4

        )

# ==========================================
# GET VERSION
# ==========================================

def get_version():

    registry = load_registry()

    return registry["current_version"]

# ==========================================
# UPDATE VERSION
# ==========================================

def increment_version():

    registry = load_registry()

    registry["current_version"] += 1

    registry["last_updated"] = time.strftime(

        "%Y-%m-%d %H:%M:%S"

    )

    save_registry(

        registry

    )

    print(

        f"[MODEL] Version Updated -> {registry['current_version']}"

    )

    return registry["current_version"]

# ==========================================
# INFO
# ==========================================

def registry_info():

    registry = load_registry()

    return {

        "version":

        registry["current_version"],

        "updated":

        registry["last_updated"]

    }

# ==========================================
# RESET
# ==========================================

def reset_registry():

    registry = {

        "current_version":1,

        "last_updated":time.strftime(

            "%Y-%m-%d %H:%M:%S"

        )

    }

    save_registry(

        registry

    )

    print(

        "[MODEL] Registry Reset"

    )

# ==========================================
# DEBUG
# ==========================================

if __name__ == "__main__":

    initialize_registry()

    print(

        registry_info()

    )