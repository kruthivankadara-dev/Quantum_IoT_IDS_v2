# ==========================================
# cloud/continual_learning_server.py
# Version 2
# ==========================================

from flask import Flask, request, jsonify

import torch
import torch.nn as nn
import numpy as np

import io
import os
import sys
import random

sys.path.append(
    os.path.abspath(".")
)

from shared.model import CNNLSTMModel
from shared.config import *

from cloud.model_registry import (
    increment_version
)

app = Flask(__name__)

# ==========================================
# LOAD MODEL
# ==========================================

print("\n[CLOUD] Loading CNN-LSTM...")

global_model = CNNLSTMModel()

global_model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location="cpu"
    )
)

global_model.train()

optimizer = torch.optim.Adam(

    global_model.parameters(),

    lr=LEARNING_RATE

)

criterion = nn.BCELoss()

# ==========================================
# BUFFERS
# ==========================================

attack_x = []
attack_y = []

benign_x = []
benign_y = []

print("[CLOUD] Ready")

# ==========================================
# BUILD DATASET
# ==========================================

def build_dataset():

    global attack_x
    global benign_x

    X = attack_x + benign_x

    Y = attack_y + benign_y

    combined = list(zip(X,Y))

    random.shuffle(combined)

    X,Y = zip(*combined)

    X = torch.stack(X)

    Y = torch.stack(Y)

    return X,Y

# ==========================================
# RETRAIN
# ==========================================

def retrain_model():

    X,Y = build_dataset()

    print()

    print("[CLOUD] Retraining Started")

    print(f"[CLOUD] Samples : {len(X)}")

    for epoch in range(
        LOCAL_EPOCHS
    ):

        optimizer.zero_grad()

        output = global_model(
            X
        )

        loss = criterion(

            output,

            Y

        )

        loss.backward()

        optimizer.step()

        print(

            f"[Epoch {epoch+1}]",

            f"Loss = {loss.item():.5f}"

        )

    version = increment_version()

    torch.save(

        global_model.state_dict(),

        MODEL_PATH

    )

    print()

    print(

        f"[CLOUD] New Version : {version}"

    )

    package = {

        "version":version,

        "weights":

        global_model.state_dict()

    }

    buffer = io.BytesIO()

    torch.save(

        package,

        buffer

    )

    buffer.seek(0)

    return buffer.getvalue()

# ==========================================
# ROUTE
# ==========================================

@app.route(

    "/retrain",

    methods=["POST"]

)

def retrain():

    global attack_x
    global attack_y

    global benign_x
    global benign_y

    data = request.json

    # ===========================
    # ATTACK
    # ===========================

    if data["type"] == "attack":

        packet = torch.tensor(

            data["packet_window"],

            dtype=torch.float32

        ).view(

            5,

            FEATURE_COUNT

        )

        attack_x.append(

            packet

        )

        attack_y.append(

            torch.tensor(

                [1.0]

            )

        )

        print(

            f"[CLOUD] Attack Buffer : {len(attack_x)}"

        )

    # ===========================
    # BENIGN SUMMARY
    # ===========================

    elif data["type"] == "benign_summary":

        samples = data["samples"]

        for sample in samples:

            packet = torch.tensor(

                sample,

                dtype=torch.float32

            ).view(

                5,

                FEATURE_COUNT

            )

            benign_x.append(

                packet

            )

            benign_y.append(

                torch.tensor(

                    [0.0]

                )

            )

        print(

            f"[CLOUD] Benign Buffer : {len(benign_x)}"

        )

    # ===========================
    # WAIT
    # ===========================

    total = len(attack_x) + len(benign_x)

    if total < BATCH_RETRAIN_TRIGGER:

        return jsonify({

            "status":"stored",

            "attack":

            len(attack_x),

            "benign":

            len(benign_x),

            "total":

            total

        })

    # ===========================
    # RETRAIN
    # ===========================

    package = retrain_model()

    attack_x.clear()
    attack_y.clear()

    benign_x.clear()
    benign_y.clear()

    print(

        "[CLOUD] Buffers Cleared"

    )

    return (

        package,

        200,

        {

            "Content-Type":

            "application/octet-stream"

        }

    )

# ==========================================
# START
# ==========================================

if __name__ == "__main__":

    print()

    print("==============================")

    print(" Continual Learning Server ")

    print("==============================")

    app.run(

        host="0.0.0.0",

        port=CLOUD_PORT,

        debug=False

    )