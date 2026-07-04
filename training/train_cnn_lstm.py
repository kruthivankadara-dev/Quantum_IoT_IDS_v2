import os
import sys
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
import joblib

sys.path.append(os.path.abspath("."))

from shared.model import CNNLSTMModel

# ==================================================
# CONFIG
# ==================================================

TRAIN_FILE = "dataset/CICIOT23/train/train.csv"

MODEL_SAVE_PATH = "models/cnn_lstm.pth"

SCALER_SAVE_PATH = "models/scaler.save"

ROWS_TO_LOAD = 100000

WINDOW_SIZE = 5

BATCH_SIZE = 256

EPOCHS = 5

LEARNING_RATE = 0.001

# ==================================================
# LOAD DATASET
# ==================================================

print("\nLoading CICIoT2023 Dataset...")

df = pd.read_csv(
    TRAIN_FILE,
    nrows=ROWS_TO_LOAD
)

print("Dataset Loaded")
print("Shape:", df.shape)

# ==================================================
# LABEL CONVERSION
# ==================================================

print("\nConverting Labels...")

y = (
    df["label"] != "BenignTraffic"
).astype(int)

X = df.drop(
    "label",
    axis=1
)

print("Attack Samples :", y.sum())
print("Benign Samples :", len(y) - y.sum())

# ==================================================
# NORMALIZATION
# ==================================================

print("\nNormalizing Features...")

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

joblib.dump(
    scaler,
    SCALER_SAVE_PATH
)

print("Scaler Saved")

# ==================================================
# TORCH CONVERSION
# ==================================================

X_tensor = torch.tensor(
    X_scaled,
    dtype=torch.float32
)

y_tensor = torch.tensor(
    y.values,
    dtype=torch.float32
)

# ==================================================
# CREATE WINDOWS
# ==================================================

print("\nCreating Sequential Windows...")

windows = []

targets = []

for i in range(
    len(X_tensor) - WINDOW_SIZE
):

    windows.append(
        X_tensor[
            i : i + WINDOW_SIZE
        ]
    )

    targets.append(
        y_tensor[
            i + WINDOW_SIZE - 1
        ]
    )

X_windows = torch.stack(
    windows
)

y_windows = torch.tensor(
    targets
).unsqueeze(1)

print(
    "Window Shape:",
    X_windows.shape
)

# ==================================================
# DATASET
# ==================================================

class PacketDataset(Dataset):

    def __init__(
        self,
        X,
        y
    ):

        self.X = X
        self.y = y

    def __len__(self):

        return len(self.X)

    def __getitem__(
        self,
        idx
    ):

        return (
            self.X[idx],
            self.y[idx]
        )

dataset = PacketDataset(
    X_windows,
    y_windows
)

loader = DataLoader(
    dataset,
    batch_size=BATCH_SIZE,
    shuffle=True
)

print(
    "Total Batches:",
    len(loader)
)

# ==================================================
# MODEL
# ==================================================

print("\nBuilding CNN-LSTM...")

device = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

print("Device:", device)

model = CNNLSTMModel().to(
    device
)

criterion = nn.BCELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)

# ==================================================
# TRAINING
# ==================================================

print("\nTraining Started...\n")

for epoch in range(EPOCHS):

    model.train()

    epoch_loss = 0

    for batch_x, batch_y in loader:

        batch_x = batch_x.to(
            device
        )

        batch_y = batch_y.to(
            device
        )

        optimizer.zero_grad()

        outputs = model(
            batch_x
        )

        loss = criterion(
            outputs,
            batch_y
        )

        loss.backward()

        optimizer.step()

        epoch_loss += (
            loss.item()
        )

    avg_loss = (
        epoch_loss /
        len(loader)
    )

    print(
        f"Epoch [{epoch+1}/{EPOCHS}] "
        f"Loss = {avg_loss:.4f}"
    )

# ==================================================
# SAVE MODEL
# ==================================================

os.makedirs(
    "models",
    exist_ok=True
)

torch.save(
    model.state_dict(),
    MODEL_SAVE_PATH
)

print("\nTraining Complete")

print(
    f"Model Saved -> {MODEL_SAVE_PATH}"
)

print(
    f"Scaler Saved -> {SCALER_SAVE_PATH}"
)