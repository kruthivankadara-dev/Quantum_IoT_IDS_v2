import os
import sys
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
import joblib

sys.path.append(os.path.abspath("."))

from shared.autoencoder import AutoEncoder

# ==========================================
# CONFIG
# ==========================================

TRAIN_FILE = "dataset/CICIOT23/train/train.csv"

AUTOENCODER_SAVE_PATH = "models/autoencoder.pth"

ROWS_TO_LOAD = 100000

WINDOW_SIZE = 10

BATCH_SIZE = 128

EPOCHS = 10

LEARNING_RATE = 0.001

# ==========================================
# LOAD DATASET
# ==========================================

print("\nLoading Dataset...")

df = pd.read_csv(
    TRAIN_FILE,
    nrows=ROWS_TO_LOAD
)

print("Dataset Loaded")

# ==========================================
# BENIGN ONLY
# ==========================================

benign_df = df[
    df["label"] == "BenignTraffic"
]

print(
    "Benign Samples:",
    len(benign_df)
)

# ==========================================
# FEATURES
# ==========================================

X = benign_df.drop(
    "label",
    axis=1
)

# ==========================================
# NORMALIZATION
# ==========================================

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

joblib.dump(
    scaler,
    "models/autoencoder_scaler.save"
)

# ==========================================
# TORCH
# ==========================================

X_tensor = torch.tensor(
    X_scaled,
    dtype=torch.float32
)

# ==========================================
# CREATE WINDOWS
# ==========================================

windows = []

for i in range(
    len(X_tensor) - WINDOW_SIZE
):

    window = X_tensor[
        i:i+WINDOW_SIZE
    ]

    windows.append(
        window.reshape(-1)
    )

X_windows = torch.stack(
    windows
)

print(
    "Window Shape:",
    X_windows.shape
)

# ==========================================
# DATASET
# ==========================================

dataset = TensorDataset(
    X_windows
)

loader = DataLoader(
    dataset,
    batch_size=BATCH_SIZE,
    shuffle=True
)

# ==========================================
# MODEL
# ==========================================

device = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

print(
    "Device:",
    device
)

model = AutoEncoder().to(
    device
)

criterion = nn.MSELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)

# ==========================================
# TRAINING
# ==========================================

print("\nTraining Autoencoder...\n")

for epoch in range(EPOCHS):

    model.train()

    total_loss = 0

    for batch in loader:

        batch_x = batch[0].to(
            device
        )

        optimizer.zero_grad()

        reconstruction = model(
            batch_x
        )

        loss = criterion(
            reconstruction,
            batch_x
        )

        loss.backward()

        optimizer.step()

        total_loss += loss.item()

    avg_loss = (
        total_loss /
        len(loader)
    )

    print(
        f"Epoch [{epoch+1}/{EPOCHS}] "
        f"Loss = {avg_loss:.6f}"
    )

# ==========================================
# SAVE
# ==========================================

torch.save(
    model.state_dict(),
    AUTOENCODER_SAVE_PATH
)

print(
    "\nAutoencoder Saved"
)

print(
    f"Saved -> {AUTOENCODER_SAVE_PATH}"
)