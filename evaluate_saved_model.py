import os
import sys
import joblib
import torch
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

sys.path.append(os.path.abspath("."))

from shared.model import CNNLSTMModel

MODEL_PATH = "models/cnn_lstm.pth"
SCALER_PATH = "models/scaler.save"
TEST_FILE = "dataset/CICIOT23/test/test.csv"

WINDOW_SIZE = 10

print("Loading test dataset...")

df = pd.read_csv(TEST_FILE)

y = (df["label"] != "BenignTraffic").astype(int)
X = df.drop("label", axis=1)

print("Loading scaler...")
scaler = joblib.load(SCALER_PATH)

X_scaled = scaler.transform(X)

X_tensor = torch.tensor(X_scaled, dtype=torch.float32)

windows = []
targets = []

for i in range(len(X_tensor) - WINDOW_SIZE + 1):
    windows.append(X_tensor[i:i+WINDOW_SIZE])
    targets.append(y.iloc[i+WINDOW_SIZE-1])

X_windows = torch.stack(windows)

print("Loading CNN-LSTM...")

model = CNNLSTMModel()

model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location="cpu"
    )
)

model.eval()

predictions = []

with torch.no_grad():

    outputs = model(X_windows)

    probs = torch.sigmoid(outputs)

    predictions = (probs >= 0.5).int().numpy().flatten()

print("\n========== RESULTS ==========")

print(
    f"Accuracy : {accuracy_score(targets, predictions)*100:.2f}%"
)

print("\nClassification Report")

print(
    classification_report(
        targets,
        predictions,
        target_names=[
            "Benign",
            "Attack"
        ]
    )
)

print("\nConfusion Matrix")

print(
    confusion_matrix(
        targets,
        predictions
    )
)