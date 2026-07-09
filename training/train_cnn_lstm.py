import os
import sys
import copy
import joblib
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.abspath("."))

from shared.model import CNNLSTMModel

TRAIN_FILE = "dataset/CICIOT23/train/train.csv"
MODEL_SAVE_PATH = "models/cnn_lstm.pth"
SCALER_SAVE_PATH = "models/scaler.save"

WINDOW_SIZE = 10
BATCH_SIZE = 512
EPOCHS = 50
LEARNING_RATE = 0.0003
PATIENCE = 8

print("Loading dataset...")
df = pd.read_csv(TRAIN_FILE)

y = (df["label"] != "BenignTraffic").astype(int)
X = df.drop("label", axis=1)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

os.makedirs("models", exist_ok=True)
joblib.dump(scaler, SCALER_SAVE_PATH)

X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
y_tensor = torch.tensor(y.values, dtype=torch.float32)

windows = []
targets = []
for i in range(len(X_tensor)-WINDOW_SIZE+1):
    windows.append(X_tensor[i:i+WINDOW_SIZE])
    targets.append(y_tensor[i+WINDOW_SIZE-1])

X_windows = torch.stack(windows)
y_windows = torch.tensor(targets).unsqueeze(1)

class PacketDataset(Dataset):
    def __init__(self, X, y):
        self.X = X
        self.y = y
    def __len__(self):
        return len(self.X)
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

X_train,X_val,y_train,y_val = train_test_split(
    X_windows,
    y_windows,
    test_size=0.2,
    random_state=42,
    stratify=y_windows.numpy()
)

train_loader=DataLoader(PacketDataset(X_train,y_train),batch_size=BATCH_SIZE,shuffle=True)
val_loader=DataLoader(PacketDataset(X_val,y_val),batch_size=BATCH_SIZE,shuffle=False)

device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
model=CNNLSTMModel().to(device)

num_positive=y_train.sum().item()
num_negative=len(y_train)-num_positive

criterion=nn.BCEWithLogitsLoss(
    pos_weight=torch.tensor([num_negative/max(num_positive,1)],dtype=torch.float32,device=device)
)

optimizer=torch.optim.AdamW(model.parameters(),lr=LEARNING_RATE,weight_decay=5e-5)
scheduler=torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer,mode="max",factor=0.5,patience=2)

best_f1=0.0
patience_counter=0

for epoch in range(EPOCHS):

    model.train()
    epoch_loss=0.0

    for batch_x,batch_y in train_loader:

        batch_x=batch_x.to(device)
        batch_y=batch_y.to(device)

        optimizer.zero_grad()

        outputs=model(batch_x)

        loss=criterion(outputs,batch_y)

        loss.backward()

        torch.nn.utils.clip_grad_norm_(model.parameters(),1.0)

        optimizer.step()

        epoch_loss+=loss.item()

    avg_loss=epoch_loss/len(train_loader)

    model.eval()

    preds=[]
    labels=[]

    with torch.no_grad():
        for batch_x,batch_y in val_loader:

            batch_x=batch_x.to(device)
            batch_y=batch_y.to(device)

            probs=torch.sigmoid(model(batch_x))
            pred=(probs>=0.5).float()

            preds.extend(pred.cpu().numpy().flatten())
            labels.extend(batch_y.cpu().numpy().flatten())

    acc=accuracy_score(labels,preds)
    prec=precision_score(labels,preds,zero_division=0)
    rec=recall_score(labels,preds,zero_division=0)
    f1=f1_score(labels,preds,zero_division=0)

    scheduler.step(f1)

    print(f"Epoch {epoch+1}/{EPOCHS} | Loss={avg_loss:.4f} | Acc={acc:.4f} | Precision={prec:.4f} | Recall={rec:.4f} | F1={f1:.4f}")

    if f1>best_f1:
        best_f1=f1
        torch.save(model.state_dict(),MODEL_SAVE_PATH)
        patience_counter=0
        print("Best model saved.")
    else:
        patience_counter+=1

    if patience_counter>=PATIENCE:
        print("Early stopping.")
        break

print("Training Complete")
print("Best F1:",best_f1)
print("Model saved to",MODEL_SAVE_PATH)