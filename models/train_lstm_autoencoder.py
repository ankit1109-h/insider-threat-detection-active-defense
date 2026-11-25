"""
train_lstm_autoencoder.py
=========================
Trains a PyTorch LSTM Binary Classifier on login session data.

Data:   data/lstm_training_data.csv
        (produced by setup/process_cert_data.py)

Output:
    models/lstm_model.pth       <- trained model weights
    models/lstm_scaler.pkl      <- StandardScaler (needed at inference)

Features (6):
    login_hour, login_day_of_week, is_weekend,
    is_after_hours, session_duration_hrs, logins_per_day

Label:
    0 = normal login session
    1 = insider threat session (from CERT dataset)
"""

import os
import pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

# ── Config ────────────────────────────────────────────────────────────────────
DATA_PATH     = "data/lstm_training_data.csv"
MODEL_PATH    = "models/lstm_model.pth"
SCALER_PATH   = "models/lstm_scaler.pkl"

FEATURES      = ["login_hour", "login_day_of_week", "is_weekend", "is_after_hours"]

SEQ_LEN       = 1      # single-step LSTM (extend to >1 when live data grows)
HIDDEN_SIZE   = 64
NUM_LAYERS    = 2
DROPOUT       = 0.3
EPOCHS        = 80
BATCH_SIZE    = 32
LEARNING_RATE = 1e-3
SEED          = 42

torch.manual_seed(SEED)
np.random.seed(SEED)

# ── Model Definition ──────────────────────────────────────────────────────────
class LoginLSTM(nn.Module):
    """
    LSTM Binary Classifier for insider threat detection.
    Input shape : (batch, seq_len, num_features)
    Output shape: (batch, 1)  — probability of being a threat
    """
    def __init__(self, input_size, hidden_size, num_layers, dropout):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size  = input_size,
            hidden_size = hidden_size,
            num_layers  = num_layers,
            batch_first = True,
            dropout     = dropout if num_layers > 1 else 0.0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1)
        )

    def forward(self, x):
        out, _ = self.lstm(x)       # out: (batch, seq_len, hidden)
        out = out[:, -1, :]         # last time step: (batch, hidden)
        out = self.dropout(out)
        return self.fc(out)         # (batch, 1) — raw logits


# ── Load & Prepare Data ───────────────────────────────────────────────────────
def load_data():
    print(f"[DATA] Loading {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)

    print(f"[DATA] Total : {len(df)} records")
    print(f"[DATA] Normal (0): {(df['label']==0).sum()}  |  Threat (1): {(df['label']==1).sum()}")

    X = df[FEATURES].values.astype(np.float32)
    y = df['label'].values.astype(np.float32)

    # Normalize features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Reshape for LSTM: (N, seq_len, features)
    X = X.reshape(-1, SEQ_LEN, len(FEATURES))

    # Class weights to handle imbalance (781 normal vs 99 threat)
    pos_count = (y == 1).sum()
    neg_count = (y == 0).sum()
    pos_weight = torch.tensor([neg_count / pos_count], dtype=torch.float32)
    print(f"[DATA] Class weight for threat class: {pos_weight.item():.2f}x")

    return X, y, scaler, pos_weight


# ── Training Loop ─────────────────────────────────────────────────────────────
def train():
    os.makedirs("models", exist_ok=True)

    X, y, scaler, pos_weight = load_data()

    # Train / test split (stratified to preserve class ratio)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )

    # PyTorch tensors
    X_tr = torch.tensor(X_train, dtype=torch.float32)
    y_tr = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_te = torch.tensor(X_test,  dtype=torch.float32)
    y_te = torch.tensor(y_test,  dtype=torch.float32).unsqueeze(1)

    train_loader = DataLoader(TensorDataset(X_tr, y_tr),
                              batch_size=BATCH_SIZE, shuffle=True)

    # Model, loss, optimizer
    model     = LoginLSTM(len(FEATURES), HIDDEN_SIZE, NUM_LAYERS, DROPOUT)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)

    print(f"\n[TRAIN] Starting training for {EPOCHS} epochs...")
    print(f"        Model params: hidden={HIDDEN_SIZE}, layers={NUM_LAYERS}, dropout={DROPOUT}")
    print("-" * 55)

    best_loss = float('inf')
    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_loader:
            optimizer.zero_grad()
            pred = model(xb)
            loss = criterion(pred, yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)
        scheduler.step(avg_loss)

        if epoch % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_pred = model(X_te)
                val_loss = criterion(val_pred, y_te).item()
            print(f"  Epoch {epoch:3d}/{EPOCHS}  train_loss={avg_loss:.4f}  val_loss={val_loss:.4f}")

        # Save best model
        if avg_loss < best_loss:
            best_loss = avg_loss
            torch.save(model.state_dict(), MODEL_PATH)

    # ── Evaluation ────────────────────────────────────────────────────────────
    print("\n[EVAL] Evaluating best model on test set...")
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()

    with torch.no_grad():
        logits = model(X_te)
        probs  = torch.sigmoid(logits).numpy().flatten()
        preds  = (probs >= 0.5).astype(int)

    print(classification_report(y_test, preds,
                                 target_names=["Normal", "Threat"],
                                 digits=3))
    try:
        auc = roc_auc_score(y_test, probs)
        print(f"  ROC-AUC Score : {auc:.4f}")
    except Exception:
        pass

    # Save scaler
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)

    print(f"\n[DONE] Model saved  : {MODEL_PATH}")
    print(f"[DONE] Scaler saved : {SCALER_PATH}")
    print("       Next step: central_server/baseline_scorer.py will load this model.")


if __name__ == "__main__":
    train()
