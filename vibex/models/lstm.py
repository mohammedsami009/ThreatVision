# models/lstm.py — LSTM anomaly detector

import numpy as np
from sklearn.preprocessing import StandardScaler
from config import LSTM_EPOCHS, LSTM_BATCH_SIZE, LSTM_THRESHOLD_PERCENTILE, N_FEATURES


def build_lstm():
    from tensorflow.keras import layers, Model

    inp = layers.Input(shape=(1, N_FEATURES))
    x   = layers.LSTM(32, return_sequences=True)(inp)
    x   = layers.LSTM(16)(x)
    x   = layers.Dense(8,  activation="relu")(x)
    out = layers.Dense(N_FEATURES, activation="linear")(x)

    model = Model(inp, out)
    model.compile(optimizer="adam", loss="mse")
    return model


def train(X_train):
    """
    Trains an LSTM autoencoder on the provided training data.

    Args:
        X_train: np.array of shape (n_samples, n_features)

    Returns:
        (LSTMModel, StandardScaler, float threshold)
    """
    print("[*] Training LSTM...")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_train).astype(np.float32)
    X_seq    = X_scaled.reshape(-1, 1, N_FEATURES)   # (samples, timesteps=1, features)

    model = build_lstm()
    model.fit(
        X_seq, X_scaled,
        epochs=LSTM_EPOCHS,
        batch_size=LSTM_BATCH_SIZE,
        validation_split=0.1,
        verbose=0,
    )

    recon     = model.predict(X_seq, verbose=0)
    errors    = np.mean(np.abs(X_scaled - recon), axis=1)
    threshold = float(np.percentile(errors, LSTM_THRESHOLD_PERCENTILE))

    print(f"[+] LSTM ready. Threshold: {threshold:.4f}")
    return model, scaler, threshold
