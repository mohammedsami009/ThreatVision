# models/autoencoder.py — Autoencoder anomaly detector

import numpy as np
from sklearn.preprocessing import StandardScaler
from config import AE_EPOCHS, AE_BATCH_SIZE, AE_THRESHOLD_PERCENTILE, N_FEATURES


def build_autoencoder():
    from tensorflow.keras import layers, Model

    inp      = layers.Input(shape=(N_FEATURES,))
    x        = layers.Dense(16, activation="relu")(inp)
    x        = layers.Dense(8,  activation="relu")(x)
    bottleneck = layers.Dense(4, activation="relu")(x)
    x        = layers.Dense(8,  activation="relu")(bottleneck)
    x        = layers.Dense(16, activation="relu")(x)
    out      = layers.Dense(N_FEATURES, activation="linear")(x)

    model = Model(inp, out)
    model.compile(optimizer="adam", loss="mse")
    return model


def train(X_train):
    """
    Trains an Autoencoder on the provided training data.

    Args:
        X_train: np.array of shape (n_samples, n_features)

    Returns:
        (Autoencoder, StandardScaler, float threshold)
    """
    print("[*] Training Autoencoder...")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_train).astype(np.float32)

    model = build_autoencoder()
    model.fit(
        X_scaled, X_scaled,
        epochs=AE_EPOCHS,
        batch_size=AE_BATCH_SIZE,
        validation_split=0.1,
        verbose=0,
    )

    recon     = model.predict(X_scaled, verbose=0)
    errors    = np.mean(np.abs(X_scaled - recon), axis=1)
    threshold = float(np.percentile(errors, AE_THRESHOLD_PERCENTILE))

    print(f"[+] Autoencoder ready. Threshold: {threshold:.4f}")
    return model, scaler, threshold
