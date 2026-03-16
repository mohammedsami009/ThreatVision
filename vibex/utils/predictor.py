# utils/predictor.py — Majority vote prediction across all 3 models

import numpy as np
from config import MAJORITY_VOTE_THRESHOLD


def predict(features, if_bundle, ae_bundle, lstm_bundle):
    """
    Runs features through all 3 models and returns a combined verdict.

    Args:
        features   : np.array of shape (1, 8)
        if_bundle  : (IsolationForest, StandardScaler)
        ae_bundle  : (Autoencoder, StandardScaler, threshold)
        lstm_bundle: (LSTMModel, StandardScaler, threshold)

    Returns:
        dict with per-model results and final verdict
    """
    if_model,   if_scaler               = if_bundle
    ae_model,   ae_scaler,   ae_thresh  = ae_bundle
    lstm_model, lstm_scaler, lstm_thresh = lstm_bundle

    # ── Isolation Forest ────────────────────────────────────
    X_if   = if_scaler.transform(features)
    if_raw = if_model.predict(X_if)[0]      # -1 anomaly, 1 normal
    if_label = 1 if if_raw == -1 else 0

    # ── Autoencoder ─────────────────────────────────────────
    X_ae     = ae_scaler.transform(features).astype(np.float32)
    ae_recon = ae_model.predict(X_ae, verbose=0)
    ae_error = float(np.mean(np.abs(X_ae - ae_recon)))
    ae_label = 1 if ae_error > ae_thresh else 0

    # ── LSTM ────────────────────────────────────────────────
    X_lstm     = lstm_scaler.transform(features).astype(np.float32).reshape(1, 1, -1)
    lstm_recon = lstm_model.predict(X_lstm, verbose=0)
    lstm_error = float(np.mean(np.abs(
        lstm_scaler.transform(features).astype(np.float32) - lstm_recon
    )))
    lstm_label = 1 if lstm_error > lstm_thresh else 0

    # ── Majority Vote ────────────────────────────────────────
    votes = if_label + ae_label + lstm_label
    is_malicious = votes >= MAJORITY_VOTE_THRESHOLD

    return {
        "isolation_forest": _label(if_label),
        "autoencoder":      _label(ae_label),
        "lstm":             _label(lstm_label),
        "votes":            votes,
        "final":            "🔴 MALICIOUS" if is_malicious else "🟢 BENIGN",
        "is_malicious":     is_malicious,
    }


def display_result(pkt_summary, result):
    print(f"\n{'─' * 62}")
    print(f"  Packet : {pkt_summary[:55]}")
    print(f"  IF     : {result['isolation_forest']}")
    print(f"  AE     : {result['autoencoder']}")
    print(f"  LSTM   : {result['lstm']}")
    print(f"  ══► VERDICT: {result['final']}  (votes: {result['votes']}/3)")


def _label(flag):
    return "MALICIOUS" if flag else "BENIGN"
