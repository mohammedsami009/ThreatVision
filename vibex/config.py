# config.py — Central configuration for the IDS

# ── Synthetic Data ──────────────────────────────────────────
N_BENIGN    = 5000
N_MALICIOUS = 500
RANDOM_SEED = 42

# ── Isolation Forest ────────────────────────────────────────
IF_N_ESTIMATORS  = 200
IF_CONTAMINATION = 0.09

# ── Autoencoder & LSTM ──────────────────────────────────────
AE_EPOCHS      = 30
AE_BATCH_SIZE  = 64
AE_THRESHOLD_PERCENTILE = 92   # reconstruction error percentile for anomaly cutoff

LSTM_EPOCHS     = 30
LSTM_BATCH_SIZE = 64
LSTM_THRESHOLD_PERCENTILE = 92

# ── Prediction ──────────────────────────────────────────────
MAJORITY_VOTE_THRESHOLD = 2    # out of 3 models must agree to flag malicious

# ── Features ────────────────────────────────────────────────
FEATURE_NAMES = [
    "pkt_size",
    "is_arp",
    "is_broadcast_dst",
    "is_broadcast_src",
    "psrc_last_octet",
    "pdst_last_octet",
    "hwsrc_first_byte",
    "inter_arrival_time",
]
N_FEATURES = len(FEATURE_NAMES)
