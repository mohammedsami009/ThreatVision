# models/isolation_forest.py — Isolation Forest anomaly detector

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from config import IF_N_ESTIMATORS, IF_CONTAMINATION, RANDOM_SEED


def train(X_train):
    """
    Trains an Isolation Forest on the provided training data.

    Args:
        X_train: np.array of shape (n_samples, n_features)

    Returns:
        (IsolationForest, StandardScaler)
    """
    print("[*] Training Isolation Forest...")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        contamination=IF_CONTAMINATION,
        random_state=RANDOM_SEED,
    )
    model.fit(X_scaled)

    print("[+] Isolation Forest ready.")
    return model, scaler
