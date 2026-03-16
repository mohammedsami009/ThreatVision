# main.py — Entry point for the Network Intrusion Detection System

import warnings
warnings.filterwarnings("ignore")

import threading
from utils.data_generator import generate_synthetic_data
from models import isolation_forest, autoencoder, lstm
from capture.sniffer import start_sniffing


def main():
    print("=" * 62)
    print("   Network Intrusion Detection System")
    print("   Models: Isolation Forest | Autoencoder | LSTM")
    print("=" * 62)

    # ── 1. Start dashboard in background thread ───────────────
    try:
        import dashboard as dash_app
        t = threading.Thread(
            target=lambda: dash_app.app.run(debug=False, port=8050, use_reloader=False),
            daemon=True
        )
        t.start()
        print("\n[+] Dashboard started → http://localhost:8050")
    except Exception as e:
        print(f"\n[!] Dashboard could not start: {e}")

    # ── 2. Generate synthetic training data ──────────────────
    print("\n[*] Generating synthetic training data...")
    X_train, y_train = generate_synthetic_data()
    print(f"[+] Dataset: {X_train.shape[0]} samples, {X_train.shape[1]} features\n")

    # ── 3. Train all models ──────────────────────────────────
    if_bundle   = isolation_forest.train(X_train)
    ae_bundle   = autoencoder.train(X_train)
    lstm_bundle = lstm.train(X_train)

    print("\n" + "=" * 62)
    print("[+] All models trained. Starting capture...")
    print("[+] Open browser → http://localhost:8050")
    print("    Press Ctrl+C to stop.\n")

    # ── 4. Start live packet capture ─────────────────────────
    start_sniffing(if_bundle, ae_bundle, lstm_bundle)


if __name__ == "__main__":
    main()
