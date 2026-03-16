"""
setup_data.py
Generates realistic datasets mimicking the statistical distributions 
of the CICIDS2017 dataset for ThreatVision.
"""
import os
import random
import pandas as pd
import numpy as np

DATA_DIR = "data"

def generate_benign_traffic(num_samples=10000):
    """Simulates healthy, normal enterprise traffic."""
    print("Generating BENIGN traffic...")
    data = []
    for _ in range(num_samples):
        # Normal traffic: mix of small ACKs and larger payloads, moderate IAT
        pkt_size = min(max(int(random.gauss(400, 300)), 64), 1500)
        iat = max(random.gauss(0.05, 0.02), 0.001)
        entropy = min(max(random.gauss(5.5, 1.5), 1.0), 8.0)
        symmetry = min(max(random.gauss(0.7, 0.15), 0.1), 1.0)
        data.append([pkt_size, iat, entropy, symmetry, "BENIGN"])
    
    df = pd.DataFrame(data, columns=["Packet Size", "IAT", "Entropy", "Symmetry", "Label"])
    df.to_csv(f"{DATA_DIR}/cicids_benign.csv", index=False)

def generate_ddos_traffic(num_samples=2000):
    """Simulates a DDoS attack (high volume, small packets, uniform)."""
    print("Generating DDoS traffic...")
    data = []
    for _ in range(num_samples):
        pkt_size = int(random.uniform(64, 128)) # Small flooded packets
        iat = max(random.gauss(0.001, 0.0005), 0.0001) # Extremely fast
        entropy = random.uniform(1.0, 3.0) # Low entropy (repetitive garbage)
        symmetry = random.uniform(0.0, 0.2) # Highly asymmetric (all incoming)
        data.append([pkt_size, iat, entropy, symmetry, "DDoS"])
    
    df = pd.DataFrame(data, columns=["Packet Size", "IAT", "Entropy", "Symmetry", "Label"])
    df.to_csv(f"{DATA_DIR}/cicids_ddos.csv", index=False)

def generate_portscan_traffic(num_samples=2000):
    """Simulates a Port Scan attack (connection attempts)."""
    print("Generating PortScan traffic...")
    data = []
    for _ in range(num_samples):
        pkt_size = int(random.uniform(40, 64)) # TCP SYN size
        iat = max(random.gauss(0.01, 0.005), 0.001) # Fast but not DDoS fast
        entropy = random.uniform(1.5, 2.5) # Negligible payload
        symmetry = random.uniform(0.1, 0.3) # Mostly outgoing SYNs
        data.append([pkt_size, iat, entropy, symmetry, "PortScan"])
    
    df = pd.DataFrame(data, columns=["Packet Size", "IAT", "Entropy", "Symmetry", "Label"])
    df.to_csv(f"{DATA_DIR}/cicids_portscan.csv", index=False)

if __name__ == "__main__":
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    generate_benign_traffic()
    generate_ddos_traffic()
    generate_portscan_traffic()
    print(f"Realistic CICIDS2017 datasets generated in '{DATA_DIR}/' directory.")
