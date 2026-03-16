"""
data_provider.py
Streams realistic network traffic from the generated CICIDS2017 datasets.
"""
import pandas as pd
import numpy as np

DATA_DIR = "data"

class DataProvider:
    def __init__(self):
        self.benign_df = pd.read_csv(f"{DATA_DIR}/cicids_benign.csv")
        self.ddos_df = pd.read_csv(f"{DATA_DIR}/cicids_ddos.csv")
        self.portscan_df = pd.read_csv(f"{DATA_DIR}/cicids_portscan.csv")
        
        self.benign_idx = 0
        self.ddos_idx = 0
        self.portscan_idx = 0

    def get_benign_baselines(self):
        """Returns the mean values of the benign dataset as a baseline."""
        means = self.benign_df[["Packet Size", "IAT", "Entropy", "Symmetry"]].mean().values
        # Normalize roughly into [0, 1] range based on max values
        max_vals = np.array([1500.0, 0.1, 8.0, 1.0])
        return (means / max_vals).tolist()

    def get_next_benign(self, normalize=True):
        row = self.benign_df.iloc[self.benign_idx]
        self.benign_idx = (self.benign_idx + 1) % len(self.benign_df)
        vals = row[["Packet Size", "IAT", "Entropy", "Symmetry"]].values.astype(float)
        if normalize:
            max_vals = np.array([1500.0, 0.1, 8.0, 1.0])
            vals = np.clip(vals / max_vals, 0.0, 1.0)
        return vals

    def get_next_ddos(self, normalize=True):
        row = self.ddos_df.iloc[self.ddos_idx]
        self.ddos_idx = (self.ddos_idx + 1) % len(self.ddos_df)
        vals = row[["Packet Size", "IAT", "Entropy", "Symmetry"]].values.astype(float)
        if normalize:
            max_vals = np.array([1500.0, 0.1, 8.0, 1.0])
            vals = np.clip(vals / max_vals, 0.0, 1.0)
        return vals

    def get_next_portscan(self, normalize=True):
        row = self.portscan_df.iloc[self.portscan_idx]
        self.portscan_idx = (self.portscan_idx + 1) % len(self.portscan_df)
        vals = row[["Packet Size", "IAT", "Entropy", "Symmetry"]].values.astype(float)
        if normalize:
            max_vals = np.array([1500.0, 0.1, 8.0, 1.0])
            vals = np.clip(vals / max_vals, 0.0, 1.0)
        return vals

# Singleton instance for the app to use
provider = DataProvider()
ALIEN_BASELINES = provider.get_benign_baselines()
