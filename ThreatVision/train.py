"""
train.py
Trains the LSTM Autoencoder exclusively on benign real-world network traffic
so it learns the \"normal\" behaviour of the network.
"""

import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from torch.utils.data import DataLoader, TensorDataset
from model import LSTMAutoencoder, SEQ_LEN

def train_model():
    print("Loading benign dataset for training...")
    try:
        df = pd.read_csv("data/cicids_benign.csv")
    except FileNotFoundError:
        print("Error: data/cicids_benign.csv not found. Run setup_data.py first.")
        return
    
    # Extract features
    features = df[["Packet Size", "IAT", "Entropy", "Symmetry"]].values.astype(float)
    
    # Normalize exactly as matched in the data_provider
    max_vals = np.array([1500.0, 0.1, 8.0, 1.0])
    features = np.clip(features / max_vals, 0.0, 1.0)
    
    # Create temporal sequences
    print(f"Creating sequences of length {SEQ_LEN}...")
    sequences = []
    for i in range(len(features) - SEQ_LEN):
        sequences.append(features[i:i+SEQ_LEN])
    
    sequences = np.array(sequences)
    tensor_x = torch.tensor(sequences, dtype=torch.float32)
    dataset = TensorDataset(tensor_x, tensor_x)
    loader = DataLoader(dataset, batch_size=32, shuffle=True)
    
    model = LSTMAutoencoder()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()
    
    epochs = 5
    print("Training LSTM Autoencoder on normal traffic...")
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for batch_x, _ in loader:
            optimizer.zero_grad()
            output = model(batch_x)
            loss = criterion(output, batch_x)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(loader):.6f}")
    
    torch.save(model.state_dict(), "threatvision_autoencoder.pth")
    print("Model trained and saved as 'threatvision_autoencoder.pth'")

if __name__ == "__main__":
    train_model()
