#!/usr/bin/env python3
"""
Network Packet Anomaly Detection
Train: Isolation Forest, Autoencoder, LSTM Autoencoder on packet features.
Live: Capture packets destined to your IP and compute anomaly scores.
"""

import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model
import warnings
warnings.filterwarnings('ignore')

# ---------------------------
# Feature extraction
# ---------------------------
def mac2int(mac):
    """Convert MAC address string to integer."""
    return int(mac.replace(':', ''), 16) if mac else 0

def ip2int(ip):
    """Convert IP address string to integer."""
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return 0

def extract_features(packet):
    """
    Extract a fixed set of numerical features from a packet.
    Returns a dictionary with feature names.
    """
    features = {}
    
    # Basic Ethernet info
    if Ether in packet:
        eth = packet[Ether]
        features['eth_dst'] = mac2int(eth.dst)
        features['eth_src'] = mac2int(eth.src)
        features['eth_type'] = eth.type
    else:
        features['eth_dst'] = features['eth_src'] = features['eth_type'] = 0
    
    # Packet length (from IP layer if present, else from Ether)
    if IP in packet:
        ip = packet[IP]
        features['ip_len'] = ip.len
        features['ip_ttl'] = ip.ttl
        features['ip_proto'] = ip.proto
        features['ip_src'] = ip2int(ip.src)
        features['ip_dst'] = ip2int(ip.dst)
        # IP flags and fragmentation
        features['ip_flags'] = ip.flags
        features['ip_frag'] = ip.frag
    else:
        features['ip_len'] = len(packet) if Ether in packet else 0
        features['ip_ttl'] = 0
        features['ip_proto'] = 0
        features['ip_src'] = 0
        features['ip_dst'] = 0
        features['ip_flags'] = 0
        features['ip_frag'] = 0
    
    # TCP specific
    if TCP in packet:
        tcp = packet[TCP]
        features['tcp_sport'] = tcp.sport
        features['tcp_dport'] = tcp.dport
        features['tcp_flags'] = tcp.flags
        features['tcp_window'] = tcp.window
        features['tcp_dataofs'] = tcp.dataofs
    else:
        features['tcp_sport'] = 0
        features['tcp_dport'] = 0
        features['tcp_flags'] = 0
        features['tcp_window'] = 0
        features['tcp_dataofs'] = 0
    
    # UDP specific
    if UDP in packet:
        udp = packet[UDP]
        features['udp_sport'] = udp.sport
        features['udp_dport'] = udp.dport
        features['udp_len'] = udp.len
    else:
        features['udp_sport'] = 0
        features['udp_dport'] = 0
        features['udp_len'] = 0
    
    # ARP specific
    if ARP in packet:
        arp = packet[ARP]
        features['arp_op'] = arp.op
        features['arp_psrc'] = ip2int(arp.psrc)
        features['arp_pdst'] = ip2int(arp.pdst)
        features['arp_hwsrc'] = mac2int(arp.hwsrc)
        features['arp_hwdst'] = mac2int(arp.hwdst)
    else:
        features['arp_op'] = 0
        features['arp_psrc'] = 0
        features['arp_pdst'] = 0
        features['arp_hwsrc'] = 0
        features['arp_hwdst'] = 0
    
    return features

def packets_to_df(packets):
    """Convert a list of Scapy packets to a DataFrame of features."""
    records = [extract_features(pkt) for pkt in packets]
    return pd.DataFrame(records)

# ---------------------------
# Training functions
# ---------------------------
def train_isolation_forest(X, contamination=0.1, random_state=42):
    """Train and return Isolation Forest model."""
    model = IsolationForest(contamination=contamination, random_state=random_state, n_jobs=-1)
    model.fit(X)
    return model

def build_autoencoder(input_dim, encoding_dim=16):
    """Build a simple dense autoencoder."""
    input_layer = layers.Input(shape=(input_dim,))
    encoded = layers.Dense(encoding_dim, activation='relu')(input_layer)
    decoded = layers.Dense(input_dim, activation='linear')(encoded)
    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

def train_autoencoder(X, encoding_dim=16, epochs=50, batch_size=32, validation_split=0.1):
    """Train autoencoder and return model and history."""
    model = build_autoencoder(X.shape[1], encoding_dim)
    history = model.fit(X, X, epochs=epochs, batch_size=batch_size,
                        validation_split=validation_split, verbose=0)
    return model, history

def build_lstm_autoencoder(seq_len, n_features, latent_dim=16):
    """Build an LSTM autoencoder for sequences of feature vectors."""
    # Encoder
    input_seq = layers.Input(shape=(seq_len, n_features))
    encoded = layers.LSTM(latent_dim, activation='relu')(input_seq)
    
    # Decoder: repeat vector to match sequence length and use LSTM
    decoded = layers.RepeatVector(seq_len)(encoded)
    decoded = layers.LSTM(n_features, activation='relu', return_sequences=True)(decoded)
    # Optional time-distributed dense for final output
    decoded = layers.TimeDistributed(layers.Dense(n_features))(decoded)
    
    autoencoder = Model(input_seq, decoded)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder

def create_sequences(data, seq_len):
    """Convert 2D array (samples, features) into 3D sequences (samples-seq_len, seq_len, features)."""
    X_seq = []
    for i in range(len(data) - seq_len + 1):
        X_seq.append(data[i:i+seq_len])
    return np.array(X_seq)

def train_lstm_autoencoder(X, seq_len=10, latent_dim=16, epochs=50, batch_size=32, validation_split=0.1):
    """Train LSTM autoencoder on sequences."""
    X_seq = create_sequences(X, seq_len)
    model = build_lstm_autoencoder(seq_len, X.shape[1], latent_dim)
    history = model.fit(X_seq, X_seq, epochs=epochs, batch_size=batch_size,
                        validation_split=validation_split, verbose=0)
    return model, history

# ---------------------------
# Live detection
# ---------------------------
class LiveDetector:
    def __init__(self, iso_model, ae_model, lstm_model, scaler, seq_len=10, threshold=None):
        self.iso_model = iso_model
        self.ae_model = ae_model
        self.lstm_model = lstm_model
        self.scaler = scaler
        self.seq_len = seq_len
        self.buffer = []          # store recent feature vectors for LSTM
        self.threshold = threshold  # optional threshold for anomaly flag
    
    def preprocess_packet(self, packet):
        """Extract features and scale."""
        feat_dict = extract_features(packet)
        # Ensure all features are present and in correct order
        feature_names = self.scaler.feature_names_in_ if hasattr(self.scaler, 'feature_names_in_') else None
        if feature_names is not None:
            feat_vec = [feat_dict.get(name, 0) for name in feature_names]
        else:
            # fallback: use all keys from a sample? better to store feature order during training.
            feat_vec = list(feat_dict.values())
        feat_vec = np.array(feat_vec).reshape(1, -1)
        return self.scaler.transform(feat_vec).flatten()
    
    def update_buffer(self, feat):
        """Add new feature to buffer, keep last seq_len."""
        self.buffer.append(feat)
        if len(self.buffer) > self.seq_len:
            self.buffer.pop(0)
    
    def compute_scores(self, feat):
        """Compute anomaly scores from all models."""
        scores = {}
        # Isolation Forest: lower score = more anomalous (decision_function)
        scores['iso'] = -self.iso_model.decision_function(feat.reshape(1, -1))[0]
        
        # Autoencoder reconstruction error
        feat_reshaped = feat.reshape(1, -1)
        recon = self.ae_model.predict(feat_reshaped, verbose=0)
        scores['ae'] = np.mean((feat_reshaped - recon)**2)
        
        # LSTM autoencoder requires a sequence
        if len(self.buffer) == self.seq_len:
            seq = np.array(self.buffer[-self.seq_len:]).reshape(1, self.seq_len, -1)
            recon_seq = self.lstm_model.predict(seq, verbose=0)
            scores['lstm'] = np.mean((seq - recon_seq)**2)
        else:
            scores['lstm'] = 0.0  # not enough data yet
        
        return scores
    
    def process_packet(self, packet):
        """Main entry for live packets: update buffer, compute scores, return combined score."""
        feat = self.preprocess_packet(packet)
        self.update_buffer(feat)
        scores = self.compute_scores(feat)
        # Combine scores (simple average, can be weighted)
        combined = np.mean(list(scores.values()))
        scores['combined'] = combined
        return scores

# ---------------------------
# Main script
# ---------------------------
if __name__ == "__main__":
    import argparse
    import time
    import sys
    
    parser = argparse.ArgumentParser(description='Network Packet Anomaly Detection')
    parser.add_argument('--mode', choices=['train', 'live'], required=True,
                        help='train: train models from pcap; live: detect anomalies on live traffic')
    parser.add_argument('--pcap', type=str, help='Path to pcap file for training')
    parser.add_argument('--interface', type=str, default='eth0', help='Network interface for live capture')
    parser.add_argument('--ip', type=str, help='Your local IP to filter packets (optional)')
    parser.add_argument('--seq_len', type=int, default=10, help='Sequence length for LSTM')
    args = parser.parse_args()
    
    if args.mode == 'train':
        if not args.pcap:
            print("Error: --pcap required for training mode")
            sys.exit(1)
        
        print(f"Reading packets from {args.pcap}...")
        packets = rdpcap(args.pcap)
        print(f"Loaded {len(packets)} packets.")
        
        # Convert to feature DataFrame
        df = packets_to_df(packets)
        print(f"Extracted {df.shape[1]} features from {df.shape[0]} packets.")
        
        # Drop constant columns (optional)
        df = df.loc[:, (df != df.iloc[0]).any()]  # keep columns that vary
        
        # Handle missing/infinite values
        df.fillna(0, inplace=True)
        df.replace([np.inf, -np.inf], 0, inplace=True)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df)
        
        # Train/test split (unsupervised, so just for monitoring)
        X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)
        
        # 1. Isolation Forest
        print("\nTraining Isolation Forest...")
        iso_model = train_isolation_forest(X_train)
        
        # 2. Autoencoder
        print("Training Autoencoder...")
        ae_model, ae_history = train_autoencoder(X_train, encoding_dim=min(16, X_train.shape[1]//2))
        
        # 3. LSTM Autoencoder
        print("Training LSTM Autoencoder...")
        lstm_model, lstm_history = train_lstm_autoencoder(X_train, seq_len=args.seq_len)
        
        # Save models and scaler
        print("\nSaving models...")
        joblib.dump(iso_model, 'iso_model.pkl')
        ae_model.save('ae_model.h5')
        lstm_model.save('lstm_model.h5')
        joblib.dump(scaler, 'scaler.pkl')
        # Also save feature names for live detection
        feature_names = df.columns.tolist()
        joblib.dump(feature_names, 'feature_names.pkl')
        joblib.dump(args.seq_len, 'seq_len.pkl')
        
        print("Training completed. Models saved.")
        
    elif args.mode == 'live':
        # Load models
        print("Loading models...")
        iso_model = joblib.load('iso_model.pkl')
        ae_model = keras.models.load_model('ae_model.h5')
        lstm_model = keras.models.load_model('lstm_model.h5')
        scaler = joblib.load('scaler.pkl')
        feature_names = joblib.load('feature_names.pkl')
        seq_len = joblib.load('seq_len.pkl')
        
        # Ensure scaler has feature names (for ordering)
        if not hasattr(scaler, 'feature_names_in_'):
            scaler.feature_names_in_ = feature_names
        
        detector = LiveDetector(iso_model, ae_model, lstm_model, scaler, seq_len)
        
        # Build BPF filter for destination IP if provided
        bpf_filter = None
        if args.ip:
            bpf_filter = f"dst host {args.ip}"
            print(f"Filtering packets for destination {args.ip}")
        
        print(f"Starting live capture on {args.interface}... Press Ctrl+C to stop.")
        
        def packet_handler(pkt):
            scores = detector.process_packet(pkt)
            # Print scores (you can customize output)
            print(f"\nPacket {pkt.summary()}")
            print(f"  ISO score: {scores['iso']:.4f}, AE score: {scores['ae']:.4f}, LSTM score: {scores['lstm']:.4f}, Combined: {scores['combined']:.4f}")
            # Optional: flag as anomaly if combined > threshold (you can set threshold based on training)
        
        # Sniff packets (may need root privileges)
        sniff(iface=args.interface, filter=bpf_filter, prn=packet_handler, store=False)