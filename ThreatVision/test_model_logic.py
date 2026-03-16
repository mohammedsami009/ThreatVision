import torch
import numpy as np
from model import LSTMAutoencoder
from data_provider import provider, ALIEN_BASELINES
from engine import calculate_jsd, calculate_trust_score

# Load model
model = LSTMAutoencoder()
model.load_state_dict(torch.load("threatvision_autoencoder.pth", map_location="cpu", weights_only=True))
model.eval()

def test_stream(name, get_func):
    features = get_func(normalize=True)
    # Convert exactly as in dashboard.py
    feature_seq = np.tile(features, (10, 1))[np.newaxis, :, :]
    tensor_input = torch.tensor(feature_seq, dtype=torch.float32)
    
    with torch.no_grad():
        mse = float(model.reconstruction_error(tensor_input).item())
        
    jsd = calculate_jsd(features, ALIEN_BASELINES)
    trust_score = calculate_trust_score(mse, jsd)
    
    print(f"--- {name} ---")
    print(f"Features: {features}")
    print(f"MSE: {mse:.4f}")
    print(f"JSD: {jsd:.4f}")
    print(f"Trust: {trust_score:.1f}")

test_stream("Benign", provider.get_next_benign)
test_stream("DDoS", provider.get_next_ddos)
test_stream("PortScan", provider.get_next_portscan)
