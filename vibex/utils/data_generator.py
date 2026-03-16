# utils/data_generator.py — Generate synthetic ARP traffic data

import numpy as np
from config import N_BENIGN, N_MALICIOUS, RANDOM_SEED


def generate_synthetic_data():
    """
    Generates labeled synthetic packet feature data.

    Features per packet:
        [pkt_size, is_arp, is_broadcast_dst, is_broadcast_src,
         psrc_last_octet, pdst_last_octet, hwsrc_first_byte, inter_arrival_time]

    Labels:
        0 = Benign
        1 = Malicious
    """
    np.random.seed(RANDOM_SEED)

    # ── Benign: normal ARP traffic ───────────────────────────
    benign = np.column_stack([
        np.random.normal(60, 5, N_BENIGN),            # pkt_size ~60 bytes
        np.ones(N_BENIGN),                             # is_arp = 1
        np.random.binomial(1, 0.95, N_BENIGN),         # mostly broadcast dst
        np.zeros(N_BENIGN),                            # src not broadcast
        np.random.randint(1, 254, N_BENIGN),           # psrc last octet (random)
        np.random.randint(1, 254, N_BENIGN),           # pdst last octet (random)
        np.random.randint(0, 255, N_BENIGN),           # hwsrc first byte (varied)
        np.random.exponential(2.0, N_BENIGN),          # normal inter-arrival gap
    ])

    # ── Malicious: ARP scan / spoofing patterns ──────────────
    malicious = np.column_stack([
        np.random.normal(60, 2, N_MALICIOUS),          # similar size
        np.ones(N_MALICIOUS),                          # is_arp = 1
        np.ones(N_MALICIOUS),                          # always broadcast dst
        np.zeros(N_MALICIOUS),                         # src not broadcast
        np.random.randint(1, 10, N_MALICIOUS),         # psrc low octets (scan)
        np.arange(1, N_MALICIOUS + 1) % 254,           # pdst sequential (scan)
        np.zeros(N_MALICIOUS),                         # hwsrc starts with 00
        np.random.exponential(0.05, N_MALICIOUS),      # very fast bursts
    ])

    X = np.vstack([benign, malicious])
    y = np.array([0] * N_BENIGN + [1] * N_MALICIOUS)

    # Shuffle
    idx = np.random.permutation(len(X))
    return X[idx], y[idx]
