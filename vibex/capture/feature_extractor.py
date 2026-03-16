# capture/feature_extractor.py — Extract numeric features from Scapy packets

import time
import numpy as np

_last_packet_time = [None]


def extract_features(pkt):
    """
    Extracts 8 numeric features from a Scapy packet.

    Returns:
        np.array of shape (1, 8)
    """
    from scapy.layers.l2 import Ether, ARP

    now = time.time()
    inter_arrival = 0.0
    if _last_packet_time[0] is not None:
        inter_arrival = now - _last_packet_time[0]
    _last_packet_time[0] = now

    # ── Ethernet ─────────────────────────────────────────────
    pkt_size = len(pkt)

    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "00:00:00:00:00:00"
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "00:00:00:00:00:00"

    is_arp           = 1 if pkt.haslayer(ARP) else 0
    is_broadcast_dst = 1 if dst_mac == "ff:ff:ff:ff:ff:ff" else 0
    is_broadcast_src = 1 if src_mac == "ff:ff:ff:ff:ff:ff" else 0

    # ── ARP fields ───────────────────────────────────────────
    psrc_last    = 0
    pdst_last    = 0
    hwsrc_first  = 0

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        try:
            psrc_last = int(arp.psrc.split(".")[-1])
        except Exception:
            psrc_last = 0
        try:
            pdst_last = int(arp.pdst.split(".")[-1])
        except Exception:
            pdst_last = 0
        try:
            hwsrc_first = int(arp.hwsrc.split(":")[0], 16)
        except Exception:
            hwsrc_first = 0

    features = np.array([[
        pkt_size,
        is_arp,
        is_broadcast_dst,
        is_broadcast_src,
        psrc_last,
        pdst_last,
        hwsrc_first,
        inter_arrival,
    ]], dtype=np.float32)

    return features
