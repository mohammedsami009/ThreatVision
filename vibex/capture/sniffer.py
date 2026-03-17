# capture/sniffer.py — Live packet capture, classification, and dashboard feed

from scapy.all import sniff
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP

from capture.feature_extractor import extract_features
from utils.predictor import predict, display_result


def _parse_pkt(pkt):
    from scapy.layers.inet import TCP, UDP, ICMP
    src_ip = dst_ip = "N/A"
    protocol = "OTHER"
    if pkt.haslayer(IP):
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "IP"
    elif pkt.haslayer(ARP):
        src_ip, dst_ip, protocol = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"
    return src_ip, dst_ip, protocol


def start_sniffing(if_bundle, ae_bundle, lstm_bundle):
    try:
        from dashboard import record_packet
        use_dashboard = True
        print("[+] Dashboard feed enabled → http://localhost:8050")
    except ImportError:
        use_dashboard = False

    print("\n[+] Sniffing live packets... Press Ctrl+C to stop.\n")

    def _callback(pkt):
        if not (pkt.haslayer(ARP) or pkt.haslayer(IP)):
            return
        features = extract_features(pkt)
        result   = predict(features, if_bundle, ae_bundle, lstm_bundle)
        display_result(pkt.summary(), result)
        if use_dashboard:
            src_ip, dst_ip, protocol = _parse_pkt(pkt)
            print(f"[sniffer] record_packet -> {src_ip} {dst_ip} {protocol} mal={result['is_malicious']} votes={result['votes']}")
            try:
                record_packet(
                    pkt_summary=pkt.summary(), src_ip=src_ip, dst_ip=dst_ip,
                    protocol=protocol, if_result=result["isolation_forest"],
                    ae_result=result["autoencoder"], lstm_result=result["lstm"],
                    votes=result["votes"],
                    verdict="MALICIOUS" if result["is_malicious"] else "BENIGN",
                )
            except Exception as e:
                print(f"[sniffer] record_packet exception: {e}")

    sniff(prn=_callback, store=False)
