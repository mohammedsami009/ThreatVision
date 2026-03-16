from scapy.all import sniff, Ether

def _resolve_iface(iface: str) -> str:
    print(f"Resolving '{iface}'...")
    from scapy.arch.windows import get_windows_if_list
    from scapy.all import get_if_list
    scapy_ifaces = get_if_list()
    win_ifaces   = get_windows_if_list()
    for w in win_ifaces:
        candidates = [
            w.get("name", "").lower(),
            w.get("description", "").lower(),
        ]
        if iface.lower() in candidates:
            guid = w.get("guid", "").upper().replace("{", "").replace("}", "")
            for s in scapy_ifaces:
                if guid in s.upper():
                    print(f"Resolved via GUID to '{s}'")
                    return s
    for w in win_ifaces:
        for ip in w.get("ips", []):
            if "." in ip and ip != "127.0.0.1" and ip != "0.0.0.0":
                guid = w.get("guid", "").upper().replace("{", "").replace("}", "")
                for s in scapy_ifaces:
                    if guid in s.upper():
                        print(f"Resolved via fallback IP {ip} to '{s}'")
                        return s
    return iface

iface_str = "Wi-Fi"
resolved = _resolve_iface(iface_str)
print(f"Listening for 5 packets on: {resolved}")

def handle_pkt(pkt):
    print("--- PACKET ---")
    if pkt.haslayer(Ether):
        print(f"Ether: src={pkt[Ether].src} dst={pkt[Ether].dst}")
    else:
        print("No Ether layer!")
    print(pkt.summary())

try:
    sniff(iface=resolved, prn=handle_pkt, count=5, timeout=10)
    print("Capture finished/timed out.")
except Exception as e:
    print(f"Error: {e}")
