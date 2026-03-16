from scapy.arch.windows import get_windows_if_list
from scapy.all import get_if_list

print("=== SCAPY INTERFACES ===")
print(get_if_list())

print("\n=== WINDOWS INTERFACES ===")
for i in get_windows_if_list():
    print(f"Name: {i.get('name')}")
    print(f"Desc: {i.get('description')}")
    print(f"IPs:  {i.get('ips')}")
    print(f"GUID: {i.get('guid')}")
    print("-")
