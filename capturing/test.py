# Define color codes as constants for easier use
'''class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m' # Resets the color

print(f"{Colors.RED}This text is red!{Colors.RESET}")
print(f"{Colors.GREEN}This text is green!{Colors.RESET}")
print("This text is normal again.")


from scapy.all import *
for iface in get_working_ifaces():
    print(f"NAME: {iface.name} \nIFACE: {iface} \n")
'''
'''from scapy.all import *

interfaces = []
for i in get_working_ifaces():
    interfaces.append(i.name)
conf.bufsize = 2**24  # 4MB
sniff(iface = interfaces,  filter="tcp", store=0, count=10000000000, prn= lambda x: x.summary())
'''

'''
import subprocess
import re

def get_tshark_interfaces():
    result = subprocess.run(
        ["tshark", "-D"],
        capture_output=True,
        text=True
    )

    interfaces = []
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+)\.\s+(.*?)\s+\((.*?)\)", line)
        if match:
            idx, device, name = match.groups()
            interfaces.append({
                "index": idx,
                "device": device,
                "name": name
            })

    return interfaces
#print(get_tshark_interfaces())

def get_relevant_interfaces():
    interfaces = get_tshark_interfaces()

    selected = []
    for iface in interfaces:
        name = iface["name"].strip().lower()

        if (
            name == "wi-fi" or
            "ethernet" in name or
            "loopback" in name
        ):
            selected.append(iface)

    return selected
print(get_relevant_interfaces())
'''
import os
print("[DB PATH]", os.path.abspath("ids.db"))