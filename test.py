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
from scapy.all import *

interfaces = []
for i in get_working_ifaces():
    interfaces.append(i.name)
conf.bufsize = 2**24  # 4MB
sniff(iface = interfaces,  filter="tcp", store=0, count=10000000000, prn= lambda x: x.summary())
