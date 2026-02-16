import socket
from scapy.all import get_working_ifaces, conf

def get_active_interface():
    #Socket connection to retrieve the outbound traffic IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

    except OSError as e:
        raise RuntimeError(f"Socket routing detection failed: {e}")
    
    #Finding the interface's name
    try:
        for iface in get_working_ifaces():
            if iface.ip == local_ip:
                return iface.name, local_ip
            
        raise RuntimeError(f"No interface found matching outbound IP {local_ip}")
    
    except Exception as e:
        raise RuntimeError(f"Interface enumeration failed: {e}")

def banner(interface, capture_filter):
    if conf.use_pcap:
        print(
            " === IDS STARTUP ===\n",
            f"Interface: {interface}\n",
            "Npcap: OK\n",
            f"Capture filter: {capture_filter}\n",
            "===================\n"
        )
    else:
        raise RuntimeError("ERROR: Npcap may be stopped. Service restart recommended.")


#print(get_working_ifaces())
#banner(get_active_interface(),"IP")