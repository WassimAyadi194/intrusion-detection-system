#interface_utils.py
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
        # tshark -D output on Windows:
        #   1. \Device\NPF_{GUID} (Wi-Fi)
        # on Linux:
        #   1. eth0
        # We capture: index, device path, and optional friendly name in parens.
        match = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?", line)
        if match:
            idx, device, friendly = match.groups()
            name = (friendly or device).strip()
            interfaces.append({
                "index": idx,
                "device": device,
                "name": name,
            })
    return interfaces


def get_relevant_interfaces():
    interfaces = get_tshark_interfaces()

    selected = []
    for iface in interfaces:
        name = iface["name"].strip().lower()
        if (
            #name == "wi-fi" or
            "ethernet" in name
            #"loopback" in name
        ):
            selected.append(iface)

    return selected


def banner(ifaces):
    names = [iface["name"] for iface in ifaces]
    print(
        " === IDS STARTUP ===\n",
        f"Interfaces : {', '.join(names)}\n",
        "Capture    : tshark (TCP+UDP)\n",
        "===================\n",
    )