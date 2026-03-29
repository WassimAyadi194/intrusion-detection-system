import time

class PortScanDetector:
    def __init__(self):
        self.vertical_scan = {}
        self.horizontal_scan = {}
        self.SCAN_WINDOW = 30
        self.PORT_THRESHOLD = 8
        self.HOST_THRESHOLD = 10

    def analyze_packet(self, pkt):

        flags = pkt["TCP"].flags

        # Only SYN packets
        if not flags & 0x02:
            return None


        src = pkt["IP"].src
        dst = pkt["IP"].dst
        dport = pkt["TCP"].dport
        now = time.time()

        alerts = []

        # ---- Vertical port scan ----
        vkey = (src, dst)

        if vkey not in self.vertical_scan:
            self.vertical_scan[vkey] = {"ports": set(), "time": now}

        self.vertical_scan[vkey]["ports"].add(dport)
        #print(f"Vertical scan key {vkey} port counts: {len(self.vertical_scan[vkey]["ports"])} // Ports: {self.vertical_scan[vkey]["ports"]}")

        if (
            len(self.vertical_scan[vkey]["ports"]) >= self.PORT_THRESHOLD
            and now - self.vertical_scan[vkey]["time"] <= self.SCAN_WINDOW
        ):
            alerts.append(f"\nVERTICAL SCAN: {src} → {dst}\n")
            del self.vertical_scan[vkey]

        # ---- Horizontal port scan ----
        hkey = (src, dport)

        if hkey not in self.horizontal_scan:
            self.horizontal_scan[hkey] = {"hosts": set(), "time": now}

        self.horizontal_scan[hkey]["hosts"].add(dst)

        if (
            len(self.horizontal_scan[hkey]["hosts"]) >= self.HOST_THRESHOLD
            and now - self.horizontal_scan[hkey]["time"] <= self.SCAN_WINDOW
        ):
            alerts.append(f"HORIZONTAL SCAN: {src} on port {dport}")
            del self.horizontal_scan[hkey]

        self.cleanup(now)

        return alerts if alerts else None

    def cleanup(self, now):
        for k in list(self.vertical_scan.keys()):
            if now - self.vertical_scan[k]["time"] > self.SCAN_WINDOW:
                del self.vertical_scan[k]

        for k in list(self.horizontal_scan.keys()):
            if now - self.horizontal_scan[k]["time"] > self.SCAN_WINDOW:
                del self.horizontal_scan[k]