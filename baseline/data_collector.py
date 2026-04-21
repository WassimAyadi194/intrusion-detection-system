# data_collector.py
import sqlite3
import time
import queue
from collections import defaultdict

DB_NAME = "ids.db"
WINDOW_SIZE = 10  # seconds per metric window


class LiveMetricsCollector:
    def __init__(self, packet_capture, engine):
        self.packet_capture = packet_capture
        self.engine = engine
        self.running = True
        self.host_data = defaultdict(lambda: {
            "syn_count": 0,
            "unique_ports": set(),
            "unique_destinations": set(),
            "packet_count": 0,          # ← NEW
        })
        self.window_start = time.time()

    def process_packet(self, pkt):
        if "IP" not in pkt or "TCP" not in pkt:
            return

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        dport = pkt["TCP"].dport
        flags = pkt["TCP"].flags
        data  = self.host_data[src]

        data["packet_count"] += 1           # ← NEW: count every TCP/IP packet

        if flags & 0x02:  # SYN — new connection attempt
            data["syn_count"] += 1

        data["unique_ports"].add(dport)
        data["unique_destinations"].add(dst)

    def flush_window(self):
        conn      = sqlite3.connect(DB_NAME, timeout=5)
        cursor    = conn.cursor()
        timestamp = int(time.time())

        snapshot = {}
        for host_ip, metrics in self.host_data.items():
            snapshot[host_ip] = {
                "syn_count":           metrics["syn_count"],
                "unique_ports":        len(metrics["unique_ports"]),
                "unique_destinations": len(metrics["unique_destinations"]),
                "packet_count":        metrics["packet_count"],    # ← NEW
            }

        for host_ip, m in snapshot.items():
            cursor.execute("""
                INSERT INTO live_metrics
                    (host_ip, timestamp, syn_count, unique_ports,
                     unique_destinations, packet_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (host_ip, timestamp,
                  m["syn_count"], m["unique_ports"],
                  m["unique_destinations"], m["packet_count"]))  # ← NEW

        conn.commit()
        conn.close()

        for host_ip, m in snapshot.items():
            self.engine.process_anomaly(
                host_ip=host_ip,
                syn_count=m["syn_count"],
                unique_ports=m["unique_ports"],
                unique_destinations=m["unique_destinations"],
                packet_count=m["packet_count"],                    # ← NEW
            )

        self.host_data.clear()
        self.window_start = time.time()

    def run(self):
        while self.running:
            try:
                pkt = self.packet_capture.collector_queue.get(timeout=1)
                self.process_packet(pkt)
            except queue.Empty:
                pass

            if time.time() - self.window_start >= WINDOW_SIZE:
                self.flush_window()

    def stop(self):
        self.running = False
        if self.host_data:
            self.flush_window()