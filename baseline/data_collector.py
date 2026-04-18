#data_collector.py
import sqlite3
import time
import queue
from collections import defaultdict
from baseline.anomaly_detector import AnomalyDetector

DB_NAME = "ids.db"
WINDOW_SIZE = 10  # seconds per metric window


class LiveMetricsCollector:
    def __init__(self, packet_capture):
        self.packet_capture = packet_capture
        self.running = True
        self.host_data = defaultdict(lambda: {
            "syn_count": 0,
            "unique_ports": set(),
            "unique_destinations": set()
        })
        self.window_start = time.time()
        self.anomaly_detector = AnomalyDetector()

    def process_packet(self, pkt):
        if "IP" not in pkt or "TCP" not in pkt:
            return

        src   = pkt["IP"].src
        dst   = pkt["IP"].dst
        dport = pkt["TCP"].dport
        flags = pkt["TCP"].flags
        data  = self.host_data[src]

        if flags & 0x02:  # SYN — new connection attempt
            data["syn_count"] += 1

        data["unique_ports"].add(dport)
        data["unique_destinations"].add(dst)

    def flush_window(self):
        conn      = sqlite3.connect(DB_NAME, timeout=5)
        cursor    = conn.cursor()
        timestamp = int(time.time())

        # Snapshot before clearing so anomaly detection can use the values
        snapshot = {}
        for host_ip, metrics in self.host_data.items():
            snapshot[host_ip] = {
                "syn_count":           metrics["syn_count"],
                "unique_ports":        len(metrics["unique_ports"]),
                "unique_destinations": len(metrics["unique_destinations"]),
            }

        for host_ip, m in snapshot.items():
            cursor.execute("""
                INSERT INTO live_metrics
                    (host_ip, timestamp, syn_count, unique_ports, unique_destinations)
                VALUES (?, ?, ?, ?, ?)
            """, (host_ip, timestamp,
                  m["syn_count"], m["unique_ports"], m["unique_destinations"]))

        conn.commit()
        conn.close()  # release lock before anomaly detector opens its own connection

        for host_ip, m in snapshot.items():
            self.anomaly_detector.analyze_and_save(
                host_ip=host_ip,
                syn_count=m["syn_count"],
                unique_ports=m["unique_ports"],
                unique_destinations=m["unique_destinations"],
            )

        self.host_data.clear()
        self.window_start = time.time()

    def run(self):
        while self.running:
            try:
                pkt = self.packet_capture.collector_queue.get(timeout=1)
                self.process_packet(pkt)
            except queue.Empty:
                pass  # normal — no packet in the last second

            if time.time() - self.window_start >= WINDOW_SIZE:
                self.flush_window()

    def stop(self):
        self.running = False
        if self.host_data:
            self.flush_window()