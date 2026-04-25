# test_anomaly.py
from baseline.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()

# This should NOT trigger — values close to the baseline you inserted
print("=== Normal traffic (expect no alerts) ===")
alerts = detector.analyze_and_save(
    host_ip="192.168.1.10",
    syn_count=5,
    unique_ports=3,
    unique_destinations=2,
)
print(f"Alerts: {len(alerts)}")

# This should trigger — syn_count of 200 is way above a baseline of ~5
print("\n=== Anomalous traffic (expect alert) ===")
alerts = detector.analyze_and_save(
    host_ip="192.168.1.10",
    syn_count=200,
    unique_ports=3,
    unique_destinations=2,
)
print(f"Alerts: {len(alerts)}")