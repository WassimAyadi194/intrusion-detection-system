"""
Run this from your project root with:
    python debug_pipeline.py

It will tell you exactly where packets are getting lost.
"""
import threading
import time
import queue
from capturing.packet_capture import PacketCapture

print("=== Step 1: Starting packet capture ===")
pc = PacketCapture()
pc.start_capture()
time.sleep(2)  # give sniff time to start
print("Capture thread started. Generate some traffic now (open a browser, ping, etc.)")
print("Waiting 10 seconds...\n")

# Monitor both queues for 10 seconds
start = time.time()
engine_count = 0
collector_count = 0

while time.time() - start < 10:
    # Drain engine_queue
    try:
        while True:
            pc.engine_queue.get_nowait()
            engine_count += 1
    except queue.Empty:
        pass

    # Drain collector_queue
    try:
        while True:
            pc.collector_queue.get_nowait()
            collector_count += 1
    except queue.Empty:
        pass

    time.sleep(0.5)

print(f"=== Step 2: Queue counts after 10s ===")
print(f"  engine_queue received:    {engine_count} packets")
print(f"  collector_queue received: {collector_count} packets")

if engine_count == 0 and collector_count == 0:
    print("\n  PROBLEM: packet_callback is never being called.")
    print("  -> Check that get_working_ifaces() is returning interfaces.")
    print("  -> Check you are running as Administrator.")
    interfaces = []
    try:
        from scapy.all import get_working_ifaces
        interfaces = [i.name for i in get_working_ifaces()]
        print(f"  -> Interfaces found: {interfaces}")
    except Exception as e:
        print(f"  -> Error getting interfaces: {e}")
elif engine_count > 0 and collector_count == 0:
    print("\n  PROBLEM: engine_queue gets packets but collector_queue does not.")
    print("  -> packet_callback is only putting into one queue.")
    print("  -> This should not happen with the current code — check packet_capture.py.")
else:
    print("\n  OK: Both queues are receiving packets.")
    print("  The problem is inside LiveMetricsCollector.process_packet or flush_window.")

    print("\n=== Step 3: Testing process_packet directly ===")
    from baseline.data_collector import LiveMetricsCollector
    collector = LiveMetricsCollector(pc)

    # Feed it some raw packets directly from the collector_queue
    processed = 0
    start2 = time.time()
    print("Feeding packets into process_packet for 5 seconds...")

    # Refill queues first
    time.sleep(5)

    while not pc.collector_queue.empty():
        pkt = pc.collector_queue.get_nowait()
        collector.process_packet(pkt)
        processed += 1

    print(f"  Packets processed: {processed}")
    print(f"  host_data contents:")
    for host, data in collector.host_data.items():
        print(f"    {host}: syn={data['syn_count']}, ports={len(data['unique_ports'])}, dests={len(data['unique_destinations'])}")

    if not collector.host_data:
        print("  PROBLEM: host_data is empty after processing packets.")
        print("  -> process_packet is filtering out all packets.")
        print("  -> Check that pkt.get('IP') and pkt.get('TCP') work on your packets.")
        print("  -> Scapy packets use layer access differently depending on version.")

        # Try a raw packet to see its structure
        try:
            pkt = pc.collector_queue.get(timeout=3)
            print(f"\n  Raw packet type: {type(pkt)}")
            print(f"  Packet summary: {pkt.summary()}")
            print(f"  Has IP layer:  {'IP' in pkt}")
            print(f"  Has TCP layer: {'TCP' in pkt}")
            print(f"  pkt.get('IP'): {pkt.get('IP')}")  # this is the likely culprit
        except queue.Empty:
            print("  No packets available to inspect.")
    else:
        print("\n  OK: host_data is being populated.")
        print("  Testing flush_window (will write to ids.db)...")
        collector.flush_window()
        print("  flush_window completed — check ids.db live_metrics table.")

pc.stop()
print("\n=== Done ===")