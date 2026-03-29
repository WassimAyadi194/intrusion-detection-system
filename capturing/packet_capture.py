from scapy.all import sniff, IP, TCP, get_working_ifaces
import threading
import queue


class PacketCapture:
    def __init__(self):
        self.engine_queue = queue.Queue()
        self.collector_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.engine_queue.put(packet)
            self.collector_queue.put(packet)

    def start_capture(self):
        def capture_thread():
            interfaces = [i.name for i in get_working_ifaces()]
            sniff(
                iface=interfaces,
                filter="tcp",
                prn=self.packet_callback,
                store=0,
                timeout=86400,
                stop_filter=lambda _: self.stop_capture.is_set()
            )
        self.capture_thread = threading.Thread(
            target=capture_thread,
            daemon=True,
            name="PacketCapture"
        )
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join(timeout=5)  # don't block forever waiting for sniff