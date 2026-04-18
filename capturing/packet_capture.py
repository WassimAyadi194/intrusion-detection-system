import subprocess
import threading
import queue
import sys

DEBUG = True  # Set to False once packets are confirmed working


class _Layer:
    def __init__(self, fields: dict):
        self._fields = fields

    def __getattr__(self, name):
        try:
            return self._fields[name]
        except KeyError:
            raise AttributeError(f"Layer has no field '{name}'")


class Packet:
    def __init__(self, ip_src, ip_dst, sport, dport, proto, flags=0):
        self._layers = {
            "IP": _Layer({"src": ip_src, "dst": ip_dst}),
        }
        if proto == "TCP":
            self._layers["TCP"] = _Layer({
                "sport": sport,
                "dport": dport,
                "flags": flags,
            })
        elif proto == "UDP":
            self._layers["UDP"] = _Layer({
                "sport": sport,
                "dport": dport,
            })

    def __getitem__(self, layer_name):
        return self._layers[layer_name]

    def __contains__(self, layer_name):
        return layer_name in self._layers

    def haslayer(self, layer_name):
        return layer_name in self._layers


def _parse_tshark_line(line: str):
    parts = line.split("|")

    if DEBUG and len(parts) < 7:
        print(f"[DEBUG] Skipped line ({len(parts)} parts): {repr(line)}", file=sys.stderr)
        return None

    if len(parts) < 7:
        return None

    ip_src, ip_dst, tcp_sport, tcp_dport, tcp_flags, udp_sport, udp_dport = parts

    if not ip_src or not ip_dst:
        if DEBUG:
            print(f"[DEBUG] Missing IP fields: {repr(line)}", file=sys.stderr)
        return None

    try:
        if tcp_sport and tcp_dport:
            sport = int(tcp_sport)
            dport = int(tcp_dport)
            flags = int(tcp_flags, 16) if tcp_flags else 0
            return Packet(ip_src, ip_dst, sport, dport, "TCP", flags)

        elif udp_sport and udp_dport:
            sport = int(udp_sport)
            dport = int(udp_dport)
            return Packet(ip_src, ip_dst, sport, dport, "UDP")

        else:
            if DEBUG:
                print(f"[DEBUG] Non-TCP/UDP packet: {repr(line)}", file=sys.stderr)
            return None

    except ValueError as e:
        if DEBUG:
            print(f"[DEBUG] ValueError parsing line {repr(line)}: {e}", file=sys.stderr)
        return None


class PacketCapture:
    def __init__(self):
        self.engine_queue = queue.Queue()
        self.collector_queue = queue.Queue()
        self._stop_event = threading.Event()

    def start_capture(self, ifaces):
        cmd = ["tshark"]

        for iface in ifaces:
            cmd += ["-i", iface]

        cmd += [
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-E", "separator=|",
            "-E", "occurrence=f",
            "-l",
        ]

        if DEBUG:
            print(f"[DEBUG] tshark command: {' '.join(cmd)}", file=sys.stderr)

        def capture_thread():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,  # capture stderr so we can print it
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError:
                raise RuntimeError("tshark not found. Install Wireshark and add it to PATH.")

            # Print tshark stderr in a separate thread so we see any startup errors
            def stderr_reader():
                for err_line in proc.stderr:
                    err_line = err_line.strip()
                    if err_line:
                        print(f"[TSHARK STDERR] {err_line}", file=sys.stderr)

            stderr_thread = threading.Thread(target=stderr_reader, daemon=True, name="TsharkStderr")
            stderr_thread.start()

            parsed_count = 0
            raw_count = 0

            try:
                for line in proc.stdout:
                    if self._stop_event.is_set():
                        break

                    line = line.strip()
                    if not line:
                        continue

                    raw_count += 1
                    if DEBUG and raw_count <= 5:
                        print(f"[DEBUG] Raw line #{raw_count}: {repr(line)}", file=sys.stderr)

                    pkt = _parse_tshark_line(line)
                    if pkt is None:
                        continue

                    parsed_count += 1
                    if DEBUG and parsed_count <= 5:
                        print(f"[DEBUG] Parsed packet #{parsed_count}: {pkt['IP'].src} -> {pkt['IP'].dst}", file=sys.stderr)

                    self.engine_queue.put(pkt)
                    self.collector_queue.put(pkt)

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

        self._capture_thread = threading.Thread(
            target=capture_thread,
            daemon=True,
            name="PacketCapture",
        )
        self._capture_thread.start()

    def stop(self):
        self._stop_event.set()
        self._capture_thread.join(timeout=5)