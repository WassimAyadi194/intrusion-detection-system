import subprocess
import threading
import queue
import ipaddress
import time
from datetime import datetime

from logs.ids_logger import get_logger
from config import (
    _MAX_RESTARTS, _RESTART_BACKOFF, _STALL_TIMEOUT, 
    _STALL_CHECK_INTERVAL, _QUEUE_WARN_INTERVAL, _QUEUE_WARN_DEPTH, 
    MAX_QUEUE_SIZE, QUEUE_SIZE_HARD_LIMIT, _HEARTBEAT_INTERVAL
    )

log = get_logger(__name__)

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

    if len(parts) < 7:
        log.debug("Skipped line (%d parts): %r", len(parts), line)
        return None

    ip_src, ip_dst, tcp_sport, tcp_dport, tcp_flags, udp_sport, udp_dport = parts

    if not ip_src or not ip_dst:
        log.debug("Missing IP fields: %r", line)
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
            log.debug("Non-TCP/UDP packet: %r", line)
            return None

    except ValueError as e:
        log.debug("ValueError parsing line %r: %s", line, e)
        return None


class PacketCapture:
    def __init__(self):
        self.engine_queue    = queue.Queue()   # unbounded; backpressure via _should_enqueue()
        self.collector_queue = queue.Queue()   # unbounded; low-priority packets dropped at limit
        self._stop_event     = threading.Event()

        self._last_packet_ts: float = 0.0
        self._last_packet_lock = threading.Lock()
    
        # 0.0 / None means the heartbeat loop has not fired yet.
        self._last_heartbeat_ts: float = 0.0
        self._last_heartbeat_wall_time: datetime | None = None  # human-readable twin


        self._STALL_TIMEOUT = _STALL_TIMEOUT

        self._ifaces: list = []   # stored at start_capture for restart use

    def start_capture(self, ifaces: list):
        self._ifaces = ifaces
        self._restart_count = 0
        self._start_ts = time.monotonic()
        log.info("Capture started on interfaces: %s", ", ".join(str(i) for i in ifaces))

        self._launch_capture_thread()
        self._launch_stall_monitor()
        self._launch_queue_monitor()
        self._launch_heartbeat()

    def stop(self):
        self._stop_event.set()
        if hasattr(self, "_capture_thread"):
            self._capture_thread.join(timeout=5)
        log.info("Packet capture stopped.")

    def _build_cmd(self) -> list[str]:
        cmd = ["tshark"]
        for iface in self._ifaces:
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
        return cmd

    def _launch_capture_thread(self):
        self._capture_thread = threading.Thread(
            target=self._capture_with_restart,
            daemon=True,
            name="PacketCapture",
        )
        self._capture_thread.start()

    def _capture_with_restart(self):
        """
        Outer loop: run tshark, restart on crash indefinitely.
        After _MAX_RESTARTS consecutive failures, logs CRITICAL, sleeps 5s,
        resets the counter, and keeps retrying.
        """
        attempt = 0
        while not self._stop_event.is_set():
            if attempt > 0:
                log.warning(
                    "tshark restarting (attempt %d/%d) after %.1fs backoff",
                    attempt, _MAX_RESTARTS, _RESTART_BACKOFF,
                )
                time.sleep(_RESTART_BACKOFF)

            exited_cleanly = self._run_tshark()

            if self._stop_event.is_set():
                # Stopped intentionally — not a crash.
                break

            attempt += 1
            if not exited_cleanly:
                log.error("tshark process exited unexpectedly (crash #%d)", attempt)

            if attempt > _MAX_RESTARTS:
                log.critical(
                    "tshark failed %d consecutive time(s) — "
                    "sleeping 5s then resetting retry counter.",
                    attempt,
                )
                time.sleep(5)
                attempt = 0   # reset: keep retrying indefinitely

        log.info("Capture thread exiting.")

    def _run_tshark(self) -> bool:
        """
        Spawn tshark and read packets until it exits or stop is requested.
        Returns True if the process exited with code 0 (clean), False otherwise.
        """
        cmd = self._build_cmd()
        log.debug("tshark command: %s", " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            log.critical("tshark not found — install Wireshark and add it to PATH.")
            return False

        def stderr_reader():
            for err_line in proc.stderr:
                err_line = err_line.strip()
                if err_line:
                    log.debug("tshark stderr: %s", err_line)

        stderr_thread = threading.Thread(
            target=stderr_reader, daemon=True, name="TsharkStderr"
        )
        stderr_thread.start()

        parsed_count = 0
        raw_count    = 0
        _last_stats  = time.monotonic()

        try:
            for line in proc.stdout:
                if self._stop_event.is_set():
                    break

                line = line.strip()
                if not line:
                    continue

                raw_count += 1
                pkt = _parse_tshark_line(line)
                if pkt is None:
                    continue

                parsed_count += 1

                # Update stall-detection timestamp.
                with self._last_packet_lock:
                    self._last_packet_ts = time.monotonic()

                self._enqueue(pkt)

                # Periodic capture stats at DEBUG level (visible when log level = DEBUG)
                _now = time.monotonic()
                if _now - _last_stats >= 5.0:
                    log.debug("capture stats: raw=%d parsed=%d", raw_count, parsed_count)
                    _last_stats = _now

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            return_code = proc.returncode

        return return_code == 0

    def _launch_stall_monitor(self):
        def _monitor():
            # Give tshark time to start before the first stall check.
            time.sleep(_STALL_TIMEOUT)
            while not self._stop_event.is_set():
                with self._last_packet_lock:
                    last = self._last_packet_ts

                if last == 0.0:
                    # No packet has ever arrived — capture may still be starting up,
                    # or tshark sees no traffic on the selected interfaces.
                    log.warning(
                        "No packets received yet — tshark may not be capturing traffic "
                        "(check interface selection or permissions)"
                    )
                else:
                    age = time.monotonic() - last
                    if age >= _STALL_TIMEOUT:
                        log.warning(
                            "Capture stall detected — no packets for %.0fs "
                            "(last packet %.0fs ago)",
                            _STALL_TIMEOUT, age,
                        )

                time.sleep(_STALL_CHECK_INTERVAL)

        t = threading.Thread(target=_monitor, daemon=True, name="StallMonitor")
        t.start()

    @staticmethod
    def _is_loopback_packet(pkt) -> bool:
        """Return True if the packet's source is a loopback address."""
        try:
            return ipaddress.ip_address(pkt["IP"].src).is_loopback
        except Exception:
            return False

    def _enqueue(self, pkt) -> None:
        eq_depth = self.engine_queue.qsize()
        cq_depth = self.collector_queue.qsize()

        overloaded = (eq_depth > MAX_QUEUE_SIZE or cq_depth > MAX_QUEUE_SIZE)
        hard_overloaded = (eq_depth > QUEUE_SIZE_HARD_LIMIT or cq_depth > QUEUE_SIZE_HARD_LIMIT)

        # HARD LIMIT: drop everything
        if hard_overloaded:
            return
        # SOFT LIMIT: drop low-value traffic only
        if overloaded and self._is_loopback_packet(pkt):
            return

        self.engine_queue.put(pkt)
        self.collector_queue.put(pkt)

    def _launch_queue_monitor(self):
        def _monitor():
            while not self._stop_event.is_set():
                time.sleep(_QUEUE_WARN_INTERVAL)
                eq = self.engine_queue.qsize()
                cq = self.collector_queue.qsize()

                if eq >= _QUEUE_WARN_DEPTH:
                    log.warning(
                        "engine_queue depth: %d — processing lag", eq
                    )
                if cq >= _QUEUE_WARN_DEPTH:
                    log.warning(
                        "collector_queue depth: %d — processing lag", cq
                    )

                # Always emit a periodic depth line at DEBUG level so operators
                # can see normal queue health without noise in production.
                log.debug(
                    "queue depths — engine: %d  collector: %d", eq, cq
                )

        t = threading.Thread(target=_monitor, daemon=True, name="QueueMonitor")
        t.start()

    def _launch_heartbeat(self):
        def _heartbeat():
            while not self._stop_event.is_set():
                time.sleep(_HEARTBEAT_INTERVAL)
                # Record when this UI tick fired (monotonic + wall-clock twin).
                self._last_heartbeat_ts = time.monotonic()
                self._last_heartbeat_wall_time = datetime.now()
                eq = self.engine_queue.qsize()
                cq = self.collector_queue.qsize()
                log.info(
                    "system healthy — engine_queue: %d  collector_queue: %d",
                    eq, cq,
                )

        t = threading.Thread(target=_heartbeat, daemon=True, name="Heartbeat")
        t.start()

    @property
    def last_heartbeat_ts(self) -> float:
        """
        Monotonic timestamp of the most recent heartbeat tick.
        Returns 0.0 until the first heartbeat fires.
        """
        return self._last_heartbeat_ts

    @property
    def last_heartbeat_wall_time(self) -> datetime | None:
        """
        Wall-clock datetime of the most recent heartbeat tick, or None if not yet started.
        Kept in sync with ``last_heartbeat_ts``; formatting is left to callers.
        """
        return self._last_heartbeat_wall_time

    @property
    def stall_detected(self) -> bool:
        """
        Return True when no packet has arrived within the stall timeout window.
        """
        with self._last_packet_lock:
            last = self._last_packet_ts
            
        if last == 0.0:
            if hasattr(self, "_start_ts"):
                return (time.monotonic() - self._start_ts) >= self._STALL_TIMEOUT
            return False
            
        return (time.monotonic() - last) >= self._STALL_TIMEOUT