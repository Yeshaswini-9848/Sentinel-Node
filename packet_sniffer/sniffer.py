import collections
import threading
import time

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .analyzer import PacketAnalyzer
from .alert_engine import AlertEngine
from .logger import TrafficLogger
from .simulator import TrafficSimulator


class NetworkSniffer:
    """
    Core network monitoring engine for the SentinelNode platform.
    Manages packet capture (via Scapy) or synthetic traffic simulation,
    feeds data through the analysis and IDS pipeline, and exposes
    enriched traffic records to the web dashboard.
    """

    MAX_QUEUE_SIZE = 200

    def __init__(self, interface=None, log_file=None):
        self.interface = interface
        self.analyzer = PacketAnalyzer()
        self.alert_engine = AlertEngine()
        self.logger = TrafficLogger(log_file)
        self.simulator = TrafficSimulator()

        self.is_monitoring = False
        self.simulation_mode = False
        self.packet_queue = []
        self.protocol_stats = collections.Counter()
        self.traffic_timeline = []  # (timestamp_str, count) tuples
        self._timeline_counter = 0
        self._timeline_last_flush = time.time()
        self._lock = threading.Lock()
        self._monitoring_thread = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_monitoring(self, simulation_mode=False):
        if self.is_monitoring:
            return
        self.simulation_mode = simulation_mode
        self.is_monitoring = True
        # Reset stats
        with self._lock:
            self.packet_queue.clear()
            self.protocol_stats.clear()
            self.traffic_timeline.clear()
            self._timeline_counter = 0
            self._timeline_last_flush = time.time()

        target = self._run_simulation if simulation_mode else self._run_sniffer
        self._monitoring_thread = threading.Thread(target=target, daemon=True)
        self._monitoring_thread.start()

    def stop_monitoring(self):
        self.is_monitoring = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=2)

    def get_latest_traffic(self):
        with self._lock:
            return list(self.packet_queue)

    def get_stats(self):
        with self._lock:
            alerts_all = self.alert_engine.alert_history
            severity_dist = self.alert_engine.get_severity_distribution()
            return {
                "packet_count": len(self.packet_queue),
                "alerts_total": len(alerts_all),
                "severity_distribution": severity_dist,
                "protocol_distribution": dict(self.protocol_stats),
                "traffic_timeline": list(self.traffic_timeline[-20:]),  # last 20 ticks
                "simulation_mode": self.simulation_mode,
                "is_monitoring": self.is_monitoring,
            }

    # ------------------------------------------------------------------
    # Internal capture loops
    # ------------------------------------------------------------------

    def _run_sniffer(self):
        if not SCAPY_AVAILABLE:
            print("[SentinelNode] Scapy unavailable — switching to Simulation Mode.")
            self.simulation_mode = True
            self._run_simulation()
            return
        try:
            sniff(
                iface=self.interface,
                prn=lambda pkt: self._process_packet(pkt, is_raw=True),
                stop_filter=lambda _: not self.is_monitoring,
            )
        except Exception as exc:
            print(f"[SentinelNode] Capture error ({exc}) — switching to Simulation Mode.")
            self.simulation_mode = True
            self._run_simulation()

    def _run_simulation(self):
        print("[SentinelNode] Operational Mode: Simulation (No Live Traffic)")
        while self.is_monitoring:
            mock = self.simulator.generate_mock_packet()
            self._process_packet(mock, is_raw=False)
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Packet processing pipeline
    # ------------------------------------------------------------------

    def _process_packet(self, packet, is_raw=True):
        if not self.is_monitoring:
            return

        packet_info = self.analyzer.analyze(packet) if is_raw else packet

        if not packet_info:
            return

        alerts = self.alert_engine.detect_suspicious(packet_info)
        packet_info["alerts"] = alerts if alerts else []
        packet_info["timestamp"] = time.strftime("%H:%M:%S")

        # Derive severity for this packet
        if alerts:
            severities = [a["severity"] for a in alerts]
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            packet_info["severity"] = next((s for s in order if s in severities), "LOW")
        else:
            packet_info["severity"] = "SAFE"

        # Update protocol distribution
        proto = packet_info.get("protocol", "OTHER")
        with self._lock:
            self.protocol_stats[proto] += 1

        # Update traffic timeline (bucket per second)
        now = time.time()
        with self._lock:
            self._timeline_counter += 1
            if now - self._timeline_last_flush >= 1.0:
                self.traffic_timeline.append({
                    "time": time.strftime("%H:%M:%S"),
                    "count": self._timeline_counter,
                })
                if len(self.traffic_timeline) > 60:
                    self.traffic_timeline.pop(0)
                self._timeline_counter = 0
                self._timeline_last_flush = now

        # Log the event
        alert_severity = packet_info["severity"]
        self.logger.log_event(
            packet_info.get("source_ip", "N/A"),
            packet_info.get("dest_ip", "N/A"),
            packet_info.get("protocol", "N/A"),
            port=packet_info.get("dst_port", "N/A"),
            alert_severity=alert_severity,
        )

        # Maintain rolling queue
        with self._lock:
            self.packet_queue.append(packet_info)
            if len(self.packet_queue) > self.MAX_QUEUE_SIZE:
                self.packet_queue.pop(0)
