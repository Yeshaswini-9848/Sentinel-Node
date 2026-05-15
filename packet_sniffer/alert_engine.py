import collections
import time


class AlertEngine:
    """
    Enterprise-grade intrusion detection engine with multi-level severity
    classification and real-time behavioral analysis.
    """

    SEVERITY_LEVELS = {
        "LOW": {"label": "LOW", "description": "Minor anomaly detected"},
        "MEDIUM": {"label": "MEDIUM", "description": "Suspicious pattern identified"},
        "HIGH": {"label": "HIGH", "description": "Potential threat detected"},
        "CRITICAL": {"label": "CRITICAL", "description": "Confirmed anomaly — immediate review required"},
    }

    # Ports that are standard/well-known and should not trigger alerts
    KNOWN_PORTS = set(range(0, 1024)) | {3306, 5432, 6379, 8080, 8443, 9000, 27017, 1433, 5000, 5001}

    def __init__(self, high_traffic_threshold=50, time_window_seconds=10):
        self.ip_counter = collections.Counter()
        self.ip_timestamps = collections.defaultdict(list)
        self.threshold = high_traffic_threshold
        self.time_window = time_window_seconds
        self.alert_history = []  # for severity distribution stats

    def _add_alert(self, message, severity, src_ip="", dst_port=""):
        alert = {
            "message": message,
            "severity": severity,
            "src_ip": src_ip,
            "dst_port": dst_port,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        self.alert_history.append(alert)
        # Keep last 200 alerts
        if len(self.alert_history) > 200:
            self.alert_history.pop(0)
        return message

    def detect_suspicious(self, packet_info):
        """
        Analyze packet info and return a list of structured alert dicts.
        Each alert has: message, severity.
        """
        alerts = []
        now = time.time()
        src_ip = packet_info.get("source_ip", "")
        dst_port = packet_info.get("dst_port")
        protocol = packet_info.get("protocol", "")

        # --- Rule 1: High-frequency traffic (DDoS pattern) ---
        if src_ip:
            self.ip_counter[src_ip] += 1
            self.ip_timestamps[src_ip].append(now)

            # Sliding window — keep only timestamps within the window
            self.ip_timestamps[src_ip] = [
                t for t in self.ip_timestamps[src_ip] if now - t <= self.time_window
            ]
            rate = len(self.ip_timestamps[src_ip])

            if rate > self.threshold * 2:
                msg = self._add_alert(
                    f"High-Frequency Flood Detected: {src_ip} — {rate} packets in {self.time_window}s (DDoS Pattern)",
                    "CRITICAL", src_ip
                )
                alerts.append({"message": msg, "severity": "CRITICAL"})
            elif rate > self.threshold:
                msg = self._add_alert(
                    f"Elevated Traffic Volume: {src_ip} — {rate} packets in {self.time_window}s (Potential Brute Force)",
                    "HIGH", src_ip
                )
                alerts.append({"message": msg, "severity": "HIGH"})

        # --- Rule 2: Non-standard/suspicious port usage ---
        if isinstance(dst_port, int) and dst_port > 1024 and dst_port not in self.KNOWN_PORTS:
            if dst_port > 49151:  # Dynamic/ephemeral range
                severity = "LOW"
                msg = self._add_alert(
                    f"Anomalous Traffic Detected: Ephemeral Port Usage ({dst_port})",
                    severity, src_ip, dst_port
                )
            else:
                severity = "MEDIUM"
                msg = self._add_alert(
                    f"Anomalous Traffic Detected: Non-Standard Port Usage ({dst_port})",
                    severity, src_ip, dst_port
                )
            alerts.append({"message": msg, "severity": severity})

        # --- Rule 3: Unknown/unusual protocol ---
        if protocol not in ("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH"):
            msg = self._add_alert(
                f"Unrecognized Protocol Observed: {protocol} — Manual inspection recommended",
                "MEDIUM", src_ip
            )
            alerts.append({"message": msg, "severity": "MEDIUM"})

        return alerts if alerts else None

    def get_severity_distribution(self):
        """Return counts of alerts by severity for dashboard charts."""
        dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for alert in self.alert_history:
            sev = alert.get("severity", "LOW")
            if sev in dist:
                dist[sev] += 1
        return dist
