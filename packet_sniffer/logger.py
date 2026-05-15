import logging
import os


class TrafficLogger:
    """
    Structured event logging engine for the network monitoring platform.
    Writes enriched log entries including severity classification to a
    persistent log file for audit and forensic analysis.
    """

    def __init__(self, log_file=None):
        if log_file is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.log_file = os.path.join(base_dir, "logs", "traffic.log")
        else:
            self.log_file = log_file
        self._setup_logger()

    def _setup_logger(self):
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Use a named logger to avoid conflicts with Flask's root logger
        self.logger = logging.getLogger("SentinelNode.Traffic")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(self.log_file, encoding="utf-8")
            formatter = logging.Formatter(
                fmt="%(asctime)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, source_ip, dest_ip, protocol, port="N/A", alert_severity="NONE"):
        """
        Write a structured log entry for a captured packet event.

        :param source_ip: Source IP address
        :param dest_ip:   Destination IP address
        :param protocol:  Network protocol (TCP/UDP/ICMP/etc.)
        :param port:      Destination port number
        :param alert_severity: Severity level from the alert engine
        """
        log_msg = (
            f"SRC={source_ip:<16} | DST={dest_ip:<16} | "
            f"PROTO={protocol:<6} | PORT={str(port):<6} | "
            f"SEVERITY={alert_severity}"
        )
        self.logger.info(log_msg)
