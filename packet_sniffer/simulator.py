import random
import time


class TrafficSimulator:
    """
    Synthetic network traffic generator for demonstration and testing
    of the SentinelNode monitoring and IDS platform in environments
    where live packet capture is unavailable.
    """

    PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
    INTERNAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
    EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 50)] + \
                   [f"198.51.100.{i}" for i in range(1, 20)]
    COMMON_PORTS = [80, 443, 22, 53, 3306, 8080, 8443, 5432]
    SUSPICIOUS_PORTS = [4444, 6666, 9001, 12345, 31337, 65500, 54321]

    def __init__(self):
        self.packet_count = 0
        # Inject occasional "attacker" IPs that fire at high frequency
        self.attack_ip = "203.0.113.99"
        self.attack_active = False
        self.attack_countdown = random.randint(5, 15)

    def generate_mock_packet(self):
        """Generate a single simulated network packet as a dict."""
        self.packet_count += 1
        self.attack_countdown -= 1

        # Activate a simulated attack burst every N packets
        if self.attack_countdown <= 0:
            self.attack_active = True
            self.attack_countdown = random.randint(30, 60)

        # During attack burst, generate high-frequency traffic from one IP
        if self.attack_active:
            if random.random() < 0.7:
                src_ip = self.attack_ip
            else:
                self.attack_active = False
                src_ip = random.choice(self.INTERNAL_IPS + self.EXTERNAL_IPS)
        else:
            src_ip = random.choice(self.INTERNAL_IPS + self.EXTERNAL_IPS)

        dst_ip = random.choice(self.INTERNAL_IPS)
        protocol = random.choice(self.PROTOCOLS)
        src_port = random.randint(1024, 65535)

        # Occasionally inject a suspicious port
        if random.random() < 0.15:
            dst_port = random.choice(self.SUSPICIOUS_PORTS)
        else:
            dst_port = random.choice(self.COMMON_PORTS)

        length = random.randint(40, 1500)

        return {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "is_simulated": True,
        }
