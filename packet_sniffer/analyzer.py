from scapy.all import IP, TCP, UDP, ICMP

class PacketAnalyzer:
    @staticmethod
    def analyze(packet):
        """Analyze a packet and extract IP, protocol, and ports."""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Map common protocols
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"OTHER({proto})")
            
            src_port = "N/A"
            dst_port = "N/A"
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = "TCP"
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = "UDP"
            
            return {
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": protocol_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": len(packet)
            }
        return None
