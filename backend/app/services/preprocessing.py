def preprocess_network_data(data):
    protocol = data.protocol.upper().strip()

    source_ip = data.source_ip.strip()
    destination_ip = data.destination_ip.strip()

    packet_size = data.packet_size

    return {
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "packet_size": packet_size
    }


def analyze_traffic(protocol: str, packet_size: int):
    suspicious_protocols = ["TELNET", "FTP"]

    if packet_size > 2000:
        return {
            "threat_detected": True,
            "threat_level": "HIGH",
            "reason": "Unusually large network packet detected"
        }

    if protocol in suspicious_protocols:
        return {
            "threat_detected": True,
            "threat_level": "MEDIUM",
            "reason": f"Potentially insecure protocol detected: {protocol}"
        }

    return {
        "threat_detected": False,
        "threat_level": "LOW",
        "reason": "Network traffic appears normal"
    }
