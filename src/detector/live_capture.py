import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from alert_manager import AlertManager
logger = logging.getLogger("live_capture")

alert_manager = AlertManager("logs/alerts.db")


def process_packet(packet):

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        src = ip_layer.src
        dst = ip_layer.dst

        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": ip_layer.proto,
            "rf_label": "Unknown",
            "rf_confidence": 0.0,
            "ae_anomaly_score": 0.0,
            "final_verdict": "Suspicious",
            "combined_confidence": 0.5
        }

        alert_manager.add_alert(alert)


def start_capture(interface):

    logger.info(f"Starting capture on {interface}")

    sniff(
        iface=interface,
        filter="tcp or udp",
        prn=process_packet,
        store=False
    )