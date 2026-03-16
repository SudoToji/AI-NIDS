import random
import threading
import time
import logging
from scapy.all import IP, TCP, send, conf

logger = logging.getLogger("traffic_generator")
conf.iface = r"\Device\NPF_Loopback"

def normal_web_traffic(target_ip, port=80, count=1):
    """
    Simulate legitimate web traffic with reduced load.
    """

    def run():
        logger.info(f"Generating normal traffic to {target_ip}:{port}")

        for _ in range(count):

            packet = IP(dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags="PA"
            )

            send(packet, verbose=False)

            # slower realistic delay
            time.sleep(random.uniform(1, 4))

        logger.info("Normal traffic simulation finished")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return {
        "type": "normal_traffic",
        "target": target_ip,
        "count": count,
        "status": "started"
    }