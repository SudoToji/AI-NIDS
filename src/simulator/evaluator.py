import time
import logging

from .attack_sim import syn_flood, port_scan, slowloris
from .traffic_gen import normal_web_traffic

logger = logging.getLogger("nids_evaluator")


def run_evaluation(target_ip):
    """
    Runs multiple traffic scenarios to evaluate NIDS detection.
    """

    logger.info("Starting evaluation scenario")

    results = []

    results.append(normal_web_traffic(target_ip, count=200))
    time.sleep(5)

    results.append(port_scan(target_ip))
    time.sleep(5)

    results.append(syn_flood(target_ip, count=500))
    time.sleep(5)

    results.append(slowloris(target_ip, connections=30))

    logger.info("Evaluation sequence finished")

    return {
        "target": target_ip,
        "scenarios": results,
        "status": "completed"
    }