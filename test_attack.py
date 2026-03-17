"""
Windows-compatible attack simulator for testing the NIDS
Run this while the Flask server is running
"""
import requests
import time
import random
import threading

API_URL = "http://localhost:5000/api/predict"

def attack_ddos():
    """Simulate DDoS attack - high packet rate, small packets"""
    print("[+] Running DDoS attack...")
    for i in range(50):
        payload = {
            "src_ip": f"192.168.1.{random.randint(100,200)}",
            "dst_ip": "127.0.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "flow_duration": random.randint(100, 1000),
            "packet_count": random.randint(50, 200),
            "byte_count": random.randint(3000, 10000),
            "fwd_packet_length_mean": random.randint(40, 60),
            "bwd_packet_length_mean": 0,
            "flow_bytes_per_sec": random.randint(50000, 200000),
            "flow_packets_per_sec": random.randint(1000, 5000),
        }
        try:
            r = requests.post(API_URL, json=payload, timeout=2)
            print(f"  Request {i+1}: {r.json().get('final_verdict', 'error')}")
        except:
            pass

def attack_portscan():
    """Simulate port scan - very short duration, many ports"""
    print("[+] Running Port Scan...")
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    for port in ports:
        payload = {
            "src_ip": f"192.168.1.{random.randint(100,200)}",
            "dst_ip": "127.0.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "flow_duration": random.randint(10, 100),
            "packet_count": random.randint(1, 3),
            "byte_count": random.randint(40, 100),
            "fwd_packet_length_mean": 40,
            "bwd_packet_length_mean": 0,
            "flow_bytes_per_sec": 1000,
            "flow_packets_per_sec": 20,
        }
        try:
            r = requests.post(API_URL, json=payload, timeout=2)
            print(f"  Port {port}: {r.json().get('final_verdict', 'error')}")
        except:
            pass

def attack_bruteforce():
    """Simulate brute force - SSH/FTP attempts"""
    print("[+] Running Brute Force attack...")
    for i in range(20):
        payload = {
            "src_ip": f"192.168.1.{random.randint(100,200)}",
            "dst_ip": "127.0.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 22,  # SSH
            "flow_duration": random.randint(500, 2000),
            "packet_count": random.randint(3, 8),
            "byte_count": random.randint(100, 500),
            "fwd_packet_length_mean": random.randint(40, 80),
            "bwd_packet_length_mean": random.randint(50, 100),
            "flow_bytes_per_sec": random.randint(5000, 20000),
            "flow_packets_per_sec": random.randint(500, 2000),
        }
        try:
            r = requests.post(API_URL, json=payload, timeout=2)
            print(f"  Attempt {i+1}: {r.json().get('final_verdict', 'error')}")
        except:
            pass

def normal_traffic():
    """Generate normal traffic"""
    print("[+] Running Normal traffic...")
    for i in range(20):
        payload = {
            "src_ip": f"10.0.0.{random.randint(1, 254)}",
            "dst_ip": "127.0.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080]),
            "flow_duration": random.randint(1000, 5000),
            "packet_count": random.randint(10, 30),
            "byte_count": random.randint(5000, 15000),
            "fwd_packet_length_mean": random.randint(500, 1400),
            "bwd_packet_length_mean": random.randint(500, 1400),
            "flow_bytes_per_sec": random.randint(10000, 50000),
            "flow_packets_per_sec": random.randint(100, 500),
        }
        try:
            r = requests.post(API_URL, json=payload, timeout=2)
            print(f"  Request {i+1}: {r.json().get('final_verdict', 'error')}")
        except:
            pass

if __name__ == "__main__":
    print("=" * 50)
    print("Windows Attack Simulator for AI-NIDS")
    print("Make sure Flask server is running first!")
    print("=" * 50)
    print()
    print("1. DDoS Attack")
    print("2. Port Scan")
    print("3. Brute Force")
    print("4. Normal Traffic")
    print("5. All Attacks (sequence)")
    print()
    
    choice = input("Select attack (1-5): ").strip()
    
    if choice == "1":
        attack_ddos()
    elif choice == "2":
        attack_portscan()
    elif choice == "3":
        attack_bruteforce()
    elif choice == "4":
        normal_traffic()
    elif choice == "5":
        normal_traffic()
        time.sleep(1)
        attack_ddos()
        time.sleep(1)
        attack_portscan()
        time.sleep(1)
        attack_bruteforce()
    else:
        print("Invalid choice")
