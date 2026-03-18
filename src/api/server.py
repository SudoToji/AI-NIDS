r"""
AI-NIDS Flask API Server
========================
REST API for Network Intrusion Detection System
Provides predictions using Random Forest + Autoencoder models

Usage:
    python -m src.api.server
    # or
    cd Project && venv\Scripts\python.exe -m src.api.server
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, UTC, timedelta
from typing import Dict, List, Optional
from collections import deque

import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from tensorflow import keras

from src.features.extractor import FEATURE_COLUMNS

# ============================================================================
# CONSTANTS - Magic numbers extracted for maintainability
# ============================================================================

# Model settings
DEFAULT_AE_THRESHOLD = 0.5
DEFAULT_ALERT_MAX_SIZE = 1000

# API settings
DEFAULT_ALERTS_LIMIT = 100
DEFAULT_TOP_ATTACKERS_LIMIT = 10
DEFAULT_TIMELINE_MINUTES = 60
TIMELINE_BUCKET_MINUTES = 5

# Simulation settings
DEFAULT_SAMPLE_COUNT = 30
DEFAULT_FALLBACK_COUNT_MIN = 10
DEFAULT_FALLBACK_COUNT_MAX = 30

# Feature indices (for direct numpy access without DataFrame)
FEATURE_PORT = 0
FEATURE_FLOW_DURATION = 1
FEATURE_TOTAL_FWD_PACKETS = 2
FEATURE_TOTAL_LEN_FWD = 3
FEATURE_FWD_PACKET_LEN_MAX = 4
FEATURE_FWD_PACKET_LEN_MIN = 5
FEATURE_FWD_PACKET_LEN_MEAN = 6
FEATURE_FWD_PACKET_LEN_STD = 7
FEATURE_BWD_PACKET_LEN_MAX = 8
FEATURE_BWD_PACKET_LEN_MIN = 9
FEATURE_BWD_PACKET_LEN_MEAN = 10
FEATURE_BWD_PACKET_LEN_STD = 11

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=None)

# Enable CORS for all routes - configure for production by restricting origins
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Thread lock for AlertStore thread safety
_alert_store_lock = threading.Lock()

@app.route('/')
def index():
    html_path = os.path.join(PROJECT_ROOT, 'dashboard.html')
    if os.path.exists(html_path):
        with open(html_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/html'}
    return "dashboard.html not found", 404

@app.route('/dashboard')
def dashboard():
    return index()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ============================================================================
# MODEL LOADING
# ============================================================================

rf_model = None
rf_metadata = None
scaler = None
autoencoder = None
ae_threshold = None

ATTACK_TYPES = ["Bots", "Brute Force", "DDoS", "DoS", "Normal Traffic", "Port Scanning", "Web Attacks"]


def load_models():
    """Load all ML models."""
    global rf_model, rf_metadata, scaler, autoencoder, ae_threshold
    
    try:
        # Load Random Forest
        rf_path = os.path.join(PROJECT_ROOT, "models", "rf_model.pkl")
        rf_model = joblib.load(rf_path)
        logger.info(f"[OK] Loaded Random Forest from {rf_path}")
    except Exception as e:
        logger.error(f"[FAIL] Failed to load RF model: {e}")
        rf_model = None
    
    try:
        # Load RF metadata
        metadata_path = os.path.join(PROJECT_ROOT, "models", "rf_metadata.pkl")
        rf_metadata = joblib.load(metadata_path)
        logger.info(f"[OK] Loaded RF metadata from {metadata_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load RF metadata: {e}")
        rf_metadata = {"class_labels": ATTACK_TYPES, "thresholds": {}}
    
    try:
        # Load Scaler
        scaler_path = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
        scaler = joblib.load(scaler_path)
        logger.info(f"[OK] Loaded Scaler from {scaler_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load scaler: {e}")
        scaler = None
    
    try:
        # Load Autoencoder
        ae_path = os.path.join(PROJECT_ROOT, "models", "autoencoder.keras")
        autoencoder = keras.models.load_model(ae_path)
        logger.info(f"[OK] Loaded Autoencoder from {ae_path}")
    except Exception as e:
        logger.error(f"[FAIL] Failed to load Autoencoder: {e}")
        autoencoder = None
    
    try:
        # Load AE threshold
        threshold_path = os.path.join(PROJECT_ROOT, "models", "autoencoder_threshold.npy")
        ae_threshold = np.load(threshold_path)
        logger.info(f"[OK] Loaded AE threshold: {ae_threshold}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load AE threshold: {e}")
        ae_threshold = DEFAULT_AE_THRESHOLD


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Alert:
    """Represents a network intrusion alert."""
    id: int
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    rf_label: str
    rf_confidence: float
    ae_anomaly_score: float
    ae_is_anomaly: bool
    final_verdict: str
    combined_confidence: float
    
    def to_dict(self):
        return asdict(self)


class AlertStore:
    """Thread-safe in-memory alert storage."""
    
    def __init__(self, max_size: int = DEFAULT_ALERT_MAX_SIZE):
        self.alerts = deque(maxlen=max_size)
        self.blocked_ips = set()
        self.next_id = 1
        self._lock = threading.Lock()
    
    def add_alert(self, alert: Alert):
        with self._lock:
            self.alerts.append(alert)
    
    def get_recent(self, n: int = DEFAULT_ALERTS_LIMIT) -> List[Alert]:
        with self._lock:
            return list(self.alerts)[-n:]
    
    def get_all(self) -> List[Alert]:
        with self._lock:
            return list(self.alerts)
    
    def block_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self.blocked_ips:
                return False
            self.blocked_ips.add(ip)
            return True
    
    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip not in self.blocked_ips:
                return False
            self.blocked_ips.discard(ip)
            return True
    
    def get_blocked_ips(self) -> List[str]:
        with self._lock:
            return list(self.blocked_ips)
    
    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self.blocked_ips
    
    def clear(self):
        with self._lock:
            self.alerts.clear()
            self.next_id = 1
    
    def get_attack_distribution(self) -> Dict[str, int]:
        with self._lock:
            distribution = {}
            for alert in self.alerts:
                label = alert.rf_label if alert.rf_label else "Normal Traffic"
                distribution[label] = distribution.get(label, 0) + 1
            return distribution
    
    def get_top_attackers(self, n: int = DEFAULT_TOP_ATTACKERS_LIMIT) -> List[Dict]:
        with self._lock:
            ip_counts = {}
            for alert in self.alerts:
                if alert.final_verdict in ["Attack", "Suspicious"]:
                    ip_counts[alert.src_ip] = ip_counts.get(alert.src_ip, 0) + 1
            
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]
            return [{"src_ip": ip, "alert_count": count} for ip, count in sorted_ips]
    
    def get_stats(self) -> Dict:
        with self._lock:
            total = len(self.alerts)
            attacks = sum(1 for a in self.alerts if a.final_verdict == "Attack")
            suspicious = sum(1 for a in self.alerts if a.final_verdict == "Suspicious")
            benign = total - attacks - suspicious
            
            return {
                "total": total,
                "attacks": attacks,
                "suspicious": suspicious,
                "benign": benign,
                "attack_rate": (attacks + suspicious) / total * 100 if total > 0 else 0
            }
    
    def get_timeline(self, minutes: int = DEFAULT_TIMELINE_MINUTES) -> Dict[str, List[Dict]]:
        """Get alert timeline for the last N minutes.
        
        Returns:
            Dict with 'timestamps' (labels) and 'attacks', 'suspicious', 'benign' arrays
        """
        with self._lock:
            now = datetime.now(UTC)
            cutoff = now - timedelta(minutes=minutes)
            
            # Create time buckets
            bucket_size = TIMELINE_BUCKET_MINUTES
            num_buckets = minutes // bucket_size
            
            buckets = {i: {"attacks": 0, "suspicious": 0, "benign": 0} for i in range(num_buckets)}
            
            for alert in self.alerts:
                try:
                    alert_time = datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00'))
                    if alert_time < cutoff:
                        continue
                    
                    minutes_ago = (now - alert_time).total_seconds() / 60
                    bucket_idx = num_buckets - 1 - int(minutes_ago // bucket_size)
                    if 0 <= bucket_idx < num_buckets:
                        if alert.final_verdict == "Attack":
                            buckets[bucket_idx]["attacks"] += 1
                        elif alert.final_verdict == "Suspicious":
                            buckets[bucket_idx]["suspicious"] += 1
                        else:
                            buckets[bucket_idx]["benign"] += 1
                except (ValueError, AttributeError):
                    continue
            
            # Build response
            timestamps = []
            attacks_data = []
            suspicious_data = []
            benign_data = []
            
            for i in range(num_buckets):
                time_label = now - timedelta(minutes=(num_buckets - i - 1) * bucket_size)
                timestamps.append(time_label.strftime("%H:%M"))
                attacks_data.append(buckets[i]["attacks"])
                suspicious_data.append(buckets[i]["suspicious"])
                benign_data.append(buckets[i]["benign"])
            
            return {
                "timestamps": timestamps,
                "attacks": attacks_data,
                "suspicious": suspicious_data,
                "benign": benign_data
            }


alert_store = AlertStore()


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features(packet_data: Dict) -> np.ndarray:
    """Extract features from packet data for model input.
    
    Maps input packet data to the correct CIC-IDS2017 feature order
    as defined in FEATURE_COLUMNS.
    """
    # Initialize all 52 features to zero
    features = np.zeros(52, dtype=np.float32)
    
    # Map input data to correct feature positions
    # FEATURE_COLUMNS order:
    # 0: "Destination Port"
    # 1: "Flow Duration"
    # 2: "Total Fwd Packets"
    # ... etc (52 total)
    
    # Basic flow info
    features[0] = packet_data.get("dst_port", 80)       # Destination Port
    features[1] = packet_data.get("flow_duration", 0)   # Flow Duration (ms)
    features[2] = packet_data.get("packet_count", 1)    # Total Fwd Packets
    features[3] = packet_data.get("byte_count", 0)      # Total Length of Fwd Packets
    
    # Forward packet lengths
    fwd_max = packet_data.get("fwd_packet_length_max", 0)
    fwd_min = packet_data.get("fwd_packet_length_min", 0)
    fwd_mean = packet_data.get("avg_packet_size", 64)
    features[4] = fwd_max       # Fwd Packet Length Max
    features[5] = fwd_min       # Fwd Packet Length Min
    features[6] = fwd_mean      # Fwd Packet Length Mean
    features[7] = packet_data.get("fwd_packet_length_std", 0)  # Fwd Packet Length Std
    
    # Backward packet lengths
    features[8] = packet_data.get("bwd_packet_length_max", 0)   # Bwd Packet Length Max
    features[9] = packet_data.get("bwd_packet_length_min", 0)   # Bwd Packet Length Min
    features[10] = packet_data.get("bwd_packet_length_mean", 0) # Bwd Packet Length Mean
    features[11] = packet_data.get("bwd_packet_length_std", 0)  # Bwd Packet Length Std
    
    # Flow rates
    duration = max(packet_data.get("flow_duration", 1), 1) / 1000  # Convert ms to seconds
    byte_count = packet_data.get("byte_count", 0)
    packet_count = packet_data.get("packet_count", 1)
    features[12] = byte_count / duration if duration > 0 else 0   # Flow Bytes/s
    features[13] = packet_count / duration if duration > 0 else 0  # Flow Packets/s
    
    # Flow IAT (Inter-Arrival Time)
    features[14] = packet_data.get("flow_iat_mean", 0)   # Flow IAT Mean
    features[15] = packet_data.get("flow_iat_std", 0)   # Flow IAT Std
    features[16] = packet_data.get("flow_iat_max", 0)    # Flow IAT Max
    features[17] = packet_data.get("flow_iat_min", 0)    # Flow IAT Min
    
    # Forward IAT
    features[18] = packet_data.get("fwd_iat_total", 0)  # Fwd IAT Total
    features[19] = packet_data.get("fwd_iat_mean", 0)    # Fwd IAT Mean
    features[20] = packet_data.get("fwd_iat_std", 0)     # Fwd IAT Std
    features[21] = packet_data.get("fwd_iat_max", 0)     # Fwd IAT Max
    features[22] = packet_data.get("fwd_iat_min", 0)      # Fwd IAT Min
    
    # Backward IAT
    features[23] = packet_data.get("bwd_iat_total", 0)   # Bwd IAT Total
    features[24] = packet_data.get("bwd_iat_mean", 0)    # Bwd IAT Mean
    features[25] = packet_data.get("bwd_iat_std", 0)     # Bwd IAT Std
    features[26] = packet_data.get("bwd_iat_max", 0)     # Bwd IAT Max
    features[27] = packet_data.get("bwd_iat_min", 0)     # Bwd IAT Min
    
    # Header lengths
    features[28] = packet_data.get("fwd_header_length", 0)   # Fwd Header Length
    features[29] = packet_data.get("bwd_header_length", 0)   # Bwd Header Length
    
    # Packet rates
    features[30] = packet_data.get("fwd_packets_per_sec", 0)  # Fwd Packets/s
    features[31] = packet_data.get("bwd_packets_per_sec", 0)  # Bwd Packets/s
    
    # Packet lengths
    features[32] = packet_data.get("min_packet_length", 0)    # Min Packet Length
    features[33] = packet_data.get("max_packet_length", 0)    # Max Packet Length
    features[34] = packet_data.get("avg_packet_size", 64)    # Packet Length Mean
    features[35] = packet_data.get("packet_length_std", 0)   # Packet Length Std
    features[36] = packet_data.get("packet_length_variance", 0)  # Packet Length Variance
    
    # TCP Flags
    features[37] = packet_data.get("fin_count", 0)      # FIN Flag Count
    features[38] = packet_data.get("psh_count", 0)     # PSH Flag Count
    features[39] = packet_data.get("ack_count", 0)      # ACK Flag Count
    
    # Additional features
    features[40] = packet_data.get("avg_packet_size", 64)     # Average Packet Size
    features[41] = packet_data.get("subflow_fwd_bytes", 0)   # Subflow Fwd Bytes
    features[42] = packet_data.get("init_win_bytes_forward", 64240)  # Init_Win_bytes_forward
    features[43] = packet_data.get("init_win_bytes_backward", 65535)  # Init_Win_bytes_backward
    features[44] = packet_data.get("act_data_pkt_fwd", 0)    # act_data_pkt_fwd
    features[45] = packet_data.get("min_seg_size_forward", 40)  # min_seg_size_forward
    
    # Active/Idle (often zero for short flows)
    features[46] = packet_data.get("active_mean", 0)     # Active Mean
    features[47] = packet_data.get("active_max", 0)      # Active Max
    features[48] = packet_data.get("active_min", 0)      # Active Min
    features[49] = packet_data.get("idle_mean", 0)       # Idle Mean
    features[50] = packet_data.get("idle_max", 0)        # Idle Max
    features[51] = packet_data.get("idle_min", 0)         # Idle Min
    
    return features.reshape(1, -1)


# ============================================================================
# ML PREDICTION
# ============================================================================

def predict_hybrid(features: np.ndarray) -> Dict:
    """Run hybrid prediction using Random Forest + Autoencoder."""
    
    verdict = "Benign"
    rf_label = "Normal Traffic"
    rf_confidence = 0.99
    ae_anomaly_score = 0.0
    ae_is_anomaly = False
    combined_confidence = 0.99
    
    # Random Forest prediction
    if rf_model is not None:
        try:
            # Get class labels from metadata
            class_labels = rf_metadata.get("class_labels", ATTACK_TYPES) if rf_metadata else ATTACK_TYPES
            
            # Scale features for RF (RF was trained on scaled features!)
            if scaler is not None:
                features_df = pd.DataFrame(features, columns=FEATURE_COLUMNS)
                features_scaled = scaler.transform(features_df)
            else:
                features_scaled = features
            
            # Predict
            rf_pred = rf_model.predict(features_scaled)[0]
            rf_proba = rf_model.predict_proba(features_scaled)[0]
            
            # Map numeric prediction to class label
            if hasattr(rf_model, "classes_") and len(rf_model.classes_) > 0:
                pred_idx = int(rf_pred)
                if pred_idx < len(class_labels):
                    rf_label = class_labels[pred_idx]
                else:
                    rf_label = str(rf_pred)
            else:
                rf_label = str(rf_pred)
            
            rf_confidence = float(max(rf_proba))
            
            # Determine verdict based on RF prediction
            if rf_label in ["Normal Traffic", "Benign"]:
                verdict = "Benign"
            else:
                verdict = "Attack"
                
        except Exception as e:
            logger.error(f"RF prediction error: {e}")
            import traceback
            traceback.print_exc()
    
    # Autoencoder anomaly detection
    if autoencoder is not None and ae_threshold is not None:
        try:
            # Scale features if scaler available
            if scaler is not None:
                features_df = pd.DataFrame(features, columns=FEATURE_COLUMNS)
                features_scaled = scaler.transform(features_df)
            else:
                features_scaled = features
            
            reconstruction = autoencoder.predict(features_scaled, verbose=0)
            mse = float(np.mean(np.square(features_scaled - reconstruction)))
            
            # Handle threshold - handle both array and scalar
            try:
                if ae_threshold.shape == ():  # 0-dimensional array
                    threshold = float(ae_threshold)
                else:
                    threshold = float(ae_threshold[0])
            except (TypeError, IndexError):
                threshold = float(ae_threshold)
            
            ae_anomaly_score = mse
            ae_is_anomaly = bool(mse > threshold)
            
            # Fusion logic - only flag suspicious if RF is NOT confident in benign
            # and AE detects anomaly (possible zero-day attack)
            if verdict == "Benign" and ae_is_anomaly and rf_confidence < 0.8:
                # RF says benign but not confident, AND AE sees anomaly → Suspicious
                verdict = "Suspicious"
                combined_confidence = min(rf_confidence, 0.6)
            elif verdict == "Attack":
                combined_confidence = max(rf_confidence, 0.8)
            else:
                # RF says Benign with high confidence, trust it
                combined_confidence = rf_confidence
                
        except Exception as e:
            logger.error(f"AE prediction error: {e}")
    
    return {
        "rf_label": rf_label,
        "rf_confidence": rf_confidence,
        "ae_anomaly_score": ae_anomaly_score,
        "ae_is_anomaly": ae_is_anomaly,
        "final_verdict": verdict,
        "combined_confidence": combined_confidence
    }


def process_packet(packet_data: Dict) -> Alert:
    """Process a packet and generate alert."""
    
    # Check if we already have properly formatted features (all 52 FEATURE_COLUMNS)
    # If so, skip extract_features and use directly
    has_all_features = all(col in packet_data for col in FEATURE_COLUMNS)
    
    if has_all_features:
        # Use features directly - build numpy array in correct order
        features = np.zeros((1, 52), dtype=np.float32)
        for i, col in enumerate(FEATURE_COLUMNS):
            features[0, i] = float(packet_data.get(col, 0) or 0)
    else:
        # Extract features from packet data
        features = extract_features(packet_data)
    
    # Run prediction
    prediction = predict_hybrid(features)
    
    # Check if IP is blocked
    src_ip = packet_data.get("src_ip", "0.0.0.0")
    if alert_store.is_blocked(src_ip):
        prediction["final_verdict"] = "Blocked"
        prediction["rf_label"] = "Blocked IP"
    
    # Create alert
    alert = Alert(
        id=alert_store.next_id,
        timestamp=datetime.now(UTC).isoformat(),
        src_ip=src_ip,
        dst_ip=packet_data.get("dst_ip", "0.0.0.0"),
        src_port=packet_data.get("src_port", 0),
        dst_port=packet_data.get("dst_port", 0),
        protocol=packet_data.get("protocol", 6),
        rf_label=prediction["rf_label"],
        rf_confidence=prediction["rf_confidence"],
        ae_anomaly_score=prediction["ae_anomaly_score"],
        ae_is_anomaly=prediction["ae_is_anomaly"],
        final_verdict=prediction["final_verdict"],
        combined_confidence=prediction["combined_confidence"]
    )
    
    alert_store.next_id += 1
    alert_store.add_alert(alert)
    
    return alert

# ============================================================================
# SIMULATION FUNCTIONS - Using Real Data Samples
# ============================================================================

# Cache for real attack samples from dataset
_real_samples_cache = {}


def _load_real_samples(attack_type: str, n: int = 20) -> List[Dict]:
    """Load real attack samples from the CIC-IDS2017 dataset."""
    global _real_samples_cache
    
    cache_key = f"{attack_type}_{n}"
    if cache_key in _real_samples_cache:
        return _real_samples_cache[cache_key]
    
    try:
        import pandas as pd
        from src.features.extractor import FEATURE_COLUMNS
        
        # Map attack types
        attack_mapping = {
            "ddos": "DDoS",
            "synflood": "DDoS", 
            "syn_flood": "DDoS",
            "dos": "DoS",
            "slowloris": "DoS",
            "portscan": "Port Scanning",
            "port_scan": "Port Scanning",
            "bruteforce": "Brute Force",
            "webattacks": "Web Attacks",
            "web_attacks": "Web Attacks",
            "normal": "Normal Traffic",
        }
        
        label = attack_mapping.get(attack_type.lower(), attack_type)
        
        # Load dataset
        data_path = os.path.join(PROJECT_ROOT, "data", "processed", "cicids2017_cleaned.csv")
        if not os.path.exists(data_path):
            return []
        
        df = pd.read_csv(data_path, usecols=FEATURE_COLUMNS + ["Attack Type"])
        samples = df[df["Attack Type"] == label].sample(n=min(n, 100), random_state=42)
        
        result = []
        for _, row in samples.iterrows():
            sample = {}
            for col in FEATURE_COLUMNS:
                sample[col] = row[col]
            result.append(sample)
        
        _real_samples_cache[cache_key] = result
        return result
        
    except Exception as e:
        logger.warning(f"Failed to load real samples for {attack_type}: {e}")
        return []


def simulate_attack(attack_type: str, target_ip: str = "127.0.0.1") -> List[Alert]:
    """Simulate an attack using REAL data samples from CIC-IDS2017."""
    import random
    
    alerts = []
    
    # Try to load real samples first
    real_samples = _load_real_samples(attack_type, n=30)
    
    if real_samples:
        # Use real samples
        for sample in real_samples:
            # Convert to packet_data format with some variation
            packet_data = {}
            for col, val in sample.items():
                # Add small random variation (±10%)
                if pd.notna(val) and val != 0:
                    variation = random.uniform(0.9, 1.1)
                    packet_data[col] = float(val) * variation
                else:
                    packet_data[col] = float(val) if pd.notna(val) else 0
            
            # Add IP info
            packet_data["src_ip"] = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            packet_data["dst_ip"] = target_ip
            
            alert = process_packet(packet_data)
            alerts.append(alert)
    else:
        # Fallback to synthetic (won't work well)
        logger.warning("Using synthetic attack simulation - results may not be accurate")
        alerts = _simulate_synthetic(attack_type, target_ip)
    
    return alerts


def _simulate_synthetic(attack_type: str, target_ip: str) -> List[Alert]:
    """Fallback synthetic simulation (not recommended)."""
    import random
    
    # Fallback stats (minimal - just to have something)
    ATTACK_STATS_FALLBACK = {
        "ddos": {"dst_port": 80, "flow_duration": 255000, "packet_count": 500, "byte_count": 25000,
                  "fwd_packet_length_mean": 54, "bwd_packet_length_mean": 0, "flow_bytes_per_sec": 98000,
                  "flow_packets_per_sec": 1960, "flow_iat_mean": 0.5, "ack_count": 0, "psh_count": 0, "fin_count": 0},
        "portscan": {"dst_port": 80, "flow_duration": 100, "packet_count": 2, "byte_count": 80,
                     "fwd_packet_length_mean": 40, "bwd_packet_length_mean": 0, "flow_bytes_per_sec": 800,
                     "flow_packets_per_sec": 20, "flow_iat_mean": 50, "ack_count": 0, "psh_count": 0, "fin_count": 0},
        "normal": {"dst_port": 443, "flow_duration": 4200000, "packet_count": 30, "byte_count": 15000,
                   "fwd_packet_length_mean": 500, "bwd_packet_length_mean": 600, "flow_bytes_per_sec": 11400000,
                   "flow_packets_per_sec": 32750, "flow_iat_mean": 145000, "ack_count": 25, "psh_count": 20, "fin_count": 1},
    }
    
    alerts = []
    count = random.randint(10, 30)
    
    attack_key = attack_type.lower().replace(" ", "").replace("_", "")
    stats = ATTACK_STATS_FALLBACK.get(attack_key, ATTACK_STATS_FALLBACK["ddos"])
    
    for i in range(count):
        variation = random.uniform(0.7, 1.3)
        
        packet_data = {
            "src_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "dst_ip": target_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": int(stats["dst_port"] * random.uniform(0.9, 1.1)),
            "flow_duration": int(stats["flow_duration"] * variation),
            "packet_count": max(1, int(stats["packet_count"] * variation)),
            "byte_count": int(stats["byte_count"] * variation),
            "fwd_packet_length_max": int(stats["fwd_packet_length_mean"] * 1.5 * variation),
            "fwd_packet_length_min": max(0, int(stats["fwd_packet_length_mean"] * 0.5 * variation)),
            "fwd_packet_length_mean": int(stats["fwd_packet_length_mean"] * variation),
            "fwd_packet_length_std": int(stats["fwd_packet_length_mean"] * 0.3 * variation),
            "bwd_packet_length_max": int(stats["bwd_packet_length_mean"] * 1.5 * variation),
            "bwd_packet_length_min": 0,
            "bwd_packet_length_mean": int(stats["bwd_packet_length_mean"] * variation),
            "bwd_packet_length_std": int(stats["bwd_packet_length_mean"] * 0.3 * variation),
            "flow_bytes_per_sec": stats["flow_bytes_per_sec"] * variation,
            "flow_packets_per_sec": stats["flow_packets_per_sec"] * variation,
            "flow_iat_mean": stats["flow_iat_mean"] * variation,
            "flow_iat_std": stats["flow_iat_mean"] * 0.4 * variation,
            "flow_iat_max": stats["flow_iat_mean"] * 2 * variation,
            "flow_iat_min": 0,
            "fwd_iat_total": stats["flow_iat_mean"] * 0.8 * variation,
            "fwd_iat_mean": stats["flow_iat_mean"] * 0.8 * variation,
            "fwd_iat_std": stats["flow_iat_mean"] * 0.3 * variation,
            "fwd_iat_max": stats["flow_iat_mean"] * 1.5 * variation,
            "fwd_iat_min": 0,
            "bwd_iat_total": stats["flow_iat_mean"] * 0.2 * variation,
            "bwd_iat_mean": stats["flow_iat_mean"] * 0.2 * variation,
            "bwd_iat_std": 0,
            "bwd_iat_max": 0,
            "bwd_iat_min": 0,
            "fwd_header_length": max(20, int(stats["packet_count"] * 20 * variation)),
            "bwd_header_length": max(20, int(stats["packet_count"] * 0.3 * 20 * variation)),
            "fwd_packets_per_sec": stats["flow_packets_per_sec"] * 0.8 * variation,
            "bwd_packets_per_sec": stats["flow_packets_per_sec"] * 0.2 * variation,
            "min_packet_length": int(stats["fwd_packet_length_mean"] * 0.5 * variation),
            "max_packet_length": int(max(stats["fwd_packet_length_mean"], stats["bwd_packet_length_mean"]) * 1.5 * variation),
            "avg_packet_size": int(stats["byte_count"] / max(stats["packet_count"], 1) * variation),
            "packet_length_std": int(stats["byte_count"] / max(stats["packet_count"], 1) * 0.3 * variation),
            "packet_length_variance": (int(stats["byte_count"] / max(stats["packet_count"], 1) * 0.3 * variation)) ** 2,
            "fin_count": stats["fin_count"],
            "psh_count": stats["psh_count"],
            "ack_count": stats["ack_count"],
            "subflow_fwd_bytes": int(stats["byte_count"] * 0.8 * variation),
            "act_data_pkt_fwd": max(1, int(stats["packet_count"] * 0.8 * variation)),
        }
        
        alert = process_packet(packet_data)
        alerts.append(alert)
    
    return alerts


def generate_normal_traffic(target_ip: str = "127.0.0.1") -> List[Alert]:
    """Generate normal traffic alerts."""
    import random
    
    alerts = []
    count = random.randint(3, 10)
    
    for i in range(count):
        # Normal traffic: larger packets, balanced bidirectional, moderate duration
        dst_port = random.choice([80, 443, 8080, 22, 3306])
        packet_count = random.randint(5, 30)
        byte_count = random.randint(2000, 15000)
        flow_duration = random.randint(200, 3000)
        fwd_len_mean = random.randint(500, 1400)  # Large HTTP/HTTPS packets
        bwd_len_mean = random.randint(500, 1400)   # Similar response size
        fin_count = random.randint(0, 1)
        psh_count = random.randint(2, 10)
        ack_count = random.randint(3, 15)
        
        flow_bytes_per_sec = byte_count / (flow_duration / 1000) if flow_duration > 0 else 0
        flow_packets_per_sec = packet_count / (flow_duration / 1000) if flow_duration > 0 else 0
        
        packet_data = {
            "src_ip": f"10.0.0.{random.randint(1, 254)}",
            "dst_ip": target_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "flow_duration": flow_duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "fwd_packet_length_max": int(fwd_len_mean * 1.2),
            "fwd_packet_length_min": int(fwd_len_mean * 0.5),
            "fwd_packet_length_mean": fwd_len_mean,
            "fwd_packet_length_std": fwd_len_mean * 0.2,
            "bwd_packet_length_max": int(bwd_len_mean * 1.2),
            "bwd_packet_length_min": int(bwd_len_mean * 0.5),
            "bwd_packet_length_mean": bwd_len_mean,
            "bwd_packet_length_std": bwd_len_mean * 0.2,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "flow_iat_mean": flow_duration / max(packet_count - 1, 1),
            "flow_iat_std": flow_duration / max(packet_count - 1, 1) * 0.4,
            "flow_iat_max": flow_duration,
            "flow_iat_min": 0,
            "fwd_iat_total": flow_duration * 0.5,
            "fwd_iat_mean": flow_duration / max(packet_count - 1, 1) * 0.5,
            "fwd_iat_std": flow_duration / max(packet_count - 1, 1) * 0.2,
            "fwd_iat_max": flow_duration * 0.6,
            "fwd_iat_min": 0,
            "bwd_iat_total": flow_duration * 0.5,
            "bwd_iat_mean": flow_duration / max(packet_count - 1, 1) * 0.5,
            "bwd_iat_std": flow_duration / max(packet_count - 1, 1) * 0.2,
            "bwd_iat_max": flow_duration * 0.6,
            "bwd_iat_min": 0,
            "fwd_header_length": int(packet_count * 0.6) * 20,
            "bwd_header_length": int(packet_count * 0.4) * 20,
            "fwd_packets_per_sec": flow_packets_per_sec * 0.6,
            "bwd_packets_per_sec": flow_packets_per_sec * 0.4,
            "min_packet_length": min(fwd_len_mean, bwd_len_mean),
            "max_packet_length": max(fwd_len_mean, bwd_len_mean),
            "avg_packet_size": byte_count / max(packet_count, 1),
            "packet_length_std": byte_count / max(packet_count, 1) * 0.25,
            "packet_length_variance": (byte_count / max(packet_count, 1) * 0.25) ** 2,
            "fin_count": fin_count,
            "psh_count": psh_count,
            "ack_count": ack_count,
            "subflow_fwd_bytes": int(byte_count * 0.6),
            "act_data_pkt_fwd": int(packet_count * 0.6),
        }
        
        alert = process_packet(packet_data)
        alerts.append(alert)
    
    return alerts


# ============================================================================
# API ROUTES
# ============================================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "models_loaded": {
            "random_forest": rf_model is not None,
            "autoencoder": autoencoder is not None,
            "scaler": scaler is not None
        },
        "timestamp": datetime.now(UTC).isoformat()
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get dashboard statistics."""
    return jsonify(alert_store.get_stats())


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Get recent alerts."""
    n = request.args.get("n", 100, type=int)
    alerts = alert_store.get_recent(n)
    return jsonify([a.to_dict() for a in alerts])


@app.route("/api/attack-distribution", methods=["GET"])
def get_attack_distribution():
    """Get attack type distribution."""
    return jsonify(alert_store.get_attack_distribution())


@app.route("/api/attack-distribution-mapped", methods=["GET"])
def get_attack_distribution_mapped():
    """Get attack distribution mapped to dashboard categories."""
    raw_dist = alert_store.get_attack_distribution()
    
    # Map to dashboard categories: DDoS, Port Scan, Others, Benign
    mapped = {
        "DDoS": 0,
        "Port Scanning": 0,
        "Others": 0,
        "Benign": 0
    }
    
    for label, count in raw_dist.items():
        if label in ["DDoS"]:
            mapped["DDoS"] += count
        elif label in ["Port Scanning"]:
            mapped["Port Scanning"] += count
        elif label in ["Normal Traffic", "Benign"]:
            mapped["Benign"] += count
        else:
            # Bots, Brute Force, DoS, Web Attacks
            mapped["Others"] += count
    
    return jsonify(mapped)


@app.route("/api/timeline", methods=["GET"])
def get_timeline():
    """Get alert timeline data for charts."""
    minutes = request.args.get("minutes", 60, type=int)
    return jsonify(alert_store.get_timeline(minutes))


@app.route("/api/top-attackers", methods=["GET"])
def get_top_attackers():
    """Get top attacking IPs."""
    n = request.args.get("n", 10, type=int)
    return jsonify(alert_store.get_top_attackers(n))


@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    """Get blocked IPs."""
    return jsonify(alert_store.get_blocked_ips())


@app.route("/api/block-ip", methods=["POST"])
def block_ip():
    """Block an IP address."""
    data = request.get_json()
    ip = data.get("ip", "")
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    success = alert_store.block_ip(ip)
    return jsonify({"ip": ip, "blocked": success})


@app.route("/api/unblock-ip", methods=["POST"])
def unblock_ip():
    """Unblock an IP address."""
    data = request.get_json()
    ip = data.get("ip", "")
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    success = alert_store.unblock_ip(ip)
    return jsonify({"ip": ip, "unblocked": success})


@app.route("/api/predict", methods=["POST"])
def predict():
    """Predict for a single packet."""
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    # Basic input validation
    if not isinstance(data, dict):
        return jsonify({"error": "Request must be JSON object"}), 400
    
    try:
        alert = process_packet(data)
        return jsonify(alert.to_dict())
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """Run attack simulation."""
    data = request.get_json() or {}
    
    # Input validation
    attack_type = data.get("type", "normal")
    target_ip = data.get("target_ip", "127.0.0.1")
    
    # Validate attack_type
    valid_types = ["normal", "ddos", "synflood", "portscan", "slowloris", "bruteforce", "webattacks"]
    if attack_type not in valid_types:
        return jsonify({
            "error": f"Invalid attack type. Must be one of: {', '.join(valid_types)}"
        }), 400
    
    # Validate target_ip format (basic check)
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({"error": "Valid target_ip required"}), 400
    target_ip = data.get("target_ip", "127.0.0.1")
    
    if attack_type == "normal":
        alerts = generate_normal_traffic(target_ip)
    else:
        alerts = simulate_attack(attack_type, target_ip)
    
    return jsonify({
        "type": attack_type,
        "target_ip": target_ip,
        "alerts_generated": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    })


@app.route("/api/clear", methods=["POST"])
def clear_alerts():
    """Clear all alerts."""
    alert_store.clear()
    return jsonify({"success": True})


# ============================================================================
# INITIALIZATION
# ============================================================================

if __name__ == "__main__":
    import os
    import sys
    
    logger.info("=" * 60)
    logger.info("AI-NIDS Flask API Server")
    logger.info("=" * 60)
    
    # Load models
    load_models()
    
    # Check for live capture flag
    LIVE_CAPTURE = os.getenv("LIVE_CAPTURE", "false").lower() == "true"
    
    if LIVE_CAPTURE:
        try:
            from src.capture.sniffer import PacketSniffer
            from src.features.extractor import extract_live_features
            
            logger.info("Starting live packet capture...")
            
            # Use already loaded global models instead of reloading
            # Models are loaded at startup via load_models()
            if scaler is None or rf_model is None or rf_metadata is None:
                logger.error("Models not loaded properly at startup")
            else:
                def on_flow_complete(flow_data):
                    """Process live flow and generate alert."""
                    try:
                        # Extract features
                        features_df = extract_live_features(flow_data)
                        features_scaled = scaler.transform(features_df)
                        
                        # Predict using already loaded global models
                        pred = rf_model.predict(features_scaled)[0]
                        rf_label = rf_metadata["class_labels"][int(pred)]
                        proba = rf_model.predict_proba(features_scaled)[0]
                        
                        # Determine verdict
                        if rf_label in ["Normal Traffic", "Benign"]:
                            verdict = "Benign"
                            confidence = float(max(proba))
                        else:
                            verdict = "Attack"
                            confidence = float(max(proba))
                        
                        # Create alert
                        with _alert_store_lock:
                            alert = Alert(
                                id=alert_store.next_id,
                                timestamp=datetime.now(UTC).isoformat(),
                                src_ip=flow_data.get("src_ip", "0.0.0.0"),
                                dst_ip=flow_data.get("dst_ip", "0.0.0.0"),
                                src_port=flow_data.get("src_port", 0),
                                dst_port=flow_data.get("dst_port", 0),
                                protocol=flow_data.get("protocol", 6),
                                rf_label=rf_label,
                                rf_confidence=confidence,
                                ae_anomaly_score=0.0,
                                ae_is_anomaly=False,
                                final_verdict=verdict,
                                combined_confidence=confidence
                            )
                            alert_store.next_id += 1
                            alert_store.add_alert(alert)
                        
                        logger.info(f"Live alert: {rf_label} - {verdict}")
                        
                    except Exception as e:
                        logger.error(f"Live capture error: {e}")
                
                # Start sniffer
                sniffer = PacketSniffer(on_flow_complete=on_flow_complete)
                sniffer.start()
                logger.info("Live packet capture started on interface")
        
        except Exception as e:
            logger.error(f"Failed to start live capture: {e}")
            logger.info("Run with LIVE_CAPTURE=true to enable (requires Npcap installed)")
    
    logger.info("Starting server on http://localhost:5000")
    logger.info("=" * 60)
    
    app.run(host="0.0.0.0", port=5000, debug=False)
