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

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Find project root: server.py → api/ → src/ → Project/
    _server_dir = os.path.dirname(os.path.abspath(__file__))  # src/api/
    _src_dir = os.path.dirname(_server_dir)                    # src/
    _project_root = os.path.dirname(_src_dir)                  # Project/
    _env_path = os.path.join(_project_root, ".env")
    load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv not installed, use system env vars
except Exception as e:
    print(f"Warning: Could not load .env file: {e}")

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

def _get_frontend_path(filename: str) -> str:
    """Get path to frontend file, checking build directory first."""
    build_path = os.path.join(PROJECT_ROOT, 'web', 'dist', filename)
    web_path = os.path.join(PROJECT_ROOT, 'web', filename)
    
    if os.path.exists(build_path):
        return build_path
    elif os.path.exists(web_path):
        return web_path
    return web_path

@app.route('/')
def index():
    # Serve the main index.html from web/ directory
    index_path = os.path.join(PROJECT_ROOT, 'web', 'index.html')
    
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/html'}
    return "Frontend not found. Please ensure web/index.html exists.", 404

@app.route('/favicon.svg')
def favicon():
    favicon_path = os.path.join(PROJECT_ROOT, 'web', 'public', 'favicon.svg')
    if os.path.exists(favicon_path):
        with open(favicon_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'image/svg+xml'}
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="%230a0f1a"/><text x="16" y="23" font-size="20" text-anchor="middle" fill="%2300d4ff">🛡</text></svg>'
    return svg, 200, {'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-cache'}

@app.route('/dashboard')
def dashboard():
    """Redirect to main index page."""
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
xgb_model = None
xgb_metadata = None
if_model = None
if_metadata = None

ATTACK_TYPES = ["Bots", "Brute Force", "DDoS", "DoS", "Normal Traffic", "Port Scanning", "Web Attacks"]


def load_models():
    """Load all ML models (RF, AE, XGBoost, Isolation Forest)."""
    global rf_model, rf_metadata, scaler, autoencoder, ae_threshold
    global xgb_model, xgb_metadata, if_model, if_metadata
    
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
    
    # Load XGBoost
    try:
        from xgboost import XGBClassifier
        xgb_path = os.path.join(PROJECT_ROOT, "models", "xgb_model.json")
        xgb_model = XGBClassifier()
        xgb_model.load_model(xgb_path)
        logger.info(f"[OK] Loaded XGBoost from {xgb_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load XGBoost: {e}")
        xgb_model = None
    
    try:
        # Load XGB metadata
        xgb_meta_path = os.path.join(PROJECT_ROOT, "models", "xgb_metadata.pkl")
        xgb_metadata = joblib.load(xgb_meta_path)
        logger.info(f"[OK] Loaded XGB metadata from {xgb_meta_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load XGB metadata: {e}")
        xgb_metadata = {"class_labels": ATTACK_TYPES}
    
    # Load Isolation Forest
    try:
        if_path = os.path.join(PROJECT_ROOT, "models", "if_model.pkl")
        if_model = joblib.load(if_path)
        logger.info(f"[OK] Loaded Isolation Forest from {if_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load Isolation Forest: {e}")
        if_model = None
    
    try:
        # Load IF metadata
        if_meta_path = os.path.join(PROJECT_ROOT, "models", "if_metadata.pkl")
        if_metadata = joblib.load(if_meta_path)
        logger.info(f"[OK] Loaded IF metadata from {if_meta_path}")
    except Exception as e:
        logger.warning(f"[WARN] Failed to load IF metadata: {e}")
        if_metadata = {"contamination": 0.1}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Alert:
    """Represents a network intrusion alert with multi-model predictions."""
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
    xgb_label: str
    xgb_confidence: float
    if_is_anomaly: bool
    if_anomaly_score: float
    final_verdict: str
    combined_confidence: float
    
    def to_dict(self) -> dict:
        """Convert alert to JSON-serializable dict.
        
        Converts NumPy types to native Python types for Flask JSON serialization.
        """
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": int(self.src_port),
            "dst_port": int(self.dst_port),
            "protocol": int(self.protocol),
            "rf_label": str(self.rf_label),
            "rf_confidence": float(self.rf_confidence),
            "ae_anomaly_score": float(self.ae_anomaly_score),
            "ae_is_anomaly": bool(self.ae_is_anomaly),
            "xgb_label": str(self.xgb_label),
            "xgb_confidence": float(self.xgb_confidence),
            "if_is_anomaly": bool(self.if_is_anomaly),
            "if_anomaly_score": float(self.if_anomaly_score),
            "final_verdict": str(self.final_verdict),
            "combined_confidence": float(self.combined_confidence),
        }


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

def _get_scaled_features(features: np.ndarray) -> np.ndarray:
    """Get scaled features using the shared scaler."""
    if scaler is not None:
        features_df = pd.DataFrame(features, columns=FEATURE_COLUMNS)
        return scaler.transform(features_df)
    return features


def predict_hybrid(features: np.ndarray) -> Dict:
    """Run hybrid prediction using RF + AE + XGBoost + Isolation Forest.
    
    Ensemble voting logic:
    - RF and XGB classify into attack types
    - AE and IF detect anomalies (zero-day attacks)
    - Final verdict combines all signals
    """
    # Default values
    verdict = "Benign"
    rf_label = "Normal Traffic"
    rf_confidence = 0.99
    ae_anomaly_score = 0.0
    ae_is_anomaly = False
    xgb_label = "Normal Traffic"
    xgb_confidence = 0.99
    if_is_anomaly = False
    if_anomaly_score = 0.0
    combined_confidence = 0.99
    
    # Get scaled features once (used by all models)
    features_scaled = _get_scaled_features(features)
    
    # Random Forest prediction
    if rf_model is not None:
        try:
            class_labels = rf_metadata.get("class_labels", ATTACK_TYPES) if rf_metadata else ATTACK_TYPES
            
            rf_pred = rf_model.predict(features_scaled)[0]
            rf_proba = rf_model.predict_proba(features_scaled)[0]
            
            if hasattr(rf_model, "classes_") and len(rf_model.classes_) > 0:
                pred_idx = int(rf_pred)
                if pred_idx < len(class_labels):
                    rf_label = class_labels[pred_idx]
                else:
                    rf_label = str(rf_pred)
            else:
                rf_label = str(rf_pred)
            
            rf_confidence = float(max(rf_proba))
                
        except Exception as e:
            logger.error(f"RF prediction error: {e}")
    
    # XGBoost prediction
    if xgb_model is not None:
        try:
            class_labels = xgb_metadata.get("class_labels", ATTACK_TYPES) if xgb_metadata else ATTACK_TYPES
            
            xgb_pred = xgb_model.predict(features_scaled)[0]
            xgb_proba = xgb_model.predict_proba(features_scaled)[0]
            
            if hasattr(xgb_model, "classes_") and len(xgb_model.classes_) > 0:
                pred_idx = int(xgb_pred)
                if pred_idx < len(class_labels):
                    xgb_label = class_labels[pred_idx]
                else:
                    xgb_label = str(xgb_pred)
            else:
                xgb_label = str(xgb_pred)
            
            xgb_confidence = float(max(xgb_proba))
                
        except Exception as e:
            logger.error(f"XGB prediction error: {e}")
    
    # Isolation Forest anomaly detection
    if if_model is not None:
        try:
            # decision_function: higher = normal, lower = anomaly
            scores = if_model.decision_function(features_scaled)[0]
            prediction = if_model.predict(features_scaled)[0]  # -1 = anomaly, 1 = normal
            if_is_anomaly = prediction == -1
            
            # Normalize score to 0-1 range (higher = more anomalous)
            # Typical range is roughly [-0.5, 0.5]
            if_anomaly_score = max(0.0, min(1.0, 0.5 - scores))
                
        except Exception as e:
            logger.error(f"IF prediction error: {e}")
    
    # Autoencoder anomaly detection
    if autoencoder is not None and ae_threshold is not None:
        try:
            reconstruction = autoencoder.predict(features_scaled, verbose=0)
            mse = float(np.mean(np.square(features_scaled - reconstruction)))
            
            try:
                if ae_threshold.shape == ():  # 0-dimensional array
                    threshold = float(ae_threshold)
                else:
                    threshold = float(ae_threshold[0])
            except (TypeError, IndexError):
                threshold = float(ae_threshold)
            
            ae_anomaly_score = mse
            ae_is_anomaly = bool(mse > threshold)
                
        except Exception as e:
            logger.error(f"AE prediction error: {e}")
    
    # Ensemble voting logic
    attack_labels = {"DDoS", "DoS", "Port Scanning", "Brute Force", "Web Attacks", "Bots"}
    benign_labels = {"Normal Traffic", "Normal", "Benign"}
    
    # Count votes for attack vs benign
    attack_votes = 0
    benign_votes = 0
    
    if rf_label not in benign_labels:
        attack_votes += 1
    else:
        benign_votes += 1
        
    if xgb_label not in benign_labels:
        attack_votes += 1
    else:
        benign_votes += 1
    
    # AE anomaly detection (weights as half vote)
    if ae_is_anomaly:
        if rf_confidence < 0.8 or xgb_confidence < 0.8:
            attack_votes += 0.5
    
    # IF anomaly detection (weights as half vote)
    if if_is_anomaly:
        if if_anomaly_score > 0.5:
            if rf_confidence < 0.85 or xgb_confidence < 0.85:
                attack_votes += 0.5
    
    # Determine final verdict
    if attack_votes >= 2:
        verdict = "Attack"
        combined_confidence = max(rf_confidence, xgb_confidence)
    elif attack_votes >= 1:
        # Models disagree, check anomaly detectors
        if ae_is_anomaly or (if_is_anomaly and if_anomaly_score > 0.6):
            verdict = "Suspicious"
            combined_confidence = min(rf_confidence, xgb_confidence, 0.7)
        else:
            verdict = "Benign"
            combined_confidence = (rf_confidence + xgb_confidence) / 2
    else:
        verdict = "Benign"
        combined_confidence = (rf_confidence + xgb_confidence) / 2
    
    return {
        "rf_label": rf_label,
        "rf_confidence": rf_confidence,
        "ae_anomaly_score": ae_anomaly_score,
        "ae_is_anomaly": ae_is_anomaly,
        "xgb_label": xgb_label,
        "xgb_confidence": xgb_confidence,
        "if_is_anomaly": if_is_anomaly,
        "if_anomaly_score": if_anomaly_score,
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
        xgb_label=prediction["xgb_label"],
        xgb_confidence=prediction["xgb_confidence"],
        if_is_anomaly=prediction["if_is_anomaly"],
        if_anomaly_score=prediction["if_anomaly_score"],
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
            "scaler": scaler is not None,
            "xgboost": xgb_model is not None,
            "isolation_forest": if_model is not None,
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
    
    # Validate target_ip format (basic check)
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({"error": "Valid target_ip required"}), 400
    
    # Handle "all" attack types
    valid_types = ["normal", "ddos", "synflood", "portscan", "slowloris", "bruteforce", "webattacks"]
    if attack_type == "all":
        # Run multiple attack simulations
        all_alerts = []
        attack_types_to_run = ["ddos", "synflood", "portscan", "bruteforce"]
        for atype in attack_types_to_run:
            alerts = simulate_attack(atype, target_ip)
            all_alerts.extend(alerts)
        # Add some normal traffic
        normal_alerts = generate_normal_traffic(target_ip)
        all_alerts.extend(normal_alerts[:5])  # Add 5 normal samples
        return jsonify({
            "type": "all",
            "target_ip": target_ip,
            "alerts_generated": len(all_alerts),
            "attacks_run": attack_types_to_run,
            "alerts": [a.to_dict() for a in all_alerts]
        })
    
    # Validate attack_type
    if attack_type not in valid_types:
        return jsonify({
            "error": f"Invalid attack type. Must be one of: {', '.join(valid_types + ['all'])}"
        }), 400
    
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
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

# TI Client singleton (lazy initialization)
_ti_client = None

def get_ti_client():
    """Get or create TI client singleton with API keys from environment."""
    global _ti_client
    if _ti_client is None:
        try:
            from src.integration.ti_client import ThreatIntelClient
            
            # Load API keys from environment variables
            vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
            abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
            
            # Initialize with API keys
            _ti_client = ThreatIntelClient(
                vt_api_key=vt_api_key,
                abuseipdb_api_key=abuseipdb_api_key,
            )
            
            # Log which APIs are enabled
            if vt_api_key:
                logger.info("ThreatIntelClient initialized with VirusTotal API")
            else:
                logger.info("ThreatIntelClient initialized (VirusTotal: DISABLED)")
            
            if abuseipdb_api_key:
                logger.info("ThreatIntelClient initialized with AbuseIPDB API")
            else:
                logger.info("ThreatIntelClient initialized (AbuseIPDB: DISABLED)")
                
        except ImportError as e:
            logger.warning(f"ThreatIntelClient not available: {e}")
            _ti_client = None
    return _ti_client


@app.route("/api/ti/test", methods=["GET"])
def test_ti():
    """Test endpoint for TI lookup debugging."""
    return jsonify({
        "status": "ok",
        "message": "TI endpoint is working",
        "client_initialized": get_ti_client() is not None
    })


@app.route("/api/ti/lookup/<ip>", methods=["GET"])
def lookup_threat_intel(ip: str):
    """Lookup threat intelligence for an IP address.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        JSON with TI data including score, reputation, and source details
    """
    import hashlib
    import re
    
    # Validate IP format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    # Check for private/internal IPs
    octets = [int(x) for x in ip.split('.')]
    is_private = (
        octets[0] == 10 or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168) or
        octets[0] == 127
    )
    
    if is_private:
        return jsonify({
            "ip": ip,
            "score": 0,
            "reputation_label": "Internal",
            "is_malicious": False,
            "sources": {},
            "message": "Private/internal IP address - no external TI available"
        })
    
    # Try to use the TI client
    ti_client = get_ti_client()
    
    if ti_client is not None:
        try:
            result = ti_client.lookup_ip(ip)
            # Build sources object matching frontend expectations
            sources = {}
            for source in result.sources:
                source_lower = source.lower()
                if source_lower == "virustotal":
                    sources["virustotal"] = {"detected": True, "score": result.threat_score}
                elif source_lower == "abuseipdb":
                    sources["abuseipdb"] = {"detected": True, "reports": 1 if result.threat_score > 20 else 0}
                elif source_lower == "otx":
                    sources["otx"] = {"detected": True, "pulses": 1 if result.threat_score > 30 else 0}
            
            return jsonify({
                "ip": ip,
                "score": result.threat_score,
                "reputation_label": result.reputation.capitalize(),
                "is_malicious": result.is_malicious,
                "sources": sources,
                "country": result.country,
                "asn": result.asn,
                "cached": result.cached
            })
        except Exception as e:
            logger.error(f"TI lookup error for {ip}: {e}")
            # Fall through to mock data
    
    # Mock TI data for demo purposes when TI client unavailable
    # Generate consistent scores based on IP for demo
    hash_val = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    mock_score = hash_val % 100
    
    if mock_score < 30:
        reputation = "Clean"
        is_malicious = False
    elif mock_score < 70:
        reputation = "Suspicious"
        is_malicious = False
    else:
        reputation = "Malicious"
        is_malicious = True
    
    # Generate mock source data
    sources = {}
    if hash_val % 3 == 0:
        sources["virustotal"] = {
            "malicious": hash_val % 10 if is_malicious else 0,
            "total": 90
        }
    if hash_val % 2 == 0:
        sources["abuseipdb"] = {
            "reports": (hash_val % 50) if mock_score > 30 else 0,
            "confidence": mock_score
        }
    if hash_val % 5 == 0:
        sources["otx"] = {
            "pulses": (hash_val % 20) if mock_score > 50 else 0
        }
    
    return jsonify({
        "ip": ip,
        "score": mock_score,
        "reputation_label": reputation,
        "is_malicious": is_malicious,
        "sources": sources,
        "mock": True  # Indicate this is mock data
    })


# ============================================================================
# GEOIP ENDPOINTS
# ============================================================================

# Lazy-loaded GeoIP service
_geoip_service = None


def get_geoip_service():
    """Get or create GeoIP service singleton."""
    global _geoip_service
    if _geoip_service is None:
        try:
            from src.utils.geoip import GeoIPService
            _geoip_service = GeoIPService()
            logger.info("GeoIPService initialized")
        except ImportError as e:
            logger.warning(f"GeoIPService not available: {e}")
            _geoip_service = None
    return _geoip_service


@app.route("/api/geo/lookup/<ip>", methods=["GET"])
def lookup_geoip(ip: str):
    """Look up geographic location for an IP address.
    
    Args:
        ip: IP address to look up
        
    Returns:
        JSON with geolocation data
    """
    import re
    
    # Validate IP format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    geoip = get_geoip_service()
    
    if geoip is None:
        return jsonify({"error": "GeoIP service not available"}), 503
    
    try:
        location = geoip.lookup(ip)
        
        if location is None:
            return jsonify({
                "ip": ip,
                "error": "Location lookup failed",
                "cached": False
            }), 200  # Return 200 with error flag
        
        return jsonify(location.to_dict())
        
    except Exception as e:
        logger.error(f"GeoIP lookup error for {ip}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/geo/attacks-map", methods=["GET"])
def get_attacks_map():
    """Get attack sources with geographic locations for map visualization.
    
    Returns top attacking IPs with their geolocation data.
    
    Query Parameters:
        n: Number of top attackers to include (default: 20)
        include_all: Include all alerts instead of just top attackers (default: false)
    """
    geoip = get_geoip_service()
    
    if geoip is None:
        return jsonify({"error": "GeoIP service not available"}), 503
    
    try:
        n = request.args.get("n", 20, type=int)
        include_all = request.args.get("include_all", "false").lower() == "true"
        
        # Get alerts
        if include_all:
            alerts = alert_store.get_all()
        else:
            # Get top attackers
            top_attackers = alert_store.get_top_attackers(n * 2)  # Get more to merge duplicates
            alerts = []
            
            # Find alerts for top attackers
            all_alerts = alert_store.get_all()
            attacker_ips = {a["src_ip"] for a in top_attackers}
            
            for alert in all_alerts:
                if alert.src_ip in attacker_ips:
                    alerts.append(alert)
        
        # Get unique IPs and their counts
        ip_counts = {}
        ip_data = {}
        
        for alert in alerts:
            src_ip = alert.src_ip
            if src_ip not in ip_counts:
                ip_counts[src_ip] = 0
            ip_data[src_ip] = alert
            ip_counts[src_ip] += 1
        
        # Sort by count and take top N
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]
        
        # Batch lookup geolocations
        ips_to_lookup = [ip for ip, _ in sorted_ips]
        locations = geoip.lookup_batch(ips_to_lookup)
        
        # Build response
        markers = []
        country_stats = {}
        
        for ip, count in sorted_ips:
            loc = locations.get(ip)
            alert = ip_data[ip]
            
            marker = {
                "ip": ip,
                "attack_count": count,
                "label": alert.rf_label,
                "verdict": alert.final_verdict,
                "confidence": float(alert.combined_confidence),
                "timestamp": alert.timestamp
            }
            
            if loc and not loc.is_private:
                marker["latitude"] = loc.latitude
                marker["longitude"] = loc.longitude
                marker["country"] = loc.country
                marker["country_code"] = loc.country_code
                marker["city"] = loc.city
                marker["isp"] = loc.isp
                marker["threat_level"] = loc.threat_level
                
                # Country stats
                if loc.country not in country_stats:
                    country_stats[loc.country] = {
                        "country": loc.country,
                        "country_code": loc.country_code,
                        "attack_count": 0,
                        "unique_ips": 0
                    }
                country_stats[loc.country]["attack_count"] += count
                country_stats[loc.country]["unique_ips"] += 1
            else:
                marker["latitude"] = None
                marker["longitude"] = None
                marker["country"] = "Unknown"
                marker["country_code"] = "XX"
            
            markers.append(marker)
        
        # Sort country stats by attack count
        sorted_countries = sorted(
            country_stats.values(),
            key=lambda x: x["attack_count"],
            reverse=True
        )
        
        return jsonify({
            "markers": markers,
            "countries": sorted_countries,
            "total_attacks": sum(ip_counts.values()),
            "unique_ips": len(ip_counts),
            "cache_stats": geoip.get_cache_stats()
        })
        
    except Exception as e:
        logger.error(f"Attacks map error: {e}")
        return jsonify({"error": str(e)}), 500


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
                        features_np = features_df.values.astype(np.float32)
                        
                        # Predict using predict_hybrid for full ensemble
                        prediction = predict_hybrid(features_np)
                        
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
                                rf_label=prediction["rf_label"],
                                rf_confidence=prediction["rf_confidence"],
                                ae_anomaly_score=prediction["ae_anomaly_score"],
                                ae_is_anomaly=prediction["ae_is_anomaly"],
                                xgb_label=prediction["xgb_label"],
                                xgb_confidence=prediction["xgb_confidence"],
                                if_is_anomaly=prediction["if_is_anomaly"],
                                if_anomaly_score=prediction["if_anomaly_score"],
                                final_verdict=prediction["final_verdict"],
                                combined_confidence=prediction["combined_confidence"]
                            )
                            alert_store.next_id += 1
                            alert_store.add_alert(alert)
                        
                        logger.info(f"Live alert: {prediction['final_verdict']} - RF:{prediction['rf_label']} XGB:{prediction['xgb_label']}")
                        
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
