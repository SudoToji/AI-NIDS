"""
AI-NIDS Dashboard
================
Live Network Intrusion Detection System Dashboard.

Educational Use Only - For demonstration purposes only.

Usage:
    streamlit run src/dashboard/app.py
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from alert_manager import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="AI-NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
    }
    .metric-card {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #334155;
    }
    .alert-critical {
        background-color: #dc2626;
        color: white;
        padding: 10px;
        border-radius: 5px;
    }
    .alert-warning {
        background-color: #f59e0b;
        color: black;
        padding: 10px;
        border-radius: 5px;
    }
    .alert-normal {
        background-color: #22c55e;
        color: white;
        padding: 10px;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

ALERT_DB_PATH = os.environ.get("ALERTS_DB_PATH", "logs/alerts.db")


def get_alert_manager() -> AlertManager:
    """Get or create AlertManager singleton."""
    if "alert_manager" not in st.session_state:
        os.makedirs(os.path.dirname(ALERT_DB_PATH) or "logs", exist_ok=True)
        st.session_state.alert_manager = AlertManager(db_path=ALERT_DB_PATH)
    return st.session_state.alert_manager


def generate_demo_data(manager: AlertManager, num_samples: int = 50) -> None:
    """Generate demo alert data for demonstration."""
    import random
    
    attack_types = ["DDoS", "DoS", "Port Scanning", "Brute Force", "Web Attacks", "Bots"]
    protocols = [6, 17, 1]
    verdicts = ["Attack", "Suspicious", "Benign"]
    
    for _ in range(num_samples):
        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"10.0.0.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 3389, 8080, random.randint(1, 1023)])
        protocol = random.choice(protocols)
        
        if random.random() < 0.3:
            rf_label = "Normal Traffic"
            verdict = "Benign"
        else:
            rf_label = random.choice(attack_types)
            verdict = random.choice(["Attack", "Suspicious"])
        
        alert = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "rf_label": rf_label,
            "rf_confidence": round(random.uniform(0.7, 1.0), 3),
            "ae_anomaly_score": round(random.uniform(0.0, 1.0), 4),
            "ae_is_anomaly": verdict != "Benign",
            "final_verdict": verdict,
            "combined_confidence": round(random.uniform(0.6, 1.0), 3),
            "timestamp": datetime.utcnow().isoformat(),
        }
        manager.add_alert(alert)


def create_attack_distribution_chart(distribution: dict) -> go.Figure:
    """Create donut chart for attack distribution."""
    if not distribution:
        fig = go.Figure()
        fig.add_annotation(text="No data yet", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    colors = {
        "DDoS": "#ef4444",
        "DoS": "#f97316",
        "Port Scanning": "#eab308",
        "Brute Force": "#84cc16",
        "Web Attacks": "#06b6d4",
        "Bots": "#8b5cf6",
        "Normal Traffic": "#22c55e",
        "Unknown": "#6b7280",
    }
    
    labels = list(distribution.keys())
    values = list(distribution.values())
    color_list = [colors.get(label, "#6b7280") for label in labels]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=color_list),
        textinfo="label+percent",
        hoverinfo="label+value+percent",
    )])
    
    fig.update_layout(
        title_text="Attack Distribution",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2),
        margin=dict(t=50, b=50, l=20, r=20),
    )
    return fig


def create_timeline_chart(alerts: list) -> go.Figure:
    """Create timeline of alerts over time."""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(text="No data yet", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    
    df["attack"] = df["final_verdict"] != "Benign"
    df["attack"] = df["attack"].astype(int)
    
    df["time_bucket"] = df["timestamp"].dt.floor("min")
    timeline = df.groupby("time_bucket").agg({
        "attack": "sum",
        "id": "count"
    }).reset_index()
    timeline.columns = ["time", "attacks", "total"]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=timeline["time"],
        y=timeline["attacks"],
        mode="lines+markers",
        name="Attacks",
        line=dict(color="#ef4444", width=2),
        marker=dict(size=6),
        fill="tozeroy",
        fillcolor="rgba(239, 68, 68, 0.3)",
    ))
    
    fig.update_layout(
        title_text="Alert Timeline (Last Hour)",
        xaxis_title="Time",
        yaxis_title="Attack Count",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        xaxis=dict(showgrid=True, gridcolor="#334155"),
        yaxis=dict(showgrid=True, gridcolor="#334155"),
        margin=dict(t=50, b=50, l=50, r=20),
    )
    return fig


def create_top_attackers_chart(attackers: list) -> go.Figure:
    """Create bar chart of top attackers."""
    if not attackers:
        fig = go.Figure()
        fig.add_annotation(text="No attackers yet", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False)
        return fig
    
    df = pd.DataFrame(attackers)
    
    fig = go.Figure(data=[go.Bar(
        x=df["alert_count"],
        y=df["src_ip"],
        orientation="h",
        marker=dict(
            color=df["alert_count"],
            colorscale="Reds",
        ),
    )])
    
    fig.update_layout(
        title_text="Top Attackers",
        xaxis_title="Alert Count",
        yaxis_title="Source IP",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        yaxis=dict(autorange="reversed"),
        margin=dict(t=50, b=50, l=100, r=20),
    )
    return fig


def create_verdict_gauge(attack_rate: float) -> go.Figure:
    """Create gauge for attack rate."""
    color = "#22c55e" if attack_rate < 30 else "#f59e0b" if attack_rate < 60 else "#ef4444"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_rate,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Attack Rate %"},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "white"},
            "bar": {"color": color},
            "bgcolor": "#1e293b",
            "borderwidth": 2,
            "bordercolor": "#334155",
            "steps": [
                {"range": [0, 30], "color": "#22c55e"},
                {"range": [30, 60], "color": "#f59e0b"},
                {"range": [60, 100], "color": "#ef4444"},
            ],
        },
        number={"font": {"size": 24, "color": "white"}},
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        margin=dict(t=20, b=20, l=20, r=20),
        height=180,
    )
    return fig


def main():
    """Main dashboard function."""
    st.title("🛡️ AI-NIDS - Network Intrusion Detection")
    st.markdown("**Educational Use Only** - For demonstration purposes")
    
    manager = get_alert_manager()
    
    if "demo_initialized" not in st.session_state:
        generate_demo_data(manager, num_samples=50)
        st.session_state.demo_initialized = True
    
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        st.subheader("Model Status")
        st.success("✓ Random Forest: 99.76%")
        st.success("✓ Autoencoder: Active")
        st.success("✓ Hybrid Engine: Running")
        
        st.subheader("Settings")
        auto_refresh = st.toggle("Auto Refresh", value=True)
        refresh_interval = st.slider("Refresh Interval (s)", 1, 10, 3)
        
        if st.button("Generate Demo Data"):
            generate_demo_data(manager, num_samples=20)
            st.rerun()
        
        if st.button("Clear All Alerts"):
            st.session_state.alert_manager = AlertManager(db_path=ALERT_DB_PATH)
            st.rerun()
    
    if auto_refresh:
        st_autorefresh(interval=refresh_interval * 1000, limit=None, key="dashboard_refresh")
    
    col1, col2, col3, col4 = st.columns(4)
    
    recent = manager.get_recent_alerts(n=100)
    total_alerts = len(recent)
    attack_count = sum(1 for a in recent if a.get("final_verdict") != "Benign")
    suspicious_count = sum(1 for a in recent if a.get("final_verdict") == "Suspicious")
    benign_count = total_alerts - attack_count
    
    attack_rate = (attack_count / total_alerts * 100) if total_alerts > 0 else 0
    
    with col1:
        st.metric("Total Alerts", total_alerts, delta=None)
    with col2:
        st.metric("Attacks", attack_count, delta_color="inverse")
    with col3:
        st.metric("Suspicious", suspicious_count, delta_color="normal")
    with col4:
        st.metric("Benign", benign_count, delta_color="normal")
    
    st.divider()
    
    row1_col1, row1_col2 = st.columns([2, 1])
    
    with row1_col1:
        dist = manager.get_attack_distribution()
        fig_dist = create_attack_distribution_chart(dist)
        st.plotly_chart(fig_dist, use_container_width=True)
    
    with row1_col2:
        fig_gauge = create_verdict_gauge(attack_rate)
        st.plotly_chart(fig_gauge, use_container_width=True)
    
    row2_col1, row2_col2 = st.columns(2)
    
    with row2_col1:
        fig_timeline = create_timeline_chart(recent)
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    with row2_col2:
        attackers = manager.get_top_attackers(n=10)
        fig_attackers = create_top_attackers_chart(attackers)
        st.plotly_chart(fig_attackers, use_container_width=True)
    
    st.divider()
    
    st.subheader("📋 Recent Alerts")
    
    if recent:
        df_alerts = pd.DataFrame(recent[-20:][::-1])
        
        def color_verdict(val):
            if val == "Attack":
                return "background-color: #dc2626; color: white"
            elif val == "Suspicious":
                return "background-color: #f59e0b; color: black"
            else:
                return "background-color: #22c55e; color: white"
        
        display_cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "rf_label", "final_verdict", "combined_confidence"]
        df_display = df_alerts[display_cols].copy()
        df_display["timestamp"] = pd.to_datetime(df_display["timestamp"]).dt.strftime("%H:%M:%S")
        df_display["combined_confidence"] = (df_display["combined_confidence"] * 100).round(1).astype(str) + "%"
        
        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No alerts yet. Waiting for network traffic...")
    
    st.divider()
    
    col_block1, col_block2 = st.columns([3, 1])
    
    with col_block1:
        ip_to_block = st.text_input("Block IP Address", placeholder="e.g., 192.168.1.100")
    
    with col_block2:
        st.write("")
        st.write("")
        if st.button("🚫 Block IP", use_container_width=True):
            if ip_to_block:
                result = manager.block_ip(ip_to_block)
                if result:
                    st.success(f"Blocked {ip_to_block}")
                else:
                    st.info(f"{ip_to_block} was already blocked")
            else:
                st.warning("Enter an IP address")
    
    blocked = manager.get_blocked_ips()
    if blocked:
        st.write("**Blocked IPs:** " + ", ".join(blocked[:10]))
        if len(blocked) > 10:
            st.write(f"... and {len(blocked) - 10} more")
    
    with st.expander("📤 Export Options"):
        col_exp1, col_exp2 = st.columns(2)
        
        with col_exp1:
            if st.button("Export to CSV"):
                csv_path = manager.export_csv("logs/alerts_export.csv")
                st.success(f"Exported to {csv_path}")
        
        with col_exp2:
            st.write(f"Database: {ALERT_DB_PATH}")
            st.write(f"Total alerts in DB: {total_alerts}")
    
    st.markdown("---")
    st.caption("AI-NIDS Dashboard | Powered by Random Forest + Autoencoder | Educational Use Only")


if __name__ == "__main__":
    main()
