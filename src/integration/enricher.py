"""Alert Enricher for adding Threat Intelligence to alerts.

Enriches raw alerts with threat intelligence data from multiple sources,
providing additional context for security analysts.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, asdict
from typing import Any

from src.integration.ti_client import ThreatIntelClient, ThreatIntelResult

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnrichedAlert:
    """Immutable enriched alert with threat intelligence data.
    
    Attributes:
        alert_id: Unique identifier for the alert.
        timestamp: ISO timestamp of when the alert was generated.
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        dst_port: Destination port.
        protocol: Network protocol (TCP, UDP, etc.).
        rf_label: Random Forest model prediction label.
        rf_confidence: Random Forest model confidence score.
        xgb_label: XGBoost model prediction label.
        xgb_confidence: XGBoost model confidence score.
        if_anomaly: Isolation Forest anomaly flag.
        ae_anomaly: Autoencoder anomaly flag.
        final_verdict: Combined verdict (Attack, Suspicious, Benign).
        combined_confidence: Combined model confidence.
        ti_score: Threat intelligence score (0-100).
        ti_reputation: Threat intelligence reputation string.
        ti_sources: List of TI sources that contributed data.
        ti_country: Country code from TI lookup.
        ti_asn: ASN from TI lookup.
        status: Alert status (new, investigating, resolved).
    """

    alert_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    rf_label: str
    rf_confidence: float
    xgb_label: str
    xgb_confidence: float
    if_anomaly: bool
    ae_anomaly: bool
    final_verdict: str
    combined_confidence: float
    ti_score: int
    ti_reputation: str
    ti_sources: list[str]
    ti_country: str
    ti_asn: str
    status: str


class AlertEnricher:
    """Enriches alerts with threat intelligence data.
    
    Takes raw alert dictionaries and enriches them with TI data
    from VirusTotal, AbuseIPDB, and AlienVault OTX.
    
    Args:
        ti_client: ThreatIntelClient instance for TI lookups.
    """

    def __init__(self, ti_client: ThreatIntelClient) -> None:
        """Initialize AlertEnricher with TI client."""
        self._ti_client = ti_client

    def _validate_alert(self, alert: dict[str, Any]) -> None:
        """Validate alert has required fields.
        
        Args:
            alert: Alert dictionary to validate.
            
        Raises:
            ValueError: If required fields are missing or invalid.
        """
        if "id" not in alert:
            raise ValueError("Alert missing required field: id")
        
        if "src_ip" not in alert:
            raise ValueError("Alert missing required field: src_ip")
        
        # Validate IP address format
        try:
            ipaddress.ip_address(alert["src_ip"])
        except ValueError:
            raise ValueError(f"Invalid IP address format: {alert['src_ip']}")

    def _lookup_ti(self, ip: str) -> ThreatIntelResult | None:
        """Look up threat intelligence for an IP.
        
        Args:
            ip: IP address to look up.
            
        Returns:
            ThreatIntelResult or None if lookup fails.
        """
        try:
            return self._ti_client.lookup_ip(ip)
        except Exception as e:
            LOGGER.warning("TI lookup failed for %s: %s", ip, e)
            return None

    def enrich_alert(self, alert: dict[str, Any]) -> EnrichedAlert:
        """Enrich an alert with threat intelligence data.
        
        Args:
            alert: Raw alert dictionary.
            
        Returns:
            EnrichedAlert with TI data added.
            
        Raises:
            ValueError: If alert is missing required fields.
        """
        self._validate_alert(alert)

        # Lookup TI for source IP
        ti_result = self._lookup_ti(alert["src_ip"])

        # Extract TI data or use defaults
        if ti_result is not None:
            ti_score = ti_result.threat_score
            ti_reputation = ti_result.reputation
            ti_sources = list(ti_result.sources)
            ti_country = ti_result.country
            ti_asn = ti_result.asn
        else:
            ti_score = 0
            ti_reputation = "unknown"
            ti_sources = []
            ti_country = ""
            ti_asn = ""

        # Build enriched alert
        return EnrichedAlert(
            alert_id=alert["id"],
            timestamp=alert.get("timestamp", ""),
            src_ip=alert["src_ip"],
            dst_ip=alert.get("dst_ip", ""),
            dst_port=alert.get("dst_port", 0),
            protocol=alert.get("protocol", "TCP"),
            rf_label=alert.get("rf_label", ""),
            rf_confidence=alert.get("rf_confidence", 0.0),
            xgb_label=alert.get("xgb_label", ""),
            xgb_confidence=alert.get("xgb_confidence", 0.0),
            if_anomaly=alert.get("if_anomaly", False),
            ae_anomaly=alert.get("ae_anomaly", False),
            final_verdict=alert.get("final_verdict", ""),
            combined_confidence=alert.get("combined_confidence", 0.0),
            ti_score=ti_score,
            ti_reputation=ti_reputation,
            ti_sources=ti_sources,
            ti_country=ti_country,
            ti_asn=ti_asn,
            status=alert.get("status", "new"),
        )

    def enrich_batch(self, alerts: list[dict[str, Any]]) -> list[EnrichedAlert]:
        """Enrich multiple alerts with threat intelligence data.
        
        Args:
            alerts: List of raw alert dictionaries.
            
        Returns:
            List of EnrichedAlert instances.
        """
        return [self.enrich_alert(alert) for alert in alerts]

    def to_dict(self, enriched_alert: EnrichedAlert) -> dict[str, Any]:
        """Convert EnrichedAlert to dictionary.
        
        Args:
            enriched_alert: EnrichedAlert instance.
            
        Returns:
            Dictionary representation of the alert.
        """
        return asdict(enriched_alert)
