"""Threat Intelligence Client for IP reputation lookups.

Integrates with VirusTotal, AbuseIPDB, and AlienVault OTX APIs
with SQLite caching to minimize API calls.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, UTC, timedelta
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

# Default cache TTL: 24 hours
DEFAULT_CACHE_TTL_SECONDS = 86400

# API endpoints
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_API_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"

# Threat score thresholds (aligned with reputation labels)
# Score >= 70: malicious (is_malicious=True)
# Score >= 40: bad (is_malicious=True) 
# Score >= 20: suspicious (is_malicious=False)
# Score < 20: clean (is_malicious=False)
MALICIOUS_THRESHOLD = 40  # Score >= 40 is considered malicious


@dataclass(frozen=True)
class ThreatIntelResult:
    """Immutable result from threat intelligence lookup.
    
    Attributes:
        ip: The IP address that was looked up.
        is_malicious: Whether the IP is considered malicious.
        threat_score: Aggregated threat score (0-100).
        sources: List of sources that contributed to the result.
        country: Country code of the IP.
        asn: Autonomous System Number.
        reputation: Overall reputation string.
        last_seen: ISO timestamp of last malicious activity.
        cached: Whether this result came from cache.
    """

    ip: str
    is_malicious: bool
    threat_score: int
    sources: list[str]
    country: str
    asn: str
    reputation: str
    last_seen: str
    cached: bool


class ThreatIntelClient:
    """Client for aggregating threat intelligence from multiple sources.
    
    Queries VirusTotal, AbuseIPDB, and AlienVault OTX APIs and caches
    results in SQLite to minimize API calls and respect rate limits.
    
    Args:
        cache_db_path: Path to SQLite cache database.
        vt_api_key: VirusTotal API key (optional).
        abuseipdb_api_key: AbuseIPDB API key (optional).
        cache_ttl_seconds: Cache TTL in seconds (default 24 hours).
    """

    def __init__(
        self,
        cache_db_path: str = "ti_cache.db",
        vt_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        """Initialize the ThreatIntelClient."""
        self._cache_db_path = cache_db_path
        self._vt_api_key = vt_api_key
        self._abuseipdb_api_key = abuseipdb_api_key
        self._cache_ttl_seconds = cache_ttl_seconds
        
        self._init_cache_db()

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database with schema."""
        with sqlite3.connect(self._cache_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ti_cache (
                    ip TEXT PRIMARY KEY,
                    is_malicious INTEGER,
                    threat_score INTEGER,
                    sources TEXT,
                    country TEXT,
                    asn TEXT,
                    reputation TEXT,
                    last_seen TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()

    def _get_cached_result(self, ip: str) -> ThreatIntelResult | None:
        """Get cached result if exists and not expired.
        
        Args:
            ip: IP address to look up.
            
        Returns:
            Cached ThreatIntelResult or None if not found/expired.
        """
        with sqlite3.connect(self._cache_db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM ti_cache WHERE ip = ?",
                (ip,),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        # Check if cache entry is expired
        timestamp = datetime.fromisoformat(row[8])
        if datetime.now(UTC) - timestamp > timedelta(seconds=self._cache_ttl_seconds):
            # Clean up expired entry
            self._delete_cached_result(ip)
            return None

        return ThreatIntelResult(
            ip=row[0],
            is_malicious=bool(row[1]),
            threat_score=row[2],
            sources=json.loads(row[3]),
            country=row[4] or "",
            asn=row[5] or "",
            reputation=row[6] or "",
            last_seen=row[7] or "",
            cached=True,
        )

    def _delete_cached_result(self, ip: str) -> None:
        """Delete a cached result by IP.
        
        Args:
            ip: IP address to delete from cache.
        """
        with sqlite3.connect(self._cache_db_path) as conn:
            conn.execute("DELETE FROM ti_cache WHERE ip = ?", (ip,))
            conn.commit()

    def _cache_result(self, result: ThreatIntelResult) -> None:
        """Cache a ThreatIntelResult to SQLite.
        
        Args:
            result: The result to cache.
        """
        with sqlite3.connect(self._cache_db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ti_cache
                (ip, is_malicious, threat_score, sources, country, asn, reputation, last_seen, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.ip,
                    int(result.is_malicious),
                    result.threat_score,
                    json.dumps(result.sources),
                    result.country,
                    result.asn,
                    result.reputation,
                    result.last_seen,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()

    def _check_virustotal(self, ip: str) -> dict[str, Any]:
        """Query VirusTotal API for IP reputation.
        
        Args:
            ip: IP address to check.
            
        Returns:
            Dict with malicious count, total engines, country, ASN.
            
        Raises:
            Exception: If API request fails.
        """
        if not self._vt_api_key:
            return {}

        url = f"{VIRUSTOTAL_API_URL}/{ip}"
        headers = {"x-apikey": self._vt_api_key}

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "country": attrs.get("country", ""),
            "asn": f"AS{attrs.get('asn', '')}" if attrs.get("asn") else "",
        }

    def _check_abuseipdb(self, ip: str) -> dict[str, Any]:
        """Query AbuseIPDB API for IP reputation.
        
        Args:
            ip: IP address to check.
            
        Returns:
            Dict with report count and confidence score.
            
        Raises:
            Exception: If API request fails.
        """
        if not self._abuseipdb_api_key:
            return {}

        headers = {
            "Key": self._abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }

        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10,
        )
        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "reports": data.get("totalReports", 0),
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", ""),
        }

    def _check_otx(self, ip: str) -> dict[str, Any]:
        """Query AlienVault OTX API for IP reputation.
        
        OTX has a free API that doesn't require authentication.
        
        Args:
            ip: IP address to check.
            
        Returns:
            Dict with pulse count and reputation.
            
        Raises:
            Exception: If API request fails.
        """
        url = f"{OTX_API_URL}/{ip}/general"

        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        pulse_info = data.get("pulse_info", {})
        reputation_score = data.get("reputation", 0)

        # Map reputation score to string
        if reputation_score >= 3:
            reputation = "malicious"
        elif reputation_score >= 1:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return {
            "pulses": pulse_info.get("count", 0),
            "reputation": reputation,
        }

    def _calculate_threat_score(
        self,
        vt_result: dict[str, Any],
        abuse_result: dict[str, Any],
        otx_result: dict[str, Any],
    ) -> int:
        """Calculate aggregated threat score from all sources.
        
        Scoring weights:
        - VirusTotal: 40% (malicious ratio)
        - AbuseIPDB: 40% (confidence score)
        - OTX: 20% (pulse count + reputation)
        
        When sources are missing, the score is NOT normalized upward.
        This prevents over-inflation when only one source responds.
        Missing sources contribute 0 to the score.
        
        Args:
            vt_result: VirusTotal API response.
            abuse_result: AbuseIPDB API response.
            otx_result: OTX API response.
            
        Returns:
            Aggregated threat score (0-100).
        """
        score = 0.0

        # VirusTotal score (0-40 points)
        if vt_result:
            malicious = vt_result.get("malicious", 0)
            total = vt_result.get("total", 1)
            vt_score = (malicious / max(total, 1)) * 100
            score += vt_score * 0.4

        # AbuseIPDB score (0-40 points)
        if abuse_result:
            abuse_score = abuse_result.get("confidence_score", 0)
            score += abuse_score * 0.4

        # OTX score (0-20 points)
        if otx_result:
            pulses = otx_result.get("pulses", 0)
            reputation = otx_result.get("reputation", "clean")
            
            # Pulse-based score (max 10 points for 10+ pulses)
            pulse_score = min(pulses * 10, 100)
            
            # Reputation-based score
            rep_scores = {"malicious": 100, "suspicious": 50, "clean": 0}
            rep_score = rep_scores.get(reputation, 0)
            
            otx_score = (pulse_score + rep_score) / 2
            score += otx_score * 0.2

        # No normalization - missing sources contribute 0
        # This prevents over-inflation when only one source responds
        return int(min(score, 100))

    def _determine_reputation(self, threat_score: int) -> str:
        """Determine reputation string from threat score.
        
        Args:
            threat_score: Aggregated threat score (0-100).
            
        Returns:
            Reputation string: 'clean', 'suspicious', 'bad', or 'malicious'.
        """
        if threat_score >= 70:
            return "malicious"
        elif threat_score >= 40:
            return "bad"
        elif threat_score >= 20:
            return "suspicious"
        else:
            return "clean"

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Look up threat intelligence for an IP address.
        
        Checks cache first, then queries all available APIs and
        aggregates the results into a single ThreatIntelResult.
        
        Args:
            ip: IP address to look up.
            
        Returns:
            ThreatIntelResult with aggregated threat intelligence.
        """
        # Check cache first
        cached = self._get_cached_result(ip)
        if cached is not None:
            return cached

        # Query all sources
        sources: list[str] = []
        vt_result: dict[str, Any] = {}
        abuse_result: dict[str, Any] = {}
        otx_result: dict[str, Any] = {}

        # VirusTotal
        try:
            vt_result = self._check_virustotal(ip)
            if vt_result:
                sources.append("VirusTotal")
        except Exception as e:
            LOGGER.warning("VirusTotal API error for %s: %s", ip, e)

        # AbuseIPDB
        try:
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result:
                sources.append("AbuseIPDB")
        except Exception as e:
            LOGGER.warning("AbuseIPDB API error for %s: %s", ip, e)

        # OTX (always available, no key required)
        try:
            otx_result = self._check_otx(ip)
            if otx_result:
                sources.append("OTX")
        except Exception as e:
            LOGGER.warning("OTX API error for %s: %s", ip, e)

        # Calculate threat score
        threat_score = self._calculate_threat_score(vt_result, abuse_result, otx_result)
        is_malicious = threat_score >= MALICIOUS_THRESHOLD

        # Extract metadata
        country = (
            vt_result.get("country")
            or abuse_result.get("country")
            or ""
        )
        asn = vt_result.get("asn", "")
        reputation = self._determine_reputation(threat_score)
        
        # last_seen is only set if we have actual data from APIs
        # (currently none of the free APIs provide this reliably)
        last_seen = ""

        # Create result
        result = ThreatIntelResult(
            ip=ip,
            is_malicious=is_malicious,
            threat_score=threat_score,
            sources=sources,
            country=country,
            asn=asn,
            reputation=reputation,
            last_seen=last_seen,
            cached=False,
        )

        # Cache the result
        self._cache_result(result)

        return result
