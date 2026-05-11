"""
GeoIP Utility - IP Geolocation Lookup
======================================
Provides IP to geographic location mapping using free ip-api.com service.
Includes in-memory caching to minimize API calls.

Usage:
    from src.utils.geoip import GeoIPService
    geoip = GeoIPService()
    location = geoip.lookup("8.8.8.8")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional
from threading import Lock

import requests

# ============================================================================
# CONSTANTS
# ============================================================================

LOGGER = logging.getLogger(__name__)

# Free GeoIP service (45 requests per minute)
GEOIP_API_URL = "http://ip-api.com/json/{}"
GEOIP_BATCH_URL = "http://ip-api.com/batch"

# Rate limiting: max requests per window
MAX_REQUESTS_PER_MINUTE = 45
RATE_LIMIT_WINDOW = 60  # seconds

# Cache TTL in seconds (24 hours)
CACHE_TTL = 86400

# Private IP ranges (no external lookup needed)
PRIVATE_IP_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("0.0.0.0", "0.255.255.255"),
]


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class GeoLocation:
    """Represents a geographic location for an IP address."""
    ip: str
    latitude: float
    longitude: float
    country: str
    country_code: str
    region: str
    region_name: str
    city: str
    zip_code: str
    timezone: str
    isp: str
    org: str
    asn: str
    is_private: bool
    threat_level: str  # "low", "medium", "high", "critical"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "region_name": self.region_name,
            "city": self.city,
            "zip_code": self.zip_code,
            "timezone": self.timezone,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "is_private": self.is_private,
            "threat_level": self.threat_level
        }


# ============================================================================
# GEOIP SERVICE
# ============================================================================

class GeoIPService:
    """
    GeoIP lookup service with caching and rate limiting.
    
    Features:
    - In-memory caching with configurable TTL
    - Rate limiting (45 req/min for ip-api.com)
    - Private IP detection
    - Batch lookup support
    """
    
    def __init__(self, cache_ttl: int = CACHE_TTL):
        """Initialize GeoIP service.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default 24 hours)
        """
        self._cache: dict[str, tuple[GeoLocation, float]] = {}
        self._lock = Lock()
        self._request_times: list[float] = []
        self._cache_ttl = cache_ttl
        
        LOGGER.info("GeoIPService initialized (cache TTL: %ds)", cache_ttl)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False
            
            # 10.x.x.x
            if octets[0] == 10:
                return True
            
            # 172.16.x.x - 172.31.x.x
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            
            # 192.168.x.x
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # 127.x.x.x (localhost)
            if octets[0] == 127:
                return True
            
            # 0.x.x.x (unspecified)
            if octets[0] == 0:
                return True
            
            # 169.254.x.x (link-local)
            if octets[0] == 169 and octets[1] == 254:
                return True
            
            return False
            
        except (ValueError, IndexError):
            return False
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits.
        
        Returns:
            True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        with self._lock:
            # Remove old requests outside the window
            self._request_times = [
                t for t in self._request_times
                if current_time - t < RATE_LIMIT_WINDOW
            ]
            
            # Check if we can make another request
            if len(self._request_times) >= MAX_REQUESTS_PER_MINUTE:
                LOGGER.warning("Rate limit reached (%d/%d)", 
                             len(self._request_times), MAX_REQUESTS_PER_MINUTE)
                return False
            
            # Record this request
            self._request_times.append(current_time)
            return True
    
    def _fetch_from_api(self, ip: str) -> Optional[dict]:
        """Fetch location from ip-api.com.
        
        Returns:
            API response dict or None on error
        """
        if not self._check_rate_limit():
            return None
        
        try:
            response = requests.get(
                GEOIP_API_URL.format(ip),
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
                else:
                    LOGGER.warning("API returned failure for %s: %s", 
                                 ip, data.get("message", "unknown"))
            else:
                LOGGER.error("API HTTP error %d for %s", 
                           response.status_code, ip)
                
        except requests.RequestException as e:
            LOGGER.error("API request failed for %s: %s", ip, e)
        
        return None
    
    def _determine_threat_level(self, country_code: str) -> str:
        """Determine threat level based on country.
        
        This is a simplified heuristic - in production you'd use
        actual threat intelligence data.
        """
        # High threat countries (common sources of automated attacks)
        high_threat = {"CN", "RU", "KP", "IR", "UA", "BY", "PK", "VN", "IN", "BR"}
        
        # Medium threat
        medium_threat = {"TR", "PL", "CZ", "RO", "ID", "TH", "MY", "PH", "EG", "ZA"}
        
        code = country_code.upper()
        
        if code in high_threat:
            return "high"
        elif code in medium_threat:
            return "medium"
        else:
            return "low"
    
    def lookup(self, ip: str) -> Optional[GeoLocation]:
        """Look up geographic location for an IP address.
        
        Args:
            ip: IP address to look up
            
        Returns:
            GeoLocation object or None if lookup failed
        """
        # Check private IP first
        if self._is_private_ip(ip):
            return GeoLocation(
                ip=ip,
                latitude=0.0,
                longitude=0.0,
                country="Private",
                country_code="PR",
                region="",
                region_name="Private Network",
                city="Internal",
                zip_code="",
                timezone="",
                isp="Local Network",
                org="Private Range",
                asn="",
                is_private=True,
                threat_level="low"
            )
        
        # Check cache
        current_time = time.time()
        with self._lock:
            if ip in self._cache:
                cached_loc, cached_time = self._cache[ip]
                if current_time - cached_time < self._cache_ttl:
                    LOGGER.debug("Cache hit for %s", ip)
                    return cached_loc
                else:
                    # Expired
                    del self._cache[ip]
        
        # Fetch from API
        LOGGER.info("Looking up %s", ip)
        api_data = self._fetch_from_api(ip)
        
        if api_data is None:
            return None
        
        # Create GeoLocation
        location = GeoLocation(
            ip=ip,
            latitude=api_data.get("lat", 0.0),
            longitude=api_data.get("lon", 0.0),
            country=api_data.get("country", "Unknown"),
            country_code=api_data.get("countryCode", "XX"),
            region=api_data.get("region", ""),
            region_name=api_data.get("regionName", ""),
            city=api_data.get("city", ""),
            zip_code=api_data.get("zip", ""),
            timezone=api_data.get("timezone", ""),
            isp=api_data.get("isp", ""),
            org=api_data.get("org", ""),
            asn=api_data.get("as", ""),
            is_private=False,
            threat_level=self._determine_threat_level(api_data.get("countryCode", ""))
        )
        
        # Cache result
        with self._lock:
            self._cache[ip] = (location, current_time)
        
        return location
    
    def lookup_batch(self, ips: list[str]) -> dict[str, Optional[GeoLocation]]:
        """Look up multiple IPs at once (more efficient).
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP to GeoLocation (or None if failed)
        """
        results = {}
        ips_to_fetch = []
        
        # Check cache and private IPs first
        for ip in ips:
            if self._is_private_ip(ip):
                results[ip] = self.lookup(ip)  # Will return cached or fresh private
            else:
                # Check cache
                current_time = time.time()
                with self._lock:
                    if ip in self._cache:
                        cached_loc, cached_time = self._cache[ip]
                        if current_time - cached_time < self._cache_ttl:
                            results[ip] = cached_loc
                            continue
                
                ips_to_fetch.append(ip)
        
        if not ips_to_fetch:
            return results
        
        # Batch API call (limited to 100 per request)
        batch_size = 100
        for i in range(0, len(ips_to_fetch), batch_size):
            batch = ips_to_fetch[i:i + batch_size]
            
            if not self._check_rate_limit():
                # Rate limited, fall back to individual lookups
                LOGGER.warning("Batch rate limited, falling back to individual lookups")
                for ip in batch:
                    results[ip] = self.lookup(ip)
                continue
            
            try:
                response = requests.post(
                    GEOIP_BATCH_URL,
                    json=[{"query": ip} for ip in batch],
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for ip, api_data in zip(batch, data):
                        if api_data.get("status") == "success":
                            location = GeoLocation(
                                ip=ip,
                                latitude=api_data.get("lat", 0.0),
                                longitude=api_data.get("lon", 0.0),
                                country=api_data.get("country", "Unknown"),
                                country_code=api_data.get("countryCode", "XX"),
                                region=api_data.get("region", ""),
                                region_name=api_data.get("regionName", ""),
                                city=api_data.get("city", ""),
                                zip_code=api_data.get("zip", ""),
                                timezone=api_data.get("timezone", ""),
                                isp=api_data.get("isp", ""),
                                org=api_data.get("org", ""),
                                asn=api_data.get("as", ""),
                                is_private=False,
                                threat_level=self._determine_threat_level(
                                    api_data.get("countryCode", "")
                                )
                            )
                            
                            # Cache
                            with self._lock:
                                self._cache[ip] = (location, time.time())
                            
                            results[ip] = location
                        else:
                            LOGGER.warning("Batch lookup failed for %s: %s",
                                         ip, api_data.get("message", "unknown"))
                            results[ip] = None
                            
            except requests.RequestException as e:
                LOGGER.error("Batch API request failed: %s", e)
                # Fall back to individual lookups
                for ip in batch:
                    results[ip] = self.lookup(ip)
        
        return results
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            return {
                "cached_ips": len(self._cache),
                "requests_this_minute": len(self._request_times)
            }
    
    def clear_cache(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
        LOGGER.info("GeoIP cache cleared")


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

# Lazy-loaded singleton
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service() -> GeoIPService:
    """Get or create the singleton GeoIP service."""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def lookup_ip(ip: str) -> Optional[GeoLocation]:
    """Quick lookup for a single IP.
    
    Args:
        ip: IP address
        
    Returns:
        GeoLocation or None
    """
    return get_geoip_service().lookup(ip)
