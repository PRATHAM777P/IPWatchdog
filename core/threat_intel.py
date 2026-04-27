"""
core/threat_intel.py – Optional threat intelligence enrichment.

Integrations
------------
- AbuseIPDB  (requires ABUSEIPDB_API_KEY in env)
- ip-api.com (free GeoIP, no key required, rate-limited to 45 req/min)

All network calls are skipped gracefully when credentials are absent or
when a request fails.  The rest of the pipeline always continues.
"""

import logging
import os
import time
from typing import Dict, List, Optional
import urllib.request
import urllib.parse
import json

logger = logging.getLogger(__name__)

_ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
_GEOIP_ENDPOINT     = "http://ip-api.com/batch"   # free, no key


class ThreatIntel:
    """
    Enriches a list of IP addresses with threat intelligence data.

    Returns a dict keyed by IP with sub-dict:
        {
            "abuse_score": int,          # 0-100 (AbuseIPDB)
            "abuse_reports": int,
            "country": str,
            "isp": str,
            "is_proxy": bool,
            "is_tor": bool,
        }
    """

    def __init__(self):
        self._abuseipdb_key: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def bulk_lookup(self, ips: List[str]) -> Dict[str, dict]:
        """Look up a list of IPs; returns empty dict entries on failure."""
        result: Dict[str, dict] = {ip: {} for ip in ips}
        if not ips:
            return result

        # GeoIP (always attempt if GEOIP_ENABLED)
        geo = self._geoip_batch(ips)
        for ip, data in geo.items():
            result[ip].update(data)

        # AbuseIPDB (only if key configured)
        if self._abuseipdb_key:
            for ip in ips:
                abuse = self._abuseipdb_check(ip)
                result[ip].update(abuse)
                time.sleep(0.05)   # stay well within rate limits

        return result

    # ------------------------------------------------------------------
    # GeoIP
    # ------------------------------------------------------------------

    def _geoip_batch(self, ips: List[str]) -> Dict[str, dict]:
        """
        ip-api.com batch endpoint: up to 100 IPs per request.
        https://ip-api.com/docs/api:batch
        """
        out: Dict[str, dict] = {}
        try:
            payload = json.dumps([
                {"query": ip, "fields": "status,country,isp,proxy,hosting,query"}
                for ip in ips[:100]
            ]).encode("utf-8")

            req = urllib.request.Request(
                _GEOIP_ENDPOINT,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for entry in data:
                ip = entry.get("query", "")
                if not ip:
                    continue
                out[ip] = {
                    "country": entry.get("country", ""),
                    "isp": entry.get("isp", ""),
                    "is_proxy": bool(entry.get("proxy", False)),
                    "is_hosting": bool(entry.get("hosting", False)),
                }

        except Exception as exc:
            logger.debug("GeoIP lookup failed (non-fatal): %s", exc)

        return out

    # ------------------------------------------------------------------
    # AbuseIPDB
    # ------------------------------------------------------------------

    def _abuseipdb_check(self, ip: str) -> dict:
        """Single IP check against AbuseIPDB."""
        if not self._abuseipdb_key:
            return {}
        try:
            params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
            req = urllib.request.Request(
                f"{_ABUSEIPDB_ENDPOINT}?{params}",
                headers={
                    "Key": self._abuseipdb_key,
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            d = data.get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "abuse_reports": d.get("totalReports", 0),
                "is_tor": bool(d.get("isTor", False)),
            }
        except Exception as exc:
            logger.debug("AbuseIPDB lookup failed for %s (non-fatal): %s", ip, exc)
            return {}
