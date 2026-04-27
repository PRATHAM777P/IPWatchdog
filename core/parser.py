"""
core/parser.py – Multi-format log parser.

Supported formats
-----------------
  auto        Auto-detect from first non-empty line
  apache      Apache Common / Combined Log Format
  nginx       Nginx default access log
  json        One JSON object per line (keys: ip, time/date, method, path, status)
  combined    Apache Combined (same regex as apache; included for clarity)
"""

import re
import json
import logging
from datetime import datetime
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Apache / Nginx combined:  IP - - [date] "METHOD /path HTTP/x.x" status bytes
_APACHE_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s'       # client IP
    r'\S+\s\S+\s'                                  # ident / auth (ignored)
    r'\[(?P<date>[^\]]+)\]\s'                      # [date]
    r'"(?P<method>[A-Z]{2,10})\s'                  # "METHOD
    r'(?P<path>\S+)\s'                             # /path
    r'HTTP/[0-9.]+"\s'                             # HTTP/x.x"
    r'(?P<status>\d{3})\s'                         # status code
    r'(?P<bytes>\d+|-)'                            # bytes
)

# Nginx default log format (same as Combined, but may omit trailing fields)
_NGINX_RE = _APACHE_RE  # identical regex; kept separate for readability

# IPv6 variant (simplified)
_IPV6_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:]{2,39})\s'
    r'\S+\s\S+\s'
    r'\[(?P<date>[^\]]+)\]\s'
    r'"(?P<method>[A-Z]{2,10})\s'
    r'(?P<path>\S+)\s'
    r'HTTP/[0-9.]+"\s'
    r'(?P<status>\d{3})\s'
    r'(?P<bytes>\d+|-)'
)


def _parse_apache_date(raw: str) -> Optional[datetime]:
    """Parse Apache/Nginx date string: 10/Oct/2023:13:55:36 -0700"""
    try:
        return datetime.strptime(raw[:20], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _detect_format(first_line: str) -> str:
    first_line = first_line.strip()
    if not first_line:
        return "unknown"
    if first_line.startswith("{"):
        return "json"
    if _APACHE_RE.match(first_line) or _IPV6_RE.match(first_line):
        return "apache"
    return "unknown"


class LogParser:
    """
    Parse a log file into a normalised DataFrame with columns:
      IP, date, hour, method, path, status, bytes, user_agent (when available)
    """

    SUPPORTED_FORMATS = {"auto", "apache", "nginx", "combined", "json"}

    def __init__(self, log_format: str = "auto"):
        fmt = log_format.lower()
        if fmt not in self.SUPPORTED_FORMATS:
            logger.warning("Unknown format '%s', falling back to auto-detect.", log_format)
            fmt = "auto"
        self.log_format = fmt
        self.detected_format = fmt

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, filepath: str) -> Optional[pd.DataFrame]:
        """Parse an entire file. Returns a DataFrame or None on failure."""
        records = []
        skipped = 0

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                fmt = self.log_format

                # Auto-detect from first non-empty line
                if fmt == "auto":
                    for line in fh:
                        if line.strip():
                            fmt = _detect_format(line)
                            self.detected_format = fmt
                            fh.seek(0)
                            break

                for line in fh:
                    rec = self._parse_line_internal(line, fmt)
                    if rec:
                        records.append(rec)
                    else:
                        skipped += 1

        except OSError as exc:
            logger.error("Cannot open log file: %s", exc)
            return None

        if not records:
            logger.warning("No valid records parsed (skipped=%d).", skipped)
            return None

        logger.info("Parsed %d records (%d skipped).", len(records), skipped)
        df = pd.DataFrame(records)
        return df

    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single line (for real-time monitoring)."""
        fmt = self.log_format if self.log_format != "auto" else "apache"
        return self._parse_line_internal(line, fmt)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_line_internal(self, line: str, fmt: str) -> Optional[dict]:
        line = line.strip()
        if not line:
            return None
        if fmt in ("apache", "nginx", "combined"):
            return self._parse_apache_line(line)
        if fmt == "json":
            return self._parse_json_line(line)
        # Fallback: try apache
        return self._parse_apache_line(line)

    @staticmethod
    def _parse_apache_line(line: str) -> Optional[dict]:
        m = _APACHE_RE.match(line) or _IPV6_RE.match(line)
        if not m:
            return None
        dt = _parse_apache_date(m.group("date"))
        return {
            "IP": m.group("ip"),
            "date": m.group("date"),
            "hour": dt.hour if dt else -1,
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "bytes": int(m.group("bytes")) if m.group("bytes") != "-" else 0,
        }

    @staticmethod
    def _parse_json_line(line: str) -> Optional[dict]:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

        # Tolerate various key names
        ip = obj.get("ip") or obj.get("remote_addr") or obj.get("client_ip", "")
        date = obj.get("time") or obj.get("date") or obj.get("timestamp", "")
        method = obj.get("method") or obj.get("request_method", "")
        path = obj.get("path") or obj.get("uri") or obj.get("request_uri", "")
        status = int(obj.get("status") or obj.get("status_code") or 0)
        size = int(obj.get("bytes") or obj.get("body_bytes_sent") or 0)

        if not ip:
            return None
        return {
            "IP": ip,
            "date": str(date),
            "hour": -1,
            "method": method.upper() if method else "",
            "path": path,
            "status": status,
            "bytes": size,
        }
