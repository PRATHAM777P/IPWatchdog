"""
IPWatchdog Configuration
All sensitive values are read from environment variables.
Copy .env.example → .env and fill in your values.
Never commit .env to version control.
"""

import os
import secrets


class AppConfig:
    # -----------------------------------------------------------------------
    # Flask core
    # -----------------------------------------------------------------------
    # SECRET_KEY is read from environment; a random key is generated as a
    # safe fallback for development only.  In production ALWAYS set this env var.
    SECRET_KEY: str = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # -----------------------------------------------------------------------
    # File upload limits
    # -----------------------------------------------------------------------
    MAX_CONTENT_LENGTH: int = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
    ALLOWED_EXTENSIONS: set = {"txt", "log"}

    # -----------------------------------------------------------------------
    # Real-time monitoring
    # -----------------------------------------------------------------------
    _raw_paths: str = os.environ.get("MONITOR_ALLOWED_PATHS", "")

    if _raw_paths:
        MONITOR_ALLOWED_PATHS: list = [p.strip() for p in _raw_paths.split(":") if p.strip()]
    else:
        # Default paths if .env is not set
        if os.name == "nt":  # Windows
            MONITOR_ALLOWED_PATHS: list = ["C:\\logs\\"]
        else:  # Linux / Mac
            MONITOR_ALLOWED_PATHS: list = ["/var/log/nginx/", "/var/log/"]

    # -----------------------------------------------------------------------
    # Threat Intelligence (all optional – features degrade gracefully if absent)
    # -----------------------------------------------------------------------
    # AbuseIPDB  https://www.abuseipdb.com/api
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    # VirusTotal https://www.virustotal.com/gui/my-apikey
    VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")

    # ip-api.com (free tier, no key required)
    GEOIP_ENABLED: bool = os.environ.get("GEOIP_ENABLED", "true").lower() == "true"

    # -----------------------------------------------------------------------
    # Detection tuning
    # -----------------------------------------------------------------------
    KMEANS_CLUSTERS: int = int(os.environ.get("KMEANS_CLUSTERS", "10"))
    ISOLATION_FOREST_CONTAMINATION: float = float(
        os.environ.get("ISOLATION_FOREST_CONTAMINATION", "0.05")
    )
    # Minimum requests from an IP before it is included in ML analysis
    MIN_REQUESTS_THRESHOLD: int = int(os.environ.get("MIN_REQUESTS_THRESHOLD", "3"))

    # -----------------------------------------------------------------------
    # Email alerting (optional)
    # -----------------------------------------------------------------------
    ALERT_EMAIL_ENABLED: bool = os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true"
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "localhost")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    ALERT_RECIPIENT: str = os.environ.get("ALERT_RECIPIENT", "")
