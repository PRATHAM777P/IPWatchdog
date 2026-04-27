# 🛡️ IPWatchdog

<div align="center">

**ML-Powered Suspicious IP Detection & Real-Time Log Monitoring**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-lightgrey.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange.svg)](https://scikit-learn.org/)
[![CodeQL](https://github.com/your-org/IPWatchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/your-org/IPWatchdog/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*Upload a log → ML detects anomalies → See exactly why each IP was flagged*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture & Workflow](#architecture--workflow)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Log Format Support](#log-format-support)
- [Detection Engine](#detection-engine)
- [Threat Intelligence](#threat-intelligence)
- [Automated Actions](#automated-actions)
- [Real-Time Monitoring](#real-time-monitoring)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Overview

**IPWatchdog** is an open-source security dashboard for web administrators and DevOps engineers. It ingests access logs from any web server, runs an ensemble ML model (Isolation Forest + KMeans) over per-IP behavioural features, and surfaces the most suspicious IP addresses — with plain-English explanations of *why* they were flagged.

Unlike simple threshold-based tools, IPWatchdog learns the shape of normal traffic for *your* server and flags statistical outliers, catching low-and-slow attacks that trip no single rule.

---

## Features

| Category | Capability |
|---|---|
| **🧠 Smarter Detection** | Isolation Forest + KMeans ensemble; 6-dimensional feature vectors per IP; heuristic fallback when sklearn is absent |
| **📡 Real-Time Monitoring** | Server-Sent Events (SSE) tail any local log file; per-line anomaly scoring; live dashboard table |
| **🎨 Better Dashboard UX** | Bootstrap 5 dark/light theme; drag-and-drop upload; progress bar; interactive Chart.js visualisations; result filtering |
| **🌐 Threat Intelligence** | GeoIP (ip-api.com, free); AbuseIPDB confidence score; Tor/proxy detection; no key required for geo |
| **⚙️ Automated Actions** | One-click `.htaccess` / Nginx ACL / iptables block-rule generation; CSV export; optional SMTP email alerts |
| **📄 Log Format Flexibility** | Auto-detects Apache, Nginx, Combined, and JSON log formats; custom-format ready |
| **🚀 Performance** | Chunked per-IP aggregation; background threading; SSE heartbeat keeps connections alive |
| **🔍 Explainability** | Per-IP reason list: error rate, burst score, method entropy, path diversity, anomaly severity label |

---

## Architecture & Workflow

```
┌──────────────────────────────────────────────────────────────────────┐
│                        IPWatchdog Pipeline                           │
│                                                                      │
│  ┌────────────┐    ┌────────────────┐    ┌───────────────────────┐  │
│  │ Log Upload │───▶│  core/parser   │───▶│   core/detector       │  │
│  │ (.log/.txt)│    │ Auto-detect:   │    │  ┌─────────────────┐  │  │
│  └────────────┘    │ • Apache       │    │  │ Feature Eng.    │  │  │
│                    │ • Nginx        │    │  │ req_count       │  │  │
│  ┌────────────┐    │ • Combined     │    │  │ error_rate      │  │  │
│  │ Whitelist/ │    │ • JSON         │    │  │ method_entropy  │  │  │
│  │ Blacklist  │    └────────────────┘    │  │ path_diversity  │  │  │
│  └─────┬──────┘                         │  │ burst_score     │  │  │
│        │                                │  └────────┬────────┘  │  │
│        │                                │           │            │  │
│        │                                │  ┌────────▼────────┐  │  │
│        │                                │  │ IsolationForest │  │  │
│        │                                │  │ +  KMeans       │  │  │
│        │                                │  │ anomaly_score   │  │  │
│        │                                │  └────────┬────────┘  │  │
│        │                                └───────────┼───────────┘  │
│        │                                            │               │
│        │          ┌─────────────────────────────────▼─────────┐    │
│        │          │           core/explainer                  │    │
│        │          │   "High error rate (52%) – possible scan" │    │
│        │          │   "Traffic burst – 80% in a single hour"  │    │
│        │          └─────────────────────────────────┬─────────┘    │
│        │                                            │               │
│        │          ┌─────────────────────────────────▼─────────┐    │
│        │          │          core/threat_intel                │    │
│        │          │   GeoIP country/ISP • AbuseIPDB score     │    │
│        │          │   Tor / proxy detection                   │    │
│        │          └─────────────────────────────────┬─────────┘    │
│        │                                            │               │
│        └──────────────────┐                        │               │
│                           ▼                        ▼               │
│                    ┌──────────────────────────────────────────┐    │
│                    │             Dashboard (Flask)             │    │
│                    │  Stats • Table • Charts • Block Rules     │    │
│                    │  CSV Export • Live Monitor (SSE)          │    │
│                    └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### Request Flow (Upload Analysis)

```
Browser ──POST /analyze──▶ app.py
                              │
                    ┌─────────▼──────────┐
                    │  1. Validate file   │  (type, size, secure_filename)
                    │  2. LogParser       │  (auto-detect format)
                    │  3. IPDetector      │  (feature eng + ML)
                    │  4. Explainer       │  (why-flagged reasons)
                    │  5. ThreatIntel     │  (GeoIP + AbuseIPDB)
                    │  6. ActionEngine    │  (.htaccess rules)
                    └─────────┬──────────┘
                              │
                    ◀─────────┘ JSON response
                    (summary, results[], top_ips[], htaccess_rules)
```

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/PRATHAM777P/IPWatchdog.git
cd IPWatchdog

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env and set at minimum SECRET_KEY

# 5. Start the app
python app.py
```

Open your browser at **http://127.0.0.1:5000**

### Sample Log Format

```
192.168.1.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
10.0.0.5 - - [10/Oct/2023:13:55:37 -0700] "POST /login HTTP/1.1" 401 512
```

---

## Configuration

All configuration is done via environment variables. Copy `.env.example` → `.env`:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(random)* | **Required in production.** Flask session key |
| `FLASK_DEBUG` | `false` | Set `true` for dev only |
| `FLASK_HOST` | `127.0.0.1` | Bind address |
| `FLASK_PORT` | `5000` | Listen port |
| `MAX_UPLOAD_MB` | `50` | Maximum log file size |
| `MONITOR_ALLOWED_PATHS` | *(empty)* | Colon-separated paths the live monitor may tail |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key (optional) |
| `GEOIP_ENABLED` | `true` | Enable free ip-api.com GeoIP lookups |
| `KMEANS_CLUSTERS` | `10` | Number of KMeans clusters |
| `ISOLATION_FOREST_CONTAMINATION` | `0.05` | Expected fraction of anomalies (0–0.5) |
| `ALERT_EMAIL_ENABLED` | `false` | Enable SMTP email alerts |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASSWORD` | *(empty)* | SMTP credentials |
| `ALERT_RECIPIENT` | *(empty)* | Alert email address |

> **Security:** Never commit your `.env` file. It is excluded by `.gitignore`.

---

## Log Format Support

| Format | Auto-detected | Example |
|---|---|---|
| Apache Common | ✅ | `1.2.3.4 - - [date] "GET / HTTP/1.1" 200 512` |
| Apache Combined | ✅ | Same + user-agent field |
| Nginx default | ✅ | Same structure as Apache Combined |
| JSON (one obj/line) | ✅ | `{"ip":"1.2.3.4","time":"...","method":"GET",...}` |

Custom formats can be added in `core/parser.py` by extending the `_parse_*` methods.

---

## Detection Engine

### Feature Vectors (per IP)

| Feature | Description |
|---|---|
| `request_count` | Total requests from this IP |
| `error_rate` | Fraction of 4xx / 5xx responses |
| `method_entropy` | Shannon entropy of HTTP method distribution |
| `path_diversity` | Unique paths / total requests |
| `avg_bytes` | Mean response size |
| `burst_score` | Peak-hour requests / total requests |

### Model Pipeline

```
Raw features ──▶ StandardScaler ──▶ IsolationForest ──▶ anomaly_score ∈ [-1, +1]
                                 ──▶ KMeans          ──▶ cluster label
```

- **IsolationForest** produces a continuous score per IP; the lower the score, the more anomalous.
- **KMeans** groups IPs into behavioural clusters for pattern overview.
- If scikit-learn is not installed, a z-score heuristic fallback is used automatically.

---

## Threat Intelligence

| Source | Cost | Key Required | Data Returned |
|---|---|---|---|
| [ip-api.com](https://ip-api.com) | Free (45 req/min) | No | Country, ISP, proxy/hosting flag |
| [AbuseIPDB](https://www.abuseipdb.com/api) | Free tier available | Yes (`ABUSEIPDB_API_KEY`) | Confidence score, report count, Tor flag |

All lookups fail silently — the pipeline always completes regardless of network availability.

---

## Automated Actions

From the **Block Rules** tab, IPWatchdog generates ready-to-use firewall rules for all flagged IPs:

- **Apache `.htaccess`** – `Deny from <ip>` rules
- **Nginx ACL** – `geo $blocked_ip` block for `nginx.conf`
- **iptables** – Shell script with `iptables -I INPUT -s <ip> -j DROP` rules

Rules can be copied or downloaded directly from the dashboard.

**Email alerting** is available via SMTP — configure `SMTP_*` and `ALERT_RECIPIENT` in `.env`.

---

## Real-Time Monitoring

The live monitor tails a local log file and scores each new line as it arrives:

1. Set `MONITOR_ALLOWED_PATHS` in `.env` to the directories you want to allow tailing.
2. Go to the **Live Monitor** tab and enter the full path to your log file.
3. New entries appear in real time with colour-coded anomaly scores.

> For security, only paths explicitly listed in `MONITOR_ALLOWED_PATHS` can be tailed.

---

## Project Structure

```
IPWatchdog/
├── app.py                   ← Flask app, routes, SSE endpoint
├── config.py                ← All config from environment variables
├── core/
│   ├── __init__.py
│   ├── parser.py            ← Multi-format log parser
│   ├── detector.py          ← IsolationForest + KMeans ensemble
│   ├── explainer.py         ← Human-readable flag reasons
│   ├── threat_intel.py      ← GeoIP + AbuseIPDB integration
│   └── actions.py           ← Block rule generators + email alerts
├── templates/
│   └── dashboard.html       ← Bootstrap 5 SPA dashboard
├── requirements.txt
├── .env.example             ← Config template (safe to commit)
├── .gitignore               ← Excludes .env, *.log, result.txt, *.csv
├── README.md
├── SECURITY.md
└── .github/
    └── workflows/
        └── codeql.yml       ← Automated CodeQL security scanning
```

---

## Contributing

Contributions are welcome! To get started:

1. Fork the repository and create a feature branch: `git checkout -b feat/your-feature`
2. Make your changes and add tests where applicable
3. Ensure the code passes CodeQL checks (runs automatically on push)
4. Open a pull request with a clear description of your changes

Please read [SECURITY.md](SECURITY.md) before submitting code that touches the detection engine or any network-facing functionality.

---

## Security

Please see [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy and security hardening notes.

Key points:
- All secrets are loaded from environment variables — never hardcoded
- File uploads are validated by extension and size before processing
- The live monitor only allows paths explicitly whitelisted by the operator
- Security headers (CSP, X-Frame-Options, etc.) are applied to every response
- CodeQL scans run on every push and pull request

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute.
