<img width="1000" height="500" alt="Image" src="https://github.com/user-attachments/assets/10ff5c4a-2659-49b6-9207-4c960364a8b4" />

<div align="center">
                    # 🛡️ IPWatchdog

**ML-Powered Suspicious IP Detection & Real-Time Log Monitoring**

*Upload a log → ML detects anomalies → See exactly why each IP was flagged*

</div>

---

<br/>

<!-- Core Badges Row 1 -->
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-D22128?style=for-the-badge&logo=apache&logoColor=white)](LICENSE)

<!-- Core Badges Row 2 -->
[![CodeQL](https://img.shields.io/github/actions/workflow/status/PRATHAM777P/IPWatchdog/codeql.yml?style=for-the-badge&logo=github-actions&logoColor=white&label=CodeQL)](https://github.com/PRATHAM777P/IPWatchdog/actions)
[![Issues](https://img.shields.io/github/issues/PRATHAM777P/IPWatchdog?style=for-the-badge&logo=github&logoColor=white&color=red)](https://github.com/PRATHAM777P/IPWatchdog/issues)
[![Stars](https://img.shields.io/github/stars/PRATHAM777P/IPWatchdog?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/PRATHAM777P/IPWatchdog/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-00d4ff?style=for-the-badge&logo=git&logoColor=white)](https://github.com/PRATHAM777P/IPWatchdog/pulls)

<br/>

---

<div align="center">

## 💡 What is IPWatchdog?

</div>

> **IPWatchdog** is an open-source security dashboard for web administrators and DevOps engineers. It ingests access logs from any web server, runs an **ensemble ML model** (Isolation Forest + KMeans) over per-IP behavioural features, and surfaces the most suspicious IP addresses — with **plain-English explanations** of *why* they were flagged.
>
> Unlike simple threshold-based tools, IPWatchdog learns the shape of **normal traffic for your server** and flags statistical outliers — catching low-and-slow attacks that trip no single rule.

---

## 📑 Table of Contents

<div align="center">

| | | |
|:---:|:---:|:---:|
| [🚀 Quick Start](#-quick-start) | [⚙️ Configuration](#️-configuration) | [📄 Log Formats](#-log-format-support) |
| [🧠 Detection Engine](#-detection-engine) | [🌐 Threat Intel](#-threat-intelligence) | [🛡️ Automated Actions](#️-automated-actions) |
| [📡 Real-Time Monitor](#-real-time-monitoring) | [🏗️ Architecture](#️-architecture--workflow) | [🤝 Contributing](#-contributing) |

</div>

---

## ✨ Features
<table>
<tr>
<td width="50%">

### 🧠 Smarter Detection
- Isolation Forest + KMeans ensemble model
- 6-dimensional feature vectors per IP
- Heuristic z-score fallback when sklearn is absent
- Statistical outlier detection (not just thresholds)

### 📡 Real-Time Monitoring
- Server-Sent Events (SSE) tail any local log file
- Per-line anomaly scoring as logs arrive
- Live colour-coded dashboard table
- Heartbeat keeps SSE connections alive

### 🎨 Better Dashboard UX
- Bootstrap 5 dark/light theme toggle
- Drag-and-drop log upload with progress bar
- Interactive Chart.js visualisations
- Result filtering & search

</td>
<td width="50%">

### 🌐 Threat Intelligence
- GeoIP lookup via ip-api.com *(free, no key)*
- AbuseIPDB confidence score & report count
- Tor exit node & proxy detection

### ⚙️ Automated Actions
- One-click `.htaccess` / Nginx ACL / iptables block rules
- CSV export of flagged IPs
- Optional SMTP email alerts on detection

### 🔍 Explainability
- Per-IP plain-English reason list
- Error rate, burst score, method entropy
- Path diversity & anomaly severity labels

</td>
</tr>
</table>

---

## 🏗️ Architecture & Workflow

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
│        │          │  "High error rate (52%) – possible scan"  │    │
│        │          │  "Traffic burst – 80% in a single hour"   │    │
│        │          └─────────────────────────────────┬─────────┘    │
│        │                                            │               │
│        │          ┌─────────────────────────────────▼─────────┐    │
│        │          │          core/threat_intel                │    │
│        │          │   GeoIP country/ISP • AbuseIPDB score     │    │
│        │          │   Tor / proxy detection                   │    │
│        │          └─────────────────────────────────┬─────────┘    │
│        └──────────────────┐                         │               │
│                           ▼                         ▼               │
│                    ┌──────────────────────────────────────────┐    │
│                    │             Dashboard (Flask)             │    │
│                    │  Stats • Table • Charts • Block Rules     │    │
│                    │  CSV Export • Live Monitor (SSE)          │    │
│                    └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 🔄 Request Flow (Upload Analysis)

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

## 🚀 Quick Start

### Prerequisites

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![pip](https://img.shields.io/badge/pip-latest-3775A9?style=flat-square&logo=pypi&logoColor=white)
![Git](https://img.shields.io/badge/Git-required-F05032?style=flat-square&logo=git&logoColor=white)

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

> 🌐 Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### Sample Log Format

```log
192.168.x.x - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
10.x.x.x  - - [10/Oct/2023:13:55:37 -0700] "POST /login HTTP/1.1" 401 512
```

---

## ⚙️ Configuration

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

> 🔒 **Security:** Never commit your `.env` file. It is excluded by `.gitignore`.

---

## 📄 Log Format Support

| Format | Auto-detected | Example |
|---|---|---|
| Apache Common | ✅ | `1.2.3.4 - - [date] "GET / HTTP/1.1" 200 512` |
| Apache Combined | ✅ | Same + user-agent field |
| Nginx default | ✅ | Same structure as Apache Combined |
| JSON (one obj/line) | ✅ | `{"ip":"1.2.3.4","time":"...","method":"GET",...}` |

> Custom formats can be added in `core/parser.py` by extending the `_parse_*` methods.

---

## 🧠 Detection Engine

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

- **IsolationForest** — continuous score per IP; lower = more anomalous
- **KMeans** — groups IPs into behavioural clusters for pattern overview
- **Fallback** — z-score heuristic used automatically if scikit-learn is absent

---

## 🌐 Threat Intelligence

| Source | Cost | Key Required | Data Returned |
|---|---|---|---|
| [ip-api.com](https://ip-api.com) | Free (45 req/min) | ❌ No | Country, ISP, proxy/hosting flag |
| [AbuseIPDB](https://www.abuseipdb.com/api) | Free tier available | ✅ `ABUSEIPDB_API_KEY` | Confidence score, report count, Tor flag |

> All lookups fail silently — the pipeline always completes regardless of network availability.

---

## 🛡️ Automated Actions

From the **Block Rules** tab, IPWatchdog generates ready-to-use firewall rules for all flagged IPs:

```bash
# Apache .htaccess
Deny from 192.168.1.100

# Nginx ACL (nginx.conf)
geo $blocked_ip { default 0; 192.168.1.100 1; }

# iptables shell script
iptables -I INPUT -s 192.168.1.100 -j DROP
```

Rules can be **copied or downloaded** directly from the dashboard. Email alerting is available via SMTP — configure `SMTP_*` and `ALERT_RECIPIENT` in `.env`.

---

## 📡 Real-Time Monitoring

<div align="center">
<img src="https://raw.githubusercontent.com/PRATHAM777P/IPWatchdog/main/assets/monitor.gif" alt="Live Monitor GIF" width="70%"/>

1. Set `MONITOR_ALLOWED_PATHS` in `.env` to the directories you want to allow tailing
2. Go to the **Live Monitor** tab and enter the full path to your log file
3. New entries appear in real time with colour-coded anomaly scores

> 🔒 For security, only paths explicitly listed in `MONITOR_ALLOWED_PATHS` can be tailed.

---

## 🗂️ Project Structure

```
IPWatchdog/
├── 📄 app.py                   ← Flask app, routes, SSE endpoint
├── ⚙️  config.py               ← All config from environment variables
├── 🧩 core/
│   ├── __init__.py
│   ├── parser.py               ← Multi-format log parser
│   ├── detector.py             ← IsolationForest + KMeans ensemble
│   ├── explainer.py            ← Human-readable flag reasons
│   ├── threat_intel.py         ← GeoIP + AbuseIPDB integration
│   └── actions.py              ← Block rule generators + email alerts
├── 🎨 templates/
│   └── dashboard.html          ← Bootstrap 5 SPA dashboard
├── 🖼️  assets/                 ← GIFs and images for README
├── 📦 requirements.txt
├── 🔒 .env.example             ← Config template (safe to commit)
├── 🚫 .gitignore               ← Excludes .env, *.log, result.txt, *.csv
├── 📖 README.md
├── 🛡️  SECURITY.md
└── 🤖 .github/
    └── workflows/
        └── codeql.yml          ← Automated CodeQL security scanning
```

---

## 🤝 Contributing

<div align="center">

**Contributions are welcome!** 🎉

</div>

1. **Fork** the repository and create a feature branch
   ```bash
   git checkout -b feat/your-awesome-feature
   ```
2. **Make your changes** and add tests where applicable
3. **Ensure** the code passes CodeQL checks *(runs automatically on push)*
4. **Open a pull request** with a clear description of your changes

Please read [SECURITY.md](SECURITY.md) before submitting code that touches the detection engine or any network-facing functionality.

---

## 🔐 Security

Key hardening points:

- 🔑 All secrets loaded from environment variables — never hardcoded
- 📁 File uploads validated by extension and size before processing
- 🚧 Live monitor only allows explicitly whitelisted paths
- 🧱 Security headers (CSP, X-Frame-Options, etc.) applied to every response
- 🤖 CodeQL scans run on every push and pull request

Please see [SECURITY.md](SECURITY.md) for our full vulnerability disclosure policy.

---

<div align="center">

## 📊 Stats

![Repo Size](https://img.shields.io/github/repo-size/PRATHAM777P/IPWatchdog?style=for-the-badge&color=00d4ff)
![Last Commit](https://img.shields.io/github/last-commit/PRATHAM777P/IPWatchdog?style=for-the-badge&color=00d4ff)
![Contributors](https://img.shields.io/github/contributors/PRATHAM777P/IPWatchdog?style=for-the-badge&color=00d4ff)

---

### 🌟 Star this repo if IPWatchdog helps secure your server!

[![Star History Chart](https://api.star-history.com/svg?repos=PRATHAM777P/IPWatchdog&type=Date)](https://star-history.com/#PRATHAM777P/IPWatchdog&Date)

---

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f3460,50:1a1f2e,100:0d1117&height=120&section=footer&animation=fadeIn" width="100%"/>

**Licensed under the [Apache 2.0 License](LICENSE)**

*Built with ❤️ by [PRATHAM777P](https://github.com/PRATHAM777P)*

</div>
