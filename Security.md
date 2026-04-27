# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Active security fixes |
| Older tagged releases | ❌ Please upgrade |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately by emailing:

> **security@your-org.example** *(replace with your actual contact)*

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if safe to share)
- Any suggested mitigations you are aware of

You will receive an acknowledgement within **48 hours** and a full response within **7 days**.

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure): we ask that you give us a reasonable time to patch the issue before public disclosure.

---

## Security Design

### Secrets Management

- **No hardcoded credentials.** The Flask `SECRET_KEY`, all API keys, and SMTP credentials are read exclusively from environment variables.
- `.env` is listed in `.gitignore` and will never be committed to version control.
- The repository provides `.env.example` as a safe, keyless template.
- A cryptographically random fallback `SECRET_KEY` is generated at startup if the variable is unset — this is safe for development only; always set it explicitly in production.

### File Upload Security

- Uploaded files are validated by extension whitelist (`{txt, log}`) *and* by content size (default 50 MB, configurable via `MAX_UPLOAD_MB`).
- `werkzeug.utils.secure_filename` is applied to every uploaded filename before it is written to a temporary directory.
- The temporary file is **always** deleted in a `finally` block after processing, regardless of success or failure.
- Uploaded log data is never persisted to disk beyond the analysis run.

### Subprocess Execution

- **No subprocess calls.** The original project used `subprocess.run(['python', ...])` to shell out to separate scripts. This has been completely removed. All processing runs in-process as Python function calls, eliminating shell-injection surface area.

### Live Monitor Path Restriction

- The `/monitor` endpoint only allows tailing files whose path starts with one of the entries in `MONITOR_ALLOWED_PATHS` (operator-configured, empty by default = feature disabled).
- Requests to tail paths outside this whitelist receive a `403 Forbidden` response.

### HTTP Security Headers

Every response includes:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | Restricts scripts/styles to self + cdn.jsdelivr.net |

### Threat Intelligence Network Calls

- All outbound lookups (GeoIP, AbuseIPDB) are wrapped in `try/except` and fail silently.
- AbuseIPDB lookups are only made when `ABUSEIPDB_API_KEY` is set.
- GeoIP lookups use ip-api.com — no IP address is stored server-side; the lookup is purely read-only.
- Requests time out after 5 seconds to prevent analysis pipeline stalls.

### Production Hardening Checklist

Before deploying IPWatchdog to a production server:

- [ ] Set a strong, random `SECRET_KEY` environment variable
- [ ] Set `FLASK_DEBUG=false`
- [ ] Bind to `127.0.0.1` (or a private interface) and use a reverse proxy (Nginx/Caddy) for TLS termination
- [ ] Set `MONITOR_ALLOWED_PATHS` to only the directories you explicitly want to allow
- [ ] Consider adding rate limiting (e.g., Flask-Limiter) to the `/analyze` endpoint
- [ ] Run behind HTTPS — log files may contain IP addresses that are personal data under GDPR/CCPA
- [ ] Review and tighten the Content-Security-Policy header for your deployment
- [ ] Enable CodeQL scanning on your fork (already configured in `.github/workflows/codeql.yml`)

### Data Privacy

IPWatchdog processes web server access logs which may contain:
- IP addresses (personal data under GDPR / CCPA)
- URL paths (which may encode user actions)

**Recommendations:**
- Do not store analysis outputs (CSV exports) longer than necessary
- Use IPWatchdog on infrastructure you own and are authorised to monitor
- Consider anonymising IP addresses in logs before sharing with third-party services
- `result.txt` and `ip_set.csv` are excluded from git via `.gitignore` — do not override this

### Known Limitations

- IPWatchdog is a detection and reporting tool. It does not apply firewall rules automatically; rule application is always a manual step.
- The ML model is unsupervised (no labelled training data). Anomaly scores reflect statistical deviation from the analysed log's baseline, not ground truth of maliciousness. False positives are possible — always review flagged IPs before blocking.
- The free ip-api.com endpoint is rate-limited to 45 requests per minute. For high-volume usage, consider a paid GeoIP provider.

---

## Automated Security Scanning

This repository uses [GitHub CodeQL](https://codeql.github.com/) to scan for:
- SQL injection, XSS, path traversal, and other CWE-top-25 issues in Python
- Runs on every push and pull request to `main`
- Results are visible in the **Security → Code scanning** tab of the repository

---

*Last updated: April 2026*
