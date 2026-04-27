"""
IPWatchdog – Suspicious IP Detection Dashboard
Entry point for the Flask web application.
"""

import os
import sys
import json
import queue
import threading
import tempfile
import time
import logging

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, Response, stream_with_context
)
from werkzeug.utils import secure_filename

from config import AppConfig
from core.parser import LogParser
from core.detector import IPDetector
from core.explainer import Explainer
from core.threat_intel import ThreatIntel
from core.actions import ActionEngine

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(AppConfig)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ipwatchdog")

# In-memory event queue for Server-Sent Events (real-time monitoring)
_sse_queue: queue.Queue = queue.Queue(maxsize=500)

# In-memory results cache (per-session in a production app you'd use Redis)
_analysis_cache: dict = {}
_cache_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in app.config["ALLOWED_EXTENSIONS"]


def read_ip_list(file_storage) -> set:
    """Read a newline-separated list of IPs from an uploaded file."""
    if not file_storage or file_storage.filename == "":
        return set()
    try:
        content = file_storage.read().decode("utf-8", errors="ignore")
        return {line.strip() for line in content.splitlines() if line.strip()}
    except Exception:
        return set()


def push_sse_event(event_type: str, data: dict) -> None:
    """Non-blocking push to the SSE queue (drops if full)."""
    try:
        _sse_queue.put_nowait({"type": event_type, "data": data})
    except queue.Full:
        pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Handle log upload and run full detection pipeline.
    Returns JSON so the frontend can update live.
    """
    if "logfile" not in request.files:
        return jsonify({"error": "No log file provided"}), 400

    log_file = request.files["logfile"]
    whitelist = read_ip_list(request.files.get("whitelist"))
    blacklist = read_ip_list(request.files.get("blacklist"))
    log_format = request.form.get("log_format", "auto")

    if log_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(log_file.filename):
        return jsonify({"error": "Invalid file type. Allowed: .txt, .log"}), 400

    # Enforce file size limit (checked again server-side)
    log_file.seek(0, 2)
    size = log_file.tell()
    log_file.seek(0)
    if size > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "File too large (max 50 MB)"}), 413

    safe_name = secure_filename(log_file.filename)
    tmp_path = os.path.join(tempfile.gettempdir(), f"ipwd_{os.getpid()}_{safe_name}")

    try:
        log_file.save(tmp_path)

        push_sse_event("status", {"message": "Parsing log file…", "pct": 10})

        # 1. Parse
        parser = LogParser(log_format=log_format)
        df = parser.parse(tmp_path)
        if df is None or df.empty:
            return jsonify({"error": "No valid log entries found. Check format."}), 422

        push_sse_event("status", {"message": f"Parsed {len(df):,} entries. Running detection…", "pct": 35})

        # 2. Detect
        detector = IPDetector()
        result_df = detector.run(df)

        push_sse_event("status", {"message": "Scoring anomalies…", "pct": 60})

        # 3. Explain
        explainer = Explainer()
        explanations = explainer.explain(result_df)

        push_sse_event("status", {"message": "Fetching threat intelligence…", "pct": 75})

        # 4. Threat intelligence (optional – only if API key set)
        intel = ThreatIntel()
        top_suspicious = result_df.head(10)["IP"].tolist()
        threat_data = intel.bulk_lookup(top_suspicious)

        push_sse_event("status", {"message": "Building report…", "pct": 90})

        # 5. Apply whitelist / blacklist overrides
        result_records = result_df.to_dict("records")
        for rec in result_records:
            ip = rec["IP"]
            rec["whitelisted"] = ip in whitelist
            rec["blacklisted"] = ip in blacklist
            rec["threat_intel"] = threat_data.get(ip, {})
            rec["explanation"] = explanations.get(ip, [])

        # 6. Summary stats
        total_ips = result_df["IP"].nunique()
        total_requests = len(df)
        suspicious_count = int((result_df["anomaly_score"] < 0).sum())
        top_ips = result_df.head(10)[["IP", "request_count", "anomaly_score"]].to_dict("records")

        # 7. Actions: generate .htaccess block
        action_engine = ActionEngine()
        flagged_ips = [r["IP"] for r in result_records if r["anomaly_score"] < 0 and not r["whitelisted"]]
        htaccess_rules = action_engine.generate_htaccess(flagged_ips)

        push_sse_event("status", {"message": "Done.", "pct": 100})

        response_payload = {
            "summary": {
                "total_requests": total_requests,
                "unique_ips": total_ips,
                "suspicious_ips": suspicious_count,
                "parse_format": parser.detected_format,
            },
            "top_ips": top_ips,
            "results": result_records[:200],  # cap UI payload
            "htaccess_rules": htaccess_rules,
        }

        # Cache for export endpoint
        session_id = str(int(time.time() * 1000))
        with _cache_lock:
            _analysis_cache[session_id] = response_payload

        response_payload["session_id"] = session_id
        return jsonify(response_payload)

    except Exception as exc:
        logger.exception("Analysis pipeline error")
        return jsonify({"error": f"Internal error: {exc}"}), 500

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/export/<session_id>")
def export_csv(session_id: str):
    """Download analysis results as CSV."""
    with _cache_lock:
        payload = _analysis_cache.get(session_id)
    if not payload:
        return jsonify({"error": "Session expired or not found"}), 404

    import csv
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["IP", "request_count", "anomaly_score", "whitelisted", "blacklisted"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(payload.get("results", []))
    buf.seek(0)

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ipwatchdog_{session_id}.csv"},
    )


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint for real-time progress updates."""

    def event_generator():
        while True:
            try:
                event = _sse_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {\"type\": \"heartbeat\"}\n\n"

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/monitor", methods=["POST"])
def monitor_start():
    """
    Start real-time log tail monitoring on a server-local log path.
    Expects JSON: {"path": "/var/log/nginx/access.log", "format": "nginx"}
    The path must be in the MONITOR_ALLOWED_PATHS whitelist (config).
    """
    body = request.get_json(silent=True) or {}
    log_path = body.get("path", "")
    log_format = body.get("format", "auto")

    allowed_paths = app.config.get("MONITOR_ALLOWED_PATHS", [])
    if not any(log_path.startswith(p) for p in allowed_paths):
        return jsonify({"error": "Path not in allowed monitor paths"}), 403

    if not os.path.isfile(log_path):
        return jsonify({"error": "File not found"}), 404

    def tail_worker():
        parser = LogParser(log_format=log_format)
        detector = IPDetector()
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(0, 2)  # jump to end
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                record = parser.parse_line(line)
                if record:
                    score = detector.score_single(record)
                    push_sse_event("live_entry", {**record, "anomaly_score": score})

    t = threading.Thread(target=tail_worker, daemon=True)
    t.start()
    return jsonify({"status": "monitoring started", "path": log_path})


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
