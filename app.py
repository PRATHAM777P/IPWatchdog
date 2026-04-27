""" IPWatchdog – Suspicious IP Detection Dashboard """

import os
import sys
import json
import queue
import threading
import tempfile
import time
import logging
from pathlib import Path

from flask import (
    Flask, render_template, request, jsonify,
    Response, stream_with_context
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
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("ipwatchdog")

_sse_queue: queue.Queue = queue.Queue(maxsize=500)
_analysis_cache: dict = {}
_cache_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[-1].lower() in app.config["ALLOWED_EXTENSIONS"]


def read_ip_list(file_storage) -> set:
    if not file_storage or file_storage.filename == "":
        return set()
    try:
        content = file_storage.read().decode("utf-8", errors="ignore")
        return {line.strip() for line in content.splitlines() if line.strip()}
    except Exception:
        logger.warning("Failed to read IP list")
        return set()


def push_sse_event(event_type: str, data: dict) -> None:
    try:
        _sse_queue.put_nowait({"type": event_type, "data": data})
    except queue.Full:
        logger.warning("SSE queue full, dropping event")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "logfile" not in request.files:
        return jsonify({"error": "No log file provided"}), 400

    log_file = request.files["logfile"]
    whitelist = read_ip_list(request.files.get("whitelist"))
    blacklist = read_ip_list(request.files.get("blacklist"))
    log_format = request.form.get("log_format", "auto")

    if log_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(log_file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    log_file.seek(0, 2)
    size = log_file.tell()
    log_file.seek(0)

    if size > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "File too large"}), 413

    safe_name = secure_filename(log_file.filename)
    tmp_path = os.path.join(tempfile.gettempdir(), f"ipwd_{os.getpid()}_{safe_name}")

    try:
        log_file.save(tmp_path)

        push_sse_event("status", {"message": "Parsing...", "pct": 10})

        parser = LogParser(log_format=log_format)
        df = parser.parse(tmp_path)

        if df is None or df.empty:
            return jsonify({"error": "Invalid log format"}), 422

        detector = IPDetector()
        result_df = detector.run(df)

        explainer = Explainer()
        explanations = explainer.explain(result_df)

        intel = ThreatIntel()
        top_ips = result_df.head(10)["IP"].tolist()
        threat_data = intel.bulk_lookup(top_ips)

        result_records = result_df.to_dict("records")

        for rec in result_records:
            ip = rec["IP"]
            rec["whitelisted"] = ip in whitelist
            rec["blacklisted"] = ip in blacklist
            rec["threat_intel"] = threat_data.get(ip, {})
            rec["explanation"] = explanations.get(ip, [])

        flagged_ips = [
            r["IP"] for r in result_records
            if r["anomaly_score"] < 0 and not r["whitelisted"]
        ]

        action_engine = ActionEngine()
        htaccess_rules = action_engine.generate_htaccess(flagged_ips)

        response_payload = {
            "summary": {
                "total_requests": len(df),
                "unique_ips": result_df["IP"].nunique(),
                "suspicious_ips": int((result_df["anomaly_score"] < 0).sum()),
            },
            "top_ips": result_df.head(10)[["IP", "request_count", "anomaly_score"]].to_dict("records"),
            "results": result_records[:200],
            "htaccess_rules": htaccess_rules,
        }

        session_id = str(int(time.time() * 1000))

        with _cache_lock:
            _analysis_cache[session_id] = response_payload

        response_payload["session_id"] = session_id
        return jsonify(response_payload)

    except Exception:
        logger.exception("Error in analyze")
        return jsonify({"error": "Internal server error"}), 500

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/export/<session_id>")
def export_csv(session_id: str):
    with _cache_lock:
        payload = _analysis_cache.get(session_id)

    if not payload:
        return jsonify({"error": "Session expired"}), 404

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
        headers={"Content-Disposition": f"attachment; filename=report.csv"},
    )


@app.route("/stream")
def stream():
    def event_generator():
        while True:
            try:
                event = _sse_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {\"type\":\"heartbeat\"}\n\n"

    return Response(stream_with_context(event_generator()), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Secure path validation
# ---------------------------------------------------------------------------
def _validated_monitor_log_path(user_path, allowed_paths):
    if not isinstance(user_path, str) or not user_path:
        raise ValueError("INVALID")

    if not os.path.isabs(user_path):
        raise ValueError("INVALID")

    try:
        real_path = Path(user_path).resolve(strict=True)
    except FileNotFoundError:
        raise ValueError("NOT_FOUND")
    except OSError:
        raise ValueError("INVALID")

    for allowed in allowed_paths or []:
        try:
            root = Path(allowed).resolve(strict=True)
            if root in real_path.parents or real_path == root:
                return str(real_path)
        except OSError:
            continue

    raise PermissionError("FORBIDDEN")


@app.route("/monitor", methods=["POST"])
def monitor_start():
    body = request.get_json(silent=True) or {}
    log_path = body.get("path", "")
    log_format = body.get("format", "auto")

    try:
        real_log_path = _validated_monitor_log_path(
            log_path,
            app.config.get("MONITOR_ALLOWED_PATHS", [])
        )

    except ValueError as exc:
        logger.warning(f"Invalid monitor request: {exc}")
        return jsonify({"error": "Invalid request"}), 400

    except PermissionError:
        logger.warning("Unauthorized path access attempt")
        return jsonify({"error": "Access denied"}), 403

    except Exception:
        logger.exception("Unexpected monitor error")
        return jsonify({"error": "Internal server error"}), 500

    def tail_worker():
        try:
            parser = LogParser(log_format=log_format)
            detector = IPDetector()

            with open(real_log_path, "r", encoding="utf-8", errors="ignore") as fh:
                fh.seek(0, 2)

                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(0.5)
                        continue

                    record = parser.parse_line(line)
                    if record:
                        score = detector.score_single(record)
                        push_sse_event("live_entry", {
                            **record,
                            "anomaly_score": score
                        })

        except Exception:
            logger.exception("tail_worker crashed")

    threading.Thread(target=tail_worker, daemon=True).start()

    return jsonify({"status": "monitoring started"}), 200


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self';"
    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False  # IMPORTANT: never enable debug in production
    )
