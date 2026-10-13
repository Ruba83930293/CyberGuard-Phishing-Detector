"""CyberGuard local Flask API and explicit frontend asset routes."""

from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import SecurityError
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis.exceptions import RedisError

from config import configure_app
from phishing_detector import analyze_url
from database import delete_history, get_history, initialize_database, save_scan

ROOT = Path(__file__).resolve().parent


def create_app(test_config=None):
    app = Flask(__name__, static_folder=None)
    configure_app(app, test_config)
    production = app.config["MODE"] == "production"
    if app.config["PROXY_HOPS"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)
    if app.config["HISTORY_ENABLED"]:
        initialize_database(app.config["DATABASE"])

    @app.before_request
    def require_production_https():
        if production and not request.is_secure:
            return jsonify(error="HTTPS is required."), 400

    @app.before_request
    def validate_api_origin():
        if request.routing_exception is not None or not request.path.startswith("/api/"):
            return None
        origin = request.headers.get("Origin")
        expected_origin = app.config["PUBLIC_ORIGIN"] if production else request.host_url.rstrip("/")
        site = request.headers.get("Sec-Fetch-Site")
        mode = request.headers.get("Sec-Fetch-Mode")
        destination = request.headers.get("Sec-Fetch-Dest")
        safe_method = request.method in {"GET", "HEAD"}
        # A user-opened JSON document is not a cross-origin fetch or a mutation.
        safe_navigation = (safe_method and origin is None and mode == "navigate"
                           and destination == "document" and request.headers.get("Sec-Fetch-User") == "?1")
        if origin is not None and origin != expected_origin:
            return jsonify(error="Cross-origin API requests are not allowed."), 403
        if site in {"cross-site", "same-site"} and not safe_navigation:
            return jsonify(error="Cross-origin API requests are not allowed."), 403
        if origin is None and not safe_navigation:
            referer = request.headers.get("Referer")
            same_origin_referer = False
            if referer is not None:
                try:
                    parts = urlsplit(referer)
                    same_origin_referer = (parts.username is None and parts.password is None
                                          and f"{parts.scheme}://{parts.netloc}" == expected_origin)
                except ValueError:
                    pass
                if not same_origin_referer:
                    return jsonify(error="Cross-origin API requests are not allowed."), 403
            # Preserve local CLI clients, but require browser provenance for writes.
            browser_metadata = any(value is not None for value in (site, mode, destination, request.headers.get("Sec-Fetch-User")))
            if not safe_method and browser_metadata and site != "same-origin" and not same_origin_referer:
                return jsonify(error="Cross-origin API requests are not allowed."), 403
        return None

    @app.get("/")
    def index():
        return send_from_directory(ROOT, "index.html")

    @app.get("/style.css")
    def stylesheet():
        return send_from_directory(ROOT, "style.css")

    @app.get("/script.js")
    def javascript():
        return send_from_directory(ROOT, "script.js")

    @app.get("/api/config")
    def frontend_config():
        return jsonify(history_enabled=app.config["HISTORY_ENABLED"])

    limiter = Limiter(
        get_remote_address, app=app, default_limits=[],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"], strategy="fixed-window",
        storage_options={"socket_connect_timeout": 2, "socket_timeout": 2} if production and not app.testing else {},
        key_prefix="cyberguard-scans",
    )
    app.extensions["scan_limiter"] = limiter

    @app.post("/api/scan")
    @limiter.limit("10 per minute;120 per hour")
    @limiter.limit("1000 per hour", key_func=lambda: "global")
    def scan():
        if not request.is_json:
            return jsonify(error="Send a JSON object with a URL using Content-Type: application/json."), 415
        payload = request.get_json()
        if not isinstance(payload, dict) or "url" not in payload or set(payload) - {"url", "save_history"}:
            return jsonify(error='Send a JSON object with "url" and optionally "save_history".'), 400
        save_enabled = payload.get("save_history", False)
        if type(save_enabled) is not bool:
            return jsonify(error="save_history must be true or false."), 400
        if save_enabled and not app.config["HISTORY_ENABLED"]:
            return jsonify(error="Persistent scan history is disabled on this public deployment."), 403
        try:
            result = analyze_url(payload["url"])
            result["history_saved"] = False
            if save_enabled:
                record = save_scan(app.config["DATABASE"], payload["url"])
                result.update(history_saved=True, saved_scan_id=record["id"], stored_url=record["normalized_url"])
            return jsonify(result)
        except ValueError as error:
            return jsonify(error=str(error)), 400

    @app.get("/api/history")
    def history():
        if not app.config["HISTORY_ENABLED"]:
            return jsonify(error="Persistent scan history is disabled on this public deployment."), 403
        if set(request.args) - {"limit", "offset"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            return jsonify(error="Use only one limit and offset parameter."), 400
        try:
            limit_text = request.args.get("limit", "20")
            offset_text = request.args.get("offset", "0")
            if not limit_text.isascii() or not limit_text.isdigit() or not offset_text.isascii() or not offset_text.isdigit():
                raise ValueError("Pagination values must be non-negative integers.")
            return jsonify(get_history(app.config["DATABASE"], int(limit_text), int(offset_text)))
        except ValueError as error:
            return jsonify(error=str(error)), 400

    @app.delete("/api/history")
    def remove_history():
        if not app.config["HISTORY_ENABLED"]:
            return jsonify(error="Persistent scan history is disabled on this public deployment."), 403
        if not request.is_json:
            return jsonify(error="Deletion requires a JSON confirmation."), 415
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {"confirm"} or payload["confirm"] is not True:
            return jsonify(error='Confirm deletion with {"confirm": true}.'), 400
        return jsonify(deleted=delete_history(app.config["DATABASE"]))

    @app.errorhandler(sqlite3.Error)
    def database_error(error):
        app.logger.error("History storage error: %s", type(error).__name__)
        return jsonify(error="History storage is unavailable. Please try again."), 503

    @app.errorhandler(RedisError)
    def rate_storage_error(error):
        app.logger.error("Rate limit storage unavailable: %s", type(error).__name__)
        return jsonify(error="Scan service temporarily unavailable. Please try again later."), 503

    @app.errorhandler(HTTPException)
    def http_error(error):
        messages = {400: "Malformed JSON request.", 413: "Request is too large. Maximum size is 16 KiB.",
                    429: "Scan rate limit exceeded. Please try again later."}
        response = error.get_response()
        message = "Untrusted request host." if isinstance(error, SecurityError) else messages.get(error.code, error.description)
        response.data = app.json.dumps({"error": message})
        response.content_type = "application/json"
        return response

    @app.errorhandler(Exception)
    def unexpected_error(error):
        app.logger.error("Unexpected URL analysis error: %s", type(error).__name__)
        return jsonify(error="Analysis failed. Please try again."), 500

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" + ("; upgrade-insecure-requests" if production else "")
        if production and request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    return app


app = create_app()

if __name__ == "__main__":
    if app.config["MODE"] == "production":
        raise RuntimeError("Use the production WSGI entry point, not Flask's development server.")
    app.run(host="127.0.0.1", port=5000, debug=False)
