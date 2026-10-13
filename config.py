"""Environment-based deployment configuration with fail-closed public defaults."""

import os
import re
from pathlib import Path
from urllib.parse import urlsplit


def configure_app(app, overrides=None):
    root = Path(__file__).resolve().parent
    app.config.update(
        MODE=os.environ.get("CYBERGUARD_ENV", "development"),
        PUBLIC_ORIGIN=os.environ.get("CYBERGUARD_PUBLIC_ORIGIN", ""),
        PROXY_HOPS=os.environ.get("CYBERGUARD_PROXY_HOPS", "0"),
        RATELIMIT_STORAGE_URI=os.environ.get("CYBERGUARD_RATE_STORAGE_URI", ""),
        DATABASE=os.environ.get("CYBERGUARD_DATABASE", str(root / "instance" / "scans.sqlite3")),
        DEBUG=False,
        MAX_CONTENT_LENGTH=16 * 1024,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
    )
    if overrides:
        app.config.update(overrides)
    mode = app.config["MODE"]
    if mode not in {"development", "production"}:
        raise ValueError("CYBERGUARD_ENV must be development or production.")
    try:
        hops = int(app.config["PROXY_HOPS"])
    except (ValueError, TypeError):
        raise ValueError("CYBERGUARD_PROXY_HOPS must be 0 or 1.") from None
    if hops not in {0, 1}:
        raise ValueError("CYBERGUARD_PROXY_HOPS must be 0 or 1.")
    app.config["PROXY_HOPS"] = hops
    production = mode == "production"
    app.config.update(HISTORY_ENABLED=not production, RATELIMIT_ENABLED=production, DEBUG=False)
    if not production:
        app.config["RATELIMIT_STORAGE_URI"] = "memory://"
        return

    origin = app.config["PUBLIC_ORIGIN"]
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname or ""
        port = parsed.port
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))
                or any(c.isspace() for c in origin) or port == 0):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("CYBERGUARD_PUBLIC_ORIGIN must be a valid HTTPS origin without a path or credentials.") from None
    app.config["PUBLIC_ORIGIN"] = f"https://{host}" + (f":{port}" if port not in {None, 443} else "")
    storage = app.config["RATELIMIT_STORAGE_URI"]
    if not (app.testing and storage == "memory://"):
        try:
            parsed_storage = urlsplit(storage)
            valid_storage = parsed_storage.scheme in {"redis", "rediss"} and bool(parsed_storage.hostname)
            parsed_storage.port
        except (ValueError, TypeError):
            valid_storage = False
        if not valid_storage:
            raise ValueError("Production requires CYBERGUARD_RATE_STORAGE_URI pointing to a dedicated Redis service.")
    app.config.update(
        DATABASE=None,
        TRUSTED_HOSTS=[host],
        MAX_CONTENT_LENGTH=16 * 1024,
        PROPAGATE_EXCEPTIONS=False,
        RATELIMIT_HEADERS_ENABLED=True,
        RATELIMIT_SWALLOW_ERRORS=False,
        RATELIMIT_IN_MEMORY_FALLBACK_ENABLED=False,
    )
