"""Production-only WSGI entry point for Gunicorn on Linux."""

import os

if os.environ.get("CYBERGUARD_ENV") != "production":
    raise RuntimeError("Set CYBERGUARD_ENV=production before starting the public WSGI server.")

from app import app as application

if application.config["MODE"] != "production" or application.config["HISTORY_ENABLED"] or application.debug:
    raise RuntimeError("The WSGI application must have production security settings before import.")
