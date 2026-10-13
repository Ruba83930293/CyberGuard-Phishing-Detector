"""Linux WSGI defaults for Render or an isolated local HTTPS reverse proxy."""

import os

port = os.environ.get("PORT")
if port is not None and (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535):
    raise ValueError("PORT must be an integer between 1 and 65535.")
bind = f"0.0.0.0:{int(port)}" if port is not None else "127.0.0.1:8000"
wsgi_app = "wsgi:application"
workers = 1
worker_class = "gthread"
threads = 2
timeout = 15
graceful_timeout = 15
keepalive = 2
backlog = 128
max_requests = 1000
max_requests_jitter = 100
limit_request_line = 4094
limit_request_fields = 32
limit_request_field_size = 4096
reload = False
control_socket_disable = True
accesslog = None
errorlog = "-"
loglevel = "warning"
# ProxyFix is the sole interpreter of explicitly trusted forwarding headers.
secure_scheme_headers = {}
forwarded_allow_ips = ""
# Gunicorn parses the empty string into an empty header allowlist.
forwarder_headers = ""
