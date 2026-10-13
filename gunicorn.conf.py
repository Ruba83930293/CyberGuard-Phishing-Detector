"""Linux WSGI defaults; run behind one isolated HTTPS reverse proxy."""

bind = "127.0.0.1:8000"
workers = 2
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
forwarder_headers = []
