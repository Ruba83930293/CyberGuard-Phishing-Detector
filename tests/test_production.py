import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from redis.exceptions import ConnectionError as RedisConnectionError

from app import create_app


class ProductionTests(unittest.TestCase):
    origin = "https://cyberguard.example"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database_path = Path(directory.name) / "should-not-exist.sqlite3"
        self.settings = {"TESTING": True, "MODE": "production", "PUBLIC_ORIGIN": self.origin,
                         "PROXY_HOPS": 0, "RATELIMIT_STORAGE_URI": "memory://", "DATABASE": str(self.database_path)}
        self.app = create_app(self.settings)
        self.client = self.app.test_client()

    def scan(self, ip="192.0.2.1", **payload):
        return self.client.post("/api/scan", base_url=self.origin,
                                headers={"Origin": self.origin, "Sec-Fetch-Site": "same-origin"},
                                environ_overrides={"REMOTE_ADDR": ip}, json={"url": "https://example.com", **payload})

    def test_production_does_not_initialize_or_use_sqlite(self):
        with patch("app.initialize_database", side_effect=AssertionError("SQLite initialization forbidden")):
            other = create_app({**self.settings, "DEBUG": True, "HISTORY_ENABLED": True, "RATELIMIT_ENABLED": False})
        self.assertFalse(other.debug)
        self.assertFalse(other.config["HISTORY_ENABLED"])
        self.assertTrue(other.config["RATELIMIT_ENABLED"])
        self.assertIsNone(other.config["DATABASE"])
        with patch("app.save_scan", side_effect=AssertionError("SQLite save forbidden")), \
                patch("app.get_history", side_effect=AssertionError("SQLite read forbidden")), \
                patch("app.delete_history", side_effect=AssertionError("SQLite deletion forbidden")):
            self.assertEqual(self.scan().status_code, 200)
            self.assertEqual(self.scan(save_history=True).status_code, 403)
            self.assertEqual(self.client.get("/api/history", base_url=self.origin).status_code, 403)
            self.assertEqual(self.client.delete("/api/history", base_url=self.origin, json={"confirm": True}).status_code, 403)
        self.assertFalse(self.database_path.exists())

    def test_public_capabilities_expose_no_configuration_secrets(self):
        response = self.client.get("/api/config", base_url=self.origin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"history_enabled": False})
        self.assertNotIn("DATABASE", response.get_data(as_text=True))

    def test_security_headers_on_pages_api_and_errors(self):
        for path in ("/", "/script.js", "/api/config", "/api/history", "/not-a-route"):
            with self.subTest(path=path):
                response = self.client.get(path, base_url=self.origin)
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")
                self.assertIn("geolocation=()", response.headers["Permissions-Policy"])
                self.assertIn("max-age=31536000", response.headers["Strict-Transport-Security"])
                self.assertIn("object-src 'none'", response.headers["Content-Security-Policy"])
                self.assertIn("upgrade-insecure-requests", response.headers["Content-Security-Policy"])
                self.assertNotIn("Access-Control-Allow-Origin", response.headers)
                response.close()

    def test_https_and_exact_public_origin_are_required(self):
        self.assertEqual(self.client.get("/", base_url="http://cyberguard.example").status_code, 400)
        self.assertEqual(self.client.get("/", base_url="https://attacker.example").status_code, 400)
        for origin in ("https://attacker.example", "https://cyberguard.example:444", "null", "http://cyberguard.example"):
            response = self.client.post("/api/scan", base_url=self.origin, headers={"Origin": origin}, json={"url": "https://example.com"})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.scan().status_code, 200)

    def test_request_size_and_url_limits_remain_enforced(self):
        response = self.client.post("/api/scan", base_url=self.origin, json={"url": "x" * 17000})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.scan(url="x" * 4097).status_code, 400)
        self.assertEqual(self.scan(url="https://user:secret@example.com").status_code, 400)

    def test_per_ip_limit_counts_invalid_requests_and_blocks_analysis(self):
        for _ in range(10):
            self.assertEqual(self.scan(url="not-a-url").status_code, 400)
        with patch("app.analyze_url", side_effect=AssertionError("Limited request reached the analyzer")):
            response = self.scan()
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 0)
        self.assertIn("rate limit", response.json["error"])
        self.assertEqual(self.scan(ip="192.0.2.2").status_code, 200)

    def test_forwarded_ip_cannot_bypass_limits_without_proxy_trust(self):
        for number in range(11):
            response = self.client.post("/api/scan", base_url=self.origin,
                                        headers={"X-Forwarded-For": f"192.0.2.{number + 1}"},
                                        json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 429)
        response = self.client.get("/", base_url="http://cyberguard.example", headers={"X-Forwarded-Proto": "https"})
        self.assertEqual(response.status_code, 400)

    def test_explicit_single_proxy_preserves_client_and_tls_origin(self):
        proxied = create_app({**self.settings, "PROXY_HOPS": 1}).test_client()
        for number in range(11):
            response = proxied.post("/api/scan", base_url="http://cyberguard.example",
                                    headers={"Origin": self.origin, "X-Forwarded-Proto": "https",
                                             "X-Forwarded-For": "192.0.2.10", "X-Forwarded-Host": "attacker.example"},
                                    json={"url": "https://example.com"})
            self.assertEqual(response.status_code, 200 if number < 10 else 429)
        response = proxied.post("/api/scan", base_url="http://cyberguard.example",
                                headers={"Origin": self.origin, "X-Forwarded-Proto": "https", "X-Forwarded-For": "192.0.2.11"},
                                json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)

    def test_proxy_trust_does_not_relax_host_or_origin_validation(self):
        proxied = create_app({**self.settings, "PROXY_HOPS": 1}).test_client()
        headers = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "192.0.2.10",
                   "X-Forwarded-Host": "cyberguard.example", "X-Forwarded-Port": "443"}
        response = proxied.get("/api/config", base_url="http://attacker.example", headers=headers)
        self.assertEqual(response.status_code, 400)
        for origin in ("https://attacker.example", "http://cyberguard.example", "null"):
            with self.subTest(origin=origin):
                response = proxied.post("/api/scan", base_url="http://cyberguard.example",
                                        headers={**headers, "Origin": origin}, json={"url": "https://example.com"})
                self.assertEqual(response.status_code, 403)
        self.assertEqual(proxied.get("/api/config", base_url="http://cyberguard.example",
                                     headers={**headers, "X-Forwarded-Proto": "http"}).status_code, 400)

    def test_single_proxy_trust_ignores_untrusted_forwarded_prefix(self):
        proxied = create_app({**self.settings, "PROXY_HOPS": 1}).test_client()
        for number in range(11):
            response = proxied.post("/api/scan", base_url="http://cyberguard.example",
                                    headers={"Origin": self.origin, "X-Forwarded-Proto": "http, https",
                                             "X-Forwarded-For": f"192.0.2.{number + 1}, 198.51.100.1"},
                                    json={"url": "https://example.com"})
            self.assertEqual(response.status_code, 200 if number < 10 else 429)

    def test_hourly_limit_and_expiration(self):
        start = time.time()
        with patch("limits.storage.memory.time.time", return_value=start) as clock:
            for window in range(12):
                clock.return_value = start + window * 61
                for _ in range(10):
                    self.assertEqual(self.scan().status_code, 200)
            clock.return_value = start + 12 * 61
            self.assertEqual(self.scan().status_code, 429)
            clock.return_value = start + 3601
            self.assertEqual(self.scan().status_code, 200)

    def test_aggregate_limit_prevents_simple_ip_rotation(self):
        for number in range(1000):
            self.assertEqual(self.scan(ip=f"2001:db8::{number + 1:x}").status_code, 200)
        self.assertEqual(self.scan(ip="198.51.100.1").status_code, 429)

    def test_rate_storage_failure_fails_closed_without_private_details(self):
        limiter = self.app.extensions["scan_limiter"]
        with patch.object(limiter.storage, "incr", side_effect=RedisConnectionError("PRIVATE_REDIS_PASSWORD")), \
                patch("app.analyze_url", side_effect=AssertionError("Unmetered analysis forbidden")), self.assertLogs(self.app.logger, level="ERROR"):
            response = self.scan()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("PRIVATE", response.get_data(as_text=True))

    def test_public_analysis_never_fetches_submitted_addresses(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
                patch.object(socket, "socket", side_effect=AssertionError("Outbound network forbidden")):
            response = self.scan(url="http://192.0.2.1/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk_score"], 40)
        self.assertFalse(response.json["history_saved"])

    def test_local_development_retains_history(self):
        local = create_app({"TESTING": True, "MODE": "development", "PROXY_HOPS": 0, "DATABASE": str(self.database_path)}).test_client()
        self.assertEqual(local.get("/api/config").json, {"history_enabled": True})
        self.assertTrue(local.post("/api/scan", json={"url": "https://example.com", "save_history": True}).json["history_saved"])
        self.assertEqual(local.get("/api/history").json["total"], 1)
        self.assertEqual(local.delete("/api/history", json={"confirm": True}).json["deleted"], 1)


class ProductionConfigurationTests(unittest.TestCase):
    def test_gunicorn_render_bind_entry_point_and_resource_defaults(self):
        path = Path(__file__).resolve().parents[1] / "gunicorn.conf.py"
        for port in ("10000", "12345"):
            with self.subTest(port=port), patch.dict(os.environ, {"PORT": port}):
                settings = runpy.run_path(str(path))
            self.assertEqual(settings["bind"], f"0.0.0.0:{port}")
            self.assertEqual(settings["wsgi_app"], "wsgi:application")
            self.assertEqual(settings["workers"], 1)
            self.assertEqual(settings["worker_class"], "gthread")
            self.assertEqual(settings["threads"], 2)
            self.assertFalse(settings["reload"])
            self.assertEqual(settings["secure_scheme_headers"], {})
            self.assertEqual(settings["forwarded_allow_ips"], "")
            self.assertEqual(settings["forwarder_headers"], "")
        with patch.dict(os.environ):
            os.environ.pop("PORT", None)
            self.assertEqual(runpy.run_path(str(path))["bind"], "127.0.0.1:8000")
        for port in ("", "0", "65536", "-1", "abc", "10000 ", "1.5"):
            with self.subTest(port=port), patch.dict(os.environ, {"PORT": port}), self.assertRaises(ValueError):
                runpy.run_path(str(path))

    @unittest.skipIf(os.name == "nt", "Gunicorn requires a Unix runtime")
    def test_gunicorn_settings_pass_native_validators(self):
        from gunicorn.config import Config

        path = Path(__file__).resolve().parents[1] / "gunicorn.conf.py"
        with patch.dict(os.environ, {"PORT": "10000"}):
            settings = runpy.run_path(str(path))
            config = Config()
        for name, value in settings.items():
            if name in config.settings:
                with self.subTest(setting=name):
                    config.set(name, value)
        self.assertEqual(config.bind, ["0.0.0.0:10000"])
        self.assertEqual(config.wsgi_app, "wsgi:application")
        self.assertEqual(config.forwarder_headers, [])
        self.assertEqual(config.forwarded_allow_ips, [])
        self.assertEqual(config.secure_scheme_headers, {})

    def test_environment_selects_production_and_ignores_sqlite_path(self):
        with patch.dict(os.environ, {"CYBERGUARD_ENV": "production", "CYBERGUARD_PUBLIC_ORIGIN": "https://cyberguard.example",
                                     "CYBERGUARD_RATE_STORAGE_URI": "redis://127.0.0.1:6379/5", "CYBERGUARD_PROXY_HOPS": "1"}), \
                patch("app.initialize_database", side_effect=AssertionError("Database must not initialize")):
            app = create_app()
        self.assertFalse(app.config["HISTORY_ENABLED"])
        self.assertIsNone(app.config["DATABASE"])
        self.assertEqual(app.config["PROXY_HOPS"], 1)

    def test_bad_or_incomplete_production_configuration_fails_startup(self):
        valid = {"MODE": "production", "TESTING": False, "PUBLIC_ORIGIN": "https://cyberguard.example", "PROXY_HOPS": 0,
                 "RATELIMIT_STORAGE_URI": "redis://127.0.0.1:6379/5"}
        for changes in ({"MODE": "prod"}, {"PUBLIC_ORIGIN": ""}, {"PUBLIC_ORIGIN": "http://cyberguard.example"},
                        {"PUBLIC_ORIGIN": "https://user:secret@cyberguard.example"}, {"PUBLIC_ORIGIN": "https://cyberguard.example/path"},
                        {"PUBLIC_ORIGIN": "https://.example"}, {"PUBLIC_ORIGIN": "https://cyberguard.example:99999"},
                        {"RATELIMIT_STORAGE_URI": ""}, {"RATELIMIT_STORAGE_URI": "memory://"}, {"PROXY_HOPS": 2}, {"PROXY_HOPS": "invalid"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                create_app({**valid, **changes})

    def test_wsgi_entry_point_refuses_accidental_development_mode(self):
        with patch.dict(os.environ, {"CYBERGUARD_ENV": "development"}), self.assertRaises(RuntimeError):
            runpy.run_path(str(Path(__file__).resolve().parents[1] / "wsgi.py"))

    def test_wsgi_exports_same_secure_app_for_module_only_target(self):
        environment = {**os.environ, "CYBERGUARD_ENV": "production",
                       "CYBERGUARD_PUBLIC_ORIGIN": "https://cyberguard.example",
                       "CYBERGUARD_RATE_STORAGE_URI": "redis://127.0.0.1:6379/5",
                       "CYBERGUARD_PROXY_HOPS": "1"}
        code = """
import os
import app as backend
import wsgi
assert wsgi.app is wsgi.application is backend.app
assert callable(wsgi.app)
assert wsgi.app.config['MODE'] == 'production'
assert not wsgi.app.debug
assert not wsgi.app.config['HISTORY_ENABLED']
assert wsgi.app.config['DATABASE'] is None
assert wsgi.app.config['RATELIMIT_ENABLED']
assert wsgi.app.config['TRUSTED_HOSTS'] == ['cyberguard.example']
client = wsgi.app.test_client()
response = client.get('/api/config', base_url='https://cyberguard.example')
assert response.status_code == 200 and response.json == {'history_enabled': False}
assert client.get('/api/history', base_url='https://cyberguard.example').status_code == 403
assert client.get('/api/config', base_url='https://attacker.example').status_code == 400
if os.name != 'nt':
    from gunicorn.util import import_app
    assert import_app('wsgi') is wsgi.app
    assert import_app('wsgi:application') is wsgi.app
"""
        result = subprocess.run([sys.executable, "-c", code], env=environment,
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wsgi_rejects_an_already_imported_development_application(self):
        with patch.dict(os.environ, {"CYBERGUARD_ENV": "production"}), self.assertRaises(RuntimeError):
            runpy.run_path(str(Path(__file__).resolve().parents[1] / "wsgi.py"))
