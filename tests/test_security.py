from pathlib import Path
import tempfile
import unittest

from app import create_app


class SecurityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.app = create_app({"TESTING": True, "DATABASE": str(Path(directory.name) / "history.sqlite3")})
        self.client = self.app.test_client()

    def test_untrusted_hosts_cannot_access_history_or_scan(self):
        for host in ("attacker.example", "localhost.attacker.example", "127.0.0.1.attacker.example"):
            for method, path in (("GET", "/api/history"), ("POST", "/api/scan"), ("DELETE", "/api/history")):
                with self.subTest(host=host, method=method):
                    response = self.client.open(path, method=method, headers={"Host": host}, json={"url": "https://example.com", "confirm": True})
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.json["error"], "Untrusted request host.")

    def test_cross_origin_requests_cannot_read_save_or_delete(self):
        self.client.post("/api/scan", json={"url": "https://example.com", "save_history": True})
        for origin in ("https://attacker.example", "null", "http://localhost:9999"):
            for method, path, payload in (("GET", "/api/history", None), ("POST", "/api/scan", {"url": "https://example.com", "save_history": True}), ("DELETE", "/api/history", {"confirm": True})):
                with self.subTest(origin=origin, method=method):
                    response = self.client.open(path, method=method, headers={"Origin": origin}, json=payload)
                    self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/api/history").json["total"], 1)

    def test_cross_site_fetch_is_rejected(self):
        response = self.client.get("/api/history", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)

    def test_same_origin_browser_and_local_cli_requests_work(self):
        for host in ("localhost:5000", "127.0.0.1:5000", "localhost:5001", "127.0.0.1:5001"):
            with self.subTest(host=host):
                response = self.client.post("/api/scan", base_url="http://" + host, headers={"Origin": "http://" + host}, json={"url": "https://example.com"})
                self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/history").status_code, 200)

    def test_same_origin_local_frontend_can_save_read_and_delete(self):
        for origin in ("http://127.0.0.1:5000", "http://localhost:5000"):
            with self.subTest(origin=origin):
                headers = {"Origin": origin, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty"}
                scan = self.client.post("/api/scan", base_url=origin, headers=headers,
                                        json={"url": "https://example.com", "save_history": True})
                self.assertEqual(scan.status_code, 200)
                self.assertTrue(scan.json["history_saved"])
                history = self.client.get("/api/history", base_url=origin, headers=headers)
                self.assertEqual(history.status_code, 200)
                self.assertEqual(history.json["total"], 1)
                deleted = self.client.delete("/api/history", base_url=origin, headers=headers, json={"confirm": True})
                self.assertEqual(deleted.status_code, 200)
                self.assertEqual(deleted.json["deleted"], 1)
                for response in (scan, history, deleted):
                    self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_safe_get_and_head_without_origin_work(self):
        for origin in ("http://127.0.0.1:5000", "http://localhost:5000"):
            for headers in ({}, {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "same-origin"},
                            {"Referer": origin + "/#history"},
                            {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}):
                for method in ("GET", "HEAD"):
                    with self.subTest(origin=origin, headers=headers, method=method):
                        response = self.client.open("/api/history", method=method, base_url=origin, headers=headers)
                        self.assertEqual(response.status_code, 200)

    def test_user_opened_history_document_is_not_a_cross_origin_fetch(self):
        for origin in ("http://127.0.0.1:5000", "http://localhost:5000"):
            headers = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
                       "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1", "Referer": "https://external.example/"}
            self.assertEqual(self.client.get("/api/history", base_url=origin, headers=headers).status_code, 200)
            self.assertEqual(self.client.get("/api/history", base_url=origin, headers={**headers, "Origin": "null"}).status_code, 403)
            for change in ({"Sec-Fetch-Dest": "iframe"}, {"Sec-Fetch-Mode": "cors"}, {"Sec-Fetch-User": ""}):
                with self.subTest(change=change):
                    self.assertEqual(self.client.get("/api/history", base_url=origin, headers={**headers, **change}).status_code, 403)

    def test_origins_must_match_scheme_host_and_port_exactly(self):
        origins = ("http://localhost:5000", "http://127.0.0.1:5001", "https://127.0.0.1:5000",
                   "http://127.0.0.1:5000.attacker.example", "http://127.0.0.1:5000@attacker.example",
                   "http://127.0.0.1:5000/", "http://127.0.0.1:5000/path", "null", "",
                   "http://127.0.0.1:5000 https://external.example")
        for origin in origins:
            for method, path, payload in (("GET", "/api/history", None),
                                          ("POST", "/api/scan", {"url": "https://example.com", "save_history": True}),
                                          ("DELETE", "/api/history", {"confirm": True}), ("OPTIONS", "/api/scan", None)):
                with self.subTest(origin=origin, method=method):
                    response = self.client.open(path, method=method, base_url="http://127.0.0.1:5000",
                                                headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"}, json=payload)
                    self.assertEqual(response.status_code, 403)
                    self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertEqual(self.client.get("/api/history").json["total"], 0)

    def test_cross_origin_metadata_without_origin_cannot_mutate_or_fetch(self):
        self.client.post("/api/scan", json={"url": "https://example.com", "save_history": True})
        for site in ("cross-site", "same-site"):
            for method, path, payload in (("GET", "/api/history", None),
                                          ("POST", "/api/scan", {"url": "https://example.com", "save_history": True}),
                                          ("DELETE", "/api/history", {"confirm": True})):
                with self.subTest(site=site, method=method):
                    headers = {"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}
                    if method == "GET":
                        headers.update({"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})
                    response = self.client.open(path, method=method, headers=headers, json=payload)
                    self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/api/history").json["total"], 1)

    def test_browser_writes_without_origin_need_same_origin_provenance(self):
        origin = "http://localhost:5000"
        for headers in ({"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "same-origin"},
                        {"Sec-Fetch-Mode": "same-origin", "Referer": origin + "/#scanner"}):
            with self.subTest(headers=headers):
                response = self.client.post("/api/scan", base_url=origin, headers=headers, json={"url": "https://example.com"})
                self.assertEqual(response.status_code, 200)
        for headers in ({"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Mode": "cors"},
                        {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}):
            with self.subTest(headers=headers):
                response = self.client.post("/api/scan", base_url=origin, headers=headers, json={"url": "https://example.com", "save_history": True})
                self.assertEqual(response.status_code, 403)
                deleted = self.client.delete("/api/history", base_url=origin, headers=headers, json={"confirm": True})
                self.assertEqual(deleted.status_code, 403)
        self.assertEqual(self.client.get("/api/history").json["total"], 0)

    def test_foreign_or_malformed_referer_without_origin_is_rejected(self):
        for referer in ("https://external.example/", "http://localhost:9999/", "http://localhost.attacker.example/",
                        "http://user:secret@localhost/", "http://[invalid/", "null", ""):
            for method, path, payload in (("GET", "/api/history", None),
                                          ("POST", "/api/scan", {"url": "https://example.com"}),
                                          ("DELETE", "/api/history", {"confirm": True})):
                with self.subTest(referer=referer, method=method):
                    response = self.client.open(path, method=method, headers={"Referer": referer}, json=payload)
                    self.assertEqual(response.status_code, 403)

    def test_injection_payload_cannot_change_sql_or_persist(self):
        payload = "https://example.com/';DROP%20TABLE%20scans;--?token=PRIVATE_TOKEN#PRIVATE_FRAGMENT"
        response = self.client.post("/api/scan", json={"url": payload, "save_history": True})
        self.assertEqual(response.status_code, 200)
        history = self.client.get("/api/history")
        self.assertEqual(history.json["total"], 1)
        self.assertEqual(history.json["scans"][0]["normalized_url"], "https://example.com")
        for value in ("DROP", "PRIVATE_TOKEN", "PRIVATE_FRAGMENT"):
            self.assertNotIn(value, history.get_data(as_text=True))

    def test_private_files_and_path_traversal_are_not_served(self):
        for path in ("/.env", "/.env.production", "/server-error.log", "/.venv/pyvenv.cfg", "/__pycache__/app.pyc", "/../app.py", "/%2e%2e/app.py", "/instance/scans.sqlite3", "/style.css/../app.py"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)


if __name__ == "__main__":
    unittest.main()
