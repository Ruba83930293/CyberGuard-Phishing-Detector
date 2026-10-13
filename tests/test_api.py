import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from app import create_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.app = create_app({"TESTING": True, "DATABASE": str(Path(directory.name) / "scans.sqlite3")})
        self.client = self.app.test_client()

    def test_scan_returns_analysis(self):
        response = self.client.post("/api/scan", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk_score"], 0)
        self.assertEqual(response.json["analysis_type"], "URL-text heuristics")

    def test_invalid_input_returns_json_error(self):
        for payload in ({}, [], None, {"url": None}, {"url": "bad"}, {"url": "https://example.com", "extra": True}):
            with self.subTest(payload=payload):
                response = self.client.post("/api/scan", data=self.app.json.dumps(payload), content_type="application/json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json)

    def test_malformed_json(self):
        response = self.client.post("/api/scan", data='{ "url":', content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "Malformed JSON request.")

    def test_content_type(self):
        response = self.client.post("/api/scan", data="url=https://example.com")
        self.assertEqual(response.status_code, 415)
        self.assertIn("error", response.json)

    def test_request_size_and_url_size_limits(self):
        response = self.client.post("/api/scan", json={"url": "x" * 17000})
        self.assertEqual(response.status_code, 413)
        self.assertIn("16 KiB", response.json["error"])
        response = self.client.post("/api/scan", json={"url": "x" * 4097})
        self.assertEqual(response.status_code, 400)
        self.assertIn("4096", response.json["error"])

    def test_method_and_private_files(self):
        response = self.client.get("/api/scan")
        self.assertEqual(response.status_code, 405)
        self.assertIn("POST", response.headers["Allow"])
        for path in ("/app.py", "/database.py", "/instance/scans.sqlite3", "/requirements.txt", "/.git/config", "/README.md", "/missing"):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_assets_and_headers(self):
        for path in ("/", "/style.css", "/script.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["Referrer-Policy"], "same-origin")
            self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)
            response.close()

    def test_internal_error_hides_details(self):
        with patch("app.analyze_url", side_effect=RuntimeError("private information")):
            with self.assertLogs(self.app.logger, level="ERROR"):
                response = self.client.post("/api/scan", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private information", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
