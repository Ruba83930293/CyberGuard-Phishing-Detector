from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import create_app


class HistoryApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "scans.sqlite3")
        self.app = create_app({"TESTING": True, "DATABASE": self.path})
        self.client = self.app.test_client()

    def scan(self, **options):
        return self.client.post("/api/scan", json={"url": "https://example.com/login?token=PRIVATE#secret", **options})

    def test_saving_requires_explicit_boolean_opt_in(self):
        self.assertFalse(self.scan().json["history_saved"])
        self.assertFalse(self.scan(save_history=False).json["history_saved"])
        self.assertEqual(self.client.get("/api/history").json["total"], 0)
        response = self.scan(save_history=True)
        self.assertTrue(response.json["history_saved"])
        self.assertEqual(response.json["stored_url"], "https://example.com")
        history = self.client.get("/api/history").json
        self.assertEqual(history["total"], 1)
        self.assertNotIn("PRIVATE", self.app.json.dumps(history))

    def test_invalid_flags_do_not_save(self):
        for value in ("true", 1, 0, None, [], {}):
            with self.subTest(value=value):
                self.assertEqual(self.scan(save_history=value).status_code, 400)
        self.assertEqual(self.client.get("/api/history").json["total"], 0)

    def test_opt_in_then_opt_out_and_latest_retrieval(self):
        saved = self.scan(save_history=True)
        self.assertEqual(saved.status_code, 200)
        self.assertFalse(self.scan(url="https://unsaved.example", save_history=False).json["history_saved"])
        latest = self.scan(url="http://192.0.2.1/login?token=PRIVATE#fragment", save_history=True)
        history = self.client.get("/api/history?limit=20&offset=0")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.headers["Cache-Control"], "no-store")
        self.assertEqual(history.json["total"], 2)
        first, second = history.json["scans"]
        self.assertEqual(first["id"], latest.json["saved_scan_id"])
        self.assertEqual(second["id"], saved.json["saved_scan_id"])
        self.assertEqual(first["normalized_url"], "http://192.0.2.1")
        self.assertEqual(first["risk_score"], latest.json["risk_score"])
        self.assertEqual(first["risk_level"], latest.json["risk_level"])
        self.assertEqual(first["reasons"], latest.json["reasons"])
        self.assertNotIn("PRIVATE", history.get_data(as_text=True))

    def test_credentials_rejected_with_and_without_saving(self):
        for save in (True, False):
            response = self.scan(url="https://user:PRIVATE@example.com", save_history=save)
            self.assertEqual(response.status_code, 400)
            self.assertIn("credentials", response.json["error"])
            self.assertNotIn("PRIVATE", response.json["error"])
        self.assertEqual(self.client.get("/api/history").json["total"], 0)

    def test_history_persists_across_app_instances(self):
        self.scan(save_history=True)
        other = create_app({"TESTING": True, "DATABASE": self.path}).test_client()
        self.assertEqual(other.get("/api/history").json["total"], 1)

    def test_delete_requires_confirmation(self):
        self.scan(save_history=True)
        for payload in ({}, {"confirm": False}, {"confirm": "true"}, {"confirm": 1}, {"confirm": True, "extra": 1}, []):
            self.assertEqual(self.client.delete("/api/history", json=payload).status_code, 400)
        self.assertEqual(self.client.delete("/api/history").status_code, 415)
        self.assertEqual(self.client.get("/api/history").json["total"], 1)
        response = self.client.delete("/api/history", json={"confirm": True})
        self.assertEqual(response.json["deleted"], 1)
        self.assertEqual(self.client.get("/api/history").json["statistics"]["total"], 0)

    def test_history_pagination_validation(self):
        for query in ("limit=0", "limit=101", "offset=-1", "limit=abc", "limit=1&limit=2", "extra=1", "offset=1000001", "limit=1%3BDROP"):
            with self.subTest(query=query):
                self.assertEqual(self.client.get("/api/history?" + query).status_code, 400)
        self.scan(save_history=True)
        self.assertEqual(len(self.client.get("/api/history?limit=1&offset=0").json["scans"]), 1)

    def test_database_failure_does_not_report_saved(self):
        with patch("app.save_scan", side_effect=sqlite3.OperationalError("private database path")):
            with self.assertLogs(self.app.logger, level="ERROR"):
                response = self.scan(save_history=True)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private database path", response.get_data(as_text=True))
        self.assertEqual(self.client.get("/api/history").json["total"], 0)


if __name__ == "__main__":
    unittest.main()
