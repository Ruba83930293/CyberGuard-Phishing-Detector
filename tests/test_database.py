import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from database import delete_history, get_history, initialize_database, save_scan, storage_url


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "history.sqlite3")
        initialize_database(self.path)

    def test_initialization_is_idempotent(self):
        save_scan(self.path, "https://example.com")
        initialize_database(self.path)
        self.assertEqual(get_history(self.path)["total"], 1)

    def test_empty_history_and_statistics(self):
        result = get_history(self.path)
        self.assertEqual(result["scans"], [])
        self.assertEqual(result["statistics"], {"total": 0, "average_score": 0, "low": 0, "medium": 0, "high": 0})

    def test_storage_normalizes_origin_and_removes_all_other_parts(self):
        for value, expected in (
            (" HTTPS://Example.COM:443/reset/my-secret?token=private#password ", "https://example.com"),
            ("http://Example.com:8080/path?password=private#token", "http://example.com:8080"),
            ("https://[2001:db8::1]:443/token?secret=private", "https://[2001:db8::1]"),
            ("https://b\u00fccher.example/path", "https://xn--bcher-kva.example"),
        ):
            with self.subTest(value=value):
                self.assertEqual(storage_url(value), expected)

    def test_saved_score_and_reasons_describe_original_url_without_values(self):
        save_scan(self.path, "https://example.com/reset/private-path?password=SECRET_PASSWORD&token=SECRET_TOKEN#SECRET_FRAGMENT")
        scan = get_history(self.path)["scans"][0]
        self.assertGreater(scan["risk_score"], 0)
        self.assertEqual(scan["normalized_url"], "https://example.com")
        self.assertTrue(scan["scanned_at"].endswith("+00:00"))
        self.assertIn("suspicious_keywords", {reason["rule"] for reason in scan["reasons"]})
        stored = json.dumps(scan)
        for secret in ("private-path", "SECRET_PASSWORD", "SECRET_TOKEN", "SECRET_FRAGMENT"):
            self.assertNotIn(secret, stored)
            self.assertNotIn(secret.encode(), Path(self.path).read_bytes())

    def test_credentials_never_reach_database(self):
        for url in ("https://user:secret@example.com", "https://user@example.com", "https://@example.com"):
            with self.assertRaisesRegex(ValueError, "credentials"):
                save_scan(self.path, url)
        self.assertEqual(get_history(self.path)["total"], 0)

    def test_statistics_order_and_pagination(self):
        for url in ("https://example.com", "http://192.0.2.1/login", "http://a.b.c.d.paypa1.example/login/verify/password/account/%2540"):
            save_scan(self.path, url)
        result = get_history(self.path, limit=1, offset=1)
        self.assertEqual(result["scans"][0]["risk_level"], "Medium")
        self.assertEqual(result["statistics"], {"total": 3, "average_score": 41.7, "low": 1, "medium": 1, "high": 1})

    def test_delete_all_and_statistics_reset(self):
        save_scan(self.path, "https://example.com")
        self.assertEqual(delete_history(self.path), 1)
        self.assertEqual(delete_history(self.path), 0)
        self.assertEqual(get_history(self.path)["statistics"]["total"], 0)

    def test_parameterized_queries_and_invalid_pagination(self):
        save_scan(self.path, "https://example.com/';DROP%20TABLE%20scans;--")
        self.assertEqual(get_history(self.path)["total"], 1)
        for limit, offset in ((0, 0), (101, 0), (True, 0), (20, -1), (20, 1000001), ("1; DROP TABLE scans", 0)):
            with self.assertRaises(ValueError):
                get_history(self.path, limit, offset)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
