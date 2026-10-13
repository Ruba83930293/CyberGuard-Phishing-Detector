import socket
import unittest
from unittest.mock import patch

from phishing_detector import analyze_url, classify_score


class DetectorTests(unittest.TestCase):
    def rules(self, value):
        return {reason["rule"]: reason["points"] for reason in analyze_url(value)["reasons"]}

    def test_plain_url_is_low_without_safety_claim(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["reasons"], [])
        self.assertIn("cannot guarantee", result["limitation"])

    def test_normalization_preserves_indicators(self):
        for value in ("example.com/a%2Fb", "//example.com/a%2Fb", "https://example.com/a%2Fb"):
            with self.subTest(value=value):
                self.assertEqual(analyze_url(value)["url"], "https://example.com/a%2Fb")
                self.assertIn("unusual_encoding", self.rules(value))

    def test_ip_addresses(self):
        for value in ("https://192.0.2.1", "https://[2001:db8::1]"):
            with self.subTest(value=value):
                self.assertEqual(self.rules(value)["ip_address"], 25)
                self.assertNotIn("excessive_subdomains", self.rules(value))

    def test_length_boundaries(self):
        base = "https://example.com/"
        for length, points in ((100, None), (101, 10), (200, 10), (201, 20)):
            with self.subTest(length=length):
                self.assertEqual(self.rules(base + "x" * (length - len(base))).get("url_length"), points)

    def test_subdomain_boundaries(self):
        self.assertNotIn("excessive_subdomains", self.rules("https://a.b.c.example.com"))
        self.assertEqual(self.rules("https://a.b.c.d.example.com")["excessive_subdomains"], 15)

    def test_credentials_are_rejected_but_at_in_path_is_allowed(self):
        for url in ("https://example.org@example.com", "https://user:secret@example.com", "https://@example.com"):
            with self.assertRaisesRegex(ValueError, "credentials"):
                analyze_url(url)
        self.assertNotIn("misleading_at", self.rules("https://example.com/contact@home"))

    def test_keyword_weight_cap_and_decoding(self):
        self.assertEqual(self.rules("https://example.com/login/verify/password/account/free")["suspicious_keywords"], 20)
        self.assertEqual(self.rules("https://example.com/%6cogin")["suspicious_keywords"], 5)

    def test_encoding_indicators(self):
        for path in ("a%2Fb", "%2540", "%00", "%61%62%63%64%65"):
            with self.subTest(path=path):
                self.assertEqual(self.rules("https://example.com/" + path)["unusual_encoding"], 20)
        self.assertNotIn("unusual_encoding", self.rules("https://example.com/a%20b"))

    def test_punycode_and_unicode(self):
        self.assertEqual(self.rules("https://xn--bcher-kva.example")["punycode"], 15)
        self.assertEqual(self.rules("https://b\u00fccher.example")["punycode"], 15)
        self.assertNotIn("lookalike_domain", self.rules("https://b\u00fccher.example"))

    def test_lookalike_indicators(self):
        for url in ("https://paypa1.example", "https://p\u0430ypal.example"):
            with self.subTest(url=url):
                self.assertEqual(self.rules(url)["lookalike_domain"], 20)
        self.assertNotIn("lookalike_domain", self.rules("https://paypal.example"))

    def test_score_cap_and_explanations(self):
        result = analyze_url("http://a.b.c.d.paypa1.example/" + "x" * 210 + "/login/verify/password/account/%2540")
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["raw_score"], sum(reason["points"] for reason in result["reasons"]))
        self.assertGreater(result["raw_score"], 100)
        self.assertTrue(all(reason["explanation"] for reason in result["reasons"]))

    def test_classification_boundaries(self):
        for score, level in ((0, "Low"), (29, "Low"), (30, "Medium"), (59, "Medium"), (60, "High"), (100, "High")):
            self.assertEqual(classify_score(score), level)

    def test_invalid_inputs(self):
        values = (None, 42, [], {}, "", "  ", "not-a-url", "not a url", "ftp://example.com", "javascript:alert(1)",
                  "https:example.com", "https:///example.com", "https://", "https://bad_domain.example", "https://-bad.example",
                  "https://example..com", "https://example.com..", "https://example.com:65536", "https://example.com:0",
                  "https://example.com:", "https://[bad]", "https://[v1.example]", "https://[::1]example.com", "https://[fe80::1%25eth0]", "https://999.999.999.999", "https://example.com/%ZZ",
                  "https://example.com/\\a", "https://example.com/\x00", "https://xn--bad-.example", "x" * 4097)
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    analyze_url(value)

    def test_optional_ports_and_local_addresses(self):
        for value in ("example.com:8080/path", "http://localhost:3000", "https://[::1]:443", "HTTPS://Example.com."):
            with self.subTest(value=value):
                self.assertIn(analyze_url(value)["risk_level"], ("Low", "Medium", "High"))

    def test_no_network_access(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
                patch.object(socket, "socket", side_effect=AssertionError("Network forbidden")):
            analyze_url("http://example.com/login/%2540")


if __name__ == "__main__":
    unittest.main()
