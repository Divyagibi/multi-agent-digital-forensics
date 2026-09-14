# -*- coding: utf-8 -*-
"""
tests/test_agent6.py
====================
Comprehensive mock-based test suite for Agent 6 -- Reputation & Threat Intelligence.

Tests cover:
    1. Valid URL analysis structure
    2. Invalid & empty URL input
    3. VirusTotal success with detections
    4. VirusTotal not configured / unavailable
    5. Google Safe Browsing threat detected
    6. Google Safe Browsing no threat detected (clean)
    7. PhishTank match (found & verified)
    8. PhishTank no match (clean)
    9. OpenPhish threat match
    10. AbuseIPDB IP reputation lookup
    11. URLHaus malware match
    12. URLHaus no match
    13. Spamhaus listed result
    14. Spamhaus not listed / not configured
    15. Service timeout resilience
    16. Rate limit (HTTP 429) handling
    17. API key missing handling (not_configured status)
    18. Multi-source failure isolation (one failed service does not crash Agent 6)
    19. DNS resolution failure handling
    20. Malformed JSON response from external service
    21. Strict schema assertion (verifies NO trust score, risk score, or classification verdicts)

Run:
    python tests/test_agent6.py
"""

import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from agents.agent6_reputation import (
    analyze_reputation,
    get_reputation_evidence,
    extract_domain_info,
    resolve_ip,
    query_virustotal,
    query_google_safe_browsing,
    query_phishtank,
    query_openphish,
    query_abuseipdb,
    query_urlhaus,
    query_spamhaus,
    query_scamadviser,
    query_public_blacklists,
    query_community_reputation
)


class TestAgent6Reputation(unittest.TestCase):

    def setUp(self):
        # Clear in-memory caches before each test
        from agents.agent6_reputation import _CACHE, _OPENPHISH_CACHE
        _CACHE.clear()
        _OPENPHISH_CACHE["feed"] = set()
        _OPENPHISH_CACHE["fetched_at"] = 0.0

    # 1. Valid URL analysis
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    def test_01_valid_url(self, mock_ip):
        result = analyze_reputation("https://example.com/test")
        self.assertIn(result.get("agent"), ("Reputation & Threat Intelligence", "Agent 6"))
        self.assertEqual(result.get("status"), "success")
        self.assertIn("input", result)
        self.assertEqual(result["input"]["domain"], "example.com")
        self.assertEqual(result["input"]["ip"], "93.184.216.34")

    # 2. Invalid URL
    def test_02_invalid_url(self):
        result = analyze_reputation("")
        self.assertEqual(result.get("status"), "error")
        self.assertTrue(len(result.get("errors", [])) > 0)
        self.assertEqual(result.get("virustotal", {}).get("status"), "error")

    # 3. VirusTotal success
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_vt_key"})
    @patch("requests.get")
    def test_03_virustotal_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 10
                    },
                    "reputation": -5,
                    "last_analysis_date": 1700000000
                }
            }
        }
        mock_get.return_value = mock_resp

        vt = query_virustotal("https://malicious.example.com")
        self.assertEqual(vt.get("status"), "success")
        self.assertEqual(vt.get("malicious"), 3)
        self.assertEqual(vt.get("suspicious"), 1)
        self.assertEqual(vt.get("harmless"), 60)
        self.assertEqual(vt.get("total_engines"), 74)
        self.assertEqual(vt.get("reputation"), -5)
        self.assertTrue(vt.get("report_available"))

    # 4. VirusTotal API unavailable / not configured
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=True)
    def test_04_virustotal_not_configured(self):
        vt = query_virustotal("https://example.com")
        self.assertEqual(vt.get("status"), "not_configured")
        self.assertIn("not configured", vt.get("message", "").lower())

    # 5. Google Safe Browsing threat detected
    @patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "dummy_gsb_key"})
    @patch("requests.post")
    def test_05_google_safe_browsing_threat(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [
                {"threatType": "MALWARE"},
                {"threatType": "SOCIAL_ENGINEERING"}
            ]
        }
        mock_post.return_value = mock_resp

        gsb = query_google_safe_browsing("https://phishing-site.example.com")
        self.assertEqual(gsb.get("status"), "success")
        self.assertTrue(gsb.get("threat_detected"))
        self.assertIn("MALWARE", gsb.get("threat_types", []))
        self.assertIn("SOCIAL_ENGINEERING", gsb.get("threat_types", []))

    # 6. Google Safe Browsing clean
    @patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "dummy_gsb_key"})
    @patch("requests.post")
    def test_06_google_safe_browsing_clean(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        gsb = query_google_safe_browsing("https://clean.example.com")
        self.assertEqual(gsb.get("status"), "success")
        self.assertFalse(gsb.get("threat_detected"))
        self.assertEqual(gsb.get("threat_types"), [])

    # 7. PhishTank match
    @patch("requests.post")
    def test_07_phishtank_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "in_database": True,
                "verified": True,
                "verified_at": "2026-01-01T12:00:00Z",
                "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=12345"
            }
        }
        mock_post.return_value = mock_resp

        pt = query_phishtank("https://phish.example.com")
        self.assertEqual(pt.get("status"), "success")
        self.assertTrue(pt.get("found"))
        self.assertTrue(pt.get("verified_phishing"))
        self.assertEqual(pt.get("verification_date"), "2026-01-01T12:00:00Z")

    # 8. PhishTank no match
    @patch("requests.post")
    def test_08_phishtank_no_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "in_database": False
            }
        }
        mock_post.return_value = mock_resp

        pt = query_phishtank("https://clean.example.com")
        self.assertEqual(pt.get("status"), "success")
        self.assertFalse(pt.get("found"))
        self.assertFalse(pt.get("verified_phishing"))

    # 9. OpenPhish match
    @patch("agents.agent6_reputation._get_openphish_feed")
    def test_09_openphish_match(self, mock_feed):
        mock_feed.return_value = ({"https://evil-bank.com/login", "http://fake-paypal.com"}, "2026-09-04T00:00:00Z")

        op = query_openphish("https://evil-bank.com/login", "evil-bank.com")
        self.assertEqual(op.get("status"), "success")
        self.assertTrue(op.get("found"))
        self.assertEqual(op.get("matched_url"), "https://evil-bank.com/login")

    # 10. AbuseIPDB lookup
    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "dummy_abuse_key"})
    @patch("requests.get")
    def test_10_abuseipdb_lookup(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "203.0.113.10",
                "abuseConfidenceScore": 35,
                "totalReports": 12,
                "countryCode": "US",
                "isp": "Cloud Provider",
                "domain": "cloud.net",
                "usageType": "Data Center/Web Hosting",
                "lastReportedAt": "2026-09-01T10:00:00Z"
            }
        }
        mock_get.return_value = mock_resp

        abuse = query_abuseipdb("203.0.113.10")
        self.assertEqual(abuse.get("status"), "success")
        self.assertEqual(abuse.get("abuse_confidence_score"), 35)
        self.assertEqual(abuse.get("total_reports"), 12)
        self.assertEqual(abuse.get("country"), "US")
        self.assertEqual(abuse.get("usage_type"), "Data Center/Web Hosting")

    # 11. URLHaus match
    @patch("requests.post")
    def test_11_urlhaus_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "date_added": "2026-08-20 14:22:10 UTC",
            "url_status": "online"
        }
        mock_post.return_value = mock_resp

        uh = query_urlhaus("https://malware-drop.com/payload.exe", "malware-drop.com")
        self.assertEqual(uh.get("status"), "success")
        self.assertTrue(uh.get("url_found"))
        self.assertEqual(uh.get("threat"), "malware_download")

    # 12. URLHaus no match
    @patch("requests.post")
    def test_12_urlhaus_no_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "no_results"
        }
        mock_post.return_value = mock_resp

        uh = query_urlhaus("https://clean-site.example.com", "clean-site.example.com")
        self.assertEqual(uh.get("status"), "success")
        self.assertFalse(uh.get("url_found"))
        self.assertFalse(uh.get("host_found"))

    # 13. Spamhaus listed
    @patch.dict(os.environ, {"SPAMHAUS_DQS_KEY": "test_dqs_key"})
    @patch("dns.resolver.Resolver")
    def test_13_spamhaus_listed(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "127.0.0.2"
        mock_resolver.resolve.return_value = [mock_rdata]
        mock_resolver_cls.return_value = mock_resolver

        sh = query_spamhaus("198.51.100.5", "example.com")
        self.assertEqual(sh.get("status"), "success")
        self.assertTrue(sh.get("listed"))
        self.assertTrue(len(sh.get("lists", [])) > 0)

    # 14. Spamhaus unlisted / not configured
    @patch.dict(os.environ, {"SPAMHAUS_DQS_KEY": ""}, clear=True)
    def test_14_spamhaus_not_configured(self):
        sh = query_spamhaus("198.51.100.5", "example.com")
        self.assertEqual(sh.get("status"), "not_configured")

    # 15. Service timeout resilience
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_key"})
    @patch("requests.get", side_effect=Exception("Request timed out"))
    def test_15_service_timeout(self, mock_get):
        vt = query_virustotal("https://example.com")
        self.assertEqual(vt.get("status"), "error")
        self.assertIn("timed out", vt.get("message", "").lower())

    # 16. Rate limit handling
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_key"})
    @patch("requests.get")
    def test_16_rate_limited(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        vt = query_virustotal("https://example.com")
        self.assertEqual(vt.get("status"), "rate_limited")

    # 17. Missing API key handling
    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}, clear=True)
    def test_17_missing_api_key(self):
        abuse = query_abuseipdb("203.0.113.1")
        self.assertEqual(abuse.get("status"), "not_configured")

    # 18. Multi-source failure isolation
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_virustotal", return_value={"status": "error", "message": "Failed"})
    @patch("agents.agent6_reputation.query_google_safe_browsing", return_value={"status": "success", "threat_detected": False, "threat_types": []})
    def test_18_multi_source_isolation(self, mock_gsb, mock_vt, mock_ip):
        result = analyze_reputation("https://example.com")
        self.assertEqual(result.get("status"), "success")
        self.assertEqual(result.get("virustotal", {}).get("status"), "error")
        self.assertEqual(result.get("google_safe_browsing", {}).get("status"), "success")

    # 19. Domain resolution failure handling
    @patch("agents.agent6_reputation.resolve_ip", return_value=None)
    def test_19_domain_resolution_failure(self, mock_ip):
        result = analyze_reputation("https://nonexistent-domain-xyz-123.fake")
        self.assertEqual(result.get("status"), "success")
        self.assertIsNone(result["input"]["ip"])

    # 20. Malformed response handling
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_key"})
    @patch("requests.get")
    def test_20_malformed_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_resp

        vt = query_virustotal("https://example.com")
        self.assertEqual(vt.get("status"), "error")

    # 21. Strict Schema Assertion: NO trust/risk scores or verdicts allowed
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    def test_21_schema_no_risk_scores(self, mock_ip):
        result = analyze_reputation("https://example.com")
        forbidden_keys = [
            "trust_score", "trustscore", "risk_score", "riskscore",
            "phishing_probability", "verdict", "final_score",
            "classification", "confidence"
        ]
        for key in forbidden_keys:
            self.assertNotIn(key, result, f"Agent 6 response MUST NOT contain '{key}'")


def run_all_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAgent6Reputation)
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)
    print("\n" + "=" * 60)
    print(f"Agent 6 Test Suite Results: Ran {test_result.testsRun} tests.")
    if test_result.wasSuccessful():
        print("ALL AGENT 6 TESTS PASSED SUCCESSFULLY.")
    else:
        print(f"FAILURES: {len(test_result.failures)}, ERRORS: {len(test_result.errors)}")
    print("=" * 60)
    return test_result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
