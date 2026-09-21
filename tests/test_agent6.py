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
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine


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
        self.assertTrue(op.get("in_feed"))
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

    # 22. End-to-End Positive Threat Intel Pipeline Contract (OpenPhish -> A6 -> Ledger -> TCE)
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation._get_openphish_feed")
    def test_22_openphish_positive_threat_intel_pipeline_contract(self, mock_feed, mock_ip):
        mock_feed.return_value = ({"https://verified-phish.com/login"}, "2026-09-04T00:00:00Z")
        
        # 1. Agent 6 Execution
        result = analyze_reputation("https://verified-phish.com/login")
        self.assertEqual(result.get("status"), "success")
        
        # 2. Raw Provider Result Inspection
        op_res = result.get("openphish", {})
        self.assertEqual(op_res.get("status"), "success")
        self.assertTrue(op_res.get("found"))
        self.assertTrue(op_res.get("in_feed"))
        self.assertEqual(op_res.get("matched_url"), "https://verified-phish.com/login")

        # 3. Evidence Generation & Invariants
        evidence_list = result.get("evidence", [])
        e6_04 = next((e for e in evidence_list if e.get("evidence_id") == "E6-04"), None)
        self.assertIsNotNone(e6_04, "Evidence E6-04 must be present in Agent 6 output")
        self.assertEqual(e6_04["type"], "threat_intelligence")
        self.assertEqual(e6_04["severity"], "critical")
        self.assertTrue(e6_04["value"])
        self.assertEqual(e6_04["source"], "OpenPhish")
        self.assertEqual(e6_04["evidence_strength"], 0.95)
        self.assertEqual(e6_04["category"], "phishing_feed_match")

        # 4. Evidence Normalizer & Ledger Ingestion
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        ledger_entry = next((e for e in ledger.entries if e.get("evidence_id") == "E6-04"), None)
        self.assertIsNotNone(ledger_entry, "Evidence E6-04 must be ingested into Ledger")
        self.assertEqual(ledger_entry["severity"], "critical")
        self.assertEqual(ledger_entry["status"], "success")
        self.assertEqual(ledger_entry["evidence_type"], "threat_intelligence")

        # 5. TCE Processing & Mathematical Contribution
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        tce_item = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-04"), None)
        self.assertIsNotNone(tce_item, "E6-04 must be evaluated in TCE evidence contributions")
        self.assertEqual(tce_item["polarity"], "risk_increasing")
        self.assertEqual(tce_item["severity_weight"], 1.0)
        self.assertEqual(tce_item["type_reliability"], 0.9)
        self.assertAlmostEqual(tce_item["base_contribution"], 1.0 * 0.95 * 0.90, places=4)
        self.assertGreater(tce_item["final_item_contribution"], 0.0)
        
        # 6. Risk Score & Verdict Invariant
        self.assertGreater(tce_eval["risk_score"], 0.0)
        self.assertNotEqual(tce_eval["verdict"], "benign")


    # 23. URLhaus End-to-End Positive Match Pipeline Contract
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_urlhaus")
    def test_23_urlhaus_positive_pipeline_contract(self, mock_uh, mock_ip):
        mock_uh.return_value = {
            "status": "success",
            "threat_detected": True,
            "url_found": True,
            "host_found": False,
            "threat": "malware_download",
            "date_added": "2026-08-20 14:22:10 UTC",
            "status_from_source": "online",
            "checked_at": "2026-09-04T00:00:00Z"
        }
        result = analyze_reputation("https://malware-drop.example.com/payload.exe")
        self.assertEqual(result.get("status"), "success")
        evidence_list = result.get("evidence", [])
        e6_06 = next((e for e in evidence_list if e.get("evidence_id") == "E6-06"), None)
        self.assertIsNotNone(e6_06)
        self.assertEqual(e6_06["severity"], "critical")
        self.assertEqual(e6_06["category"], "threat_intel_blocklist")
        self.assertEqual(e6_06["type"], "threat_intelligence")
        self.assertTrue(e6_06["value"])

    # 24. Public Blacklist Filtering: Clean vs Listed
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_public_blacklists")
    def test_24_dnsbl_clean_vs_listed_filtering(self, mock_bl, mock_ip):
        # 1. Clean case: all queried DNSBLs return listed=False
        mock_bl.return_value = [
            {"source": "Spamcop BL", "listed": False, "source_status": "success"},
            {"source": "SURBL", "listed": False, "source_status": "success"}
        ]
        res_clean = analyze_reputation("https://clean-site.example.com")
        e6_08_clean = next((e for e in res_clean["evidence"] if e.get("evidence_id") == "E6-08"), None)
        self.assertIsNotNone(e6_08_clean)
        self.assertEqual(e6_08_clean["value"], 0)
        self.assertEqual(e6_08_clean["severity"], "info")
        self.assertEqual(e6_08_clean["category"], "clean_reputation_check")

        # 2. Listed case: 1 DNSBL returns listed=True
        from agents.agent6_reputation import _CACHE
        _CACHE.clear()
        mock_bl.return_value = [
            {"source": "Spamcop BL", "listed": True, "source_status": "success"},
            {"source": "SURBL", "listed": False, "source_status": "success"}
        ]
        res_listed = analyze_reputation("https://spam-domain.example.com")
        e6_08_listed = next((e for e in res_listed["evidence"] if e.get("evidence_id") == "E6-08"), None)
        self.assertIsNotNone(e6_08_listed)
        self.assertEqual(e6_08_listed["value"], 1)
        self.assertEqual(e6_08_listed["severity"], "medium")
        self.assertEqual(e6_08_listed["category"], "blacklist_entry")

    # 25. Multiple Independent Threat-Intel Confirmations (VT + GSB + OpenPhish)
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_virustotal", return_value={"status": "success", "malicious": 10, "suspicious": 2})
    @patch("agents.agent6_reputation.query_google_safe_browsing", return_value={"status": "success", "threat_detected": True, "threat_types": ["MALWARE"]})
    @patch("agents.agent6_reputation.query_openphish", return_value={"status": "success", "found": True, "in_feed": True, "matched_url": "https://multi-malicious.com"})
    def test_25_multiple_threat_intel_confirmations(self, mock_op, mock_gsb, mock_vt, mock_ip):
        result = analyze_reputation("https://multi-malicious.com")
        self.assertEqual(result["status"], "success")
        
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        # Corroborating items evaluated
        e6_01 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-01"), None)
        e6_02 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-02"), None)
        e6_04 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-04"), None)
        
        self.assertIsNotNone(e6_01)
        self.assertIsNotNone(e6_02)
        self.assertIsNotNone(e6_04)
        self.assertEqual(e6_01["polarity"], "risk_increasing")
        self.assertEqual(e6_02["polarity"], "risk_increasing")
        self.assertEqual(e6_04["polarity"], "risk_increasing")
        self.assertGreaterEqual(tce_eval["risk_score"], 60.0)

    # 26. Conflicting Provider Results (VT Malicious vs GSB Clean)
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_virustotal", return_value={"status": "success", "malicious": 5})
    @patch("agents.agent6_reputation.query_google_safe_browsing", return_value={"status": "success", "threat_detected": False, "threat_types": []})
    def test_26_conflicting_provider_results_preserved(self, mock_gsb, mock_vt, mock_ip):
        result = analyze_reputation("https://conflict-site.com")
        self.assertEqual(result["status"], "success")
        
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        e6_01 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-01"), None)
        e6_02 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-02"), None)
        
        # VT malicious is risk_increasing
        self.assertEqual(e6_01["polarity"], "risk_increasing")
        self.assertEqual(e6_01["severity_weight"], 1.0)
        # GSB clean is neutral, weight 0.0
        self.assertEqual(e6_02["polarity"], "neutral")
        self.assertEqual(e6_02["severity_weight"], 0.0)
        # Risk score is not zero due to VT
        self.assertGreater(tce_eval["risk_score"], 0.0)

    # 27. HTTP 500 & Connection Failures Produce Neutral Telemetry
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_virustotal", return_value={"status": "error", "message": "HTTP 500 Internal Server Error"})
    @patch("agents.agent6_reputation.query_phishtank", return_value={"status": "unavailable", "message": "Connection refused"})
    def test_27_provider_failure_produces_neutral_evidence(self, mock_pt, mock_vt, mock_ip):
        result = analyze_reputation("https://failing-provider.com")
        self.assertEqual(result["status"], "success")
        
        evidence_list = result["evidence"]
        e6_01 = next((e for e in evidence_list if e.get("evidence_id") == "E6-01"), None)
        e6_03 = next((e for e in evidence_list if e.get("evidence_id") == "E6-03"), None)
        
        self.assertEqual(e6_01["severity"], "info")
        self.assertEqual(e6_03["severity"], "info")
        self.assertEqual(e6_01["category"], "clean_reputation_check")
        self.assertEqual(e6_03["category"], "clean_reputation_check")

    # 28. Evidence ID Inventory & Schema Validation
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    def test_28_evidence_id_inventory_and_schema_validation(self, mock_ip):
        from services.evidence_schema import validate_evidence_item
        result = analyze_reputation("https://schema-test.example.com")
        self.assertEqual(result["status"], "success")
        
        evidence_list = result["evidence"]
        self.assertEqual(len(evidence_list), 10)
        
        expected_ids = [f"E6-{i:02d}" for i in range(1, 11)]
        actual_ids = [e["evidence_id"] for e in evidence_list]
        self.assertEqual(actual_ids, expected_ids)
        self.assertEqual(len(set(actual_ids)), 10, "Evidence IDs must be strictly unique")
        
        for item in evidence_list:
            is_valid, err = validate_evidence_item(item)
            self.assertTrue(is_valid, f"Item {item.get('evidence_id')} failed validation: {err}")

    # 29. PhishTank Unverified Community Submission (in_database=True, verified=False)
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_phishtank", return_value={
        "status": "success",
        "found": True,
        "in_database": True,
        "verified_phishing": False,
        "verification_date": "Not Available"
    })
    def test_29_phishtank_unverified_submission_is_not_critical(self, mock_pt, mock_ip):
        from agents.agent6_reputation import _CACHE
        _CACHE.clear()
        result = analyze_reputation("https://unverified-submission.example.com")
        self.assertEqual(result["status"], "success")
        
        evidence_list = result["evidence"]
        e6_03 = next((e for e in evidence_list if e.get("evidence_id") == "E6-03"), None)
        self.assertIsNotNone(e6_03)
        self.assertEqual(e6_03["severity"], "info")
        self.assertEqual(e6_03["category"], "clean_reputation_check")
        self.assertFalse(e6_03["value"])
        
        # Test in Evidence Ledger & TCE
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        e6_03_contrib = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-03"), None)
        self.assertIsNotNone(e6_03_contrib)
        self.assertEqual(e6_03_contrib["polarity"], "neutral")
        self.assertEqual(e6_03_contrib["severity_weight"], 0.0)

    # 30. PhishTank Verified Phishing (in_database=True, verified=True)
    @patch("agents.agent6_reputation.resolve_ip", return_value="93.184.216.34")
    @patch("agents.agent6_reputation.query_phishtank", return_value={
        "status": "success",
        "found": True,
        "in_database": True,
        "verified_phishing": True,
        "verification_date": "2026-09-01T12:00:00Z"
    })
    def test_30_phishtank_verified_phishing_is_critical(self, mock_pt, mock_ip):
        from agents.agent6_reputation import _CACHE
        _CACHE.clear()
        result = analyze_reputation("https://verified-phish.example.com")
        self.assertEqual(result["status"], "success")
        
        evidence_list = result["evidence"]
        e6_03 = next((e for e in evidence_list if e.get("evidence_id") == "E6-03"), None)
        self.assertIsNotNone(e6_03)
        self.assertEqual(e6_03["severity"], "critical")
        self.assertEqual(e6_03["category"], "phishing_feed_match")
        self.assertTrue(e6_03["value"])
        self.assertEqual(e6_03["evidence_strength"], 0.95)
        
        # Test in Evidence Ledger & TCE
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        e6_03_contrib = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E6-03"), None)
        self.assertIsNotNone(e6_03_contrib)
        self.assertEqual(e6_03_contrib["polarity"], "risk_increasing")
        self.assertEqual(e6_03_contrib["severity_weight"], 1.0)

    # 31. PhishTank String Boolean Parsing ("y" vs "n")
    @patch("requests.post")
    def test_31_phishtank_string_parsing(self, mock_post):
        # Case A: verified="y", valid="y"
        mock_resp_a = MagicMock()
        mock_resp_a.status_code = 200
        mock_resp_a.json.return_value = {
            "results": {
                "in_database": "y",
                "verified": "y",
                "valid": "y",
                "verified_at": "2026-05-01T00:00:00Z"
            }
        }
        mock_post.return_value = mock_resp_a
        pt_a = query_phishtank("https://phish-y.example.com")
        self.assertTrue(pt_a["verified_phishing"])
        self.assertTrue(pt_a["in_database"])

        # Case B: in_database="y", verified="n", valid="y" (unverified community submission)
        mock_resp_b = MagicMock()
        mock_resp_b.status_code = 200
        mock_resp_b.json.return_value = {
            "results": {
                "in_database": "y",
                "verified": "n",
                "valid": "y"
            }
        }
        mock_post.return_value = mock_resp_b
        pt_b = query_phishtank("https://unverified-n.example.com")
        self.assertFalse(pt_b["verified_phishing"])
        self.assertTrue(pt_b["in_database"])


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

