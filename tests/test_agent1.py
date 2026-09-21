# -*- coding: utf-8 -*-
"""
tests/test_agent1.py
====================
Comprehensive mock-based unit & pipeline test suite for Agent 1 -- Domain Identity.

Covers all 11 core provider states & pipeline contracts:
    1. Valid domain with complete RDAP/WHOIS data
    2. Domain with privacy-redacted registration data
    3. Domain with missing RDAP data (HTTP 404)
    4. Provider unavailable (HTTP 500 / Network Error)
    5. Provider timeout (10-second limit exceeded)
    6. Malformed provider response (Invalid JSON)
    7. Internationalized / Punycode domain
    8. High-entropy domain
    9. Normal low-entropy domain
    10. Target without DNSSEC dependency
    11. Target with DNSSEC presence (A1 decoupled identity focus)
    12. Young domain (<30 days) contract & TCE risk contribution
    13. Mature domain (>=730 days) contract & TCE mitigation
    14. Deep subdomain / www / path / query param normalization
    15. Invalid / empty URL input
    16. End-to-End Evidence Pipeline Contract (A1 -> Schema -> Normalizer -> Ledger -> TCE)
    17. Strict Schema Assertion (NO trust_score, risk_score, or verdicts in Agent output)

Run:
    python -m unittest tests/test_agent1.py
"""

import sys
import os
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent1_domain import (
    analyze_domain,
    extract_domain,
    calculate_domain_age,
    extract_entity_information,
    extract_domain_status,
    query_rdap
)
from services.evidence_schema import validate_evidence_item
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine


def _make_rdap_payload(reg_days_ago=1000, exp_days_future=365, org="Google LLC", country="US", registrar="MarkMonitor Inc."):
    now = datetime.now(timezone.utc)
    reg_date = (now - timedelta(days=reg_days_ago)).isoformat()
    exp_date = (now + timedelta(days=exp_days_future)).isoformat()
    return {
        "status": ["clientTransferProhibited", "serverDeleteProhibited"],
        "events": [
            {"eventAction": "registration", "eventDate": reg_date},
            {"eventAction": "expiration", "eventDate": exp_date}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", registrar]]]
            },
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Domain Administrator"],
                    ["org", {}, "text", org],
                    ["country", {}, "text", country]
                ]]
            }
        ]
    }


class TestAgent1DomainIdentity(unittest.TestCase):

    # 1. Valid domain with complete RDAP/WHOIS data
    @patch("agents.agent1_domain.query_rdap")
    def test_01_valid_domain_complete_rdap(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=1500, org="Example Corp", country="US", registrar="Example Registrar LLC")}
        res = analyze_domain("https://example.com")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_name"], "example.com")
        self.assertEqual(res["data"]["registrar"], "Example Registrar LLC")
        self.assertEqual(res["data"]["registrant_organization"], "Example Corp")
        self.assertEqual(res["data"]["registrant_country"], "US")
        self.assertTrue(res["data"]["whois_available"])
        self.assertEqual(len(res["evidence"]), 9)

    # 2. Domain with privacy-redacted registration data
    @patch("agents.agent1_domain.query_rdap")
    def test_02_privacy_redacted_domain(self, mock_rdap):
        payload = _make_rdap_payload(reg_days_ago=500, org="Withheld for Privacy", country="IS", registrar="NameCheap Inc.")
        mock_rdap.return_value = {"success": True, "data": payload}
        res = analyze_domain("https://privacy-domain.com")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["registrant_organization"], "Withheld for Privacy")
        # Ensure privacy masking is not classified as verified corporate registrant
        e1_07 = next((e for e in res["evidence"] if e["evidence_id"] == "E1-07"), None)
        self.assertIsNotNone(e1_07)
        self.assertEqual(e1_07["category"], "registrant_org_telemetry")
        self.assertEqual(e1_07["severity"], "info")

    # 3. Domain with missing RDAP data (HTTP 404)
    @patch("agents.agent1_domain.query_rdap")
    def test_03_missing_rdap_data_404(self, mock_rdap):
        mock_rdap.return_value = {"success": False, "error": "Domain 'nonexistent.xyz' not found in RDAP (HTTP 404)"}
        res = analyze_domain("https://nonexistent.xyz")
        self.assertEqual(res["status"], "partial")
        self.assertFalse(res["data"]["whois_available"])
        # Check evidence consistency (E1-01 and E1-06 present without ID collision)
        eids = [e["evidence_id"] for e in res["evidence"]]
        self.assertIn("E1-01", eids)
        self.assertIn("E1-06", eids)
        self.assertNotIn("E1-02", eids)

    # 4. Provider unavailable (HTTP 500 / Network Error)
    @patch("agents.agent1_domain.query_rdap")
    def test_04_provider_unavailable_500(self, mock_rdap):
        mock_rdap.return_value = {"success": False, "error": "RDAP returned HTTP 500"}
        res = analyze_domain("https://example.net")
        self.assertEqual(res["status"], "partial")
        self.assertFalse(res["data"]["whois_available"])
        self.assertGreater(len(res["errors"]), 0)

    # 5. Provider timeout
    @patch("agents.agent1_domain.query_rdap")
    def test_05_provider_timeout(self, mock_rdap):
        mock_rdap.return_value = {"success": False, "error": "RDAP request timed out (10-second limit exceeded)"}
        res = analyze_domain("https://timeout-target.com")
        self.assertEqual(res["status"], "partial")
        self.assertIn("timed out", res["errors"][0].lower())

    # 6. Malformed provider response
    @patch("agents.agent1_domain.query_rdap")
    def test_06_malformed_provider_response(self, mock_rdap):
        mock_rdap.return_value = {"success": False, "error": "Failed to parse RDAP JSON response (malformed data)"}
        res = analyze_domain("https://malformed-target.com")
        self.assertEqual(res["status"], "partial")
        self.assertIn("malformed", res["errors"][0].lower())

    # 7. Internationalized / Punycode domain
    @patch("agents.agent1_domain.query_rdap")
    def test_07_punycode_domain(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=400, org="IDN Owner", registrar="Puny Registrar")}
        res = analyze_domain("https://xn--e1afmkfd.xn--p1ai")
        self.assertEqual(res["status"], "success")
        self.assertIn("xn--", res["data"]["domain_name"])

    # 8. High-entropy domain extraction
    @patch("agents.agent1_domain.query_rdap")
    def test_08_high_entropy_domain(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=20, org="Unknown")}
        res = analyze_domain("https://asdfghjklqwertyuiopzxcvbnm123456789.com/test")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_name"], "asdfghjklqwertyuiopzxcvbnm123456789.com")

    # 9. Normal low-entropy domain
    @patch("agents.agent1_domain.query_rdap")
    def test_09_normal_low_entropy_domain(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=2000, org="Normal Co")}
        res = analyze_domain("https://bank.com")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_name"], "bank.com")

    # 10. Missing DNSSEC data (A1 focuses strictly on domain identity without DNSSEC assumptions)
    @patch("agents.agent1_domain.query_rdap")
    def test_10_missing_dnssec_decoupled(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=1000)}
        res = analyze_domain("https://nodnssec.org")
        self.assertEqual(res["status"], "success")
        self.assertNotIn("dnssec", res["data"])

    # 11. Valid DNSSEC target (A1 identity extraction preserves domain without DNSSEC collision)
    @patch("agents.agent1_domain.query_rdap")
    def test_11_valid_dnssec_decoupled(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=1000)}
        res = analyze_domain("https://validdnssec.gov")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_name"], "validdnssec.gov")

    # 12. Young domain (<30 days) contract & TCE contribution
    @patch("agents.agent1_domain.query_rdap")
    def test_12_young_domain_tce_contribution(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=5, org="Privacy Guard")}
        res = analyze_domain("https://young-phish.biz")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_age_days"], 5)
        
        e1_02 = next((e for e in res["evidence"] if e["evidence_id"] == "E1-02"), None)
        self.assertIsNotNone(e1_02)
        self.assertEqual(e1_02["severity"], "medium")
        self.assertEqual(e1_02["category"], "domain_age_young")
        self.assertEqual(e1_02["evidence_strength"], 0.80)

        # Test TCE calculation
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(res)
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        
        e1_02_contrib = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E1-02"), None)
        self.assertIsNotNone(e1_02_contrib)
        self.assertEqual(e1_02_contrib["polarity"], "risk_increasing")
        self.assertEqual(e1_02_contrib["severity_weight"], 0.45)
        self.assertGreater(e1_02_contrib["base_contribution"], 0.0)
        self.assertGreater(tce_eval["risk_score"], 0.0)

    # 13. Mature domain (>=730 days) contract & TCE mitigation
    @patch("agents.agent1_domain.query_rdap")
    def test_13_mature_domain_contract(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=2500, org="Long Standing Enterprise Inc.")}
        res = analyze_domain("https://mature-domain.com")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["domain_age_days"], 2500)
        
        e1_02 = next((e for e in res["evidence"] if e["evidence_id"] == "E1-02"), None)
        self.assertIsNotNone(e1_02)
        self.assertIn(e1_02["severity"], ["info", "low"])
        self.assertEqual(e1_02["category"], "domain_age_established")

        e1_07 = next((e for e in res["evidence"] if e["evidence_id"] == "E1-07"), None)
        self.assertIsNotNone(e1_07)
        self.assertEqual(e1_07["category"], "whois_verified_registrant")

    # 14. Normalization: Subdomains, www, paths, query parameters
    def test_14_normalization_variations(self):
        self.assertEqual(extract_domain("https://www.example.com/login"), "example.com")
        self.assertEqual(extract_domain("https://login.sub.example.co.uk/auth?user=1"), "example.co.uk")
        self.assertEqual(extract_domain("http://deep.nested.domain.org/path/to/page#hash"), "domain.org")

    # 15. Invalid / empty URL input
    def test_15_invalid_url_handling(self):
        for invalid_input in ["", "   ", "hello", "not-a-url"]:
            res = analyze_domain(invalid_input)
            self.assertEqual(res["status"], "error")
            self.assertGreater(len(res["errors"]), 0)

    # 16. End-to-End Pipeline Contract (A1 -> Schema -> Normalizer -> Ledger -> TCE)
    @patch("agents.agent1_domain.query_rdap")
    def test_16_end_to_end_pipeline_contract(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=10, org="Recent Phish Corp")}
        res = analyze_domain("https://pipeline-test.com")
        self.assertEqual(res["status"], "success")
        
        # Schema validation for all evidence items
        for ev in res["evidence"]:
            valid, errs = validate_evidence_item(ev)
            self.assertTrue(valid, f"Evidence {ev.get('evidence_id')} failed schema: {errs}")

        # Ledger ingestion
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(res)
        self.assertEqual(len(ledger.entries), len(res["evidence"]))

        # TCE calculation
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)
        self.assertIn("trust_score", tce_eval)
        self.assertIn("risk_score", tce_eval)
        self.assertIn("verdict", tce_eval)

    # 17. Strict Schema Assertion: NO trust/risk scores or verdicts in Agent output
    @patch("agents.agent1_domain.query_rdap")
    def test_17_schema_no_risk_scores(self, mock_rdap):
        mock_rdap.return_value = {"success": True, "data": _make_rdap_payload(reg_days_ago=1000)}
        res = analyze_domain("https://example.com")
        forbidden_keys = [
            "trust_score", "trustscore", "risk_score", "riskscore",
            "phishing_probability", "verdict", "final_score",
            "classification", "confidence"
        ]
        for key in forbidden_keys:
            self.assertNotIn(key, res, f"Agent 1 response MUST NOT contain '{key}'")


def run_all_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAgent1DomainIdentity)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "=" * 60)
    print(f"Agent 1 Test Suite Results: Ran {result.testsRun} tests.")
    if result.wasSuccessful():
        print("ALL AGENT 1 TESTS PASSED SUCCESSFULLY.")
    else:
        print(f"FAILURES: {len(result.failures)}, ERRORS: {len(result.errors)}")
    print("=" * 60)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
