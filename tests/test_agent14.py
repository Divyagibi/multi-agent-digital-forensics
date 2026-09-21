"""
Unit Tests for Agent 14: Historical Evidence Agent
Covers Wayback CDX parsing, snapshot evolution, identity shifts,
historical DNS & IP changes, previous reputation, domain reuse,
parked periods, temporal inconsistencies, and Flask API endpoint.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

from app import app
from agents.agent14_history import (
    analyze_history,
    _normalize_url,
    _extract_registered_domain,
    _parse_wayback_snapshots,
    _analyze_historical_content,
    _analyze_historical_ownership,
    _analyze_historical_dns,
    _analyze_historical_reputation,
    _detect_domain_reuse,
    _evaluate_historical_inconsistencies,
    _build_master_timeline,
    _is_safe_url,
    _fetch_current_page_and_claims,
)
from services.evidence_schema import validate_evidence_item, validate_agent_result
from services.evidence_normalizer import normalize_evidence_item
from services.evidence_ledger import EvidenceLedger
from services.tce_config import resolve_evidence_polarity
from services.trust_calculation_engine import TrustCalculationEngine

# Mock CDX Data Fixtures
MOCK_CDX_ROWS = [
    ["timestamp", "original", "mimetype", "statuscode", "digest"],
    ["20190415120000", "https://example-history.com/", "text/html", "200", "DIGEST111"],
    ["20200520140000", "https://example-history.com/", "text/html", "200", "DIGEST222"],
    ["20210625100000", "https://example-history.com/", "text/html", "200", "DIGEST333"],
    ["20220710180000", "https://example-history.com/", "text/html", "302", "DIGEST444"],
    ["20230815120000", "https://example-history.com/", "text/html", "200", "DIGEST555"],
    ["20240901090000", "https://example-history.com/", "text/html", "200", "DIGEST666"],
    ["20251010160000", "https://example-history.com/", "text/html", "200", "DIGEST777"],
    ["20260215110000", "https://example-history.com/", "text/html", "200", "DIGEST888"],
]

MOCK_CURRENT_CLAIM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Apex Global Industries | Online Retailer</title>
</head>
<body>
    <h1>Apex Global Industries</h1>
    <p>Established in 2005. Providing world class global goods since 2005.</p>
</body>
</html>
"""


class TestAgent14History(unittest.TestCase):
    """Test suite for Agent 14 Historical Evidence module."""

    def setUp(self):
        self.client = app.test_client()

    def test_normalize_url(self):
        self.assertEqual(_normalize_url("example-history.com"), "https://example-history.com")
        self.assertEqual(_normalize_url("http://test.org/archive"), "http://test.org/archive")
        self.assertEqual(_normalize_url(""), "")

    def test_extract_registered_domain(self):
        self.assertIn(_extract_registered_domain("https://sub.example-history.com/page"), ["example-history.com", "sub.example-history.com"])
        self.assertEqual(_extract_registered_domain(""), "")

    def test_parse_wayback_snapshots_available(self):
        wb, selected, ev = _parse_wayback_snapshots(MOCK_CDX_ROWS[1:], "example-history.com")
        self.assertTrue(wb["available"])
        self.assertEqual(wb["snapshot_count"], 8)
        self.assertEqual(wb["earliest_snapshot"]["date"], "2019-04-15")
        self.assertEqual(wb["latest_snapshot"]["date"], "2026-02-15")
        self.assertTrue(len(selected) >= 5)
        self.assertTrue(len(ev) > 0)

    def test_parse_wayback_snapshots_empty(self):
        wb, selected, ev = _parse_wayback_snapshots([], "empty-history.com")
        self.assertFalse(wb["available"])
        self.assertEqual(wb["snapshot_count"], 0)
        self.assertIsNone(wb["earliest_snapshot"])
        self.assertEqual(len(selected), 0)

    def test_analyze_historical_content_identity_shift(self):
        snapshots = [
            {"date": "2019-04-15", "year": "2019", "url": "https://example.com", "status": 200, "snapshot_url": "url1", "company_name": "ABC Tech Solutions", "business_category": "Software", "is_parked": False, "digest": "D1"},
            {"date": "2022-05-10", "year": "2022", "url": "https://example.com", "status": 200, "snapshot_url": "url2", "company_name": "ABC Tech Solutions", "business_category": "Software", "is_parked": False, "digest": "D2"},
            {"date": "2024-08-15", "year": "2024", "url": "https://example.com", "status": 200, "snapshot_url": "url3", "company_name": "Quick Cash Loans", "business_category": "Financial Services", "is_parked": False, "digest": "D3"},
        ]
        history, inactive, redirects, ev = _analyze_historical_content(snapshots, "Quick Cash Loans", "example.com")
        self.assertTrue(len(history["identity_changes"]) >= 1)
        self.assertEqual(history["identity_changes"][0]["from"], "ABC Tech Solutions")
        self.assertEqual(history["identity_changes"][0]["to"], "Quick Cash Loans")
        self.assertTrue(len(history["business_category_changes"]) >= 1)

    def test_analyze_historical_content_parked_period(self):
        snapshots = [
            {"date": "2020-01-10", "year": "2020", "url": "https://example.com", "status": 200, "snapshot_url": "url1", "company_name": "Travel Blog", "business_category": "Travel", "is_parked": False, "digest": "D1"},
            {"date": "2022-06-15", "year": "2022", "url": "https://example.com", "status": 200, "snapshot_url": "url2", "company_name": None, "business_category": "Parked", "is_parked": True, "digest": "D2"},
            {"date": "2024-03-20", "year": "2024", "url": "https://example.com", "status": 200, "snapshot_url": "url3", "company_name": "Crypto Casino", "business_category": "Gambling", "is_parked": False, "digest": "D3"},
        ]
        history, inactive, redirects, ev = _analyze_historical_content(snapshots, "Crypto Casino", "example.com")
        self.assertEqual(len(inactive), 1)
        self.assertEqual(inactive[0]["period"], "2022")
        self.assertEqual(inactive[0]["status"], "parked_or_inactive")

    def test_analyze_historical_content_redirects(self):
        snapshots = [
            {"date": "2021-01-10", "year": "2021", "url": "https://example.com", "status": 301, "snapshot_url": "url1", "redirect_url": "https://destination-corp.com"},
        ]
        history, inactive, redirects, ev = _analyze_historical_content(snapshots, "Current", "example.com")
        self.assertEqual(len(redirects), 1)
        self.assertEqual(redirects[0]["status_code"], 301)

    def test_analyze_historical_ownership_available(self):
        mock_override = lambda dom: (
            [{"date": "2019", "registrar": "GoDaddy", "registrant": "Company A"}, {"date": "2024", "registrar": "Namecheap", "registrant": "Company B"}],
            [{"date": "2024", "previous_entity": "Company A", "new_entity": "Company B"}]
        )
        ownership, ev = _analyze_historical_ownership("example.com", mock_override)
        self.assertTrue(ownership["available"])
        self.assertEqual(len(ownership["records"]), 2)
        self.assertEqual(len(ownership["possible_ownership_changes"]), 1)

    def test_analyze_historical_ownership_unavailable(self):
        ownership, ev = _analyze_historical_ownership("example.com", None)
        self.assertFalse(ownership["available"])
        self.assertEqual(len(ownership["records"]), 0)

    def test_analyze_historical_dns_available(self):
        mock_override = lambda dom: (
            [{"date": "2021", "type": "A", "value": "192.0.2.1"}, {"date": "2024", "type": "A", "value": "198.51.100.2"}],
            [{"date": "2024", "type": "A", "from": "192.0.2.1", "to": "198.51.100.2"}],
            [{"date": "2024", "from": "192.0.2.1", "to": "198.51.100.2"}],
            [{"date": "2024", "from": "ns1.hostA.com", "to": "ns1.cloudflare.com"}]
        )
        dns_res, infra_res, ev = _analyze_historical_dns("example.com", mock_override)
        self.assertTrue(dns_res["available"])
        self.assertEqual(len(infra_res["ip_changes"]), 1)
        self.assertEqual(len(infra_res["nameserver_changes"]), 1)

    def test_analyze_historical_dns_unavailable(self):
        dns_res, infra_res, ev = _analyze_historical_dns("example.com", None)
        self.assertFalse(dns_res["available"])
        self.assertEqual(len(infra_res["ip_changes"]), 0)

    def test_analyze_historical_reputation_found(self):
        mock_override = lambda dom: [
            {"date": "2021-05-10", "title": "Phishing campaign alert", "sentiment": "negative", "source": "Security Alert"},
            {"date": "2025-08-20", "title": "New management launch", "sentiment": "positive", "source": "News Media"}
        ]
        rep_res, ev = _analyze_historical_reputation("example.com", "Apex", MagicMock(), mock_override)
        self.assertEqual(len(rep_res["reports"]), 2)
        self.assertEqual(len(rep_res["negative_reports"]), 1)
        self.assertEqual(len(rep_res["positive_reports"]), 1)

    def test_analyze_historical_reputation_empty(self):
        rep_res, ev = _analyze_historical_reputation("example.com", "Apex", MagicMock(), lambda d: [])
        self.assertEqual(len(rep_res["reports"]), 0)
        self.assertEqual(len(rep_res["negative_reports"]), 0)

    def test_detect_domain_reuse_true(self):
        web_hist = {
            "identity_changes": [{"from": "Travel Agency", "to": "Loan Provider", "approximate_date": "2024"}]
        }
        reuse, ev = _detect_domain_reuse(web_hist, [], {"possible_ownership_changes": []})
        self.assertTrue(reuse["possible"])
        self.assertTrue(len(reuse["evidence"]) >= 1)

    def test_detect_domain_reuse_false(self):
        web_hist = {"identity_changes": [], "business_category_changes": []}
        reuse, ev = _detect_domain_reuse(web_hist, [], {"possible_ownership_changes": []})
        self.assertFalse(reuse["possible"])

    def test_evaluate_historical_inconsistencies(self):
        claimed_year = 2005
        earliest_snap = {"date": "2023-04-10", "url": "url1"}
        inconsistencies, ev = _evaluate_historical_inconsistencies(claimed_year, earliest_snap, {}, [])
        self.assertEqual(len(inconsistencies), 1)
        self.assertEqual(inconsistencies[0]["type"], "historical_claim_comparison")
        self.assertIn("2005", inconsistencies[0]["claim"])
        self.assertIn("2023-04-10", inconsistencies[0]["historical_evidence"])

    def test_build_master_timeline(self):
        wb = {"earliest_snapshot": {"date": "2019-01-01", "url": "url1"}, "latest_snapshot": {"date": "2026-01-01", "url": "url2"}}
        web_hist = {"timeline": [{"date": "2022", "event": "Major redesign"}]}
        ownership = {"possible_ownership_changes": [{"date": "2023", "previous_entity": "A", "new_entity": "B"}]}
        dns = {"changes": [{"date": "2024", "type": "A", "from": "1.1.1.1", "to": "2.2.2.2"}]}
        rep = {"reports": [{"date": "2021", "title": "Security report", "sentiment": "negative"}]}
        inactive = [{"period": "2020", "status": "parked_or_inactive"}]

        timeline = _build_master_timeline(wb, web_hist, ownership, dns, rep, inactive)
        self.assertTrue(len(timeline) >= 6)
        dates = [e["date"] for e in timeline]
        self.assertIn("2019-01-01", dates)
        self.assertIn("2026-01-01", dates)

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_analyze_history_complete_flow(self, mock_fetch):
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])

        mock_cdx = lambda d: (MOCK_CDX_ROWS[1:], 8)
        result = analyze_history("https://example-history.com", cdx_override=mock_cdx)

        self.assertIn(result["agent"], ("Historical Evidence", "Agent 14"))
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["wayback_history"]["available"])
        self.assertEqual(result["wayback_history"]["snapshot_count"], 8)
        self.assertTrue(len(result["historical_screenshots"]) > 0)
        self.assertTrue(len(result["timeline"]) > 0)
        self.assertTrue(len(result["evidence"]) > 0)

    def test_analyze_history_empty_url(self):
        result = analyze_history("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent14_history.requests.Session.get")
    def test_analyze_history_timeout_or_error(self, mock_get):
        mock_get.side_effect = Exception("Wayback connection error")
        result = analyze_history("https://unreachable-domain-xyz.com")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_api_endpoint_agent14(self, mock_fetch):
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])

        mock_cdx = lambda d: (MOCK_CDX_ROWS[1:], 8)
        with patch("agents.agent14_history._query_wayback_cdx", return_value=(MOCK_CDX_ROWS[1:], 8, [])):
            resp = self.client.post("/api/agent14", json={"url": "https://example-history.com"})
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertIn(data["agent"], ("Historical Evidence", "Agent 14"))
            self.assertEqual(data["status"], "completed")
            self.assertIn("wayback_history", data)
            self.assertIn("timeline", data)
            self.assertIn("domain_reuse", data)

    def test_ssrf_protection_and_safety_checks(self):
        """Test SSRF protection blocks private IPs, localhost, cloud metadata."""
        self.assertFalse(_is_safe_url("http://localhost/test"))
        self.assertFalse(_is_safe_url("http://127.0.0.1:8080/admin"))
        self.assertFalse(_is_safe_url("http://169.254.169.254/latest/meta-data/"))
        self.assertFalse(_is_safe_url("http://10.0.0.1/intranet"))
        self.assertFalse(_is_safe_url("http://192.168.1.1/router"))
        self.assertFalse(_is_safe_url("http://metadata.google.internal/computeMetadata/v1/"))
        self.assertTrue(_is_safe_url("https://example.com/index.html"))

        # Verify _fetch_current_page_and_claims rejects SSRF target
        session = MagicMock()
        html, final_url, soup, yr, errors = _fetch_current_page_and_claims("http://127.0.0.1:5000", session)
        self.assertIsNone(html)
        self.assertTrue(any("SSRF" in err for err in errors))

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_common_evidence_schema_and_ledger_ingestion(self, mock_fetch):
        """Test that all A14 evidence items validate and ingest cleanly into EvidenceLedger."""
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])
        mock_cdx = lambda d: (MOCK_CDX_ROWS[1:], 8)

        result = analyze_history("https://example-history.com", cdx_override=mock_cdx)
        self.assertTrue(validate_agent_result(result))

        ledger = EvidenceLedger()
        for ev in result["evidence"]:
            self.assertTrue(validate_evidence_item(ev))
            self.assertIn("category", ev)
            norm = normalize_evidence_item(ev, "A14", "https://example-history.com")
            ledger.add_entry(norm)

        self.assertEqual(len(ledger.entries), len(result["evidence"]))

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_no_forbidden_agent_scores_or_verdicts(self, mock_fetch):
        """Ensure A14 strictly outputs forensic observations and no agent-level risk scores or verdicts."""
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])
        result = analyze_history("https://example-history.com", cdx_override=lambda d: (MOCK_CDX_ROWS[1:], 8))

        forbidden_keys = {"trust_score", "risk_score", "is_scam", "is_legitimate", "final_verdict", "risk_level"}
        for k in forbidden_keys:
            self.assertNotIn(k, result)
            self.assertNotIn(k, result.get("data", {}))

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_tce_integration_and_polarity_resolution(self, mock_fetch):
        """Verify that all A14 evidence item categories resolve cleanly in TCE taxonomy."""
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])
        result = analyze_history("https://example-history.com", cdx_override=lambda d: (MOCK_CDX_ROWS[1:], 8))

        for ev in result["evidence"]:
            cat = ev.get("category")
            polarity = resolve_evidence_polarity(cat, ev.get("finding", ""))
            self.assertIn(polarity, {"risk_reducing", "risk_increasing", "neutral"})

    @patch("agents.agent14_history._fetch_current_page_and_claims")
    def test_scope_boundaries_and_temporal_provenance(self, mock_fetch):
        """Verify A14 preserves historical provenance and does not claim current live A1/A2 ownership/DNS."""
        soup = BeautifulSoup(MOCK_CURRENT_CLAIM_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_CURRENT_CLAIM_HTML, "https://example-history.com", soup, 2005, [])
        result = analyze_history("https://example-history.com", cdx_override=lambda d: (MOCK_CDX_ROWS[1:], 8))

        # Check that snapshots retain historical timestamps and URLs
        for snap in result["wayback_history"]["selected_snapshots"]:
            self.assertIn("timestamp", snap)
            self.assertIn("date", snap)
            self.assertIn("snapshot_url", snap)

        # Check timeline events preserve temporal source attribution
        for event in result["timeline"]:
            self.assertIn("date", event)
            self.assertIn("source", event)
            self.assertIn("event", event)


if __name__ == "__main__":
    unittest.main()
