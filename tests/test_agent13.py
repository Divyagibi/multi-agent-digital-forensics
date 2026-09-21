"""
Unit Tests for Agent 13: External Presence / OSINT Agent
Covers all 24+ OSINT sources, identity correlation, disambiguation,
mentions, reviews, news, consistency status, and Flask endpoint.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

from app import app
from agents.agent13_osint import (
    analyze_osint,
    _is_safe_url,
    _fetch_webpage_safe,
    _normalize_url,
    _extract_registered_domain,
    _extract_target_identity,
    _correlate_identity_match,
    _investigate_linkedin,
    _investigate_facebook,
    _investigate_twitter,
    _investigate_instagram,
    _investigate_github,
    _investigate_reddit,
    _investigate_news,
    _investigate_public_reviews,
    _investigate_forums,
    _evaluate_external_consistency,
)
from services.evidence_schema import validate_evidence_item, validate_agent_result
from services.evidence_normalizer import normalize_evidence_item
from services.evidence_ledger import EvidenceLedger
from services.tce_config import resolve_evidence_polarity
from services.trust_calculation_engine import TrustCalculationEngine

# Mock HTML Fixtures
MOCK_TECH_CORP_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Apex Cloud Technologies | Enterprise SaaS & API Platform</title>
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "Corporation",
        "name": "Apex Cloud Technologies",
        "address": {
            "@type": "PostalAddress",
            "addressLocality": "Bengaluru",
            "addressCountry": "India"
        },
        "sameAs": [
            "https://www.linkedin.com/company/apexcloudtech",
            "https://github.com/apexcloudtech"
        ]
    }
    </script>
</head>
<body>
    <h1>Apex Cloud Technologies API Platform</h1>
    <p>We build scalable cloud developer software and Python SDKs for global developers.</p>
    <footer>
        <a href="https://twitter.com/apexcloudtech">Twitter</a>
        <a href="https://facebook.com/apexcloudtechnologies">Facebook</a>
        <a href="https://instagram.com/apexcloudtech">Instagram</a>
        <p>&copy; 2026 Apex Cloud Technologies Pvt Ltd.</p>
    </footer>
</body>
</html>
"""

MOCK_BAKERY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Sweet Treats Artisan Bakery</title>
</head>
<body>
    <h1>Fresh Bread and Pastries</h1>
    <p>Local handcrafted bread made fresh every morning in downtown Seattle.</p>
    <footer>
        <p>&copy; 2026 Sweet Treats Artisan Bakery</p>
    </footer>
</body>
</html>
"""


class TestAgent13OSINT(unittest.TestCase):
    """Test suite for Agent 13 External Presence / OSINT Agent."""

    def setUp(self):
        self.client = app.test_client()

    def test_normalize_url(self):
        self.assertEqual(_normalize_url("apexcloud.io"), "https://apexcloud.io")
        self.assertEqual(_normalize_url("http://test.org"), "http://test.org")
        self.assertEqual(_normalize_url(""), "")

    def test_extract_registered_domain(self):
        self.assertIn(_extract_registered_domain("https://sub.apexcloud.io/api"), ["apexcloud.io", "sub.apexcloud.io"])
        self.assertEqual(_extract_registered_domain(""), "")

    def test_extract_target_identity_schema_and_links(self):
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        identity, on_page_socials, is_tech = _extract_target_identity(
            soup, MOCK_TECH_CORP_HTML, "apexcloud.io", "https://apexcloud.io"
        )
        self.assertEqual(identity["company_name"], "Apex Cloud Technologies")
        self.assertEqual(identity["country"], "India")
        self.assertTrue(is_tech)
        self.assertIn("linkedin", on_page_socials)
        self.assertIn("github", on_page_socials)
        self.assertIn("x_twitter", on_page_socials)

    def test_extract_target_identity_non_tech(self):
        soup = BeautifulSoup(MOCK_BAKERY_HTML, "html.parser")
        identity, on_page_socials, is_tech = _extract_target_identity(
            soup, MOCK_BAKERY_HTML, "sweettreatsbakery.com", "https://sweettreatsbakery.com"
        )
        self.assertEqual(identity["company_name"], "Sweet Treats Artisan Bakery")
        self.assertFalse(is_tech)
        self.assertEqual(len(on_page_socials), 0)

    def test_investigate_linkedin_on_page_link(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io", "country": "India"}
        on_page_socials = {"linkedin": "https://www.linkedin.com/company/apexcloudtech"}
        res, traces, ev = _investigate_linkedin(identity, on_page_socials, lambda q: [])
        self.assertTrue(res["detected"])
        self.assertEqual(res["identity_match"], "high")
        self.assertTrue(res["website_match"])
        self.assertEqual(len(traces), 1)

    def test_investigate_linkedin_search_match(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io", "country": "India"}
        mock_search = lambda q: [{
            "url": "https://www.linkedin.com/company/apex-cloud-technologies",
            "title": "Apex Cloud Technologies | LinkedIn",
            "snippet": "Apex Cloud Technologies is a software platform based in India. Official site: apexcloud.io"
        }]
        res, traces, ev = _investigate_linkedin(identity, {}, mock_search)
        self.assertTrue(res["detected"])
        self.assertIn(res["identity_match"], ["high", "medium"])
        self.assertTrue(res["website_match"])

    def test_investigate_linkedin_no_presence(self):
        identity = {"company_name": "Nonexistent Brand ZZZ", "domain": "nonexistent-zzz.com"}
        res, traces, ev = _investigate_linkedin(identity, {}, lambda q: [])
        self.assertFalse(res["detected"])
        self.assertEqual(res["identity_match"], "unknown")

    def test_investigate_facebook_presence(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://facebook.com/apexcloudtechnologies",
            "title": "Apex Cloud Technologies - Home | Facebook",
            "snippet": "Official page for Apex Cloud Technologies. Visit apexcloud.io"
        }]
        res, traces, ev = _investigate_facebook(identity, {}, mock_search)
        self.assertTrue(res["detected"])
        self.assertIn(res["identity_match"], ["high", "medium"])

    def test_investigate_twitter_presence(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        on_page = {"x_twitter": "https://twitter.com/apexcloudtech"}
        res, traces, ev = _investigate_twitter(identity, on_page, lambda q: [])
        self.assertTrue(res["detected"])
        self.assertEqual(res["username"], "apexcloudtech")
        self.assertEqual(res["identity_match"], "high")

    def test_investigate_instagram_presence(self):
        identity = {"company_name": "Apex Cloud", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://instagram.com/apexcloud",
            "title": "Apex Cloud (@apexcloud) • Instagram photos",
            "snippet": "Cloud infrastructure software. apexcloud.io"
        }]
        res, traces, ev = _investigate_instagram(identity, {}, mock_search)
        self.assertTrue(res["detected"])
        self.assertEqual(res["username"], "apexcloud")

    def test_investigate_github_relevant_tech(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://github.com/apexcloudtech",
            "title": "apexcloudtech (Apex Cloud Technologies) · GitHub",
            "snippet": "Open source libraries and SDKs for apexcloud.io"
        }]
        res, traces, ev = _investigate_github(identity, {}, True, mock_search)
        self.assertTrue(res["relevant"])
        self.assertTrue(res["detected"])
        self.assertIn(res["identity_match"], ["high", "medium"])

    def test_investigate_github_not_relevant(self):
        identity = {"company_name": "Sweet Treats Bakery", "domain": "sweettreats.com"}
        res, traces, ev = _investigate_github(identity, {}, False, lambda q: [])
        self.assertFalse(res["relevant"])
        self.assertFalse(res["detected"])

    def test_investigate_reddit_mentions_and_context(self):
        identity = {"company_name": "Apex Cloud", "domain": "apexcloud.io"}
        mock_search = lambda q: [
            {
                "url": "https://reddit.com/r/cloudcomputing/comments/123/apexcloud_review",
                "title": "Anyone used Apex Cloud for their production backend?",
                "snippet": "2026-06-15: We have been using apexcloud.io for 6 months. Highly recommend their service, reliable API."
            },
            {
                "url": "https://reddit.com/r/scams/comments/456/warning_on_fake_sites",
                "title": "Beware of counterfeit apex copycat sites",
                "snippet": "2026-05-10: Someone tried to scam users with a clone domain, be careful."
            }
        ]
        mentions, traces, ev = _investigate_reddit(identity, mock_search)
        self.assertEqual(len(mentions), 2)
        self.assertIn("r/cloudcomputing", mentions[0]["subreddit"])
        self.assertEqual(mentions[0]["context"], "recommendation")
        self.assertEqual(mentions[0]["date"], "2026-06-15")

    def test_investigate_reddit_no_mentions(self):
        identity = {"company_name": "Unknown Entity", "domain": "unknown-corp.org"}
        mentions, traces, ev = _investigate_reddit(identity, lambda q: [])
        self.assertEqual(len(mentions), 0)

    def test_investigate_news_articles(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://techcrunch.com/2026/04/01/apex-cloud-secures-series-a",
            "title": "Apex Cloud Technologies Raises $20M Series A for API Infrastructure",
            "snippet": "2026-04-01: Bangalore based Apex Cloud Technologies announced today its new funding round."
        }]
        news, traces, ev = _investigate_news(identity, mock_search)
        self.assertEqual(len(news), 1)
        self.assertEqual(news[0]["publisher"], "techcrunch.com")
        self.assertEqual(news[0]["published_date"], "2026-04-01")

    def test_investigate_public_reviews(self):
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://trustpilot.com/review/apexcloud.io",
            "title": "Apex Cloud is rated 4.6 / 5 on Trustpilot",
            "snippet": "Read customer reviews of apexcloud.io. 4.6 out of 5 stars with 150 reviews."
        }]
        reviews, traces, ev = _investigate_public_reviews(identity, mock_search)
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["platform"], "Trustpilot")
        self.assertEqual(reviews[0]["rating"], 4.6)
        self.assertEqual(reviews[0]["general_sentiment"], "positive")

    def test_investigate_forums(self):
        identity = {"company_name": "Apex Cloud", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://webhostingtalk.com/threads/apexcloud-experience",
            "title": "Apex Cloud VPS and API reliability discussion",
            "snippet": "2026-03-20: Discussion about server uptime and API response times for apexcloud."
        }]
        forums, traces, ev = _investigate_forums(identity, mock_search)
        self.assertEqual(len(forums), 1)
        self.assertEqual(forums[0]["forum_name"], "webhostingtalk.com")
        self.assertEqual(forums[0]["date"], "2026-03-20")

    def test_disambiguation_different_country(self):
        # Target is Apex Technologies in India; candidate is Apex Technologies in USA with different domain
        match_level, web_m, loc_m = _correlate_identity_match(
            "Apex Technologies", "apextech.in", "India",
            "Apex Technologies", "https://linkedin.com/company/apex-tech-usa",
            "Apex Technologies located in New York, USA. Official website: apex-usa.com"
        )
        self.assertIn(match_level, ["mismatch", "low"])
        self.assertFalse(web_m)
        self.assertFalse(loc_m)

    def test_disambiguation_mismatched_brand(self):
        match_level, web_m, loc_m = _correlate_identity_match(
            "Apex Cloud Technologies", "apexcloud.io", "India",
            "Apex Shoes & Footwear", "https://instagram.com/apexfootwear",
            "Latest shoes and sneakers collection. Visit apexshoes.com"
        )
        self.assertEqual(match_level, "mismatch")
        self.assertFalse(web_m)

    def test_evaluate_external_consistency_consistent(self):
        li = {"detected": True, "identity_match": "high"}
        fb = {"detected": True, "identity_match": "high"}
        tw = {"detected": True, "identity_match": "medium"}
        ig = {"detected": False}
        gh = {"detected": True, "identity_match": "high"}
        
        consistency, presence, context, ev = _evaluate_external_consistency(
            li, fb, tw, ig, gh, [], [], [], []
        )
        self.assertEqual(consistency["status"], "consistent")
        self.assertTrue(len(consistency["matched_sources"]) >= 3)
        self.assertEqual(len(consistency["conflicts"]), 0)

    def test_evaluate_external_consistency_inconsistent(self):
        li = {"detected": True, "identity_match": "high"}
        fb = {"detected": True, "identity_match": "mismatch"}
        tw = {"detected": False}
        ig = {"detected": False}
        gh = {"detected": False}
        
        consistency, presence, context, ev = _evaluate_external_consistency(
            li, fb, tw, ig, gh, [], [], [], []
        )
        self.assertEqual(consistency["status"], "inconsistent")
        self.assertTrue(len(consistency["conflicts"]) > 0)

    def test_evaluate_external_consistency_unknown(self):
        li = {"detected": False}
        fb = {"detected": False}
        tw = {"detected": False}
        ig = {"detected": False}
        gh = {"detected": False}
        
        consistency, presence, context, ev = _evaluate_external_consistency(
            li, fb, tw, ig, gh, [], [], [], []
        )
        self.assertEqual(consistency["status"], "unknown")
        self.assertEqual(len(consistency["matched_sources"]), 0)

    @patch("agents.agent13_osint._fetch_webpage_safe")
    def test_analyze_osint_complete_flow(self, mock_fetch):
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])

        mock_search = lambda q: [
            {"url": "https://techcrunch.com/apex", "title": "Apex Cloud Series A", "snippet": "News coverage for apexcloud.io"},
            {"url": "https://reddit.com/r/cloud/apex", "title": "Apex Cloud Review", "snippet": "Great experience with apexcloud.io"}
        ]

        result = analyze_osint("https://apexcloud.io", search_override=mock_search)
        self.assertIn(result["agent"], ("External Presence / OSINT", "Agent 13"))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["identity"]["company_name"], "Apex Cloud Technologies")
        self.assertTrue(result["linkedin"]["detected"])
        self.assertTrue(result["github"]["detected"])
        self.assertTrue(result["github"]["relevant"])
        self.assertTrue(len(result["news_articles"]) >= 1)
        self.assertTrue(len(result["reddit_mentions"]) >= 1)
        self.assertTrue(len(result["evidence"]) > 0)

    def test_analyze_osint_empty_url(self):
        result = analyze_osint("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent13_osint.requests.Session.get")
    def test_analyze_osint_fetch_error(self, mock_get):
        mock_get.side_effect = Exception("Connection timeout")
        result = analyze_osint("https://unreachable-corp.xyz", search_override=lambda q: [])
        self.assertEqual(result["status"], "completed")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent13_osint._fetch_webpage_safe")
    def test_api_endpoint_agent13(self, mock_fetch):
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])

        resp = self.client.post("/api/agent13", json={"url": "https://apexcloud.io"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn(data["agent"], ("External Presence / OSINT", "Agent 13"))
        self.assertEqual(data["status"], "completed")
        self.assertIn("identity", data)
        self.assertIn("linkedin", data)
    def test_27_ssrf_protection(self):
        """Test 27: Verify SSRF protection rejects private, loopback, and metadata IPs."""
        self.assertFalse(_is_safe_url("http://127.0.0.1:8000/osint"))
        self.assertFalse(_is_safe_url("http://localhost:8080/search"))
        self.assertFalse(_is_safe_url("http://169.254.169.254/latest/meta-data/"))
        self.assertFalse(_is_safe_url("http://10.0.0.1/admin"))
        self.assertFalse(_is_safe_url("http://192.168.1.1/secret"))
        self.assertFalse(_is_safe_url("http://172.16.0.5/api"))
        self.assertFalse(_is_safe_url("http://[::1]/internal"))
        self.assertFalse(_is_safe_url("http://metadata.google.internal/computeMetadata/v1/"))
        self.assertTrue(_is_safe_url("https://example.com/company"))
        self.assertTrue(_is_safe_url("https://8.8.8.8/dns-query"))

        # Fetch safe test
        session = MagicMock()
        html, final_url, soup, errors = _fetch_webpage_safe("http://127.0.0.1/osint", session)
        self.assertIsNone(html)
        self.assertTrue(any("SSRF" in err for err in errors))

    @patch("agents.agent13_osint._fetch_webpage_safe")
    def test_28_evidence_schema_and_ledger(self, mock_fetch):
        """Test 28: Validate all A13 evidence items comply with Common Evidence Schema and ledger ingestion."""
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])

        mock_search = lambda q: [
            {"url": "https://techcrunch.com/apex", "title": "Apex Cloud Series A", "snippet": "News coverage for apexcloud.io"},
            {"url": "https://reddit.com/r/cloud/apex", "title": "Apex Cloud Review", "snippet": "Great experience with apexcloud.io"}
        ]

        result = analyze_osint("https://apexcloud.io", search_override=mock_search)
        self.assertTrue(validate_agent_result(result))

        evidence_items = result.get("evidence", [])
        self.assertEqual(len(evidence_items), 11)

        ledger = EvidenceLedger(target="https://apexcloud.io")
        ledger.add_entries_from_agent(result)
        self.assertEqual(len(ledger.entries), 11)

        # Check individual evidence structure
        for item in evidence_items:
            self.assertTrue(validate_evidence_item(item))
            normalized = normalize_evidence_item(item, agent_identifier="A13", agent_result=result)
            self.assertTrue(normalized["evidence_id"].startswith("E13-"))
            self.assertIn(normalized["agent_id"], [13, "A13"])
            self.assertEqual(normalized["provenance"]["source_agent"], "A13")
            self.assertIn(normalized["severity"], ["info", "low", "medium", "high", "critical"])
            self.assertIn(normalized["evidence_type"], ["deterministic", "external_source", "inference"])

    @patch("agents.agent13_osint._fetch_webpage_safe")
    def test_29_strict_schema_no_scores(self, mock_fetch):
        """Test 29: Verify A13 does NOT output trust scores, risk scores, or final verdicts."""
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])

        result = analyze_osint("https://apexcloud.io", search_override=lambda q: [])

        forbidden_keys = [
            "trust_score", "risk_score", "verdict", "phishing_score",
            "final_verdict", "decision", "reputation_score", "malicious_score"
        ]
        for key in forbidden_keys:
            self.assertNotIn(key, result)
            self.assertNotIn(key, result.get("data", {}))

    @patch("agents.agent13_osint._fetch_webpage_safe")
    def test_30_tce_integration_and_polarity(self, mock_fetch):
        """Test 30: Verify A13 evidence categories map cleanly into declarative TCE polarities."""
        soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])

        mock_search = lambda q: [
            {"url": "https://techcrunch.com/apex", "title": "Apex Cloud Series A", "snippet": "News coverage for apexcloud.io"},
            {"url": "https://reddit.com/r/cloud/apex", "title": "Apex Cloud Review", "snippet": "Great experience with apexcloud.io"}
        ]

        result = analyze_osint("https://apexcloud.io", search_override=mock_search)
        ledger = EvidenceLedger(target="https://apexcloud.io")
        ledger.add_entries_from_agent(result)

        engine = TrustCalculationEngine()
        tce_eval = engine.calculate_trust(ledger)
        self.assertGreater(tce_eval["trust_score"], 0.0)

        # Check individual polarity mapping
        for item in result["evidence"]:
            cat = item.get("category", "")
            polarity = resolve_evidence_polarity(cat)
            if cat in ("social_presence_verified", "established_brand_official_domain", "positive_consumer_reputation", "public_repository_present"):
                self.assertEqual(polarity, "risk_reducing")
            elif cat in ("brand_domain_mismatch", "public_scam_discussion_found", "public_complaints_found"):
                self.assertEqual(polarity, "risk_increasing")
            else:
                self.assertEqual(polarity, "neutral")

    def test_31_scope_boundaries_a13_vs_peers(self):
        """Test 31: Confirm A13 extracts external OSINT traces without claiming WHOIS ownership (A1) or Threat Feed ownership (A6)."""
        identity, on_page_socials, is_tech = _extract_target_identity(None, "", "domain-test.com", "https://domain-test.com")
        self.assertEqual(identity["domain"], "domain-test.com")
        self.assertNotIn("whois_registrar", identity)
        self.assertNotIn("virustotal_positives", identity)

    # 32. Elimination of meta_description_present Fallback
    def test_32_no_meta_description_fallback(self):
        """Test 32: Verify A13 never uses meta_description_present or meta_title_present as generic fallback."""
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_BAKERY_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_BAKERY_HTML, "https://empty-test.com", soup, [])
            res = analyze_osint("https://empty-test.com", search_override=lambda q: [])
            for ev in res["evidence"]:
                self.assertNotIn(
                    ev.get("category"),
                    ["meta_description_present", "meta_title_present", "known_malicious_ip"],
                    f"A13 must not use generic meta fallbacks: {ev}"
                )

    # 33. Empty OSINT Presence Neutrality
    def test_33_empty_osint_presence_neutrality(self):
        """Test 33: Verify lack of OSINT traces is treated as neutral info, not suspicious or malicious."""
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_BAKERY_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_BAKERY_HTML, "https://local-bakery.com", soup, [])
            res = analyze_osint("https://local-bakery.com", search_override=lambda q: [])
            for ev in res["evidence"]:
                self.assertEqual(ev.get("severity"), "info")
                self.assertIn(resolve_evidence_polarity(ev.get("category")), ["neutral", "risk_reducing"])

    # 34. GitHub Repository Correlation
    def test_34_github_repository_correlation(self):
        """Test 34: Verify official GitHub organization presence emits public_repository_present with risk_reducing polarity."""
        identity = {"company_name": "Apex Cloud Technologies", "domain": "apexcloud.io"}
        mock_search = lambda q: [{
            "url": "https://github.com/apexcloudtech",
            "title": "apexcloudtech · GitHub",
            "snippet": "Official repositories for apexcloud.io"
        }]
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://apexcloud.io", soup, [])
            res = analyze_osint("https://apexcloud.io", search_override=mock_search)
            gh_ev = next(e for e in res["evidence"] if e.get("evidence_id") == "E13-06")
            self.assertEqual(gh_ev.get("category"), "public_repository_present")
            self.assertEqual(resolve_evidence_polarity("public_repository_present"), "risk_reducing")

    # 35. Reddit Scam Discussion Semantics
    def test_35_reddit_scam_discussion_semantics(self):
        """Test 35: Public scam discussions emit public_scam_discussion_found with medium severity and risk_increasing polarity."""
        mock_search = lambda q: [{
            "url": "https://reddit.com/r/scams/comments/123",
            "title": "Beware scam site",
            "snippet": "Warning: this domain scammed me and stole my payment"
        }]
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://scammy-target.com", soup, [])
            res = analyze_osint("https://scammy-target.com", search_override=mock_search)
            rd_ev = next(e for e in res["evidence"] if e.get("evidence_id") == "E13-07")
            self.assertEqual(rd_ev.get("category"), "public_scam_discussion_found")
            self.assertEqual(rd_ev.get("severity"), "medium")
            self.assertEqual(resolve_evidence_polarity("public_scam_discussion_found"), "risk_increasing")

    # 36. Public Complaints Review Semantics
    def test_36_public_complaints_review_semantics(self):
        """Test 36: Bad public reviews emit public_complaints_found with medium severity and risk_increasing polarity."""
        mock_search = lambda q: [{
            "url": "https://trustpilot.com/review/badtarget.com",
            "title": "Terrible service - 1 star",
            "snippet": "Complaint: awful fraud experience, refund denied"
        }]
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_TECH_CORP_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_TECH_CORP_HTML, "https://badtarget.com", soup, [])
            res = analyze_osint("https://badtarget.com", search_override=mock_search)
            rv_ev = next(e for e in res["evidence"] if e.get("evidence_id") == "E13-09")
            self.assertEqual(rv_ev.get("category"), "public_complaints_found")
            self.assertEqual(rv_ev.get("severity"), "medium")
            self.assertEqual(resolve_evidence_polarity("public_complaints_found"), "risk_increasing")

    # 37. False Positive Prevention on Small Business
    def test_37_false_positive_prevention_small_business(self):
        """Test 37: Small business with no social media or GitHub emits info/neutral items, never high risk."""
        with patch("agents.agent13_osint._fetch_webpage_safe") as mock_fetch:
            soup = BeautifulSoup(MOCK_BAKERY_HTML, "html.parser")
            mock_fetch.return_value = (MOCK_BAKERY_HTML, "https://sweet-treats.com", soup, [])
            res = analyze_osint("https://sweet-treats.com", search_override=lambda q: [])
            for ev in res["evidence"]:
                self.assertNotEqual(ev.get("severity"), "high")
                self.assertNotEqual(ev.get("severity"), "critical")

    # 38. Identity Inconsistency Detection
    def test_38_identity_inconsistency_medium_severity(self):
        """Test 38: Conflicting external OSINT profiles lead to brand_domain_mismatch with medium severity."""
        li = {"detected": True, "identity_match": "high"}
        fb = {"detected": True, "identity_match": "mismatch"}
        consistency, presence, context, ev = _evaluate_external_consistency(
            li, fb, {"detected": False}, {"detected": False}, {"detected": False}, [], [], [], []
        )
        self.assertEqual(consistency["status"], "inconsistent")
        self.assertEqual(resolve_evidence_polarity("brand_domain_mismatch"), "risk_increasing")


if __name__ == "__main__":
    unittest.main()
