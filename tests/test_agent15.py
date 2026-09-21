"""
Unit tests for Agent 15: User Trust Signals Agent
Tests passive OSINT evidence collection, Trustpilot parsing, Google reviews,
Reddit discussions, scam complaints, official website testimonials,
cross-source corroboration, timeline, and Flask endpoint without score calculation.
"""

import unittest
from unittest.mock import MagicMock, patch
import json

from agents.agent15_trust import (
    analyze_user_trust,
    _normalize_url,
    _extract_domain_info,
    _generate_search_identities,
    classify_sentiment,
    classify_complaint_category,
    extract_website_testimonials,
    check_trustpilot,
    check_google_reviews,
    search_reddit_discussions,
    search_scam_complaints_and_forums,
    detect_recurring_patterns,
    detect_review_anomalies,
    build_evidence_timeline,
    _is_safe_url
)
from services.evidence_schema import validate_evidence_item, validate_agent_result
from services.evidence_normalizer import normalize_evidence_item
from services.evidence_ledger import EvidenceLedger
from services.tce_config import resolve_evidence_polarity
from services.trust_calculation_engine import TrustCalculationEngine
from app import app


class TestAgent15UserTrust(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. URL Normalization & Identity Resolution
    def test_01_url_normalization(self):
        self.assertEqual(_normalize_url("example.com"), "https://example.com")
        self.assertEqual(_normalize_url("http://example.com/path"), "http://example.com/path")
        self.assertEqual(_normalize_url(""), "")

    def test_02_domain_and_identity_extraction(self):
        info = _extract_domain_info("https://www.shop-example.com/store/item?id=123")
        self.assertTrue("shop-example.com" in info["domain"] or "shop-example.com" in info["hostname"])
        self.assertEqual(info["hostname"], "www.shop-example.com")
        self.assertTrue(len(info["brand"]) > 0)

    def test_03_search_identities_generation(self):
        queries = _generate_search_identities("example.com", "Example Corp", "Example")
        self.assertIn("example.com", queries)
        self.assertIn("example.com reviews", queries)
        self.assertIn("example.com scam", queries)
        self.assertIn('"Example Corp" reviews', queries)

    # 2. Sentiment Classification
    def test_04_sentiment_classification(self):
        self.assertEqual(classify_sentiment("Fast delivery and great customer service! Loved it."), "positive")
        self.assertEqual(classify_sentiment("Paid money but order was never delivered. Total scam and thieves!"), "negative")
        self.assertEqual(classify_sentiment("Does anyone know if this website is reliable?"), "neutral")
        self.assertEqual(classify_sentiment("Product was great quality but the refund took months and customer service was terrible."), "mixed")

    # 3. Standardized Complaint Category Mapping
    def test_05_complaint_categories(self):
        self.assertEqual(classify_complaint_category("Never received package, item never arrived"), "non_delivery")
        self.assertEqual(classify_complaint_category("Asked for refund and chargeback but refund was denied"), "refund_issue")
        self.assertEqual(classify_complaint_category("Late delivery and shipping delay"), "delivery_issue")
        self.assertEqual(classify_complaint_category("Found duplicate unauthorized charge on card"), "unauthorized_charge")
        self.assertEqual(classify_complaint_category("Cannot cancel monthly recurring subscription"), "subscription_issue")
        self.assertEqual(classify_complaint_category("Poor quality broken material"), "product_quality")
        self.assertEqual(classify_complaint_category("Support is completely unresponsive and ignored emails"), "customer_support")

    # 4. Domain with Trustpilot Profile
    @patch("agents.agent15_trust.requests.get")
    def test_06_trustpilot_profile_found(self, mock_get):
        mock_html = """
        <html>
            <span class="business-unit-name">Test Merchant</span>
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "aggregateRating": {
                    "ratingValue": "4.3",
                    "reviewCount": "1250"
                }
            }
            </script>
            <article class="review-card">
                <span class="consumer-name">Alice Smith</span>
                <h2 class="review-title">Fast delivery and superb support</h2>
                <p class="review-content">Great service, order arrived in 2 days.</p>
                <div data-service-review-rating="5"></div>
                <time datetime="2026-02-10">Feb 10, 2026</time>
            </article>
        </html>
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = mock_html
        mock_get.return_value = mock_resp

        data = check_trustpilot("example.com")
        self.assertTrue(data["available"])
        self.assertEqual(data["rating"], 4.3)
        self.assertEqual(data["review_count"], 1250)
        self.assertEqual(len(data["reviews"]), 1)
        self.assertEqual(data["reviews"][0]["sentiment"], "positive")

    # 5. Domain without Trustpilot Profile
    @patch("agents.agent15_trust.requests.get")
    def test_07_trustpilot_profile_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Page not found"
        mock_get.return_value = mock_resp

        data = check_trustpilot("unknown-site-12345.com")
        self.assertFalse(data["available"])
        self.assertEqual(len(data["reviews"]), 0)

    # 6. Google Reviews Discovery
    @patch("agents.agent15_trust.requests.get")
    def test_08_google_reviews_found(self, mock_get):
        mock_html = """
        <html>
            <div class="result">
                <a class="result__title">Example Company - Google Maps</a>
                <a class="result__url" href="https://maps.google.com/place/example">https://maps.google.com/place/example</a>
                <a class="result__snippet">Rating: 4.5 · ‎320 reviews · in Seattle, WA. Official domain is example.com</a>
            </div>
        </html>
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = mock_html
        mock_get.return_value = mock_resp

        data = check_google_reviews("example.com", "Example Company")
        self.assertTrue(data["available"])
        self.assertEqual(data["rating"], 4.5)
        self.assertEqual(data["review_count"], 320)
        self.assertEqual(data["entity_match"], "confirmed")

    # 7. Google Reviews Not Found
    @patch("agents.agent15_trust.requests.get")
    def test_09_google_reviews_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><div>No public maps profiles matching</div></html>"
        mock_get.return_value = mock_resp

        data = check_google_reviews("random-nonexistent-domain.xyz", "Random Co")
        self.assertFalse(data["available"])

    # 8. Reddit Discussions Found
    @patch("agents.agent15_trust.requests.get")
    def test_10_reddit_discussions_found(self, mock_get):
        mock_reddit_json = {
            "data": {
                "children": [
                    {
                        "data": {
                            "title": "Has anyone ordered from example.com recently?",
                            "selftext": "I ordered an item last week and it was great quality and arrived quickly.",
                            "subreddit": "onlinepurchases",
                            "permalink": "/r/onlinepurchases/comments/123/example_com_review/",
                            "created_utc": 1772640000
                        }
                    },
                    {
                        "data": {
                            "title": "Beware of refund delays on example.com",
                            "selftext": "Had a problem getting a refund after returning my order.",
                            "subreddit": "Scams",
                            "permalink": "/r/Scams/comments/456/example_com_refund_delay/",
                            "created_utc": 1770000000
                        }
                    }
                ]
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_reddit_json
        mock_get.return_value = mock_resp

        data = search_reddit_discussions("example.com", "Example")
        self.assertTrue(data["available"])
        self.assertEqual(data["discussions_found"], 2)
        self.assertTrue(any(d["sentiment"] == "positive" for d in data["discussions"]))
        self.assertTrue(any(d["category"] == "refund_issue" for d in data["discussions"]))

    # 9. No Reddit Discussions
    @patch("agents.agent15_trust.requests.get")
    def test_11_no_reddit_discussions(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"children": []}}
        mock_get.return_value = mock_resp

        data = search_reddit_discussions("obscure-domain-99.org", "Obscure Co")
        self.assertFalse(data["available"])
        self.assertEqual(data["discussions_found"], 0)

    # 10. Official Website Customer Testimonials (Self-Published Claims)
    def test_12_customer_testimonials_extraction(self):
        html_doc = """
        <html>
            <div class="testimonials">
                <div class="testimonial">
                    <blockquote>Our workflow improved tenfold after using their tools.</blockquote>
                    <strong class="name">Sarah Jenkins</strong>
                    <span class="company">Acme Cloud Solutions</span>
                    <a href="https://linkedin.com/in/sarahjenkins">LinkedIn Profile</a>
                </div>
                <div class="testimonial">
                    <blockquote>Good support and reliable delivery on all hardware orders.</blockquote>
                    <strong class="name">Mark Davis</strong>
                    <a href="https://external-company.com">Company Link</a>
                </div>
                <div class="testimonial">
                    <blockquote>Best vendor we have partnered with this year.</blockquote>
                    <span class="name">David Wilson</span>
                </div>
            </div>
        </html>
        """
        testimonials = extract_website_testimonials(html_doc, "https://example.com")
        self.assertEqual(len(testimonials), 3)
        self.assertEqual(testimonials[0]["verification"], "verified")
        self.assertEqual(testimonials[1]["verification"], "partially_verified")
        self.assertEqual(testimonials[2]["verification"], "not_verified")
        self.assertTrue("Self-Published" in testimonials[0]["source"])

    # 11. No Website Testimonials
    def test_13_no_testimonials_on_website(self):
        html_doc = "<html><body><h1>Simple Documentation Page</h1><p>No reviews here.</p></body></html>"
        testimonials = extract_website_testimonials(html_doc, "https://example.com")
        self.assertEqual(len(testimonials), 0)

    # 12. Scam Complaints and Public Forums
    @patch("agents.agent15_trust.requests.get")
    def test_14_scam_complaints_and_forums(self, mock_get):
        mock_html = """
        <html>
            <div class="result">
                <a class="result__title">PissedConsumer: example.com non-delivery complaints</a>
                <a class="result__url" href="https://pissedconsumer.com/company/example-com">https://pissedconsumer.com/company/example-com</a>
                <a class="result__snippet">Multiple users report order never arrived and no response from support.</a>
            </div>
            <div class="result">
                <a class="result__title">ScamAdviser: is example.com a scam?</a>
                <a class="result__url" href="https://scamadviser.com/check-website/example.com">https://scamadviser.com/check-website/example.com</a>
                <a class="result__snippet">Consumer report alleging refund issues and fraud complaints.</a>
            </div>
        </html>
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = mock_html
        mock_get.return_value = mock_resp

        scam_complaints, forums = search_scam_complaints_and_forums("example.com", "Example")
        self.assertTrue(len(scam_complaints) > 0)
        self.assertTrue(len(forums) > 0)
        self.assertEqual(scam_complaints[0]["sentiment"], "negative")

    # 13. Multiple Recurring Complaints & Cross-Source Corroboration
    def test_15_recurring_complaints_and_corroboration(self):
        mock_evidence = [
            {"source": "Trustpilot", "category": "refund_issue", "sentiment": "negative"},
            {"source": "Reddit", "category": "refund_issue", "sentiment": "negative"},
            {"source": "Complaint Forum", "category": "refund_issue", "sentiment": "negative"},
            {"source": "Trustpilot", "category": "delivery_issue", "sentiment": "negative"},
            {"source": "Trustpilot", "category": "delivery_issue", "sentiment": "negative"}
        ]
        recurring, cross = detect_recurring_patterns(mock_evidence)
        
        # Refund issue is reported on 3 independent sources -> cross-source corroborated
        refund_pat = next((r for r in recurring if r["pattern"] == "refund_issue"), None)
        self.assertIsNotNone(refund_pat)
        self.assertEqual(refund_pat["occurrences"], 3)
        self.assertTrue(refund_pat["cross_source_corroboration"])

        # Delivery issue is reported only on Trustpilot -> single-source repetition
        deliv_pat = next((r for r in recurring if r["pattern"] == "delivery_issue"), None)
        self.assertIsNotNone(deliv_pat)
        self.assertEqual(deliv_pat["occurrences"], 2)
        self.assertFalse(deliv_pat["cross_source_corroboration"])

    # 14. Review Duplication & Anomalies Detection
    def test_16_review_anomalies_detection(self):
        reviews = [
            {"title": "Great Product", "text": "This service is wonderful and completely exceeded my expectations every time."},
            {"title": "Superb Experience", "text": "This service is wonderful and completely exceeded my expectations every time."},
            {"title": "Awesome", "text": "This service is wonderful and completely exceeded my expectations every time."}
        ]
        anomalies = detect_review_anomalies(reviews)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["type"], "possible_review_anomaly")

    # 15. Evidence Timeline Builder
    def test_17_evidence_timeline(self):
        evidence_records = [
            {"date": "2024-05-12", "sentiment": "positive"},
            {"date": "2024-08-19", "sentiment": "positive"},
            {"date": "2025-02-10", "sentiment": "negative"},
            {"date": "2026-01-15", "sentiment": "mixed"}
        ]
        timeline = build_evidence_timeline(evidence_records)
        self.assertTrue(len(timeline) >= 3)
        periods = [t["period"] for t in timeline]
        self.assertIn("2026", periods)
        self.assertIn("2025", periods)
        self.assertIn("2024", periods)

    # 16. Comprehensive Analysis Entrypoint
    @patch("agents.agent15_trust.requests.get")
    def test_18_analyze_user_trust_full_flow(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
        <html>
            <head><title>Example Store - Quality Products</title></head>
            <body>
                <div class="testimonial">
                    <blockquote>Wonderful quality and quick shipping.</blockquote>
                    <span class="name">Bob</span>
                </div>
            </body>
        </html>
        """
        mock_resp.json.return_value = {"data": {"children": []}}
        mock_get.return_value = mock_resp

        result = analyze_user_trust("https://example.com")
        self.assertIn(result["agent"], ("User Trust Signals", "Agent 15"))
        self.assertEqual(result["status"], "completed")
        self.assertIn("input", result)
        self.assertIn("trustpilot", result)
        self.assertIn("google_reviews", result)
        self.assertIn("reddit", result)
        self.assertIn("review_summary", result)
        self.assertIn("customer_testimonials", result)
        self.assertIn("recurring_complaints", result)
        self.assertIn("timeline", result)
        self.assertIn("evidence", result)
        self.assertEqual(len(result["customer_testimonials"]), 1)

    # 17. Invalid Input Handling
    def test_19_invalid_url(self):
        result = analyze_user_trust("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    # 18. Network Timeout / Error Resilience
    @patch("agents.agent15_trust.requests.get", side_effect=Exception("Connection timed out"))
    def test_20_network_error_resilience(self, mock_get):
        result = analyze_user_trust("https://example.com")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(len(result["errors"]) > 0)
        self.assertEqual(result["review_summary"]["total"], 0)

    # 19. Flask API Endpoint - Success
    @patch("agents.agent15_trust.analyze_user_trust")
    def test_21_flask_endpoint_success(self, mock_analyze):
        mock_analyze.return_value = {
            "agent": "Agent 15",
            "status": "completed",
            "input": {"original_url": "https://example.com", "domain": "example.com", "company_name": "Example"},
            "trustpilot": {"available": False},
            "google_reviews": {"available": False},
            "reddit": {"available": False, "discussions": []},
            "user_reviews": [],
            "scam_complaints": [],
            "customer_testimonials": [],
            "complaint_forums": [],
            "review_summary": {"total": 0, "positive": 0, "negative": 0, "neutral": 0, "mixed": 0, "unknown": 0},
            "recurring_complaints": [],
            "positive_signals": [],
            "negative_signals": [],
            "cross_source_patterns": [],
            "review_anomalies": [],
            "timeline": [],
            "evidence": [],
            "errors": [],
            "checked_at": "2026-09-04T00:00:00Z"
        }

        response = self.app.post(
            "/api/agent15",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn(data["agent"], ("User Trust Signals", "Agent 15"))
        self.assertEqual(data["status"], "completed")

    # 20. Flask API Endpoint - Missing URL
    def test_22_flask_endpoint_missing_url(self):
        response = self.app.post(
            "/api/agent15",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn("error", data)

    # 21. SSRF Protection & Safety Checks
    def test_23_ssrf_protection_and_safety_checks(self):
        """Verify SSRF filters block private networks, localhost, link-local, cloud metadata."""
        self.assertFalse(_is_safe_url("http://localhost/review"))
        self.assertFalse(_is_safe_url("http://127.0.0.1:8080/trust"))
        self.assertFalse(_is_safe_url("http://169.254.169.254/latest/meta-data/"))
        self.assertFalse(_is_safe_url("http://10.0.0.1/admin"))
        self.assertFalse(_is_safe_url("http://192.168.1.1/feedback"))
        self.assertFalse(_is_safe_url("http://metadata.google.internal/computeMetadata/v1/"))
        self.assertTrue(_is_safe_url("https://example.com/"))

        # Verify analyze_user_trust rejects SSRF target
        res = analyze_user_trust("http://127.0.0.1:5000/internal")
        self.assertEqual(res["status"], "completed")
        self.assertTrue(any("SSRF" in str(err) for err in res["errors"]))

    # 22. Common Evidence Schema & Evidence Ledger Ingestion
    @patch("agents.agent15_trust.requests.get")
    def test_24_common_evidence_schema_and_ledger_ingestion(self, mock_get):
        """Verify that all A15 evidence items validate and ingest into EvidenceLedger."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><head><title>Test Store</title></head></html>"
        mock_resp.json.return_value = {"data": {"children": []}}
        mock_get.return_value = mock_resp

        result = analyze_user_trust("https://example.com")
        self.assertTrue(validate_agent_result(result))

        ledger = EvidenceLedger()
        for ev in result["evidence"]:
            self.assertTrue(validate_evidence_item(ev))
            self.assertIn("category", ev)
            norm = normalize_evidence_item(ev, "A15", "https://example.com")
            ledger.add_entry(norm)

        self.assertEqual(len(ledger.entries), len(result["evidence"]))

    # 23. Strict Absence of Forbidden Scores / Verdicts
    @patch("agents.agent15_trust.requests.get")
    def test_25_no_forbidden_agent_scores_or_verdicts(self, mock_get):
        """Verify A15 emits only forensic observations and no agent-level risk scores or verdicts."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><head><title>Test Store</title></head></html>"
        mock_resp.json.return_value = {"data": {"children": []}}
        mock_get.return_value = mock_resp

        result = analyze_user_trust("https://example.com")
        forbidden = {"trust_score", "risk_score", "is_scam", "is_legitimate", "final_verdict", "risk_level"}
        for k in forbidden:
            self.assertNotIn(k, result)
            self.assertNotIn(k, result.get("data", {}))

    # 24. TCE Polarity Resolution
    @patch("agents.agent15_trust.requests.get")
    def test_26_tce_integration_and_polarity_resolution(self, mock_get):
        """Verify that all A15 evidence item categories resolve cleanly in TCE polarity taxonomy."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><head><title>Test Store</title></head></html>"
        mock_resp.json.return_value = {"data": {"children": []}}
        mock_get.return_value = mock_resp

        result = analyze_user_trust("https://example.com")
        for ev in result["evidence"]:
            cat = ev.get("category")
            polarity = resolve_evidence_polarity(cat, ev.get("finding", ""))
            self.assertIn(polarity, {"risk_reducing", "risk_increasing", "neutral"})

    # 26. DEF-10: Review Sentiment and Community Discussion Mapping
    @patch("agents.agent15_trust.requests.get")
    def test_28_regression_def10_review_sentiment_mapping(self, mock_get):
        """DEF-10: Verify that general negative community discussions are mapped to public_complaints_found with low severity, not scam_fraud_keywords."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><head><title>Test Store</title></head></html>"
        # Mock negative reddit discussion
        mock_resp.json.return_value = {
            "data": {
                "children": [
                    {"data": {"title": "Terrible customer service delay complaint, worst support", "selftext": "Avoid this store due to terrible customer service and awful delay", "score": 5, "num_comments": 2, "permalink": "/r/reviews/1"}}
                ]
            }
        }
        mock_get.return_value = mock_resp

        result = analyze_user_trust("https://example.com")
        e15_03 = next((e for e in result["evidence"] if e.get("evidence_id") == "E15-03"), None)
        self.assertIsNotNone(e15_03)
        self.assertEqual(e15_03.get("category"), "public_complaints_found")
        self.assertEqual(e15_03.get("severity"), "low")


if __name__ == "__main__":
    unittest.main()

