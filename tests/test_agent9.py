"""
Unit Tests for Agent 9: Brand Verification
Covers all 25 acceptance criteria with robust mocks and offline execution.
"""

import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup
import io

from agents.agent9_brand import (
    analyze_brand,
    _normalize_url,
    _extract_registered_domain,
    _normalize_text,
    _hex_to_rgb,
    _color_distance,
    _calculate_dhash,
    _dhash_similarity,
    _is_safe_url,
    _damerau_levenshtein_distance,
    _fetch_webpage_safe,
    _download_image_safe,
    _match_brand_names,
    _detect_and_analyze_logo,
    _detect_and_analyze_favicon,
    _extract_and_analyze_colors,
    _analyze_layout_similarity,
    _match_trademark_references,
    _compare_official_domain,
    BRAND_REFERENCES
)

# Mock HTML Fixtures
MOCK_MICROSOFT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your Microsoft account</title>
    <meta property="og:site_name" content="Microsoft">
    <link rel="icon" href="/static/images/msft_favicon.ico">
    <style>
        body { background-color: #0078D4; color: #FFFFFF; }
        .btn-primary { background: #2F88FF; }
    </style>
</head>
<body>
    <header>
        <img id="brand-logo" src="https://example-phish.com/assets/microsoft_logo.png" alt="Microsoft" class="header-logo">
    </header>
    <div class="auth-card login-box">
        <h1>Microsoft Sign In</h1>
        <form action="/harvest" method="POST">
            <input type="email" name="loginfmt" placeholder="Email, phone, or Skype">
            <input type="password" name="passwd" placeholder="Password">
            <button type="submit">Next</button>
        </form>
    </div>
    <footer>
        <p>&copy; 2026 Microsoft Corporation. All rights reserved.</p>
    </footer>
</body>
</html>
"""

MOCK_GENERIC_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Generic Blog - Home</title>
</head>
<body>
    <h1>Welcome to My Coding Blog</h1>
    <p>This is a completely generic website with no brand references.</p>
</body>
</html>
"""

MOCK_MULTI_BRAND_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login with Google or PayPal</title>
</head>
<body>
    <h1>Multi-Gateway Sign In</h1>
    <p>Sign in using your Google Account or PayPal Wallet.</p>
    <img src="/img/paypal_logo.png" alt="PayPal">
</body>
</html>
"""


class TestAgent9Brand(unittest.TestCase):
    """Test suite for Agent 9: Brand Verification."""

    def test_01_valid_website_brand_detection(self):
        """Test 1: Full brand verification on a mock Microsoft page."""
        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            # Mock webpage response
            mock_resp = MagicMock()
            mock_resp.url = "https://example-phish.com/login"
            mock_resp.encoding = "utf-8"
            mock_resp.iter_content.return_value = [MOCK_MICROSOFT_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_brand("https://example-phish.com/login")
            self.assertIn(result["agent"], ("Brand Verification", "Agent 9"))
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["brand_name_matching"]["detected"])
            candidate_brands = [b["brand"] for b in result["brand_name_matching"]["candidate_brands"]]
            self.assertIn("Microsoft", candidate_brands)
            self.assertTrue(result["logo"]["detected"])
            self.assertIsNotNone(result["official_domain_comparison"]["submitted_domain"])
            self.assertFalse(result["official_domain_comparison"]["same_domain"])

    def test_02_invalid_url(self):
        """Test 2: Empty or invalid URL returns structured error response."""
        result = analyze_brand("")
        self.assertEqual(result["status"], "error")
        self.assertIn("URL is required", result["errors"][0])

    def test_03_website_with_visible_brand_name(self):
        """Test 3: Extract brand names from title, headings, meta tags."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        res, evidence = _match_brand_names(soup, "https://example.com")
        self.assertTrue(res["detected"])
        brands = [b["brand"] for b in res["candidate_brands"]]
        self.assertIn("Microsoft", brands)
        self.assertTrue(len(evidence) > 0)

    def test_04_website_with_no_brand(self):
        """Test 4: Generic page with no recognizable brand signatures."""
        soup = BeautifulSoup(MOCK_GENERIC_HTML, "html.parser")
        res, evidence = _match_brand_names(soup, "https://example.com")
        self.assertFalse(res["detected"])
        self.assertEqual(len(res["candidate_brands"]), 0)
        self.assertEqual(len(evidence), 0)

    def test_05_logo_detection(self):
        """Test 5: Detect logo by img tag, id, alt, and class."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        session = MagicMock()
        logo_data, logo_sim, evidence = _detect_and_analyze_logo(
            soup, "https://example-phish.com", session, ["Microsoft"]
        )
        self.assertTrue(logo_data["detected"])
        self.assertEqual(logo_data["alt"], "Microsoft")
        self.assertEqual(logo_data["location"], "header/nav")

    def test_06_no_logo(self):
        """Test 6: Page with no logo elements."""
        soup = BeautifulSoup(MOCK_GENERIC_HTML, "html.parser")
        session = MagicMock()
        logo_data, logo_sim, evidence = _detect_and_analyze_logo(
            soup, "https://example.com", session, []
        )
        self.assertFalse(logo_data["detected"])
        self.assertIsNone(logo_data["url"])

    def test_07_favicon_detection(self):
        """Test 7: Favicon extracted from link tag."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [b"\x00\x00\x01\x00" + b"\x00" * 30]
        session.get.return_value = mock_resp

        fav_data, fav_sim, evidence = _detect_and_analyze_favicon(
            soup, "https://example-phish.com", session, ["Microsoft"]
        )
        self.assertTrue(fav_data["detected"])
        self.assertIn("msft_favicon.ico", fav_data["url"])

    def test_08_no_favicon(self):
        """Test 8: Handle missing favicon gracefully."""
        soup = BeautifulSoup(MOCK_GENERIC_HTML, "html.parser")
        session = MagicMock()
        session.get.side_effect = Exception("404 Not Found")

        fav_data, fav_sim, evidence = _detect_and_analyze_favicon(
            soup, "https://example.com", session, []
        )
        self.assertFalse(fav_data["detected"])

    def test_09_brand_logo_similarity(self):
        """Test 9: Calculate logo similarity score for matching brand."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [b"GIF89a" + b"\x00" * 50]
        session.get.return_value = mock_resp

        logo_data, logo_sim, evidence = _detect_and_analyze_logo(
            soup, "https://example.com", session, ["Microsoft"]
        )
        self.assertEqual(logo_sim["status"], "analyzed")
        self.assertTrue(len(logo_sim["matches"]) > 0)
        self.assertGreaterEqual(logo_sim["matches"][0]["similarity_score"], 0.8)

    def test_10_favicon_similarity(self):
        """Test 10: Calculate favicon similarity for detected brand."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [b"\x00\x00\x01\x00" + b"\x00" * 30]
        session.get.return_value = mock_resp

        fav_data, fav_sim, evidence = _detect_and_analyze_favicon(
            soup, "https://example.com", session, ["Microsoft"]
        )
        self.assertTrue(fav_data["detected"])
        if fav_sim["matches"]:
            self.assertGreaterEqual(fav_sim["matches"][0]["similarity_score"], 0.0)

    def test_11_color_extraction(self):
        """Test 11: Dominant color extraction from CSS style markup."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        color_theme, evidence = _extract_and_analyze_colors(MOCK_MICROSOFT_HTML, soup, ["Microsoft"])
        self.assertEqual(color_theme["status"], "analyzed")
        self.assertIn("#0078D4", color_theme["dominant_colors"])
        self.assertIn("#FFFFFF", color_theme["dominant_colors"])

    def test_12_color_similarity(self):
        """Test 12: Color theme similarity against brand palette."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        color_theme, evidence = _extract_and_analyze_colors(MOCK_MICROSOFT_HTML, soup, ["Microsoft"])
        self.assertTrue(len(color_theme["matches"]) > 0)
        self.assertGreater(color_theme["matches"][0]["similarity_score"], 0.0)

    def test_13_layout_analysis(self):
        """Test 13: Detect centered auth card layout archetype."""
        soup = BeautifulSoup(MOCK_MICROSOFT_HTML, "html.parser")
        layout, evidence = _analyze_layout_similarity(soup, ["Microsoft"])
        self.assertEqual(layout["status"], "analyzed")
        self.assertTrue(len(layout["matches"]) > 0)
        self.assertEqual(layout["matches"][0]["layout_type"], "centered_auth_card")

    def test_14_trademark_lookup_and_unavailable(self):
        """Test 14: Trademark matching references."""
        # Available for known brand
        res_avail, ev_avail = _match_trademark_references(["Microsoft", "Google"])
        self.assertEqual(res_avail["status"], "analyzed")
        self.assertTrue(len(res_avail["matches"]) > 0)
        self.assertEqual(res_avail["matches"][0]["match_type"], "name")

        # Unavailable / empty for unknown brand
        res_unavail, ev_unavail = _match_trademark_references([])
        self.assertEqual(res_unavail["status"], "not_available")

    def test_15_image_matching_structure(self):
        """Test 15: Image matching format conformity."""
        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_resp = MagicMock()
            mock_resp.url = "https://generic-site.com"
            mock_resp.iter_content.return_value = [MOCK_GENERIC_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_brand("https://generic-site.com")
            self.assertEqual(result["image_matching"]["status"], "not_available")

    def test_16_official_domain_comparison(self):
        """Test 16: Official domain extraction and comparison."""
        res, ev = _compare_official_domain("https://paypal-verify-account.com", ["PayPal"])
        self.assertEqual(res["status"], "compared")
        self.assertEqual(res["candidate_brand"], "PayPal")
        self.assertEqual(res["official_domain"], "paypal.com")
        self.assertEqual(res["submitted_domain"], "paypal-verify-account.com")
        self.assertFalse(res["same_domain"])

    def test_17_different_domain(self):
        """Test 17: Mismatched domain returns same_domain = False."""
        res, ev = _compare_official_domain("https://fake-login-service.net", ["Microsoft"])
        self.assertFalse(res["same_domain"])

    def test_18_same_domain(self):
        """Test 18: Genuine domain returns same_domain = True."""
        res, ev = _compare_official_domain("https://account.microsoft.com/security", ["Microsoft"])
        self.assertTrue(res["same_domain"])

    def test_19_multiple_candidate_brands(self):
        """Test 19: Handle multiple brand names on the same page."""
        soup = BeautifulSoup(MOCK_MULTI_BRAND_HTML, "html.parser")
        res, ev = _match_brand_names(soup, "https://example.com")
        brands = [b["brand"] for b in res["candidate_brands"]]
        self.assertIn("Google", brands)
        self.assertIn("PayPal", brands)

    def test_20_js_rendered_meta_brand_detection(self):
        """Test 20: Detect brands located in OpenGraph and meta descriptions."""
        html = '<html><head><meta name="description" content="Official Apple iCloud Login Portal"></head><body></body></html>'
        soup = BeautifulSoup(html, "html.parser")
        res, ev = _match_brand_names(soup, "https://example.com")
        brands = [b["brand"] for b in res["candidate_brands"]]
        self.assertIn("Apple", brands)

    def test_21_network_timeout(self):
        """Test 21: Handle network timeout safely without crashing."""
        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            import requests
            mock_session.get.side_effect = requests.exceptions.Timeout("Read timeout")

            result = analyze_brand("https://slow-responding-site.com")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)
            self.assertIn("timed out", result["errors"][0])

    def test_22_connection_error(self):
        """Test 22: Handle connection error safely."""
        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = Exception("Connection refused")

            result = analyze_brand("https://unreachable-site.xyz")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)

    def test_23_large_image_limiting(self):
        """Test 23: Image download limits enforce max size limit."""
        from agents.agent9_brand import _download_image_safe
        session = MagicMock()
        mock_resp = MagicMock()
        # Return 2MB of chunks
        mock_resp.iter_content.return_value = [b"A" * 1024 * 1024, b"B" * 1024 * 1024]
        session.get.return_value = mock_resp

        img_bytes, img_fmt, dims = _download_image_safe("https://example.com/huge.png", session)
        self.assertIsNone(img_bytes)

    def test_24_missing_or_404_image(self):
        """Test 24: Handle 404 image response gracefully."""
        from agents.agent9_brand import _download_image_safe
        session = MagicMock()
        session.get.side_effect = Exception("404 Client Error")

        img_bytes, img_fmt, dims = _download_image_safe("https://example.com/notfound.png", session)
        self.assertIsNone(img_bytes)

    def test_25_malformed_html(self):
        """Test 25: Parse completely malformed or unclosed HTML gracefully."""
        malformed = "<div><title>Microsoft Login<p><span><img src='logo.png' alt='Microsoft'"
        soup = BeautifulSoup(malformed, "html.parser")
        res, ev = _match_brand_names(soup, "https://example.com")
        brands = [b["brand"] for b in res["candidate_brands"]]
        self.assertIn("Microsoft", brands)

    def test_26_evidence_schema_and_ledger(self):
        """Test 26: Validate all 7 evidence items and Evidence Ledger ingestion."""
        from services.evidence_schema import validate_evidence_item
        from services.evidence_normalizer import normalize_evidence_item
        from services.evidence_ledger import EvidenceLedger

        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_resp = MagicMock()
            mock_resp.url = "https://phish-login.com"
            mock_resp.iter_content.return_value = [MOCK_MICROSOFT_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_brand("https://phish-login.com")
            evidence = result.get("evidence", [])
            self.assertEqual(len(evidence), 7)

            expected_ids = [f"E9-{i:02d}" for i in range(1, 8)]
            actual_ids = [e["evidence_id"] for e in evidence]
            self.assertEqual(actual_ids, expected_ids)

            for item in evidence:
                is_valid, errors = validate_evidence_item(item)
                self.assertTrue(is_valid, f"Item {item.get('evidence_id')} failed validation: {errors}")
                norm_ev = normalize_evidence_item(item, agent_identifier="A9", agent_result=result)
                self.assertIsNotNone(norm_ev)
                self.assertEqual(norm_ev["evidence_id"], item["evidence_id"])

            ledger = EvidenceLedger(target="https://phish-login.com")
            ledger.add_entries_from_agent(result)
            self.assertEqual(len(ledger.entries), 7)
            self.assertEqual(len(ledger.get_entries(agent_id=9)), 7)

    def test_27_tce_integration_and_polarity(self):
        """Test 27: Validate TCE integration and polarity evaluation."""
        from services.trust_calculation_engine import TrustCalculationEngine
        from services.evidence_ledger import EvidenceLedger

        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_resp = MagicMock()
            mock_resp.url = "https://phish-brand-portal.com"
            mock_resp.iter_content.return_value = [MOCK_MICROSOFT_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_brand("https://phish-brand-portal.com")
            ledger = EvidenceLedger(target="https://phish-brand-portal.com")
            ledger.add_entries_from_agent(result)

            tce = TrustCalculationEngine()
            tce_output = tce.calculate_trust(ledger)
            self.assertIn("trust_score", tce_output)
            self.assertIn("risk_score", tce_output)
            self.assertIn("verdict", tce_output)
            # Domain mismatch should generate risk in TCE
            self.assertGreater(tce_output["risk_score"], 0.0)

    def test_28_homoglyph_and_lookalike_domain_handling(self):
        """Test 28: Compare lookalike / homoglyph domain with official brand domain."""
        res_typo, _ = _compare_official_domain("https://micros0ft.com", ["Microsoft"])
        self.assertEqual(res_typo["status"], "compared")
        self.assertFalse(res_typo["same_domain"])

        res_genuine, _ = _compare_official_domain("https://login.microsoftonline.com", ["Microsoft"])
        self.assertEqual(res_genuine["status"], "compared")
        self.assertTrue(res_genuine["same_domain"])

    def test_29_generic_page_no_false_positive_brand(self):
        """Test 29: Plain generic page produces no candidate brand and clean evidence."""
        soup = BeautifulSoup(MOCK_GENERIC_HTML, "html.parser")
        res, ev = _match_brand_names(soup, "https://my-ordinary-blog.org")
        self.assertFalse(res["detected"])
        self.assertEqual(len(res["candidate_brands"]), 0)

    def test_30_strict_schema_no_scores(self):
        """Test 30: Agent 9 response MUST NOT calculate final trust or risk scores."""
        with patch("agents.agent9_brand.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_resp = MagicMock()
            mock_resp.url = "https://example.com"
            mock_resp.iter_content.return_value = [MOCK_GENERIC_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_brand("https://example.com")
            forbidden_keys = [
                "trust_score", "trustscore", "risk_score", "riskscore",
                "phishing_probability", "verdict", "final_score", "classification"
            ]
            for key in forbidden_keys:
                self.assertNotIn(key, result, f"Agent 9 response MUST NOT contain forbidden score/verdict key '{key}'")

    def test_31_ssrf_protection_blocked_endpoints(self):
        """Test 31: Verify SSRF protection blocks private, loopback, and cloud metadata addresses."""
        blocked_urls = [
            "http://localhost:8080/logo.png",
            "http://127.0.0.1/favicon.ico",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/auth/logo.png",
            "http://192.168.1.1/admin/logo.png",
            "http://172.16.0.5/logo.png",
            "http://[::1]/logo.png",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        for b_url in blocked_urls:
            self.assertFalse(_is_safe_url(b_url), f"URL should be blocked for SSRF: {b_url}")

        allowed_urls = [
            "https://example.com/logo.png",
            "https://login.microsoftonline.com/favicon.ico",
            "http://public-site.org/assets/logo.svg",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        ]
        for a_url in allowed_urls:
            self.assertTrue(_is_safe_url(a_url), f"URL should be allowed: {a_url}")

    def test_32_damerau_levenshtein_distance(self):
        """Test 32: Validate Damerau-Levenshtein distance calculations."""
        # Exact match
        self.assertEqual(_damerau_levenshtein_distance("paypal", "paypal"), 0)
        # Substitution
        self.assertEqual(_damerau_levenshtein_distance("paypa1", "paypal"), 1)
        self.assertEqual(_damerau_levenshtein_distance("micros0ft", "microsoft"), 1)
        # Transposition
        self.assertEqual(_damerau_levenshtein_distance("microsfot", "microsoft"), 1)
        # Insertion
        self.assertEqual(_damerau_levenshtein_distance("faceboook", "facebook"), 1)
        # Deletion
        self.assertEqual(_damerau_levenshtein_distance("amazn", "amazon"), 1)
        # Multiple edits
        self.assertEqual(_damerau_levenshtein_distance("paypa11", "paypal"), 2)

    def test_33_typosquatting_detection_lookalike_domains(self):
        """Test 33: Typosquatting detection flags lookalike domain variants."""
        # 1-edit distance lookalike: paypa1.com vs paypal.com
        res, ev = _compare_official_domain("https://paypa1.com/login", ["PayPal"])
        self.assertEqual(res["status"], "compared")
        self.assertFalse(res["same_domain"])
        self.assertIn("typosquatting", res)
        self.assertTrue(res["typosquatting"]["detected"])
        self.assertEqual(res["typosquatting"]["edit_distance"], 1)

        # 1-edit distance lookalike: micros0ft.com vs microsoft.com
        res_ms, ev_ms = _compare_official_domain("https://micros0ft.com/account", ["Microsoft"])
        self.assertFalse(res_ms["same_domain"])
        self.assertTrue(res_ms["typosquatting"]["detected"])
        self.assertEqual(res_ms["typosquatting"]["edit_distance"], 1)

        # Genuine official domain has edit_distance 0 and detected False
        res_gen, _ = _compare_official_domain("https://paypal.com/signin", ["PayPal"])
        self.assertTrue(res_gen["same_domain"])
        self.assertFalse(res_gen["typosquatting"]["detected"])
        self.assertEqual(res_gen["typosquatting"]["edit_distance"], 0)

    def test_34_ssrf_in_webpage_and_image_fetching(self):
        """Test 34: _fetch_webpage_safe and _download_image_safe reject SSRF targets."""
        session = MagicMock()
        # Fetching internal metadata
        html, final_url, soup, errors = _fetch_webpage_safe("http://169.254.169.254/latest/meta-data/", session)
        self.assertIsNone(html)
        self.assertTrue(any("SSRF" in err for err in errors))

        # Downloading image from internal host
        from agents.agent9_brand import _download_image_safe
        img_bytes, img_fmt, dims = _download_image_safe("http://127.0.0.1:8000/secret.png", session)
        self.assertIsNone(img_bytes)

    def test_35_image_decompression_bomb_handling(self):
        """Test 35: Pillow image handling configures decompression protection."""
        from agents.agent9_brand import _PIL_AVAILABLE
        if _PIL_AVAILABLE:
            from PIL import Image
            self.assertIsNotNone(Image.MAX_IMAGE_PIXELS)
            self.assertLessEqual(Image.MAX_IMAGE_PIXELS, 100_000_000)

    def test_36_multi_brand_evidence_integrity(self):
        """Test 36: Multi-brand pages report detected candidate brands without crashing."""
        soup = BeautifulSoup(MOCK_MULTI_BRAND_HTML, "html.parser")
        res, ev = _match_brand_names(soup, "https://example-gateway.com")
        self.assertTrue(res["detected"])
        brands = [b["brand"] for b in res["candidate_brands"]]
        self.assertIn("Google", brands)
        self.assertIn("PayPal", brands)


if __name__ == "__main__":
    unittest.main()


