"""
Unit Tests for Agent 10: Visual & UI Analysis
Covers all 20 acceptance criteria with robust mocks and offline execution.
"""

import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

from agents.agent10_visual import (
    analyze_visual,
    _normalize_url,
    _extract_registered_domain,
    _capture_screenshot,
    _extract_ocr_text,
    _detect_trust_badges,
    _detect_payment_logos,
    _analyze_reviews,
    _analyze_visual_consistency,
    _detect_suspicious_patterns,
    TRUSTED_BADGES_DATA,
    PAYMENT_LOGOS_DATA
)

# Mock HTML Fixtures
MOCK_DECEPTIVE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Urgent Account Verification Required</title>
    <style>
        body { font-family: 'Arial', sans-serif; font-size: 14px; }
        .btn-action { background: red; color: white; padding: 10px; }
    </style>
</head>
<body>
    <header>
        <h1>Security Alert: Immediate Action Required</h1>
    </header>
    
    <div class="banner">
        <p>Act now! Only 2 minutes remaining before your account will be suspended.</p>
        <p>Only 1 item left in stock! 50 people are viewing this right now.</p>
    </div>

    <div class="badges">
        <img src="/img/norton_secured.png" alt="Norton Secured" class="trust-seal">
        <img src="/img/ssl_badge.png" alt="100% Secure Checkout">
    </div>

    <div class="payments">
        <img src="/img/visa_logo.png" alt="Visa Verified">
        <img src="/img/paypal_logo.png" alt="Pay with PayPal">
    </div>

    <div class="reviews-section">
        <div class="testimonial-card">
            <img src="/img/avatar1.jpg" alt="User Avatar">
            <p>Best service ever! Highly recommended.</p>
            <span>John Doe</span>
        </div>
        <div class="testimonial-card">
            <img src="/img/avatar1.jpg" alt="User Avatar">
            <p>Best service ever! Highly recommended.</p>
            <span>John Doe</span>
        </div>
        <div class="rating">5.0 / 5 stars</div>
    </div>

    <div class="cta-box">
        <a href="/login/harvest" class="btn-action">Download Software Update</a>
    </div>
</body>
</html>
"""

MOCK_CLEAN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Legitimate Corporate Portal</title>
    <style>
        body { font-family: 'Inter', sans-serif; }
        .btn-primary { background: blue; padding: 8px 16px; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to Corporate Cloud Services</h1>
    </header>
    <div class="content">
        <p>Empowering global enterprises with secure distributed workflows.</p>
    </div>
    <footer>
        <p>&copy; 2026 Corporate Inc. All rights reserved.</p>
    </footer>
</body>
</html>
"""


class TestAgent10Visual(unittest.TestCase):
    """Test suite for Agent 10: Visual & UI Analysis."""

    def test_01_valid_website_visual_analysis(self):
        """Test 1: Full visual analysis on a mock deceptive page."""
        with patch("agents.agent10_visual.requests.Session") as mock_session_cls, \
             patch("agents.agent10_visual._capture_screenshot") as mock_screenshot, \
             patch("agents.agent10_visual._extract_ocr_text") as mock_ocr:

            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            mock_resp = MagicMock()
            mock_resp.url = "https://urgent-verification-portal.com"
            mock_resp.encoding = "utf-8"
            mock_resp.iter_content.return_value = [MOCK_DECEPTIVE_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            mock_screenshot.return_value = (
                {"status": "completed", "screenshot_captured": True, "width": 1920, "height": 1080},
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
            )
            mock_ocr.return_value = {
                "status": "completed",
                "text": "Act now! Only 2 minutes remaining! 100% Secure",
                "detected_terms": ["Act Now", "100% Secure"]
            }

            result = analyze_visual("https://urgent-verification-portal.com")
            self.assertIn(result["agent"], ("Visual/UI Analysis", "Agent 10"))
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["screenshot_analysis"]["screenshot_captured"])
            self.assertEqual(result["ocr"]["status"], "completed")
            self.assertTrue(len(result["trust_badges"]["detected"]) > 0)
            self.assertTrue(len(result["payment_logos"]["detected"]) > 0)
            self.assertTrue(result["reviews"]["detected"])
            self.assertTrue(len(result["suspicious_design_patterns"]) > 0)

    def test_02_invalid_url(self):
        """Test 2: Empty or invalid URL handling."""
        result = analyze_visual("")
        self.assertEqual(result["status"], "error")
        self.assertIn("URL is required", result["errors"][0])

    def test_03_screenshot_capture_success(self):
        """Test 3: Screenshot capture helper handling."""
        with patch("agents.agent10_visual.sync_playwright") as mock_pw:
            mock_p = MagicMock()
            mock_pw.return_value.__enter__.return_value = mock_p
            mock_browser = MagicMock()
            mock_p.chromium.launch.return_value = mock_browser
            mock_page = MagicMock()
            mock_browser.new_context.return_value.new_page.return_value = mock_page
            mock_page.screenshot.return_value = b"fake_png_bytes"

            res, raw_bytes = _capture_screenshot("https://example.com")
            self.assertEqual(res["status"], "completed")
            self.assertTrue(res["screenshot_captured"])
            self.assertEqual(res["width"], 1920)

    def test_04_screenshot_failure_handling(self):
        """Test 4: Screenshot error returns clear not_available status."""
        with patch("agents.agent10_visual.sync_playwright", side_effect=Exception("Browser launch failed")):
            res, raw_bytes = _capture_screenshot("https://example.com")
            self.assertEqual(res["status"], "not_available")
            self.assertFalse(res["screenshot_captured"])
            self.assertIsNotNone(res["error"])

    def test_05_ocr_text_extraction(self):
        """Test 5: OCR text extraction and pattern identification."""
        with patch("agents.agent10_visual.pytesseract.image_to_string", return_value="100% Secure Verified Payment Act Now"):
            with patch("agents.agent10_visual.Image.open") as mock_img_open:
                mock_img = MagicMock()
                mock_img_open.return_value = mock_img

                res = _extract_ocr_text(b"fake_image_bytes")
                self.assertEqual(res["status"], "completed")
                self.assertIn("100% Secure", res["text"])
                self.assertTrue(len(res["detected_terms"]) > 0)

    def test_06_no_visible_text_ocr(self):
        """Test 6: Blank screenshot returns empty text without crashing."""
        with patch("agents.agent10_visual.pytesseract.image_to_string", return_value=""):
            with patch("agents.agent10_visual.Image.open") as mock_img_open:
                res = _extract_ocr_text(b"blank_image_bytes")
                self.assertEqual(res["status"], "completed")
                self.assertEqual(res["text"], "")
                self.assertEqual(len(res["detected_terms"]), 0)

    def test_07_trust_badge_detection(self):
        """Test 7: Detect Norton Secured and 100% Secure trust badges."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        badges, evidence = _detect_trust_badges(soup, "", "https://example.com")
        self.assertTrue(len(badges["detected"]) > 0)
        names = [b["badge_name"] for b in badges["detected"]]
        self.assertTrue(any("Norton" in n for n in names))

    def test_08_unverified_badge_detection(self):
        """Test 8: Unlinked trust badges flagged as unverified/potentially_suspicious."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        badges, evidence = _detect_trust_badges(soup, "", "https://example.com")
        self.assertTrue(len(badges["suspicious_indicators"]) > 0)
        verifications = [b["verification"] for b in badges["detected"]]
        self.assertTrue(any(v in ("potentially_suspicious", "unverified") for v in verifications))


    def test_09_payment_logo_detection(self):
        """Test 9: Detect Visa and PayPal payment logos."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        payments, evidence = _detect_payment_logos(soup, MOCK_DECEPTIVE_HTML, "", "https://example.com")
        self.assertTrue(len(payments["detected"]) > 0)
        p_names = [p["name"] for p in payments["detected"]]
        self.assertIn("Visa", p_names)
        self.assertIn("PayPal", p_names)

    def test_10_no_payment_logos(self):
        """Test 10: Clean website with no payment logos."""
        soup = BeautifulSoup(MOCK_CLEAN_HTML, "html.parser")
        payments, evidence = _detect_payment_logos(soup, MOCK_CLEAN_HTML, "", "https://example.com")
        self.assertEqual(len(payments["detected"]), 0)

    def test_11_review_detection(self):
        """Test 11: Identify customer testimonials and review blocks."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        reviews, evidence = _analyze_reviews(soup)
        self.assertTrue(reviews["detected"])
        self.assertGreater(reviews["review_count_visible"], 0)

    def test_12_repeated_suspicious_reviews(self):
        """Test 12: Detect duplicate wording and repeated avatars."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        reviews, evidence = _analyze_reviews(soup)
        self.assertTrue(len(reviews["suspicious_indicators"]) > 0)
        self.assertTrue(any("identical" in ind for ind in reviews["suspicious_indicators"]))

    def test_13_visual_consistency_check(self):
        """Test 13: Consistency audit executes cleanly on webpage."""
        soup = BeautifulSoup(MOCK_CLEAN_HTML, "html.parser")
        consistency, evidence = _analyze_visual_consistency(soup, MOCK_CLEAN_HTML)
        self.assertEqual(consistency["status"], "analyzed")
        self.assertTrue(len(consistency["indicators"]) > 0)

    def test_14_suspicious_urgency_text(self):
        """Test 14: Detect high-pressure urgency keywords."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        patterns, evidence = _detect_suspicious_patterns(soup, MOCK_DECEPTIVE_HTML, "")
        urgency_items = [p for p in patterns if p["pattern"] == "urgency"]
        self.assertTrue(len(urgency_items) > 0)

    def test_15_suspicious_scarcity_text(self):
        """Test 15: Detect fake scarcity and social proof pressure."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        patterns, evidence = _detect_suspicious_patterns(soup, MOCK_DECEPTIVE_HTML, "")
        scarcity_items = [p for p in patterns if p["pattern"] == "fake_scarcity"]
        self.assertTrue(len(scarcity_items) > 0)

    def test_16_fear_intimidation_triggers(self):
        """Test 16: Detect account suspension / security threat warnings."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        patterns, evidence = _detect_suspicious_patterns(soup, MOCK_DECEPTIVE_HTML, "")
        fear_items = [p for p in patterns if p["pattern"] == "fear"]
        self.assertTrue(len(fear_items) > 0)

    def test_17_deceptive_button_cta(self):
        """Test 17: Detect deceptive buttons leading to login / credential endpoints."""
        soup = BeautifulSoup(MOCK_DECEPTIVE_HTML, "html.parser")
        patterns, evidence = _detect_suspicious_patterns(soup, MOCK_DECEPTIVE_HTML, "")
        btn_items = [p for p in patterns if p["pattern"] == "deceptive_button"]
        self.assertTrue(len(btn_items) > 0)

    def test_18_page_timeout_handling(self):
        """Test 18: Handle network timeout gracefully."""
        with patch("agents.agent10_visual.requests.Session") as mock_session_cls, \
             patch("agents.agent10_visual._capture_screenshot") as mock_screenshot:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            import requests
            mock_session.get.side_effect = requests.exceptions.Timeout("Read timeout")
            mock_screenshot.return_value = ({"status": "not_available", "screenshot_captured": False}, None)

            result = analyze_visual("https://slow-responding-host.com")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)
            self.assertIn("timed out", result["errors"][0])

    def test_19_connection_failure(self):
        """Test 19: Handle connection error gracefully."""
        with patch("agents.agent10_visual.requests.Session") as mock_session_cls, \
             patch("agents.agent10_visual._capture_screenshot") as mock_screenshot:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = Exception("Connection refused")
            mock_screenshot.return_value = ({"status": "not_available", "screenshot_captured": False}, None)

            result = analyze_visual("https://unreachable-host.net")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)

    def test_20_clean_site_no_deceptive_patterns(self):
        """Test 20: Clean corporate website yields no false positives."""
        soup = BeautifulSoup(MOCK_CLEAN_HTML, "html.parser")
        patterns, evidence = _detect_suspicious_patterns(soup, MOCK_CLEAN_HTML, "")
        self.assertEqual(len(patterns), 0)


if __name__ == "__main__":
    unittest.main()
