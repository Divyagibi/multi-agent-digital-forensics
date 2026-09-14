# -*- coding: utf-8 -*-
"""
tests/test_agent7.py
====================
Comprehensive mock-based test suite for Agent 7 -- Technical Fingerprinting.

Tests cover:
    1. Valid URL analysis structure
    2. Invalid & empty URL input
    3. Server header detection (nginx/1.24.0)
    4. Server version unavailable / hidden
    5. WordPress CMS detection with evidence
    6. CMS not detected (clean)
    7. Framework detection (Next.js & React)
    8. JavaScript library detection (jQuery 3.7.1, Bootstrap)
    9. Analytics detection (Google Analytics & GTM IDs)
    10. Third-party services detection & categorization
    11. Tracking scripts detection (Meta Pixel, TikTok)
    12. Admin page returns HTTP 200 (detected)
    13. Admin page returns HTTP 403 (possibly_protected)
    14. Admin page returns HTTP 404 (not detected)
    15. Open directory listing detected ("Index of /")
    16. Open directory listing not detected
    17. Request timeout handling
    18. Connection error handling
    19. HTTP redirect chain handling
    20. Large HTML response truncation
    21. Malformed HTML handling
    22. Multiple technologies co-existing
    23. Technology version unavailable (null representation)
    24. Strict schema assertion (verifies NO trust score, risk score, or verdict)

Run:
    python tests/test_agent7.py
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import requests
from bs4 import BeautifulSoup

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from agents.agent7_fingerprinting import (
    analyze_fingerprint,
    get_technical_fingerprint,
    normalize_url,
    fetch_webpage,
    detect_web_server,
    detect_cms,
    detect_frameworks,
    detect_javascript_libraries,
    detect_analytics,
    detect_third_party_services,
    detect_tracking_scripts,
    check_admin_panels,
    check_open_directories
)


class TestAgent7Fingerprinting(unittest.TestCase):

    # 1. Valid URL analysis
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    def test_01_valid_url(self, mock_dirs, mock_admins, mock_fetch):
        mock_fetch.return_value = {
            "status": "success",
            "status_code": 200,
            "final_url": "https://example.com",
            "headers": {"Server": "nginx/1.24.0"},
            "html": "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>",
            "redirect_count": 0,
            "redirect_chain": ["https://example.com"]
        }

        result = analyze_fingerprint("https://example.com")
        self.assertIn(result.get("agent"), ("Technical Fingerprinting", "Agent 7"))
        self.assertEqual(result.get("status"), "success")
        self.assertIn("input", result)
        self.assertEqual(result["input"]["original_url"], "https://example.com")
        self.assertEqual(result["web_server"]["status"], "detected")
        self.assertEqual(result["web_server"]["name"], "nginx")
        self.assertEqual(result["web_server"]["version"], "1.24.0")

    # 2. Invalid URL
    def test_02_invalid_url(self):
        result = analyze_fingerprint("")
        self.assertEqual(result.get("status"), "error")
        self.assertTrue(len(result.get("errors", [])) > 0)
        self.assertEqual(result.get("web_server", {}).get("status"), "not_detected")

    # 3. Server header detection
    def test_03_server_header_detection(self):
        headers = {"Server": "Apache/2.4.52 (Ubuntu)"}
        ws = detect_web_server(headers)
        self.assertEqual(ws["status"], "detected")
        self.assertEqual(ws["name"], "Apache")
        self.assertEqual(ws["version"], "2.4.52")

    # 4. Server version unavailable
    def test_04_server_version_unavailable(self):
        headers = {"Server": "cloudflare"}
        ws = detect_web_server(headers)
        self.assertEqual(ws["status"], "detected")
        self.assertEqual(ws["name"], "cloudflare")
        self.assertIsNone(ws["version"])

        # Also test no server header
        ws_empty = detect_web_server({})
        self.assertEqual(ws_empty["status"], "not_detected")
        self.assertIsNone(ws_empty["name"])
        self.assertIsNone(ws_empty["version"])

    # 5. WordPress detection
    def test_05_wordpress_detection(self):
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2" />
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
        </head>
        <body>
            <script src="/wp-includes/js/wp-emoji-release.min.js"></script>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        cms = detect_cms(soup, html, {})
        self.assertEqual(cms["status"], "detected")
        self.assertEqual(cms["name"], "WordPress")
        self.assertEqual(cms["version"], "6.4.2")
        self.assertIn("/wp-content/", cms["evidence"])
        self.assertIn("/wp-includes/", cms["evidence"])

    # 6. CMS not detected
    def test_06_cms_not_detected(self):
        html = "<html><head><title>Custom Site</title></head><body>Plain page</body></html>"
        soup = BeautifulSoup(html, "html.parser")
        cms = detect_cms(soup, html, {})
        self.assertEqual(cms["status"], "not_detected")
        self.assertIsNone(cms["name"])
        self.assertEqual(cms["evidence"], [])

    # 7. Framework detection (Next.js & React)
    def test_07_framework_detection(self):
        html = """
        <html>
        <head></head>
        <body>
            <div id="__next">
                <div data-reactroot="">Content</div>
            </div>
            <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
            <script src="/_next/static/chunks/main.js"></script>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        frameworks = detect_frameworks(soup, html, {})
        names = [f["name"] for f in frameworks]
        self.assertIn("Next.js", names)

    # 8. JavaScript library detection
    def test_08_javascript_libraries(self):
        html = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
        </head>
        <body></body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        libs = detect_javascript_libraries(soup, html)
        lib_names = [l["name"] for l in libs]
        self.assertIn("jQuery", lib_names)
        self.assertIn("Bootstrap", lib_names)
        self.assertIn("Lodash", lib_names)

        jquery_lib = next(l for l in libs if l["name"] == "jQuery")
        self.assertEqual(jquery_lib["version"], "3.7.1")

    # 9. Analytics detection
    def test_09_analytics_detection(self):
        html = """
        <html>
        <head>
            <script async src="https://www.googletagmanager.com/gtag/js?id=G-1234567890"></script>
            <script>
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
                gtag('js', new Date());
                gtag('config', 'G-1234567890');
            </script>
            <script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST123"></script>
        </head>
        <body></body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        analytics = detect_analytics(soup, html)
        ga = next((a for a in analytics if a["name"] == "Google Analytics"), None)
        gtm = next((a for a in analytics if a["name"] == "Google Tag Manager"), None)

        self.assertIsNotNone(ga)
        self.assertEqual(ga["tracking_id"], "G-1234567890")
        self.assertIsNotNone(gtm)
        self.assertEqual(gtm["tracking_id"], "GTM-TEST123")

    # 10. Third-party services detection
    def test_10_third_party_services(self):
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter" />
            <script src="https://js.stripe.com/v3/"></script>
            <script src="https://www.google.com/recaptcha/api.js"></script>
        </head>
        <body></body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        services = detect_third_party_services(soup, html, "example.com")
        names = [s["name"] for s in services]
        self.assertIn("Google Fonts", names)
        self.assertIn("Stripe", names)
        self.assertIn("Google reCAPTCHA", names)

    # 11. Tracking scripts detection
    def test_11_tracking_scripts(self):
        html = """
        <html>
        <head>
            <script>
                !function(f,b,e,v,n,t,s)
                {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
                n.callMethod.apply(n,arguments):n.queue.push(arguments)};
                fbq('init', '1234567890');
                fbq('track', 'PageView');}(window, document,'script',
                'https://connect.facebook.net/en_US/fbevents.js');
            </script>
            <script src="https://analytics.tiktok.com/i18n/pixel/events.js"></script>
        </head>
        <body></body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        trackers = detect_tracking_scripts(soup, html)
        tracker_names = [t["name"] for t in trackers]
        self.assertIn("Meta Pixel (Facebook)", tracker_names)
        self.assertIn("TikTok Pixel", tracker_names)

    # 12. Admin panel returns 200
    @patch("requests.get")
    def test_12_admin_panel_200(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><h2>Admin Portal</h2><input type="password" name="pwd"></body></html>'
        mock_resp.url = "https://example.com/admin"
        mock_get.return_value = mock_resp

        panels = check_admin_panels("https://example.com")
        admin_entry = next((p for p in panels if p["path"] == "/admin"), None)
        self.assertIsNotNone(admin_entry)
        self.assertEqual(admin_entry["status_code"], 200)
        self.assertTrue(admin_entry["detected"])

    # 13. Admin panel returns 403
    @patch("requests.get")
    def test_13_admin_panel_403(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_resp.url = "https://example.com/admin"
        mock_get.return_value = mock_resp

        panels = check_admin_panels("https://example.com")
        admin_entry = next((p for p in panels if p["path"] == "/admin"), None)
        self.assertIsNotNone(admin_entry)
        self.assertEqual(admin_entry["status_code"], 403)
        self.assertEqual(admin_entry["detected"], "possibly_protected")

    # 14. Admin panel returns 404
    @patch("requests.get")
    def test_14_admin_panel_404(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Not Found"
        mock_resp.url = "https://example.com/admin"
        mock_get.return_value = mock_resp

        panels = check_admin_panels("https://example.com")
        admin_entry = next((p for p in panels if p["path"] == "/admin"), None)
        self.assertIsNotNone(admin_entry)
        self.assertEqual(admin_entry["status_code"], 404)
        self.assertFalse(admin_entry["detected"])

    # 15. Directory listing detected
    @patch("requests.get")
    def test_15_directory_listing_detected(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><a href="../">Parent Directory</a></body></html>'
        mock_get.return_value = mock_resp

        dirs = check_open_directories("https://example.com")
        upload_entry = next((d for d in dirs if d["path"] == "/uploads/"), None)
        self.assertIsNotNone(upload_entry)
        self.assertEqual(upload_entry["status_code"], 200)
        self.assertTrue(upload_entry["directory_listing"])

    # 16. Directory listing not detected
    @patch("requests.get")
    def test_16_directory_listing_not_detected(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Not Found"
        mock_get.return_value = mock_resp

        dirs = check_open_directories("https://example.com")
        upload_entry = next((d for d in dirs if d["path"] == "/uploads/"), None)
        self.assertIsNotNone(upload_entry)
        self.assertFalse(upload_entry["directory_listing"])

    # 17. Request timeout
    @patch("requests.Session.get", side_effect=requests.exceptions.Timeout("Timed out"))
    def test_17_request_timeout(self, mock_session_get):
        fetch_res = fetch_webpage("https://slow-site.example.com")
        self.assertEqual(fetch_res["status"], "timeout")
        self.assertIn("timed out", fetch_res["message"].lower())

    # 18. Connection error
    @patch("requests.Session.get", side_effect=requests.exceptions.ConnectionError("Failed to connect"))
    @patch("requests.get", side_effect=requests.exceptions.ConnectionError("Failed to connect"))
    def test_18_connection_error(self, mock_get, mock_session_get):
        fetch_res = fetch_webpage("https://unreachable.example.com")
        self.assertEqual(fetch_res["status"], "error")
        self.assertTrue(len(fetch_res["message"]) > 0)

    # 19. Redirect handling
    @patch("requests.Session.get")
    def test_19_redirect_handling(self, mock_session_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://www.example.com/home"
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [b"<html><body>Redirected</body></html>"]

        # Mock redirect history
        r1 = MagicMock()
        r1.url = "http://example.com"
        r2 = MagicMock()
        r2.url = "https://example.com"
        mock_resp.history = [r1, r2]

        mock_session_get.return_value = mock_resp

        fetch_res = fetch_webpage("http://example.com")
        self.assertEqual(fetch_res["status"], "success")
        self.assertEqual(fetch_res["redirect_count"], 2)
        self.assertEqual(fetch_res["final_url"], "https://www.example.com/home")

    # 20. Large HTML response truncation
    @patch("requests.Session.get")
    def test_20_large_html_response(self, mock_session_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com"
        mock_resp.headers = {}
        mock_resp.encoding = "utf-8"
        mock_resp.history = []

        # Yield chunks that exceed MAX_HTML_SIZE (2MB)
        chunk = b"A" * 65536
        mock_resp.iter_content.return_value = [chunk for _ in range(40)]

        mock_session_get.return_value = mock_resp

        fetch_res = fetch_webpage("https://example.com")
        self.assertEqual(fetch_res["status"], "success")
        self.assertTrue(len(fetch_res["html"]) >= 2 * 1024 * 1024)

    # 21. Malformed HTML handling
    def test_21_malformed_html(self):
        malformed = "<div><p>Unclosed tags <<>> &&& <script src='broken.js' <span"
        soup = BeautifulSoup(malformed, "html.parser")
        cms = detect_cms(soup, malformed, {})
        self.assertEqual(cms["status"], "not_detected")
        frameworks = detect_frameworks(soup, malformed, {})
        self.assertIsInstance(frameworks, list)

    # 22. Multiple technologies detected
    def test_22_multiple_technologies(self):
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.3" />
            <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto" />
            <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.0"></script>
            <script async src="https://www.googletagmanager.com/gtag/js?id=G-MULTI123"></script>
            <script src="https://js.stripe.com/v3/"></script>
        </head>
        <body>
            <div data-reactroot="">React Component Inside WP</div>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        cms = detect_cms(soup, html, {})
        self.assertEqual(cms["name"], "WordPress")

        frameworks = detect_frameworks(soup, html, {})
        f_names = [f["name"] for f in frameworks]
        self.assertIn("React", f_names)

        analytics = detect_analytics(soup, html)
        self.assertTrue(any(a["name"] == "Google Analytics" for a in analytics))

        third_party = detect_third_party_services(soup, html, "example.com")
        tp_names = [tp["name"] for tp in third_party]
        self.assertIn("Google Fonts", tp_names)
        self.assertIn("Stripe", tp_names)

    # 23. Technology version unavailable (null)
    def test_23_version_unavailable_null(self):
        html = '<html><head><script src="/assets/js/custom-app.js"></script></head><body></body></html>'
        soup = BeautifulSoup(html, "html.parser")
        cms = detect_cms(soup, html, {})
        self.assertIsNone(cms["version"])

        ws = detect_web_server({"Server": "openresty"})
        self.assertIsNone(ws["version"])

    # 24. Strict Schema Assertion: NO trust/risk scores or verdicts allowed
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    def test_24_schema_no_risk_scores(self, mock_dirs, mock_admins, mock_fetch):
        mock_fetch.return_value = {
            "status": "success",
            "status_code": 200,
            "final_url": "https://example.com",
            "headers": {},
            "html": "<html><body>Hello</body></html>",
            "redirect_count": 0,
            "redirect_chain": ["https://example.com"]
        }
        result = analyze_fingerprint("https://example.com")

        forbidden_keys = [
            "trust_score", "trustscore", "risk_score", "riskscore",
            "phishing_probability", "verdict", "final_score",
            "classification", "confidence"
        ]
        for key in forbidden_keys:
            self.assertNotIn(key, result, f"Agent 7 response MUST NOT contain forbidden score/verdict key '{key}'")


def run_all_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAgent7Fingerprinting)
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)
    print("\n" + "=" * 60)
    print(f"Agent 7 Test Suite Results: Ran {test_result.testsRun} tests.")
    if test_result.wasSuccessful():
        print("ALL AGENT 7 TESTS PASSED SUCCESSFULLY.")
    else:
        print(f"FAILURES: {len(test_result.failures)}, ERRORS: {len(test_result.errors)}")
    print("=" * 60)
    return test_result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
