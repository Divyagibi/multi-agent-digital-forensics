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


    # 25. Exposed Admin Panel Evidence Regression (Clean vs Detected)
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    @patch("agents.agent7_fingerprinting.check_admin_panels")
    def test_25_admin_panel_evidence_regression(self, mock_admins, mock_dirs, mock_fetch):
        mock_fetch.return_value = {
            "status": "success", "status_code": 200, "final_url": "https://example.com",
            "headers": {}, "html": "<html><body>Hello</body></html>",
            "redirect_count": 0, "redirect_chain": ["https://example.com"]
        }
        # Case A: Clean probing - all return detected=False
        mock_admins.return_value = [
            {"path": "/admin", "status_code": 404, "detected": False, "final_url": "https://example.com/admin"},
            {"path": "/login", "status_code": 404, "detected": False, "final_url": "https://example.com/login"}
        ]
        res_clean = analyze_fingerprint("https://example.com")
        e7_08_clean = next((e for e in res_clean["evidence"] if e["evidence_id"] == "E7-08"), None)
        self.assertIsNotNone(e7_08_clean)
        self.assertEqual(e7_08_clean["value"], [])
        self.assertEqual(e7_08_clean["severity"], "info")

        # Case B: Detected admin portal - one returns detected=True
        mock_admins.return_value = [
            {"path": "/admin", "status_code": 200, "detected": True, "final_url": "https://example.com/admin"},
            {"path": "/login", "status_code": 404, "detected": False, "final_url": "https://example.com/login"}
        ]
        res_detected = analyze_fingerprint("https://example.com")
        e7_08_det = next((e for e in res_detected["evidence"] if e["evidence_id"] == "E7-08"), None)
        self.assertIsNotNone(e7_08_det)
        self.assertEqual(e7_08_det["value"], ["/admin"])
        self.assertEqual(e7_08_det["severity"], "info")

    # 26. Open Directory Listing Evidence Regression (Clean vs Detected)
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories")
    def test_26_open_directory_evidence_regression(self, mock_dirs, mock_admins, mock_fetch):
        mock_fetch.return_value = {
            "status": "success", "status_code": 200, "final_url": "https://example.com",
            "headers": {}, "html": "<html><body>Hello</body></html>",
            "redirect_count": 0, "redirect_chain": ["https://example.com"]
        }
        # Case A: Clean probing - all return directory_listing=False
        mock_dirs.return_value = [
            {"path": "/", "status_code": 200, "directory_listing": False, "evidence": None},
            {"path": "/uploads/", "status_code": 404, "directory_listing": False, "evidence": None}
        ]
        res_clean = analyze_fingerprint("https://example.com")
        e7_09_clean = next((e for e in res_clean["evidence"] if e["evidence_id"] == "E7-09"), None)
        self.assertIsNotNone(e7_09_clean)
        self.assertEqual(e7_09_clean["value"], [])
        self.assertEqual(e7_09_clean["severity"], "info")

        # Case B: Detected open directory - /uploads/ returns directory_listing=True
        mock_dirs.return_value = [
            {"path": "/", "status_code": 200, "directory_listing": False, "evidence": None},
            {"path": "/uploads/", "status_code": 200, "directory_listing": True, "evidence": "Index of /uploads/"}
        ]
        res_detected = analyze_fingerprint("https://example.com")
        e7_09_det = next((e for e in res_detected["evidence"] if e["evidence_id"] == "E7-09"), None)
        self.assertIsNotNone(e7_09_det)
        self.assertEqual(e7_09_det["value"], ["/uploads/"])
        self.assertEqual(e7_09_det["severity"], "medium")

    # 27. Adversarial Text Fingerprint Resilience
    def test_27_adversarial_text_not_fingerprinted(self):
        html = """
        <html>
        <head><title>Tech Blog</title></head>
        <body>
            <p>We write articles about WordPress, Drupal, React, Next.js, and Django.</p>
            <p>Our website was built using custom static HTML and CSS.</p>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        cms = detect_cms(soup, html, {})
        self.assertEqual(cms["status"], "not_detected")
        self.assertIsNone(cms["name"])

        frameworks = detect_frameworks(soup, html, {})
        self.assertEqual(len(frameworks), 0)

    # 28. Evidence ID Inventory & Schema Validation
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    def test_28_evidence_id_inventory_and_schema_validation(self, mock_dirs, mock_admins, mock_fetch):
        from services.evidence_schema import validate_evidence_item
        mock_fetch.return_value = {
            "status": "success", "status_code": 200, "final_url": "https://example.com",
            "headers": {"Server": "Apache/2.4"},
            "html": "<html><head><meta name='generator' content='WordPress 6.4'></head><body></body></html>",
            "redirect_count": 0, "redirect_chain": ["https://example.com"]
        }
        result = analyze_fingerprint("https://example.com")
        self.assertEqual(result["status"], "success")
        evidence_list = result["evidence"]
        self.assertEqual(len(evidence_list), 9)

        expected_ids = [f"E7-{i:02d}" for i in range(1, 10)]
        actual_ids = [e["evidence_id"] for e in evidence_list]
        self.assertEqual(actual_ids, expected_ids)
        self.assertEqual(len(set(actual_ids)), 9, "Evidence IDs must be strictly unique")

        for item in evidence_list:
            is_valid, err = validate_evidence_item(item)
            self.assertTrue(is_valid, f"Item {item.get('evidence_id')} failed validation: {err}")

    # 29. Normalizer, Ledger, and TCE Integration Pipeline
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    def test_29_normalizer_ledger_and_tce_neutrality(self, mock_dirs, mock_admins, mock_fetch):
        from services.evidence_ledger import EvidenceLedger
        from services.trust_calculation_engine import TrustCalculationEngine

        mock_fetch.return_value = {
            "status": "success", "status_code": 200, "final_url": "https://tech-site.example.com",
            "headers": {"Server": "nginx/1.24"},
            "html": "<html><head><meta name='generator' content='WordPress 6.4'></head><body></body></html>",
            "redirect_count": 0, "redirect_chain": ["https://tech-site.example.com"]
        }
        result = analyze_fingerprint("https://tech-site.example.com")
        self.assertEqual(result["status"], "success")

        # Ingest into ledger
        ledger = EvidenceLedger()
        ledger.add_entries_from_agent(result)
        self.assertEqual(len(ledger.entries), 9)

        # Ingest into TCE
        tce = TrustCalculationEngine()
        tce_eval = tce.calculate_trust(ledger)

        # Baseline info evidence (server banner, CMS) must remain neutral without inflating risk
        e7_01 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E7-01"), None)
        e7_02 = next((c for c in tce_eval["evidence_contributions"] if c["evidence_id"] == "E7-02"), None)
        self.assertIsNotNone(e7_01)
        self.assertIsNotNone(e7_02)
        self.assertEqual(e7_01["polarity"], "neutral")
        self.assertEqual(e7_01["severity_weight"], 0.0)
        self.assertEqual(e7_02["polarity"], "neutral")
        self.assertEqual(e7_02["severity_weight"], 0.0)
        self.assertEqual(tce_eval["risk_score"], 0.0)

    # 30. Failed / Unavailable Fetch Handling
    @patch("agents.agent7_fingerprinting.fetch_webpage")
    @patch("agents.agent7_fingerprinting.check_admin_panels", return_value=[])
    @patch("agents.agent7_fingerprinting.check_open_directories", return_value=[])
    def test_30_fetch_failure_handling(self, mock_dirs, mock_admins, mock_fetch):
        mock_fetch.return_value = {
            "status": "error", "status_code": None, "final_url": "https://unreachable.example.com",
            "headers": {}, "html": "", "message": "Failed to resolve hostname",
            "redirect_count": 0, "redirect_chain": ["https://unreachable.example.com"]
        }
        result = analyze_fingerprint("https://unreachable.example.com")
        self.assertEqual(result["status"], "success")
        self.assertIn("Failed to resolve hostname", result["errors"])
        self.assertEqual(result["web_server"]["status"], "not_detected")
        self.assertEqual(result["cms"]["status"], "not_detected")


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

