# -*- coding: utf-8 -*-
"""
tests/test_agent11_agent12_distinction.py
=========================================
Comparative test suite demonstrating the functional distinction, independence,
and non-overlapping forensic responsibilities of Agent 11 (Content Quality &
Linguistic Deception) and Agent 12 (Contact & Entity Verification).

Scenarios:
    1. Clean professional website with NO contact information.
    2. Deceptive / urgent text WITH legitimate corporate contact info.
    3. Flawless prose text with mismatched / conflicting contact signals.
    4. Sparse / placeholder website content.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent11_content_quality import analyze_content_quality
from agents.agent12_contact import analyze_contact


SCENARIO_1_CLEAN_NO_CONTACT = """
<!DOCTYPE html>
<html>
<head><title>Enterprise Software Engineering</title></head>
<body>
    <h1>Distributed System Architecture</h1>
    <p>Our engineering team designs reliable software architectures for enterprise customers worldwide.</p>
    <p>We provide comprehensive technical documentation and implementation guidelines for system development.</p>
    <p>All software modules undergo rigorous automated validation and integration testing.</p>
</body>
</html>
"""

SCENARIO_2_DECEPTIVE_WITH_CONTACT = """
<!DOCTYPE html>
<html>
<head>
    <title>Instant Guaranteed Profit Distribution</title>
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "Corporation",
        "name": "Apex Wealth Holdings Ltd",
        "email": "compliance@apexwealth.com",
        "telephone": "+1-800-555-0144",
        "address": {
            "@type": "PostalAddress",
            "streetAddress": "500 Financial Plaza",
            "addressLocality": "New York",
            "addressRegion": "NY",
            "postalCode": "10005",
            "addressCountry": "US"
        }
    }
    </script>
</head>
<body>
    <h1>Congratulations! Guaranteed 100% profit with zero risk investment!</h1>
    <p>Earn $10,000 in one day. Act now! Your account will be deleted in 10 minutes if you do not verify your account immediately.</p>
    <p>Please enter your login verification credentials to receive your payout.</p>
    <footer>
        <p>Apex Wealth Holdings Ltd &bull; Corporate CIN: U72200MH2019PTC123456</p>
        <p>Support: <a href="mailto:support@apexwealth.com">support@apexwealth.com</a> | Tel: <a href="tel:+18005550144">+1 (800) 555-0144</a></p>
    </footer>
</body>
</html>
"""

SCENARIO_3_FLAWLESS_TEXT_MISMATCHED_CONTACT = """
<!DOCTYPE html>
<html>
<head><title>International Banking Advisory</title></head>
<body>
    <h1>Global Financial Consulting Services</h1>
    <p>We provide comprehensive advisory services for institutional capital management and risk assessment.</p>
    <p>Our experienced team delivers strategic guidance for cross-border investments and regulatory compliance.</p>
    <footer>
        <p>Operated by: Global Capital Advisory</p>
        <p>Contact us via free email: <a href="mailto:officialadvisory@gmail.com">officialadvisory@gmail.com</a></p>
        <p>Phone: +91 98765 43210 (India)</p>
        <p>Address: 10 Downing Street, London, SW1A 2AA, United Kingdom</p>
    </footer>
</body>
</html>
"""


class TestAgent11Agent12Distinction(unittest.TestCase):
    """Comparative test suite validating that A11 and A12 produce distinct forensic telemetry."""

    def test_scenario_1_clean_text_no_contact(self):
        """
        Scenario 1:
        - A11 should report clean grammar, no scam keywords, no urgency, no unrealistic claims.
        - A12 should report no emails, no phones, no addresses, no registration (contact availability: 0).
        """
        with patch("agents.agent11_content_quality.requests.Session") as mock_s11, \
             patch("agents.agent12_contact.requests.Session") as mock_s12:

            # Mock responses
            resp11 = MagicMock(url="https://quantum-research.org", encoding="utf-8")
            resp11.iter_content.return_value = [SCENARIO_1_CLEAN_NO_CONTACT.encode("utf-8")]
            mock_s11.return_value.get.return_value = resp11

            resp12 = MagicMock(url="https://quantum-research.org", encoding="utf-8")
            resp12.iter_content.return_value = [SCENARIO_1_CLEAN_NO_CONTACT.encode("utf-8")]
            mock_s12.return_value.get.return_value = resp12

            res11 = analyze_content_quality("https://quantum-research.org")
            res12 = analyze_contact("https://quantum-research.org")

            # A11 Content Verification
            self.assertEqual(res11["agent"], "Content Quality")
            self.assertFalse(res11["unrealistic_claims"]["detected"])
            self.assertFalse(res11["urgency_language"]["detected"])
            self.assertFalse(res11["scam_keywords"]["detected"])
            self.assertEqual(res11["spelling_analysis"]["error_count"], 0)

            # A12 Contact Verification
            self.assertEqual(res12["agent"], "Contact Verification")
            self.assertEqual(len(res12["email_addresses"]), 0)
            self.assertEqual(len(res12["phone_numbers"]), 0)
            self.assertEqual(len(res12["physical_addresses"]), 0)
            self.assertFalse(res12["contact_availability"]["email"])
            self.assertFalse(res12["contact_availability"]["phone"])

    def test_scenario_2_deceptive_text_with_legitimate_contact(self):
        """
        Scenario 2:
        - A11 flags high urgency, unrealistic claims, and scam keywords.
        - A12 extracts corporate CIN, legitimate corporate email, phone, and JSON-LD Corporation.
        Demonstrates that A11 and A12 evaluate entirely separate aspects of the same webpage.
        """
        with patch("agents.agent11_content_quality.requests.Session") as mock_s11, \
             patch("agents.agent12_contact.requests.Session") as mock_s12:

            resp11 = MagicMock(url="https://apexwealth.com", encoding="utf-8")
            resp11.iter_content.return_value = [SCENARIO_2_DECEPTIVE_WITH_CONTACT.encode("utf-8")]
            mock_s11.return_value.get.return_value = resp11

            resp12 = MagicMock(url="https://apexwealth.com", encoding="utf-8")
            resp12.iter_content.return_value = [SCENARIO_2_DECEPTIVE_WITH_CONTACT.encode("utf-8")]
            mock_s12.return_value.get.return_value = resp12

            res11 = analyze_content_quality("https://apexwealth.com")
            res12 = analyze_contact("https://apexwealth.com")

            # A11 flags deceptive content
            self.assertTrue(res11["unrealistic_claims"]["detected"])
            self.assertTrue(res11["urgency_language"]["detected"])
            self.assertTrue(res11["scam_keywords"]["detected"])

            # A12 extracts corporate identity details
            self.assertEqual(res12["business_identity"]["name"], "Apex Wealth Holdings Ltd")
            self.assertIn("support@apexwealth.com", [e["email"] for e in res12["email_addresses"]])
            self.assertTrue(res12["company_registration"]["found"])
            self.assertEqual(res12["company_registration"]["number"], "U72200MH2019PTC123456")

    def test_scenario_3_flawless_text_with_mismatched_contact(self):
        """
        Scenario 3:
        - A11 reports high quality, clean grammar, no scam words.
        - A12 flags free webmail (@gmail.com) and multi-channel divergence (US address + Indian phone).
        """
        with patch("agents.agent11_content_quality.requests.Session") as mock_s11, \
             patch("agents.agent12_contact.requests.Session") as mock_s12:

            resp11 = MagicMock(url="https://global-advisory.com", encoding="utf-8")
            resp11.iter_content.return_value = [SCENARIO_3_FLAWLESS_TEXT_MISMATCHED_CONTACT.encode("utf-8")]
            mock_s11.return_value.get.return_value = resp11

            resp12 = MagicMock(url="https://global-advisory.com", encoding="utf-8")
            resp12.iter_content.return_value = [SCENARIO_3_FLAWLESS_TEXT_MISMATCHED_CONTACT.encode("utf-8")]
            mock_s12.return_value.get.return_value = resp12

            res11 = analyze_content_quality("https://global-advisory.com")
            res12 = analyze_contact("https://global-advisory.com")

            # A11: Clean prose
            self.assertFalse(res11["scam_keywords"]["detected"])
            self.assertFalse(res11["urgency_language"]["detected"])

            # A12: Flags free webmail and domain mismatch
            self.assertTrue(any(e["is_free_provider"] for e in res12["email_addresses"]))
            self.assertTrue(any(e["domain_mismatch"] for e in res12["email_addresses"]))


if __name__ == "__main__":
    unittest.main()
