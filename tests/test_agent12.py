"""
Unit Tests for Agent 12: Contact Verification
Covers business identity, email validation, phone normalization,
physical addresses, Google Maps presence, social media profiles,
Indian CIN/GSTIN, European VAT, identity cross-checking, and Flask endpoint.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

from app import app
from agents.agent12_contact import (
    analyze_contact,
    _normalize_url,
    _extract_registered_domain,
    _extract_structured_data,
    _detect_business_identity,
    _find_contact_page,
    _extract_and_validate_emails,
    _extract_and_validate_phones,
    _extract_and_check_addresses,
    _detect_google_maps,
    _extract_social_media,
    _extract_registration_and_tax,
    _perform_identity_cross_check,
)

# Mock HTML Fixtures
MOCK_FULL_LEGIT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Acme Global Solutions - Enterprise Cloud Technologies</title>
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "Corporation",
        "name": "Acme Global Solutions Inc",
        "email": "contact@acme-global.com",
        "telephone": "+1-800-555-0199",
        "address": {
            "@type": "PostalAddress",
            "streetAddress": "100 Tech Park Way, Suite 400",
            "addressLocality": "San Jose",
            "addressRegion": "CA",
            "postalCode": "95110",
            "addressCountry": "US"
        }
    }
    </script>
</head>
<body>
    <header>
        <img src="/images/logo.png" class="logo" alt="Acme Global Solutions" />
        <nav>
            <a href="/about">About Us</a>
            <a href="/contact-us">Contact Us</a>
        </nav>
    </header>

    <main>
        <h1>Welcome to Acme Global</h1>
        <p>Reach our direct support team at <a href="mailto:support@acme-global.com">support@acme-global.com</a> or call <a href="tel:+18005550199">+1 (800) 555-0199</a>.</p>
        <p>Chat with us on <a href="https://wa.me/18005550199">WhatsApp Direct</a>.</p>
        
        <iframe src="https://www.google.com/maps/embed?pb=!1m18!1m12!3d37.3382!2d-121.8863!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x0%3A0x0!2zMzfCsDIwJzE3LjUiTiAxMjHCsDUzJzEwLjciVw!5e0!3m2!1sen!2sus!4v1" width="600" height="450"></iframe>
    </main>

    <footer>
        <p>Corporate Reg / CIN: U72200KA2018PTC112233</p>
        <p>GSTIN: 29ABCDE1234F1Z5 | VAT: GB123456789</p>
        <div>
            <a href="https://www.linkedin.com/company/acmeglobalsolutions">LinkedIn</a>
            <a href="https://twitter.com/acmeglobal">Twitter</a>
            <a href="https://github.com/acmeglobal">GitHub</a>
        </div>
        <p>&copy; 2026 Acme Global Solutions Inc. All rights reserved.</p>
    </footer>
</body>
</html>
"""

MOCK_SUSPICIOUS_CONTACT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Instant Quick Cash Loan Pro</title>
</head>
<body>
    <h1>Get Emergency Funds Now</h1>
    <p>For urgent customer service, email us at <a href="mailto:quickcashloan@gmail.com">quickcashloan@gmail.com</a>.</p>
    <p>Alternative email: fastfunds@yahoo.com</p>
    <p>Call or WhatsApp: +91 98765 43210</p>
    <div>
        <a href="https://facebook.com/quickcashloans">Facebook</a>
    </div>
    <footer>
        <p>&copy; 2026 Instant Quick Cash Loan Pro</p>
    </footer>
</body>
</html>
"""


class TestAgent12Contact(unittest.TestCase):
    """Test suite for Agent 12 Contact Verification module."""

    def setUp(self):
        self.client = app.test_client()

    def test_normalize_url(self):
        self.assertEqual(_normalize_url("example.com"), "https://example.com")
        self.assertEqual(_normalize_url("http://test.org/page"), "http://test.org/page")
        self.assertEqual(_normalize_url(""), "")

    def test_extract_registered_domain(self):
        self.assertIn(_extract_registered_domain("https://sub.acme-global.com/contact"), ["acme-global.com", "sub.acme-global.com"])
        self.assertEqual(_extract_registered_domain(""), "")

    def test_extract_structured_data_json_ld(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        summary, entities = _extract_structured_data(soup)
        self.assertTrue(summary["organization_found"])
        self.assertTrue(summary["contact_information_found"])
        self.assertIn("organization", entities)
        self.assertEqual(entities["organization"]["name"], "Acme Global Solutions Inc")

    def test_detect_business_identity_from_title_and_footer(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        _, entities = _extract_structured_data(soup)
        biz_id, evidence = _detect_business_identity(soup, entities)
        self.assertIsNotNone(biz_id["name"])
        self.assertTrue(len(evidence) > 0)
        self.assertTrue("Acme" in biz_id["name"])

    def test_find_contact_page(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        contact_info = _find_contact_page(soup, "https://acme-global.com")
        self.assertTrue(contact_info["found"])
        self.assertIn("/contact-us", contact_info["url"])

    def test_extract_and_validate_emails_business(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        emails, validations, evidence = _extract_and_validate_emails(soup, MOCK_FULL_LEGIT_HTML, "acme-global.com")
        self.assertTrue(len(emails) >= 1)
        found_emails = [e["email"] for e in emails]
        self.assertIn("support@acme-global.com", found_emails)
        # Should detect as business / not free provider
        support_entry = next(e for e in emails if "support@acme-global.com" in e["email"])
        self.assertFalse(support_entry["is_free_provider"])
        self.assertFalse(support_entry["domain_mismatch"])

    def test_extract_and_validate_emails_free_webmail(self):
        soup = BeautifulSoup(MOCK_SUSPICIOUS_CONTACT_HTML, "html.parser")
        emails, validations, evidence = _extract_and_validate_emails(soup, MOCK_SUSPICIOUS_CONTACT_HTML, "quickcashpro.com")
        self.assertTrue(len(emails) >= 2)
        gmail_entry = next((e for e in emails if "gmail.com" in e["email"]), None)
        self.assertIsNotNone(gmail_entry)
        self.assertTrue(gmail_entry["is_free_provider"])

    def test_extract_and_validate_emails_domain_mismatch(self):
        html = "<p>Contact us at vendor-sales@external-provider.com</p>"
        soup = BeautifulSoup(html, "html.parser")
        emails, validations, evidence = _extract_and_validate_emails(soup, html, "mycompany.com")
        self.assertEqual(len(emails), 1)
        self.assertTrue(emails[0]["domain_mismatch"])
        self.assertFalse(emails[0]["is_free_provider"])

    def test_extract_and_validate_phones_e164(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        phones, validations, evidence = _extract_and_validate_phones(soup, MOCK_FULL_LEGIT_HTML)
        self.assertTrue(len(phones) >= 1)
        phone_nums = [p["number"] for p in phones]
        self.assertTrue(any("8005550199" in p.replace("-", "").replace(" ", "").replace("+", "").replace("(", "").replace(")", "") for p in phone_nums))

    def test_extract_and_validate_phones_whatsapp(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        phones, validations, evidence = _extract_and_validate_phones(soup, MOCK_FULL_LEGIT_HTML)
        sources = [p["source"] for p in phones]
        self.assertTrue(any("WhatsApp" in s or "tel:" in s for s in sources))

    def test_extract_and_check_addresses_json_ld(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        _, entities = _extract_structured_data(soup)
        addresses, consistency, evidence = _extract_and_check_addresses(soup, MOCK_FULL_LEGIT_HTML, entities)
        self.assertTrue(len(addresses) >= 1)
        self.assertTrue(any("San Jose" in a["address"] for a in addresses))
        self.assertTrue(consistency.get("consistent", False) or consistency.get("status") == "single_address_identified")

    def test_extract_and_check_addresses_html_block(self):
        html = "<address>456 Commerce Boulevard, Floor 3, New York, NY 10001, USA</address>"
        soup = BeautifulSoup(html, "html.parser")
        addresses, consistency, evidence = _extract_and_check_addresses(soup, html, {})
        self.assertEqual(len(addresses), 1)
        self.assertIn("New York", addresses[0]["address"])

    def test_detect_google_maps_iframe(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        maps_data, verif, evidence = _detect_google_maps(soup)
        self.assertTrue(maps_data["detected"])
        self.assertTrue(len(maps_data["links"]) >= 1)
        self.assertEqual(verif["status"], "not_available")

    def test_detect_google_maps_links(self):
        html = '<a href="https://maps.google.com/?q=Acme+Headquarters">Find us on Google Maps</a>'
        soup = BeautifulSoup(html, "html.parser")
        maps_data, verif, evidence = _detect_google_maps(soup)
        self.assertTrue(maps_data["detected"])
        self.assertIn("https://maps.google.com/?q=Acme+Headquarters", maps_data["links"])

    def test_extract_social_media_profiles(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        socials, consistency, evidence = _extract_social_media(soup, "Acme Global Solutions")
        self.assertTrue(len(socials) >= 2)
        platforms = [s["platform"] for s in socials]
        self.assertIn("LinkedIn", platforms)
        self.assertIn("GitHub", platforms)

    def test_extract_social_media_handle_match(self):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        socials, consistency, evidence = _extract_social_media(soup, "Acme Global Solutions")
        self.assertEqual(consistency["status"], "consistent")

    def test_extract_indian_cin(self):
        html = "<p>Registered Office: Tower A. CIN: U72200KA2018PTC112233.</p>"
        biz_reg, biz_verif, taxes, comp_reg, evidence = _extract_registration_and_tax(html, "Tech Corp")
        self.assertTrue(biz_reg["found_on_website"])
        self.assertEqual(biz_reg["registration_number"], "U72200KA2018PTC112233")
        self.assertTrue(comp_reg["found"])
        self.assertEqual(comp_reg["number"], "U72200KA2018PTC112233")
        self.assertEqual(biz_verif["status"], "not_available")

    def test_extract_indian_gstin(self):
        html = "<p>Tax Invoices GSTIN: 29ABCDE1234F1Z5 (Karnataka)</p>"
        biz_reg, biz_verif, taxes, comp_reg, evidence = _extract_registration_and_tax(html, "Tech Corp")
        self.assertTrue(len(taxes) >= 1)
        gst = next((t for t in taxes if t["type"] == "GSTIN"), None)
        self.assertIsNotNone(gst)
        self.assertEqual(gst["number"], "29ABCDE1234F1Z5")
        self.assertTrue(gst["format_valid"])

    def test_extract_european_vat(self):
        html = "<p>VAT Registration Number: GB123456789</p>"
        biz_reg, biz_verif, taxes, comp_reg, evidence = _extract_registration_and_tax(html, "Tech Corp")
        self.assertTrue(len(taxes) >= 1)
        vat = next((t for t in taxes if t["type"] == "VAT"), None)
        self.assertIsNotNone(vat)
        self.assertEqual(vat["number"], "GB123456789")

    def test_extract_company_registration_crn(self):
        html = "<p>Company Registration No: 12345678-AB</p>"
        biz_reg, biz_verif, taxes, comp_reg, evidence = _extract_registration_and_tax(html, "Tech Corp")
        self.assertTrue(comp_reg["found"])
        self.assertEqual(comp_reg["number"], "12345678-AB")

    def test_identity_cross_check_consistent(self):
        emails = [{"email": "info@acme.com", "domain_mismatch": False, "is_free_provider": False}]
        phones = [{"number": "+18005550199"}]
        addresses = [{"address": "100 Tech Park"}]
        socials = [{"platform": "LinkedIn", "handle": "acme"}]
        taxes = [{"type": "GSTIN", "number": "29ABCDE1234F1Z5"}]
        comp_reg = {"found": True, "number": "U72200KA2018PTC112233"}
        
        cross_check, evidence = _perform_identity_cross_check(
            "Acme Solutions", emails, phones, addresses, socials, taxes, comp_reg
        )
        self.assertEqual(cross_check["status"], "consistent")
        self.assertEqual(len(cross_check["conflicts"]), 0)

    def test_identity_cross_check_conflicts(self):
        emails = [{"email": "scam@thirdparty-unrelated.com", "domain_mismatch": True, "is_free_provider": False}]
        cross_check, evidence = _perform_identity_cross_check(
            "Acme Solutions", emails, [], [], [], [], {"found": False}
        )
        self.assertEqual(cross_check["status"], "inconsistent")
        self.assertTrue(len(cross_check["conflicts"]) > 0)

    @patch("agents.agent12_contact._fetch_webpage_safe")
    def test_analyze_contact_complete_flow(self, mock_fetch):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_FULL_LEGIT_HTML, "https://acme-global.com", soup, [])

        result = analyze_contact("https://acme-global.com")
        self.assertIn(result["agent"], ("Contact Verification", "Agent 12"))
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["contact_availability"]["email"])
        self.assertTrue(result["contact_availability"]["phone"])
        self.assertTrue(result["contact_availability"]["physical_address"])
        self.assertTrue(result["contact_availability"]["google_maps"])
        self.assertTrue(result["contact_availability"]["social_media"])
        self.assertTrue(result["contact_availability"]["business_registration"])
        self.assertTrue(result["contact_availability"]["tax_registration"])
        self.assertTrue(len(result["evidence"]) > 0)

    def test_analyze_contact_empty_url(self):
        result = analyze_contact("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent12_contact.requests.Session.get")
    def test_analyze_contact_timeout_or_error(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        result = analyze_contact("https://unreachable-domain-xyz.com")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(len(result["errors"]) > 0)

    @patch("agents.agent12_contact._fetch_webpage_safe")
    def test_api_endpoint_agent12(self, mock_fetch):
        soup = BeautifulSoup(MOCK_FULL_LEGIT_HTML, "html.parser")
        mock_fetch.return_value = (MOCK_FULL_LEGIT_HTML, "https://acme-global.com", soup, [])

        resp = self.client.post("/api/agent12", json={"url": "https://acme-global.com"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn(data["agent"], ("Contact Verification", "Agent 12"))
        self.assertEqual(data["status"], "completed")
        self.assertIn("business_identity", data)
        self.assertIn("email_addresses", data)
        self.assertIn("phone_numbers", data)
        self.assertIn("contact_availability", data)


if __name__ == "__main__":
    unittest.main()
