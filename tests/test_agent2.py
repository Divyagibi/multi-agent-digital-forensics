# -*- coding: utf-8 -*-
"""
tests/test_agent2.py
====================
Comprehensive test suite for Agent 2 -- DNS & Infrastructure.

Tests cover:
    1. Normal public domain               — https://example.com
    2. Domain with IPv4 & IPv6 records    — https://www.google.com
    3. Domain with MX mail servers        — https://google.com
    4. Domain with Authoritative NS       — https://example.com
    5. Domain with TXT records            — https://example.com
    6. Domain with CNAME alias            — https://www.github.com
    7. Domain without one or more records — e.g. apex domain without CNAME
    8. Invalid URL / Hostname             — "hello", "not-a-domain", ""
    9. Structure & Type verification      — validates no trust scores or risk scores
    10. Mocked comprehensive DNS records resolution (A, AAAA, MX, NS, TXT, CNAME, PTR)
    11. DNS timeout and provider failure handling
    12. DNSSEC enabled vs not detected validation
    13. CDN multi-signal detection
    14. Evidence ID stability and collision prevention
    15. TCE integration, neutral polarity and zero risk contribution
    16. Evidence Ledger normalization and cross-agent contradiction correlation

Run:
    python -m unittest tests/test_agent2.py
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import dns.resolver

# Ensure parent directory is in sys.path so we can import agents/ and services/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent2_dns import (
    analyze_dns,
    get_dns_records,
    extract_host_and_domain,
    query_a_records,
    query_aaaa_records,
    query_mx_records,
    query_ns_records,
    query_txt_records,
    query_cname_records,
    perform_reverse_dns,
    check_dnssec_status,
    get_hosting_provider_info,
    detect_cdn
)
from services.evidence_schema import validate_evidence_item, validate_agent_result
from services.evidence_normalizer import normalize_evidence_item, normalize_target
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.analysis_pipeline import finalize_session_from_agent_results


# ---------------------------------------------------------------------------
# Display & Validation Helpers
# ---------------------------------------------------------------------------

def print_separator(char="=", width=60):
    print(char * width)


def display_result(result: dict, test_label: str):
    """Print a readable formatted summary of an analyze_dns() result."""
    print_separator()
    print(f"  TEST: {test_label}")
    print_separator()

    status = result.get("status", "unknown")
    data   = result.get("data", {})
    errors = result.get("errors", [])

    print(f"  Overall Status    : {status.upper()}")
    print()
    print("  ===== AGENT 2 — DNS & INFRASTRUCTURE =====")
    print()
    print(f"  Domain / Hostname : {data.get('domain', 'Not Available')}")
    print(f"  Resolved Server IP: {data.get('server_ip', 'Not Available')}")
    print(f"  All Server IPs    : {data.get('server_ips', [])}")

    hosting = data.get("hosting_provider", {})
    if isinstance(hosting, dict):
        print(f"  Hosting Org       : {hosting.get('organization', 'Not Available')}")
        print(f"  ASN / Network     : {hosting.get('asn', 'Not Available')} (Net: {hosting.get('network', 'Not Available')})")
    else:
        print(f"  Hosting Provider  : {hosting}")

    cdn = data.get("cdn", {})
    if isinstance(cdn, dict):
        print(f"  CDN Detected      : {'Yes - ' + str(cdn.get('provider')) if cdn.get('detected') else 'No'}")
        if cdn.get("evidence"):
            print(f"  CDN Evidence      :")
            for ev in cdn.get("evidence", []):
                print(f"      • {ev}")
    else:
        print(f"  CDN               : {cdn}")

    dnssec = data.get("dnssec", {})
    if isinstance(dnssec, dict):
        print(f"  DNSSEC Status     : {dnssec.get('status', 'Not detected')} (DS: {dnssec.get('ds_present')}, DNSKEY: {dnssec.get('dnskey_present')})")
    else:
        print(f"  DNSSEC Status     : {dnssec}")

    print()
    print(f"  A Records (IPv4)  : {data.get('a_records', [])}")
    print(f"  AAAA Records (IPv6): {data.get('aaaa_records', [])}")

    mx_list = data.get("mx_records", [])
    if mx_list:
        print(f"  MX Records        :")
        for mx in mx_list:
            if isinstance(mx, dict):
                print(f"      • [Priority {mx.get('priority')}] {mx.get('exchange')}")
            else:
                print(f"      • {mx}")
    else:
        print(f"  MX Records        : None detected")

    print(f"  NS Records        : {data.get('ns_records', [])}")
    print(f"  TXT Records       : {len(data.get('txt_records', []))} records found")
    for txt in data.get("txt_records", [])[:3]:
        print(f"      • {txt[:80]}{'...' if len(txt) > 80 else ''}")
    if len(data.get("txt_records", [])) > 3:
        print(f"      ... and {len(data.get('txt_records', [])) - 3} more")

    print(f"  CNAME Records     : {data.get('cname_records', [])}")

    rev_dns = data.get("reverse_dns", {})
    if isinstance(rev_dns, dict):
        print(f"  Reverse DNS (PTR) :")
        for ip, ptrs in rev_dns.items():
            print(f"      • {ip} -> {ptrs if ptrs else 'No PTR'}")
    else:
        print(f"  Reverse DNS       : {rev_dns}")

    if errors:
        print()
        print("  --- Non-Fatal Warnings / Query Notes ---")
        for e in errors:
            print(f"      [!] {e}")

    print()


def validate_structure(result: dict, test_label: str):
    """Validate data schema and enforce strict evidence collection rules."""
    assert isinstance(result, dict), f"[{test_label}] Result must be a dict"
    assert "status" in result, f"[{test_label}] Missing 'status'"
    assert "data" in result, f"[{test_label}] Missing 'data'"
    assert "errors" in result, f"[{test_label}] Missing 'errors'"
    assert result["status"] in ("success", "partial", "error"), \
        f"[{test_label}] Invalid status: {result['status']}"

    data = result["data"]
    assert isinstance(data, dict), f"[{test_label}] 'data' must be a dict"

    required_fields = [
        "domain",
        "a_records",
        "aaaa_records",
        "mx_records",
        "ns_records",
        "txt_records",
        "cname_records",
        "reverse_dns",
        "dnssec",
        "server_ips",
        "server_ip",
        "hosting_provider",
        "cdn"
    ]
    for field in required_fields:
        assert field in data, f"[{test_label}] Missing required field: '{field}'"

    # Strict forbidden fields (No scoring, no classification, no other agents' domains)
    forbidden_fields = [
        "trust_score", "risk_score", "risk", "confidence", "is_phishing",
        "classification", "verdict", "phishing_probability",
        # Agent 1 fields
        "domain_age", "registration_date", "expiry_date", "registrar",
        # Agent 3 fields
        "ssl_certificate", "tls_version", "cipher_suite", "hsts",
        # Agent 4 fields
        "page_title", "meta_description", "company_name"
    ]
    for forbidden in forbidden_fields:
        assert forbidden not in data, \
            f"[{test_label}] Forbidden field '{forbidden}' found in Agent 2 data"


# ---------------------------------------------------------------------------
# Test Case Suite
# ---------------------------------------------------------------------------

class TestAgent2DNS(unittest.TestCase):
    """Formal unit test suite for Agent 2 — DNS & Infrastructure."""

    def test_1_normal_domain(self):
        label = "Test 1: Normal public domain (https://example.com)"
        result = analyze_dns("https://example.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertIn(data["domain"], ("example.com", "www.example.com"))
        self.assertGreater(len(data["a_records"]), 0, "example.com should have at least one A record")
        self.assertNotEqual(data["server_ip"], "Not Available")

    def test_2_domain_with_ipv6(self):
        label = "Test 2: Domain with IPv4 & IPv6 (https://www.google.com)"
        result = analyze_dns("https://www.google.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertGreater(len(data["a_records"]), 0, "google.com must have IPv4 A records")
        self.assertGreater(len(data["aaaa_records"]), 0, "google.com must have IPv6 AAAA records")

    def test_3_domain_with_mx(self):
        label = "Test 3: Domain with MX records (https://google.com)"
        result = analyze_dns("https://google.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertGreater(len(data["mx_records"]), 0, "google.com must have MX mail records")
        self.assertIn("priority", data["mx_records"][0])
        self.assertIn("exchange", data["mx_records"][0])

    def test_4_domain_with_ns_and_txt(self):
        label = "Test 4: Domain with NS and TXT records (https://example.com)"
        result = analyze_dns("https://example.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertGreater(len(data["ns_records"]), 0, "example.com must have authoritative NS records")
        self.assertGreater(len(data["txt_records"]), 0, "example.com must have TXT records")

    def test_5_domain_with_cname(self):
        label = "Test 5: Domain with CNAME (https://www.github.com)"
        result = analyze_dns("https://www.github.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertIsInstance(data["cname_records"], list)

    def test_6_invalid_domain_handling(self):
        invalid_inputs = ["hello", "not-a-domain", "", "   "]
        for inp in invalid_inputs:
            label = f"Test 6: Invalid input ({repr(inp)})"
            result = analyze_dns(inp)
            validate_structure(result, label)
            self.assertEqual(result["status"], "error", f"Expected error status for {repr(inp)}")
            self.assertGreater(len(result["errors"]), 0, "Error message must be present")

    def test_7_cdn_detection_cloudflare(self):
        label = "Test 7: CDN Detection (https://www.cloudflare.com)"
        result = analyze_dns("https://www.cloudflare.com")
        display_result(result, label)
        validate_structure(result, label)

        data = result["data"]
        self.assertIn("detected", data["cdn"])

    def test_8_compatibility_wrapper(self):
        label = "Test 8: Compatibility function get_dns_records('example.com')"
        res = get_dns_records("example.com")
        self.assertIsInstance(res, dict)
        self.assertIn("data", res)
        self.assertIn("a_records", res["data"])

    def test_mocked_comprehensive_dns_success(self):
        """Verify complete DNS record collection and schema validation under mocked resolver."""
        with patch("agents.agent2_dns._get_configured_resolver") as mock_res_factory, \
             patch("agents.agent2_dns.get_hosting_provider_info") as mock_host_info, \
             patch("agents.agent2_dns.requests.head") as mock_head:
            
            mock_resolver = MagicMock()
            mock_res_factory.return_value = mock_resolver

            def resolve_side_effect(target, qtype):
                if qtype == "A":
                    r1 = MagicMock(); r1.__str__.return_value = "93.184.216.34"
                    r2 = MagicMock(); r2.__str__.return_value = "93.184.216.35"
                    return [r1, r2]
                elif qtype == "AAAA":
                    r1 = MagicMock(); r1.__str__.return_value = "2606:2800:220:1:248:1893:25c8:1946"
                    return [r1]
                elif qtype == "MX":
                    r1 = MagicMock(); r1.preference = 10; r1.exchange = "mail.example.com."
                    r2 = MagicMock(); r2.preference = 20; r2.exchange = "backup.example.com."
                    return [r1, r2]
                elif qtype == "NS":
                    r1 = MagicMock(); r1.target = "ns1.example.com."
                    r2 = MagicMock(); r2.target = "ns2.example.com."
                    return [r1, r2]
                elif qtype == "TXT":
                    r1 = MagicMock(); r1.strings = [b"v=spf1 include:_spf.example.com ~all"]
                    r2 = MagicMock(); r2.strings = [b"v=DMARC1; p=reject;"]
                    return [r1, r2]
                elif qtype == "CNAME":
                    r1 = MagicMock(); r1.target = "alias.example.net."
                    return [r1]
                elif qtype in ("DS", "DNSKEY"):
                    r1 = MagicMock()
                    return [r1]
                raise dns.resolver.NXDOMAIN()

            mock_resolver.resolve.side_effect = resolve_side_effect

            mock_host_info.return_value = {
                "organization": "Example Cloud Hosting LLC",
                "asn": "AS12345",
                "network": "EXAMPLE-NET",
                "country": "US"
            }

            mock_head.return_value.headers = {"Server": "cloudflare", "CF-RAY": "12345"}

            res = analyze_dns("https://example.com/test")
            self.assertEqual(res["status"], "success")
            self.assertEqual(len(res["errors"]), 0)

            data = res["data"]
            self.assertEqual(data["a_records"], ["93.184.216.34", "93.184.216.35"])
            self.assertEqual(data["aaaa_records"], ["2606:2800:220:1:248:1893:25c8:1946"])
            self.assertEqual(len(data["mx_records"]), 2)
            self.assertEqual(data["mx_records"][0]["priority"], 10)
            self.assertEqual(data["mx_records"][1]["priority"], 20)
            self.assertEqual(len(data["ns_records"]), 2)
            self.assertEqual(len(data["txt_records"]), 2)
            self.assertEqual(data["cname_records"], ["alias.example.net"])
            self.assertTrue(data["dnssec"]["ds_present"])
            self.assertTrue(data["dnssec"]["dnskey_present"])
            self.assertEqual(data["dnssec"]["status"], "Enabled")
            self.assertEqual(data["server_ip"], "93.184.216.34")
            self.assertEqual(data["hosting_provider"]["asn"], "AS12345")
            self.assertTrue(data["cdn"]["detected"])

            # Validate agent result schema
            valid_res, errs = validate_agent_result(res)
            self.assertTrue(valid_res, f"Schema validation errors: {errs}")

            # Validate evidence items
            ev_ids = [e["evidence_id"] for e in res["evidence"]]
            self.assertEqual(ev_ids, ["E2-01", "E2-02", "E2-03", "E2-04", "E2-05", "E2-06", "E2-07", "E2-08", "E2-09", "E2-10", "E2-11"])
            for ev in res["evidence"]:
                is_valid, ev_errs = validate_evidence_item(ev)
                self.assertTrue(is_valid, f"Invalid evidence item {ev}: {ev_errs}")

    def test_mocked_timeout_and_error_handling(self):
        """Verify behavior when DNS queries time out or encounter server failures."""
        with patch("agents.agent2_dns._get_configured_resolver") as mock_res_factory, \
             patch("agents.agent2_dns.get_hosting_provider_info") as mock_host_info:
            
            mock_resolver = MagicMock()
            mock_res_factory.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.Timeout()
            mock_host_info.return_value = {
                "organization": "Not Available",
                "asn": "Not Available",
                "network": "Not Available",
                "country": "Not Available"
            }

            res = analyze_dns("https://timeout-site.org")
            self.assertIn(res["status"], ("error", "partial"))
            self.assertTrue(len(res["errors"]) > 0)
            self.assertEqual(res["data"]["server_ip"], "Not Available")
            self.assertEqual(res["data"]["a_records"], [])

            # Evidence items should only contain DNSSEC (E2-08) and CDN (E2-11)
            ev_ids = [e["evidence_id"] for e in res["evidence"]]
            self.assertEqual(ev_ids, ["E2-08", "E2-11"])

    def test_dnssec_enabled_vs_not_detected(self):
        """Verify DNSSEC status determination with enabled and absent states."""
        mock_resolver = MagicMock()

        # Case 1: Both DS and DNSKEY present
        mock_resolver.resolve.side_effect = lambda target, qtype: [MagicMock()] if qtype in ("DS", "DNSKEY") else []
        res1 = check_dnssec_status(mock_resolver, "secure.gov", "secure.gov")
        self.assertEqual(res1["status"], "Enabled")
        self.assertTrue(res1["ds_present"])
        self.assertTrue(res1["dnskey_present"])

        # Case 2: Neither present (NXDOMAIN or NoAnswer)
        def no_dnssec(target, qtype):
            raise dns.resolver.NoAnswer()
        mock_resolver.resolve.side_effect = no_dnssec
        res2 = check_dnssec_status(mock_resolver, "insecure.com", "insecure.com")
        self.assertEqual(res2["status"], "Not detected")
        self.assertFalse(res2["ds_present"])
        self.assertFalse(res2["dnskey_present"])

    def test_cdn_multi_signal_detection(self):
        """Verify CDN detection across multiple corroborating signals."""
        # 1. CNAME detection
        cdn1 = detect_cdn("cdn-site.com", ["d12345.cloudfront.net"], [], {}, [], "Other")
        self.assertTrue(cdn1["detected"])
        self.assertEqual(cdn1["provider"], "Amazon CloudFront")

        # 2. Nameserver detection
        cdn2 = detect_cdn("cf-site.com", [], ["ns1.cloudflare.com"], {}, [], "Other")
        self.assertTrue(cdn2["detected"])
        self.assertEqual(cdn2["provider"], "Cloudflare")

        # 3. No CDN
        cdn3 = detect_cdn("direct-site.com", [], ["ns1.customdomain.com"], {}, [], "Internal DC")
        self.assertFalse(cdn3["detected"])
        self.assertIsNone(cdn3["provider"])

    def test_evidence_id_stability_and_no_collision(self):
        """Verify that missing optional records do not cause Evidence ID shifts or collisions."""
        with patch("agents.agent2_dns._get_configured_resolver") as mock_res_factory, \
             patch("agents.agent2_dns.get_hosting_provider_info") as mock_host_info:
            
            mock_resolver = MagicMock()
            mock_res_factory.return_value = mock_resolver

            # Only A record present, no AAAA, no MX, no TXT, no CNAME
            def resolve_sparse(target, qtype):
                if qtype == "A":
                    r = MagicMock(); r.__str__.return_value = "10.0.0.1"
                    return [r]
                raise dns.resolver.NoAnswer()

            mock_resolver.resolve.side_effect = resolve_sparse
            mock_host_info.return_value = {"organization": "Sparse Hosting", "asn": "AS100", "network": "NET", "country": "US"}

            res = analyze_dns("https://sparse-site.com")
            ev_dict = {e["evidence_id"]: e for e in res["evidence"]}

            # Ensure E2-01 is A records, E2-08 is DNSSEC, E2-09 is Server IP, E2-10 is Hosting, E2-11 is CDN
            self.assertEqual(ev_dict["E2-01"]["finding"], "DNS A records")
            self.assertEqual(ev_dict["E2-08"]["finding"], "DNSSEC record status")
            self.assertEqual(ev_dict["E2-09"]["finding"], "Primary resolved IP")
            self.assertEqual(ev_dict["E2-10"]["finding"], "Hosting provider organization")
            self.assertEqual(ev_dict["E2-11"]["finding"], "CDN provider detected")

            # Missing records must not shift IDs (e.g. E2-08 is never reused for CNAME or MX)
            self.assertNotIn("E2-02", ev_dict)
            self.assertNotIn("E2-03", ev_dict)
            self.assertNotIn("E2-06", ev_dict)

    def test_tce_neutral_polarity_and_zero_base_contribution(self):
        """Verify that all A2 info telemetry enters TCE with neutral polarity and exactly 0.00 base contribution."""
        with patch("agents.agent2_dns._get_configured_resolver") as mock_res_factory, \
             patch("agents.agent2_dns.get_hosting_provider_info") as mock_host_info:
            
            mock_resolver = MagicMock()
            mock_res_factory.return_value = mock_resolver

            def resolve_full(target, qtype):
                if qtype == "A":
                    r = MagicMock(); r.__str__.return_value = "192.0.2.1"
                    return [r]
                raise dns.resolver.NoAnswer()

            mock_resolver.resolve.side_effect = resolve_full
            mock_host_info.return_value = {"organization": "Test ISP", "asn": "AS123", "network": "TEST", "country": "CA"}

            res = analyze_dns("https://tce-test-domain.org")
            session = finalize_session_from_agent_results("https://tce-test-domain.org", {"agent2": res}, enable_aere=False)

            tce_summary = session["tce_summary"]
            self.assertIsNotNone(tce_summary)
            for item in tce_summary["evidence_contributions"]:
                if item["evidence_id"].startswith("E2-"):
                    self.assertEqual(item["severity"], "info")
                    self.assertEqual(item["base_contribution"], 0.00)
                    self.assertEqual(item["final_item_contribution"], 0.00)
                    self.assertEqual(item["polarity"], "neutral")

    def test_ledger_normalization_and_contradiction_correlation(self):
        """Verify that Evidence Ledger correlates cross-agent country contradiction between A2 and A12."""
        a2_result = {
            "agent_id": 2,
            "agent": "Agent 2",
            "status": "success",
            "target": "https://contradiction-example.com",
            "data": {},
            "evidence": [{
                "evidence_id": "E2-10",
                "type": "deterministic",
                "finding": "Hosting provider organization",
                "value": "Russian Server Farm",
                "severity": "info",
                "source": "BGP / IP Geolocation",
                "evidence_strength": 1.0,
                "metadata": {"country": "RU", "asn": "AS1234"}
            }],
            "errors": []
        }

        a12_result = {
            "agent_id": 12,
            "agent": "Agent 12",
            "status": "success",
            "target": "https://contradiction-example.com",
            "data": {},
            "evidence": [{
                "evidence_id": "E12-01",
                "type": "deterministic",
                "finding": "Declared organization contact address",
                "value": "123 Main St, New York, USA",
                "severity": "info",
                "source": "Website Contact Page",
                "evidence_strength": 0.9,
                "metadata": {"country": "US"}
            }],
            "errors": []
        }

        ledger = EvidenceLedger(target="https://contradiction-example.com")
        ledger.add_entries_from_agent(a2_result)
        ledger.add_entries_from_agent(a12_result)
        rels = ledger.correlate_relationships()

        contradiction_rels = [r for r in rels if r["relationship_type"] == "contradiction"]
        self.assertEqual(len(contradiction_rels), 1)
        self.assertIn("Factual location discrepancy", contradiction_rels[0]["description"])


# ---------------------------------------------------------------------------
# Procedural compatibility runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 2 — DNS & INFRASTRUCTURE: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAgent2DNS)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print_separator("=", 70)
    print(f"  RESULTS: {result.testsRun - len(result.failures) - len(result.errors)} passed, {len(result.failures) + len(result.errors)} failed out of {result.testsRun} tests")
    if result.wasSuccessful():
        print("  [OK] All Agent 2 tests passed successfully.")
    else:
        print(f"  [FAIL] {len(result.failures) + len(result.errors)} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    unittest.main()
