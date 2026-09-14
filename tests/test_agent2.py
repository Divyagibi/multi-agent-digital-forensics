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

Run:
    python tests/test_agent2.py
"""

import sys
import os
import json
from datetime import datetime

# Ensure parent directory is in sys.path so we can import agents/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent2_dns import analyze_dns, get_dns_records


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

    print(f"  [PASS] Structure validation passed for: {test_label}")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_normal_domain():
    label = "Test 1: Normal public domain (https://example.com)"
    result = analyze_dns("https://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain"] in ("example.com", "www.example.com")
    assert len(data["a_records"]) > 0, "example.com should have at least one A record"
    assert data["server_ip"] != "Not Available"
    print("  [PASS] example.com resolved A records successfully.\n")
    return result


def test_2_domain_with_ipv6():
    label = "Test 2: Domain with IPv4 & IPv6 (https://www.google.com)"
    result = analyze_dns("https://www.google.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert len(data["a_records"]) > 0, "google.com must have IPv4 A records"
    assert len(data["aaaa_records"]) > 0, "google.com must have IPv6 AAAA records"
    print("  [PASS] google.com resolved both IPv4 and IPv6.\n")
    return result


def test_3_domain_with_mx():
    label = "Test 3: Domain with MX records (https://google.com)"
    result = analyze_dns("https://google.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert len(data["mx_records"]) > 0, "google.com must have MX mail records"
    assert "priority" in data["mx_records"][0]
    assert "exchange" in data["mx_records"][0]
    print("  [PASS] MX records preserved priority and exchange.\n")
    return result


def test_4_domain_with_ns_and_txt():
    label = "Test 4: Domain with NS and TXT records (https://example.com)"
    result = analyze_dns("https://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert len(data["ns_records"]) > 0, "example.com must have authoritative NS records"
    assert len(data["txt_records"]) > 0, "example.com must have TXT records"
    print("  [PASS] NS and TXT records extracted cleanly.\n")
    return result


def test_5_domain_with_cname():
    label = "Test 5: Domain with CNAME (https://www.github.com)"
    result = analyze_dns("https://www.github.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    print(f"  [INFO] www.github.com CNAME records: {data['cname_records']}")
    print("  [PASS] CNAME query completed without error.\n")
    return result


def test_6_invalid_domain_handling():
    invalid_inputs = ["hello", "not-a-domain", "", "   "]
    for inp in invalid_inputs:
        label = f"Test 6: Invalid input ({repr(inp)})"
        result = analyze_dns(inp)
        validate_structure(result, label)
        assert result["status"] == "error", f"Expected error status for {repr(inp)}"
        assert len(result["errors"]) > 0, "Error message must be present"
        print(f"  [PASS] Invalid input {repr(inp)} handled gracefully.\n")


def test_7_cdn_detection_cloudflare():
    label = "Test 7: CDN Detection (https://www.cloudflare.com)"
    result = analyze_dns("https://www.cloudflare.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert "detected" in data["cdn"]
    print(f"  [PASS] CDN detection executed. Detected: {data['cdn']['detected']} ({data['cdn']['provider']})\n")
    return result


def test_8_compatibility_wrapper():
    label = "Test 8: Compatibility function get_dns_records('example.com')"
    res = get_dns_records("example.com")
    assert isinstance(res, dict)
    assert "data" in res
    assert "a_records" in res["data"]
    print("  [PASS] get_dns_records compatibility wrapper works.\n")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 2 — DNS & INFRASTRUCTURE: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    passed = 0
    failed = 0
    test_functions = [
        test_1_normal_domain,
        test_2_domain_with_ipv6,
        test_3_domain_with_mx,
        test_4_domain_with_ns_and_txt,
        test_5_domain_with_cname,
        test_6_invalid_domain_handling,
        test_7_cdn_detection_cloudflare,
        test_8_compatibility_wrapper,
    ]

    for test_fn in test_functions:
        try:
            test_fn()
            passed += 1
        except AssertionError as ae:
            print(f"  [FAIL] Assertion error: {ae}\n")
            failed += 1
        except Exception as ex:
            print(f"  [FAIL] Unexpected exception: {type(ex).__name__}: {ex}\n")
            failed += 1

    print_separator("=", 70)
    print(f"  RESULTS: {passed} passed, {failed} failed out of {passed + failed} tests")
    if failed == 0:
        print("  [OK] All Agent 2 tests passed successfully.")
    else:
        print(f"  [FAIL] {failed} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    run_all_tests()
