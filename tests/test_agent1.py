# -*- coding: utf-8 -*-
"""
tests/test_agent1.py
====================
Comprehensive test suite for Agent 1 -- Domain Identity.

Tests cover:
    1. Normal domain                  — https://example.com
    2. URL with www                   — https://www.example.com
    3. URL with path                  — https://example.com/login
    4. URL with query parameters      — https://example.com/login?id=123
    5. Invalid URL                    — "hello", "not-a-url", ""
    6. Privacy-protected / incomplete — a domain likely to have redacted WHOIS

Run:
    python tests/test_agent1.py
"""

import sys
import os
import json
from datetime import datetime

# Ensure parent directory is in sys.path so we can import agents/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent1_domain import analyze_domain


# ---------------------------------------------------------------------------
# Display Helpers
# ---------------------------------------------------------------------------

def print_separator(char="=", width=60):
    print(char * width)


def display_result(result: dict, test_label: str):
    """Print a well-formatted summary of an analyze_domain() result."""
    print_separator()
    print(f"  TEST: {test_label}")
    print_separator()

    status = result.get("status", "unknown")
    data   = result.get("data", {})
    errors = result.get("errors", [])

    print(f"  Overall Status    : {status.upper()}")
    print()
    print("  ===== AGENT 1 — DOMAIN IDENTITY =====")
    print()
    print(f"  Domain Name             : {data.get('domain_name', 'Not Available')}")

    age_days  = data.get("domain_age_days",  "Not Available")
    age_years = data.get("domain_age_years", "Not Available")
    if age_days != "Not Available" and age_years != "Not Available":
        print(f"  Domain Age              : {age_days} days ({age_years} years)")
    else:
        print(f"  Domain Age              : Not Available")

    print(f"  Registration Date       : {data.get('registration_date', 'Not Available')}")
    print(f"  Expiry Date             : {data.get('expiry_date',        'Not Available')}")
    print(f"  Registrar               : {data.get('registrar',          'Not Available')}")

    whois_avail = data.get("whois_available", False)
    print(f"  WHOIS Available         : {'Yes' if whois_avail else 'No'}")

    print(f"  Registrant Organization : {data.get('registrant_organization', 'Not Available')}")
    print(f"  Registrant Country      : {data.get('registrant_country',      'Not Available')}")

    domain_status = data.get("domain_status", [])
    if domain_status:
        print(f"  Domain Status           :")
        for s in domain_status:
            print(f"      • {s}")
    else:
        print(f"  Domain Status           : Not Available")

    whois_info = data.get("whois_information", {})
    if whois_info and whois_info.get("whois_available"):
        print()
        print("  --- WHOIS Information Block ---")
        print(f"    Registration Date       : {whois_info.get('registration_date', 'Not Available')}")
        print(f"    Expiry Date             : {whois_info.get('expiry_date',        'Not Available')}")
        print(f"    Registrar               : {whois_info.get('registrar',          'Not Available')}")
        print(f"    Registrant Organization : {whois_info.get('registrant_organization', 'Not Available')}")
        print(f"    Registrant Country      : {whois_info.get('registrant_country',      'Not Available')}")

    if errors:
        print()
        print("  --- Non-Fatal Errors / Warnings ---")
        for e in errors:
            print(f"      [!] {e}")

    print()


def validate_structure(result: dict, test_label: str):
    """
    Validate that the result has the required output structure.
    Raises AssertionError if any structural requirement is violated.
    """
    # Top-level keys
    assert isinstance(result, dict), f"[{test_label}] Result must be a dict"
    assert "status" in result,  f"[{test_label}] Missing 'status'"
    assert "data"   in result,  f"[{test_label}] Missing 'data'"
    assert "errors" in result,  f"[{test_label}] Missing 'errors'"

    assert result["status"] in ("success", "partial", "error"), \
        f"[{test_label}] 'status' must be success/partial/error, got: {result['status']}"

    assert isinstance(result["errors"], list), \
        f"[{test_label}] 'errors' must be a list"

    data = result["data"]
    assert isinstance(data, dict), f"[{test_label}] 'data' must be a dict"

    # Required data fields
    required_fields = [
        "domain_name",
        "domain_age_days",
        "domain_age_years",
        "registration_date",
        "expiry_date",
        "registrar",
        "whois_available",
        "whois_information",
        "registrant_organization",
        "registrant_country",
        "domain_status",
    ]
    for field in required_fields:
        assert field in data, f"[{test_label}] Missing required data field: '{field}'"

    # Types
    assert isinstance(data["whois_available"], bool), \
        f"[{test_label}] 'whois_available' must be bool"
    assert isinstance(data["domain_status"], list), \
        f"[{test_label}] 'domain_status' must be a list"
    assert isinstance(data["whois_information"], dict), \
        f"[{test_label}] 'whois_information' must be a dict"

    # IMPORTANT: No trust/risk fields allowed
    forbidden_fields = [
        "trust_score", "risk_score", "risk", "confidence", "is_phishing",
        "classification", "verdict", "phishing_probability",
        # Agent 2 fields that must NOT appear
        "nameservers", "a_records", "mx_records", "ns_records",
        "txt_records", "cname_records", "reverse_dns", "dnssec",
        "hosting_provider", "server_ip", "cdn",
        # Agent 3 fields
        "ssl_certificate", "tls_version", "cipher_suite", "hsts",
        # Unspecified extras
        "last_updated", "data_source",
    ]
    for forbidden in forbidden_fields:
        assert forbidden not in data, \
            f"[{test_label}] Forbidden field '{forbidden}' found in data — " \
            f"this field belongs to another agent or is not in Agent 1's spec"

    print(f"  [PASS] Structure validation passed for: {test_label}")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_normal_domain():
    """Test 1: Normal domain — https://example.com"""
    label = "Test 1: Normal domain (https://example.com)"
    result = analyze_domain("https://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "example.com", \
        f"Expected 'example.com', got '{data['domain_name']}'"
    print(f"  [PASS] Domain name correctly extracted: example.com\n")
    return result


def test_2_www_prefix():
    """Test 2: URL with www — https://www.example.com"""
    label = "Test 2: www prefix (https://www.example.com)"
    result = analyze_domain("https://www.example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "example.com", \
        f"Expected 'example.com' (www stripped), got '{data['domain_name']}'"
    print(f"  [PASS] www prefix correctly stripped: example.com\n")
    return result


def test_3_url_with_path():
    """Test 3: URL with path — https://example.com/login"""
    label = "Test 3: URL with path (https://example.com/login)"
    result = analyze_domain("https://example.com/login")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "example.com", \
        f"Expected 'example.com', got '{data['domain_name']}'"
    print(f"  [PASS] Path correctly stripped: example.com\n")
    return result


def test_4_url_with_query_params():
    """Test 4: URL with query parameters — https://example.com/login?id=123"""
    label = "Test 4: Query parameters (https://example.com/login?id=123)"
    result = analyze_domain("https://example.com/login?id=123")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "example.com", \
        f"Expected 'example.com', got '{data['domain_name']}'"
    print(f"  [PASS] Query parameters correctly stripped: example.com\n")
    return result


def test_5_invalid_url():
    """Test 5: Invalid URL inputs"""
    invalid_inputs = ["hello", "not-a-url", "", "   "]

    for inp in invalid_inputs:
        label = f"Test 5: Invalid input ({repr(inp)})"
        result = analyze_domain(inp)

        assert isinstance(result, dict), f"[{label}] Must return a dict"
        assert "status" in result,       f"[{label}] Missing 'status'"
        assert result["status"] == "error", \
            f"[{label}] Invalid input must return status='error', got '{result['status']}'"
        assert len(result.get("errors", [])) > 0, \
            f"[{label}] errors list must not be empty for invalid input"

        print_separator("-", 60)
        print(f"  TEST: {label}")
        print(f"  Status : {result['status'].upper()}")
        print(f"  Error  : {result['errors'][0] if result['errors'] else 'N/A'}")
        print(f"  [PASS] Invalid input handled gracefully\n")


def test_6_deep_subdomain():
    """Test 6: Deep subdomain URL — registrable domain must be extracted correctly"""
    label = "Test 6: Deep subdomain (https://login.shop.example.com/account)"
    result = analyze_domain("https://login.shop.example.com/account")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "example.com", \
        f"Expected 'example.com' (deep subdomain stripped), got '{data['domain_name']}'"
    print(f"  [PASS] Subdomains correctly stripped: example.com\n")
    return result


def test_7_privacy_protected_domain():
    """
    Test 7: Domain likely to have privacy-protected or partial WHOIS.

    The agent must NOT crash when registrant information is unavailable.
    All fields should either contain a value or "Not Available".
    """
    label = "Test 7: Privacy-protected WHOIS (https://www.google.com)"
    result = analyze_domain("https://www.google.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "google.com", \
        f"Expected 'google.com', got '{data['domain_name']}'"

    # Even if registrant info is unavailable, these must be strings or lists
    assert isinstance(data["registrant_organization"], str)
    assert isinstance(data["registrant_country"], str)
    assert isinstance(data["domain_status"], list)

    print(f"  [PASS] Privacy/partial WHOIS handled gracefully\n")
    return result


def test_8_multi_part_tld():
    """
    Test 8: Multi-part TLD domain (e.g. co.uk).

    The registrable domain for https://www.bbc.co.uk/news
    should be bbc.co.uk, not bbc.co or co.uk.
    """
    label = "Test 8: Multi-part TLD (https://www.bbc.co.uk/news)"
    result = analyze_domain("https://www.bbc.co.uk/news")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["domain_name"] == "bbc.co.uk", \
        f"Expected 'bbc.co.uk', got '{data['domain_name']}'"
    print(f"  [PASS] Multi-part TLD correctly identified: bbc.co.uk\n")
    return result


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 1 — DOMAIN IDENTITY: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    passed = 0
    failed = 0
    test_functions = [
        test_1_normal_domain,
        test_2_www_prefix,
        test_3_url_with_path,
        test_4_url_with_query_params,
        test_5_invalid_url,
        test_6_deep_subdomain,
        test_7_privacy_protected_domain,
        test_8_multi_part_tld,
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
        print("  [OK] All tests passed.")
    else:
        print(f"  [FAIL] {failed} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    run_all_tests()
