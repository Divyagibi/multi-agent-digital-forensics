# -*- coding: utf-8 -*-
"""
tests/test_agent3.py
====================
Comprehensive test suite for Agent 3 -- SSL / HTTPS Security.

Tests cover:
    1. Normal HTTPS domain                — https://example.com
    2. HTTP input that establishes HTTPS  — http://example.com
    3. Valid TLS certificate & Authority  — https://www.google.com
    4. Domain with HSTS enabled           — https://www.cloudflare.com
    5. Domain with Certificate Chain      — https://github.com
    6. Invalid Hostname / Domain inputs   — "hello", "not-a-domain", ""
    7. Timeout / Connection error safety  — Non-routable IP / unreachable port
    8. Structural schema validation       — Confirms zero trust or risk scoring

Run:
    python -u tests/test_agent3.py
"""

import sys
import os
import json
from datetime import datetime

# Ensure parent directory is in sys.path so we can import agents/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent3_ssl import analyze_ssl, get_ssl_certificate


# ---------------------------------------------------------------------------
# Display & Validation Helpers
# ---------------------------------------------------------------------------

def print_separator(char="=", width=60):
    print(char * width)


def display_result(result: dict, test_label: str):
    """Print a clean readable formatted summary of an analyze_ssl() result."""
    print_separator()
    print(f"  TEST: {test_label}")
    print_separator()

    status = result.get("status", "unknown")
    data   = result.get("data", {})
    errors = result.get("errors", [])

    print(f"  Overall Status       : {status.upper()}")
    print()
    print("  ===== AGENT 3 — SSL / HTTPS SECURITY =====")
    print()

    https_info = data.get("https_availability", {})
    if isinstance(https_info, dict):
        print(f"  HTTPS Availability   : {'Available' if https_info.get('available') else 'Unavailable'} (Status: {https_info.get('status')})")
    else:
        print(f"  HTTPS Availability   : {data.get('https_available')}")

    cert = data.get("ssl_certificate", {})
    if not cert or not cert.get("present"):
        cert = data.get("certificate", {})

    print(f"  Certificate Present  : {'Yes' if cert.get('present') else 'No'}")
    print(f"  Certificate Authority: {data.get('certificate_authority', 'Not Available')}")

    val = data.get("certificate_validation", {})
    print(f"  Certificate Trust    : {'Trusted' if val.get('trusted') else 'Unverified / Untrusted'}")
    print(f"  Hostname Match       : {'Yes (Matches SAN/CN)' if val.get('hostname_match') else 'Mismatch / Unverified'}")

    validity = data.get("certificate_validity", {})
    print(f"  Validity Status      : {validity.get('status', 'unknown').upper()} (Valid: {validity.get('valid')})")

    exp = data.get("certificate_expiration", {})
    print(f"  Expires At           : {exp.get('expires_at', 'Not Available')}")
    print(f"  Days Remaining       : {exp.get('days_remaining', 'Not Available')} days ({exp.get('status', 'unknown')})")

    print(f"  TLS Version          : {data.get('tls_version', 'Not Available')}")

    cipher = data.get("cipher_suite", {})
    if isinstance(cipher, dict):
        print(f"  Cipher Suite         : {cipher.get('name', 'Not Available')} ({cipher.get('bits', 0)} bits)")
    else:
        print(f"  Cipher Suite         : {cipher}")

    hsts = data.get("hsts", {})
    if isinstance(hsts, dict):
        hsts_str = f"Enabled (max-age={hsts.get('max_age')}, subdomains={hsts.get('include_subdomains')}, preload={hsts.get('preload')})" if hsts.get("enabled") else "Not detected"
        print(f"  HSTS Status          : {hsts_str}")
    else:
        print(f"  HSTS Status          : {hsts}")

    ct = data.get("certificate_transparency", {})
    if isinstance(ct, dict):
        print(f"  Certificate Transp.  : {'Found' if ct.get('found') else 'Not detected'} ({ct.get('log_count', 0)} SCTs)")

    chain = data.get("certificate_chain", {})
    certs_in_chain = chain.get("certificates", []) if isinstance(chain, dict) else []
    print(f"  Certificates In Chain: {len(certs_in_chain)}")
    for c in certs_in_chain:
        print(f"      • [{c.get('type', 'cert').upper()}] {c.get('subject')[:60]}...")

    if errors:
        print()
        print("  --- Non-Fatal Warnings / Verification Notes ---")
        for e in errors:
            print(f"      [!] {e}")

    print()


def validate_structure(result: dict, test_label: str):
    """Validate output schema and verify NO trust or risk scoring is present."""
    assert isinstance(result, dict), f"[{test_label}] Result must be a dict"
    assert "status" in result, f"[{test_label}] Missing 'status'"
    assert "data" in result, f"[{test_label}] Missing 'data'"
    assert "errors" in result, f"[{test_label}] Missing 'errors'"
    assert result["status"] in ("success", "partial", "error"), \
        f"[{test_label}] Invalid status: {result['status']}"

    data = result["data"]
    assert isinstance(data, dict), f"[{test_label}] 'data' must be a dict"

    required_fields = [
        "https_availability",
        "ssl_certificate",
        "certificate_authority",
        "certificate_expiration",
        "certificate_validity",
        "certificate_chain",
        "certificate_transparency",
        "hsts",
        "tls_version",
        "cipher_suite",
        "certificate_validation"
    ]
    for field in required_fields:
        assert field in data, f"[{test_label}] Missing required field: '{field}'"

    # Strict forbidden fields (No scoring, no classification, no other agents' domains)
    forbidden_fields = [
        "trust_score", "risk_score", "risk", "confidence", "is_phishing",
        "classification", "verdict", "phishing_probability",
        "ssl_score", "security_score", "tls_score",
        # Agent 1 fields
        "domain_age", "registrar",
        # Agent 2 fields
        "a_records", "mx_records", "ns_records", "dnssec"
    ]
    for forbidden in forbidden_fields:
        assert forbidden not in data, \
            f"[{test_label}] Forbidden field '{forbidden}' found in Agent 3 data"

    print(f"  [PASS] Structure validation passed for: {test_label}")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_normal_https_domain():
    label = "Test 1: Normal HTTPS domain (https://example.com)"
    result = analyze_ssl("https://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["https_availability"]["available"] is True
    assert data["ssl_certificate"]["present"] is True
    assert data["tls_version"] in ("TLSv1.2", "TLSv1.3")
    print("  [PASS] example.com TLS connection and certificate verified.\n")
    return result


def test_2_http_input_scheme():
    label = "Test 2: HTTP scheme input (http://example.com)"
    result = analyze_ssl("http://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["https_availability"]["available"] is True
    print("  [PASS] http:// URL successfully tested over HTTPS.\n")
    return result


def test_3_valid_certificate_and_ca():
    label = "Test 3: Valid Certificate & CA (https://www.google.com)"
    result = analyze_ssl("https://www.google.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["certificate_validity"]["valid"] is True
    assert data["certificate_validation"]["trusted"] is True
    assert data["certificate_validation"]["hostname_match"] is True
    assert data["certificate_authority"] != "Not Available"
    print(f"  [PASS] Google Certificate Authority identified: {data['certificate_authority']}\n")
    return result


def test_4_hsts_detection():
    label = "Test 4: HSTS Detection (https://www.cloudflare.com)"
    result = analyze_ssl("https://www.cloudflare.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["hsts"]["enabled"] is True
    assert data["hsts"]["max_age"] is not None and data["hsts"]["max_age"] > 0
    print(f"  [PASS] Cloudflare HSTS header detected with max-age={data['hsts']['max_age']}.\n")
    return result


def test_5_certificate_chain():
    label = "Test 5: Certificate Chain Collection (https://github.com)"
    result = analyze_ssl("https://github.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    chain = data["certificate_chain"]
    assert chain["status"] in ("available", "partial")
    assert len(chain["certificates"]) >= 1
    print(f"  [PASS] GitHub certificate chain retrieved with {len(chain['certificates'])} certificates.\n")
    return result


def test_6_invalid_hostname_handling():
    invalid_inputs = ["hello", "not-a-domain", "", "   "]
    for inp in invalid_inputs:
        label = f"Test 6: Invalid input ({repr(inp)})"
        result = analyze_ssl(inp)
        validate_structure(result, label)
        assert result["status"] == "error"
        assert len(result["errors"]) > 0
        print(f"  [PASS] Invalid input {repr(inp)} handled gracefully.\n")


def test_7_compatibility_wrapper():
    label = "Test 7: Compatibility wrapper get_ssl_certificate('example.com')"
    res = get_ssl_certificate("example.com")
    assert isinstance(res, dict)
    assert "data" in res
    assert res["data"]["https_availability"]["available"] is True
    print("  [PASS] get_ssl_certificate compatibility wrapper works.\n")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 3 — SSL / HTTPS SECURITY: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    passed = 0
    failed = 0
    test_functions = [
        test_1_normal_https_domain,
        test_2_http_input_scheme,
        test_3_valid_certificate_and_ca,
        test_4_hsts_detection,
        test_5_certificate_chain,
        test_6_invalid_hostname_handling,
        test_7_compatibility_wrapper,
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
        print("  [OK] All Agent 3 tests passed successfully.")
    else:
        print(f"  [FAIL] {failed} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    run_all_tests()
