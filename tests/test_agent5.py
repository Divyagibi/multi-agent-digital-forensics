# -*- coding: utf-8 -*-
"""
tests/test_agent5.py
====================
Comprehensive test suite for Agent 5 -- URL Structure Analysis.

Tests cover:
    1. Normal domain URL                   — https://example.com/login?id=123
    2. IPv4 address hostname               — http://192.168.1.10/login & http://93.184.216.34/
    3. IPv6 address hostname               — http://[2001:db8::1]/login
    4. URL with Suspicious Characters      — https://example.com@evil.com & excessive hyphens
    5. URL Shorteners                      — https://bit.ly/3abc & https://tinyurl.com/test
    6. Punycode (xn--) domain              — https://xn--pple-43d.com
    7. Homograph / Confusable attack       — Cyrillic look-alikes (e.g. 'а' in https://exаmple.com)
    8. Excessive Subdomains                — https://one.two.three.four.example.com
    9. Suspicious Query Parameters         — https://example.com/login?redirect=https://evil.com&next=dashboard
    10. Percent & Double Encoding          — https://example.com/login%3Fuser%3Dadmin & %252F
    11. Invalid & Empty URLs               — "", "   ", None
    12. Schema & Structure Assertion       — Verifies strictly zero trust or risk scores

Run:
    python -u tests/test_agent5.py
"""

import sys
import os
import json
from datetime import datetime

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from agents.agent5_url import analyze_url, get_url_structure


# ---------------------------------------------------------------------------
# Display & Validation Helpers
# ---------------------------------------------------------------------------

def print_separator(char="=", width=60):
    print(char * width)


def display_result(result: dict, test_label: str):
    """Print a clean readable formatted summary of an analyze_url() result."""
    print_separator()
    print(f"  TEST: {test_label}")
    print_separator()

    status = result.get("status", "unknown")
    data   = result.get("data", {})
    errors = result.get("errors", [])

    print(f"  Overall Status       : {status.upper()}")
    print()
    print("  ===== AGENT 5 — URL STRUCTURE ANALYSIS =====")
    print()

    print(f"  Original URL         : {data.get('original_url') or data.get('raw_url', 'N/A')}")
    parsed = data.get("parsed_url", {})
    print(f"  Parsed Scheme/Host   : {parsed.get('scheme')}://{parsed.get('hostname')}{parsed.get('path', '')}")

    url_len = data.get("url_length", {})
    print(f"  URL Length           : {url_len.get('value')} chars")
    breakdown = data.get("length_analysis", {})
    print(f"  Length Breakdown     : Host: {breakdown.get('hostname_length')}, Path: {breakdown.get('path_length')}, Query: {breakdown.get('query_length')}")

    ip_info = data.get("ip_instead_of_domain", {})
    print(f"  IP Instead of Domain : {'YES (' + str(ip_info.get('ip_version')) + ': ' + str(ip_info.get('ip')) + ')' if ip_info.get('detected') else 'No (Named Domain)'}")

    susp_chars = data.get("suspicious_characters", {})
    print(f"  Suspicious Chars     : {', '.join(susp_chars.get('characters', [])) if susp_chars.get('detected') else 'None detected'}")

    shortener = data.get("url_shortener", {})
    print(f"  URL Shortener        : {'YES (' + str(shortener.get('service')) + ')' if shortener.get('detected') else 'No'}")

    puny = data.get("punycode_domain", {})
    print(f"  Punycode (xn--)      : {'YES (' + ', '.join(puny.get('labels', [])) + ')' if puny.get('detected') else 'No'}")

    homo = data.get("homograph_detection", {})
    print(f"  Homograph Detection  : {'POTENTIAL SPOOFING: ' + str(homo.get('reason')) if homo.get('detected') else 'No suspicious Unicode/confusables'}")
    if homo.get("confusable_characters"):
        for c in homo["confusable_characters"]:
            safe_char = repr(c['character'])
            print(f"      • Character {safe_char} ({c['unicode']}) looks like ASCII '{c['looks_like']}'")

    sub = data.get("subdomain_analysis", {})
    print(f"  Subdomain Depth      : {sub.get('subdomain_count', 0)} ({', '.join(sub.get('subdomains', [])) or 'None'}) [Excessive: {sub.get('excessive_subdomains')}]")

    qp = data.get("query_parameters", {})
    print(f"  Query Parameters     : {qp.get('count', 0)} ({', '.join(qp.get('parameters', [])) or 'None'})")

    sqp = data.get("suspicious_query_parameters", {})
    if sqp.get("detected"):
        for p in sqp.get("parameters", []):
            print(f"      • {p['name']}: {p['reason']}")

    enc = data.get("encoded_url", {})
    print(f"  Encoded Characters   : {', '.join(enc.get('encoded_sequences', [])) if enc.get('detected') else 'None detected'}")
    if enc.get("double_encoding"):
        print(f"      • Double Encoding Detected!")

    red = data.get("redirect_analysis", {})
    print(f"  HTTP Redirects       : {red.get('redirect_count', 0)} hops (Final URL: {red.get('final_url')})")

    if errors:
        print()
        print("  --- Non-Fatal Warnings ---")
        for e in errors:
            print(f"      [!] {e}")

    print()


def validate_structure(result: dict, test_label: str):
    """Validate data schema and enforce strict evidence collection rules."""
    assert isinstance(result, dict), f"[{test_label}] Result must be a dict"
    assert "status" in result, f"[{test_label}] Missing 'status'"
    assert "data" in result, f"[{test_label}] Missing 'data'"
    assert "errors" in result, f"[{test_label}] Missing 'errors'"

    data = result["data"]
    assert isinstance(data, dict), f"[{test_label}] 'data' must be a dict"

    required_fields = [
        "url_length",
        "ip_instead_of_domain",
        "suspicious_characters",
        "redirect_analysis",
        "url_shortener",
        "punycode_domain",
        "homograph_detection",
        "subdomain_analysis",
        "query_parameters",
        "suspicious_query_parameters",
        "encoded_url"
    ]
    for field in required_fields:
        assert field in data, f"[{test_label}] Missing required field: '{field}'"

    # Strict forbidden fields (No scoring, no classification, no other agents' domains)
    forbidden_fields = [
        "trust_score", "risk_score", "risk", "confidence", "is_phishing",
        "classification", "verdict", "phishing_probability",
        # Agent 1 fields
        "domain_age", "registrar",
        # Agent 2 fields
        "a_records", "ns_records", "dnssec",
        # Agent 3 fields
        "ssl_certificate", "tls_version", "cipher_suite",
        # Agent 4 fields
        "page_title", "meta_description"
    ]
    for forbidden in forbidden_fields:
        assert forbidden not in data, \
            f"[{test_label}] Forbidden field '{forbidden}' found in Agent 5 data"

    print(f"  [PASS] Structure validation passed for: {test_label}")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_normal_url():
    label = "Test 1: Normal URL (https://example.com/login?id=123)"
    result = analyze_url("https://example.com/login?id=123")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["url_length"]["value"] == len("https://example.com/login?id=123")
    assert data["ip_instead_of_domain"]["detected"] is False
    assert data["url_shortener"]["detected"] is False
    assert data["query_parameters"]["count"] == 1
    assert "id" in data["query_parameters"]["parameters"]
    print("  [PASS] Normal URL parsed successfully.\n")


def test_2_ip_hostnames():
    # IPv4
    label_v4 = "Test 2a: IPv4 hostname (http://192.168.1.10/login)"
    res_v4 = analyze_url("http://192.168.1.10/login")
    display_result(res_v4, label_v4)
    validate_structure(res_v4, label_v4)
    assert res_v4["data"]["ip_instead_of_domain"]["detected"] is True
    assert res_v4["data"]["ip_instead_of_domain"]["ip_version"] == "IPv4"
    assert res_v4["data"]["ip_instead_of_domain"]["ip"] == "192.168.1.10"

    # IPv6
    label_v6 = "Test 2b: IPv6 hostname (http://[2001:db8::1]/login)"
    res_v6 = analyze_url("http://[2001:db8::1]/login")
    display_result(res_v6, label_v6)
    validate_structure(res_v6, label_v6)
    assert res_v6["data"]["ip_instead_of_domain"]["detected"] is True
    assert res_v6["data"]["ip_instead_of_domain"]["ip_version"] == "IPv6"
    print("  [PASS] IP hostname detection passed.\n")


def test_3_suspicious_characters():
    label = "Test 3: Suspicious characters (https://example.com@evil.com/path//login)"
    result = analyze_url("https://example.com@evil.com/path//login")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["suspicious_characters"]["detected"] is True
    assert "@" in data["suspicious_characters"]["characters"]
    assert "//" in data["suspicious_characters"]["characters"]
    print("  [PASS] Suspicious characters detected.\n")


def test_4_url_shortener():
    label = "Test 4: URL Shortener (https://bit.ly/3xyz)"
    result = analyze_url("https://bit.ly/3xyz")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["url_shortener"]["detected"] is True
    assert data["url_shortener"]["service"] == "bit.ly"
    print("  [PASS] URL Shortener detected.\n")


def test_5_punycode_and_homograph():
    # Punycode
    label_puny = "Test 5a: Punycode domain (https://xn--pple-43d.com)"
    res_puny = analyze_url("https://xn--pple-43d.com")
    display_result(res_puny, label_puny)
    validate_structure(res_puny, label_puny)
    assert res_puny["data"]["punycode_domain"]["detected"] is True

    # Homograph attack (using Cyrillic 'а' U+0430 inside "exаmple.com")
    cyrillic_a = "\u0430"
    homo_url = f"https://ex{cyrillic_a}mple.com/login"
    label_homo = f"Test 5b: Homograph look-alike attack ({homo_url})"
    res_homo = analyze_url(homo_url)
    display_result(res_homo, label_homo)
    validate_structure(res_homo, label_homo)
    assert res_homo["data"]["homograph_detection"]["detected"] is True
    assert len(res_homo["data"]["homograph_detection"]["confusable_characters"]) > 0
    print("  [PASS] Punycode and Homograph attack detection passed.\n")


def test_6_excessive_subdomains():
    label = "Test 6: Excessive subdomains (https://one.two.three.four.example.com)"
    result = analyze_url("https://one.two.three.four.example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["subdomain_analysis"]["subdomain_count"] == 4
    assert data["subdomain_analysis"]["excessive_subdomains"] is True
    print("  [PASS] Subdomain depth & excessive subdomains flag verified.\n")


def test_7_query_params_and_encoding():
    label = "Test 7: Query parameters & percent/double encoding"
    url = "https://example.com/login%3Fuser%3Dadmin?redirect=https://evil.com/target&token=%252Fsecret"
    result = analyze_url(url)
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["query_parameters"]["present"] is True
    assert data["suspicious_query_parameters"]["detected"] is True
    assert data["encoded_url"]["detected"] is True
    assert data["encoded_url"]["double_encoding"] is True
    print("  [PASS] Query parameters, redirect payloads, and double encoding detected.\n")


def test_8_invalid_urls():
    invalid_inputs = ["", "   ", None]
    for inp in invalid_inputs:
        label = f"Test 8: Invalid input ({repr(inp)})"
        result = analyze_url(inp)
        validate_structure(result, label)
        assert result["status"] == "error"
        print(f"  [PASS] Invalid input {repr(inp)} handled gracefully.\n")


def test_9_compatibility_wrapper():
    label = "Test 9: Compatibility wrapper get_url_structure('https://example.com')"
    res = get_url_structure("https://example.com")
    assert isinstance(res, dict)
    assert "data" in res
    assert res["data"]["url_length"]["value"] == len("https://example.com")
    print("  [PASS] get_url_structure compatibility wrapper works.\n")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 5 — URL STRUCTURE ANALYSIS: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    passed = 0
    failed = 0
    test_functions = [
        test_1_normal_url,
        test_2_ip_hostnames,
        test_3_suspicious_characters,
        test_4_url_shortener,
        test_5_punycode_and_homograph,
        test_6_excessive_subdomains,
        test_7_query_params_and_encoding,
        test_8_invalid_urls,
        test_9_compatibility_wrapper
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
        print("  [OK] All Agent 5 tests passed successfully.")
    else:
        print(f"  [FAIL] {failed} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    run_all_tests()
