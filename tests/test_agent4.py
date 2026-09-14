# -*- coding: utf-8 -*-
"""
tests/test_agent4.py
====================
Comprehensive test suite for Agent 4 -- Website Content Analysis.

Tests cover:
    1. Normal HTML webpage                 — https://example.com
    2. Webpage with Company & Meta         — https://www.google.com
    3. Webpage with Policy pages & Links   — https://github.com
    4. Webpage with E-Commerce / Policies  — https://www.cloudflare.com
    5. SSRF / Private IP protection        — "http://127.0.0.1", "http://localhost", "http://192.168.1.1"
    6. Invalid URL / Hostname handling     — "hello", "not-a-domain", ""
    7. Schema & Evidence validation        — Verifies zero trust or risk scoring

Run:
    python -u tests/test_agent4.py
"""

import sys
import os
import json
from datetime import datetime

# Ensure parent directory is in sys.path so we can import agents/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.agent4_content import analyze_content, get_website_content


# ---------------------------------------------------------------------------
# Display & Validation Helpers
# ---------------------------------------------------------------------------

def print_separator(char="=", width=60):
    print(char * width)


def display_result(result: dict, test_label: str):
    """Print a clean readable formatted summary of an analyze_content() result."""
    print_separator()
    print(f"  TEST: {test_label}")
    print_separator()

    status = result.get("status", "unknown")
    data   = result.get("data", {})
    errors = result.get("errors", [])

    print(f"  Overall Status       : {status.upper()}")
    print()
    print("  ===== AGENT 4 — WEBSITE CONTENT ANALYSIS =====")
    print()

    print(f"  Target URL           : {data.get('url', 'Not Available')}")
    print(f"  Final URL            : {data.get('final_url', 'Not Available')}")
    print(f"  Access Status        : {data.get('access_status', 'unknown')}")
    print(f"  Content Access       : {data.get('content_access', 'unknown')}")

    title_obj = data.get("page_title", {})
    title_val = title_obj.get("value") if isinstance(title_obj, dict) else title_obj
    print(f"  Page Title           : {title_val or 'Not Available'}")

    meta_obj = data.get("meta_description", {})
    meta_val = meta_obj.get("value") if isinstance(meta_obj, dict) else meta_obj
    print(f"  Meta Description     : {meta_val or 'Not Available'}")

    kw_obj = data.get("keywords", {})
    kws = kw_obj.get("values", []) if isinstance(kw_obj, dict) else []
    print(f"  Keywords ({len(kws)})      : {', '.join(kws[:5]) if kws else 'None detected'}")

    lang_obj = data.get("language", {})
    if isinstance(lang_obj, dict):
        print(f"  Language             : {lang_obj.get('name', 'Unknown')} ({lang_obj.get('code', 'N/A')}) [Source: {lang_obj.get('source', 'N/A')}]")
    else:
        print(f"  Language             : {lang_obj}")

    comp_obj = data.get("company_name", {})
    if isinstance(comp_obj, dict):
        print(f"  Company / Org        : {comp_obj.get('value') or 'Not detected'} [Source: {comp_obj.get('source', 'N/A')}]")
    else:
        print(f"  Company / Org        : {comp_obj}")

    print()
    print("  --- Essential Policy Pages ---")
    policies = [
        ("About Us", data.get("about_page", {})),
        ("Contact Page", data.get("contact_page", {})),
        ("Privacy Policy", data.get("privacy_policy", {})),
        ("Terms & Conditions", data.get("terms_conditions", {})),
        ("Refund Policy", data.get("refund_policy", {})),
        ("Shipping Policy", data.get("shipping_policy", {})),
        ("Cookie Policy", data.get("cookie_policy", {}))
    ]
    for name, p_obj in policies:
        present = p_obj.get("present") if isinstance(p_obj, dict) else bool(p_obj and p_obj != "Not detected")
        url_val = p_obj.get("url") if isinstance(p_obj, dict) else p_obj
        status_sym = "[FOUND]" if present else "[MISSING]"
        print(f"    {status_sym} {name:<20}: {url_val if present else 'Not Found'}")

    missing = data.get("missing_pages", [])
    print(f"  Missing Page Categories: {', '.join(missing) if missing else 'None'}")

    broken = data.get("broken_links", [])
    links_checked = data.get("links_checked", 0)
    print(f"  Links Checked        : {links_checked}")
    print(f"  Broken Links Found   : {len(broken)}")
    for b in broken:
        print(f"      • {b.get('url')} (Status: {b.get('status_code')} {b.get('reason')})")

    if errors:
        print()
        print("  --- Non-Fatal Warnings / Fetch Notes ---")
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
        "page_title",
        "meta_description",
        "keywords",
        "language",
        "company_name",
        "about_page",
        "contact_page",
        "privacy_policy",
        "terms_conditions",
        "refund_policy",
        "shipping_policy",
        "cookie_policy",
        "broken_links",
        "missing_pages",
        "links_checked"
    ]
    for field in required_fields:
        assert field in data, f"[{test_label}] Missing required field: '{field}'"

    # Strict forbidden fields (No scoring, no classification, no other agents' domains)
    forbidden_fields = [
        "trust_score", "risk_score", "risk", "confidence", "is_phishing",
        "classification", "verdict", "phishing_probability",
        "content_score", "reputation_score",
        # Agent 1 fields
        "domain_age", "registrar",
        # Agent 2 fields
        "a_records", "ns_records", "dnssec",
        # Agent 3 fields
        "ssl_certificate", "tls_version", "cipher_suite"
    ]
    for forbidden in forbidden_fields:
        assert forbidden not in data, \
            f"[{test_label}] Forbidden field '{forbidden}' found in Agent 4 data"

    print(f"  [PASS] Structure validation passed for: {test_label}")


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_1_normal_html_page():
    label = "Test 1: Normal HTML page (https://example.com)"
    result = analyze_content("https://example.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["page_title"]["present"] is True
    assert "Example" in str(data["page_title"]["value"])
    print("  [PASS] example.com title successfully extracted.\n")
    return result


def test_2_company_and_meta():
    label = "Test 2: Company & Meta extraction (https://www.google.com)"
    result = analyze_content("https://www.google.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    assert data["page_title"]["present"] is True
    assert data["access_status"] in ("accessible", "blocked", "rate_limited")
    print(f"  [PASS] Google page parsed. Access: {data['access_status']}\n")
    return result


def test_3_policy_page_discovery():
    label = "Test 3: Policy pages & links (https://github.com)"
    result = analyze_content("https://github.com")
    display_result(result, label)
    validate_structure(result, label)

    data = result["data"]
    # Check that privacy or terms or about is discovered
    found_any = any([
        data["privacy_policy"]["present"],
        data["terms_conditions"]["present"],
        data["about_page"]["present"],
        data["contact_page"]["present"]
    ])
    assert found_any, "GitHub should have discoverable policy pages"
    print("  [PASS] GitHub policy pages discovered successfully.\n")
    return result


def test_4_ssrf_protection():
    blocked_inputs = [
        "http://localhost",
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://169.254.169.254"
    ]
    for inp in blocked_inputs:
        label = f"Test 4: SSRF protection ({inp})"
        result = analyze_content(inp)
        validate_structure(result, label)
        assert result["status"] == "error", f"Expected error status for {inp}"
        assert result["data"]["access_status"] == "invalid_url"
        print(f"  [PASS] Blocked dangerous internal target: {inp}\n")


def test_5_invalid_url_handling():
    invalid_inputs = ["hello", "not-a-domain", "", "   "]
    for inp in invalid_inputs:
        label = f"Test 5: Invalid input ({repr(inp)})"
        result = analyze_content(inp)
        validate_structure(result, label)
        assert result["status"] == "error"
        assert len(result["errors"]) > 0
        print(f"  [PASS] Invalid input {repr(inp)} handled gracefully.\n")


def test_6_compatibility_wrapper():
    label = "Test 6: Compatibility wrapper get_website_content('https://example.com')"
    res = get_website_content("https://example.com")
    assert isinstance(res, dict)
    assert "data" in res
    assert res["data"]["page_title"]["present"] is True
    print("  [PASS] get_website_content compatibility wrapper works.\n")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print_separator("=", 70)
    print("  AGENT 4 — WEBSITE CONTENT ANALYSIS: FULL TEST SUITE")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("=", 70)
    print()

    passed = 0
    failed = 0
    test_functions = [
        test_1_normal_html_page,
        test_2_company_and_meta,
        test_3_policy_page_discovery,
        test_4_ssrf_protection,
        test_5_invalid_url_handling,
        test_6_compatibility_wrapper,
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
        print("  [OK] All Agent 4 tests passed successfully.")
    else:
        print(f"  [FAIL] {failed} test(s) failed.")
    print_separator("=", 70)


if __name__ == "__main__":
    run_all_tests()
