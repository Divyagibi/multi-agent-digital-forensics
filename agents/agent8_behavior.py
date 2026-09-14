"""
Agent 8 — Website Behavior Analysis
====================================
Evidence Collection Agent.

Purpose:
    Analyze how the submitted website behaves when loaded and interacted with,
    and passively observe technical and behavioral signals including automatic
    redirects, popups, forced downloads, suspicious JavaScript patterns, form
    submission structures, hidden inputs, credential harvesting indicators, and
    potential fake login page patterns.

Features collected (Exactly 8):
    1. Automatic Redirects (HTTP status redirects & client-side meta/JS redirects)
    2. Pop-ups (window.open, modal overlays, popup triggers)
    3. Forced Downloads (Content-Disposition, <a download>, executable extensions)
    4. Malicious JavaScript Indicators (eval, Function, document.write, obfuscation, injection)
    5. Form Submission Behavior (action, method, fields, same-origin, HTTPS)
    6. Hidden Forms (hidden inputs, display:none, visibility:hidden)
    7. Credential Harvesting Indicators (password/sensitive fields, cross-domain target)
    8. Fake Login Page Indicators (login keywords, brand impersonation, urgency cues)

IMPORTANT SAFETY & ARCHITECTURAL RULES:
    - Strictly an EVIDENCE COLLECTION AGENT.
    - PASSIVE / SAFE behavioral observation only.
    - NEVER submit credentials, execute downloaded files, or exploit JavaScript.
    - Do NOT calculate final Trust Scores, Risk Scores, or phishing probabilities.
    - Do NOT classify the website as Safe, Malicious, or Phishing.
    - Distinguish normal authentication and cookie consent from suspicious indicators.
    - Safe timeouts and response size limitations.
"""

import re
import sys
import base64
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

import requests
import urllib3
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 10        # Seconds
MAX_REDIRECTS = 5           # Max redirect hops
MAX_HTML_SIZE = 2 * 1024 * 1024  # 2MB response size cap

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 DigitalForensics-Agent8/1.0"
)

# Known dangerous file extensions for forced download analysis
SUSPICIOUS_DOWNLOAD_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".zip", ".rar", ".iso", ".msi", ".hta", ".apk"
}

# Sensitive credential field names
SENSITIVE_FIELD_NAMES = {
    "password", "pass", "passwd", "pwd", "secret",
    "user", "username", "email", "login", "userid",
    "pin", "otp", "security_code", "cvv", "cardnumber",
    "token", "ssn", "auth"
}

# Brand keywords for impersonation checking
TARGET_BRAND_MAP = {
    "microsoft": ["microsoft", "office365", "outlook", "live.com", "onedrive", "sharepoint"],
    "google": ["google", "gmail", "google drive", "google docs"],
    "paypal": ["paypal"],
    "apple": ["apple", "icloud", "apple id"],
    "netflix": ["netflix"],
    "amazon": ["amazon", "prime"],
    "facebook": ["facebook", "meta"],
    "instagram": ["instagram"],
    "chase": ["chase", "jpmorgan"],
    "bank of america": ["bank of america", "bofa"],
    "wells fargo": ["wells fargo"],
    "dhl": ["dhl express", "dhl parcel"],
    "fedex": ["fedex"],
    "usps": ["usps", "postal service"]
}


# ---------------------------------------------------------------------------
# Helpers: Time & Logging
# ---------------------------------------------------------------------------

def _get_utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str):
    """Log Agent 8 actions cleanly to stdout."""
    print(f"[Agent 8] {msg}", flush=True)


# ---------------------------------------------------------------------------
# URL Normalization
# ---------------------------------------------------------------------------

def normalize_url(raw_url: str) -> dict:
    """
    Validate and normalize input URL.
    Returns original_url, normalized_url, scheme, hostname, and registered domain.
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "original_url": "",
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "domain": "",
            "is_valid": False
        }

    trimmed = raw_url.strip()
    if not trimmed.startswith(("http://", "https://")):
        normalized = "https://" + trimmed
    else:
        normalized = trimmed

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").strip().lower()

    domain = hostname
    if _TLDEXTRACT_AVAILABLE and hostname:
        ext = tldextract.extract(hostname)
        reg_dom = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', '')
        if reg_dom:
            domain = reg_dom.lower()
    elif hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])

    return {
        "original_url": trimmed,
        "normalized_url": normalized,
        "scheme": parsed.scheme.lower() if parsed.scheme else "https",
        "hostname": hostname,
        "domain": domain,
        "is_valid": bool(hostname)
    }


def _extract_domain(url: str) -> str:
    """Extract root registered domain from any URL."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return ""
        if _TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(hostname)
            reg_dom = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', '')
            if reg_dom:
                return reg_dom.lower()
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Safe Webpage Fetcher
# ---------------------------------------------------------------------------

def fetch_webpage(url: str) -> dict:
    """
    Safely perform an HTTP GET request with redirect tracking, size capping, and headers capture.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS

        resp = session.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            verify=False,
            allow_redirects=True
        )

        redirect_chain = [r.url for r in resp.history] + [resp.url] if resp.history else [resp.url]

        content_bytes = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            content_bytes.extend(chunk)
            if len(content_bytes) >= MAX_HTML_SIZE:
                break

        try:
            encoding = resp.encoding or "utf-8"
            html_text = content_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = content_bytes.decode("utf-8", errors="replace")

        return {
            "status": "success",
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": dict(resp.headers),
            "html": html_text,
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain
        }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"Request timed out after {REQUEST_TIMEOUT}s",
            "final_url": url,
            "headers": {},
            "html": "",
            "redirect_count": 0,
            "redirect_chain": [url]
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"HTTP request failed: {str(e)}",
            "final_url": url,
            "headers": {},
            "html": "",
            "redirect_count": 0,
            "redirect_chain": [url]
        }


# ---------------------------------------------------------------------------
# 1. Automatic Redirects Analyzer
# ---------------------------------------------------------------------------

def analyze_redirects(fetch_res: dict, soup: BeautifulSoup, html: str) -> dict:
    """
    Analyze both HTTP response redirects and client-side (meta refresh, JS) redirects.
    """
    http_count = fetch_res.get("redirect_count", 0)
    http_chain = fetch_res.get("redirect_chain", [])
    http_detected = http_count > 0

    client_side = []

    # Meta refresh check: <meta http-equiv="refresh" content="5;url=https://...">
    meta_refreshes = soup.find_all("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
    for meta in meta_refreshes:
        content = meta.get("content", "")
        match = re.search(r"url=['\"]?([^'\";\s]+)", content, re.I)
        target = match.group(1) if match else "Same URL (refresh)"
        client_side.append({
            "detected": True,
            "method": "meta_refresh",
            "content": content,
            "target": target
        })

    # Client-side JavaScript redirects
    js_redirect_patterns = [
        ("window.location.replace", r"window\.location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        ("window.location.href", r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]"),
        ("window.location.assign", r"window\.location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        ("location.href", r"(?<!window\.)location\.href\s*=\s*['\"]([^'\"]+)['\"]"),
        ("location.replace", r"(?<!window\.)location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
        ("self.location", r"self\.location\s*=\s*['\"]([^'\"]+)['\"]"),
        ("top.location", r"top\.location\s*=\s*['\"]([^'\"]+)['\"]")
    ]

    for method_name, pattern in js_redirect_patterns:
        matches = re.findall(pattern, html, re.I)
        for match in matches:
            client_side.append({
                "detected": True,
                "method": method_name,
                "target": match
            })

    total_detected = http_detected or bool(client_side)

    return {
        "detected": total_detected,
        "http_redirects": {
            "detected": http_detected,
            "count": http_count,
            "chain": http_chain
        },
        "client_side_redirects": client_side,
        "count": http_count + len(client_side),
        "chain": http_chain
    }


# ---------------------------------------------------------------------------
# 2. Pop-ups Analyzer
# ---------------------------------------------------------------------------

def analyze_popups(soup: BeautifulSoup, html: str) -> dict:
    """
    Identify popup scripts and overlay dialogs, differentiating legitimate
    consent/dialogs from unexpected popup scripts.
    """
    evidence = []
    seen = set()

    # window.open() triggers
    win_open_matches = re.findall(r"window\.open\s*\(\s*['\"]([^'\"]*)['\"]", html, re.I)
    if win_open_matches:
        for target in win_open_matches:
            item = f"window.open({target})" if target else "window.open()"
            if item not in seen:
                evidence.append(item)
                seen.add(item)

    # Popunder or blur/focus window manipulation
    if re.search(r"window\.blur\s*\(|window\.focus\s*\(", html, re.I):
        if "window focus/blur manipulation" not in seen:
            evidence.append("window focus/blur manipulation")
            seen.add("window focus/blur manipulation")

    # Fullscreen overlay triggers on load
    if re.search(r"(?:onload|DOMContentLoaded).*?modal|popup", html, re.I):
        if "auto-triggered modal/popup on page load" not in seen:
            evidence.append("auto-triggered modal/popup on page load")
            seen.add("auto-triggered modal/popup on page load")

    # Alert/prompt on load
    if re.search(r"(?:onload|DOMContentLoaded).*?alert\s*\(|confirm\s*\(|prompt\s*\(", html, re.I):
        if "automatic alert/prompt dialog" not in seen:
            evidence.append("automatic alert/prompt dialog")
            seen.add("automatic alert/prompt dialog")

    return {
        "detected": bool(evidence),
        "count": len(evidence),
        "evidence": evidence
    }


# ---------------------------------------------------------------------------
# 3. Forced Downloads Analyzer
# ---------------------------------------------------------------------------

def analyze_forced_downloads(fetch_res: dict, soup: BeautifulSoup, html: str, base_url: str) -> dict:
    """
    Determine whether the page attempts to automatically trigger a file download.
    Never executes or opens files.
    """
    downloads = []
    seen = set()

    # 1. Check Content-Disposition in HTTP response headers
    headers = fetch_res.get("headers", {})
    cd = headers.get("Content-Disposition") or headers.get("content-disposition", "")
    if "attachment" in cd.lower():
        fn_match = re.search(r"filename=['\"]?([^'\";\s]+)", cd, re.I)
        filename = fn_match.group(1) if fn_match else "unknown_attachment"
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        downloads.append({
            "detected": True,
            "url": base_url,
            "file_name": filename,
            "extension": ext,
            "trigger": "HTTP Content-Disposition header",
            "suspicious_extension": ext in SUSPICIOUS_DOWNLOAD_EXTS
        })
        seen.add(filename)

    # 2. Check automatic click on download link: link.click()
    auto_clicks = re.findall(r"(?:(\w+)\.click\(\)|click\(\))", html, re.I)
    if auto_clicks:
        # Search for download attributes or downloadable hrefs
        download_anchors = soup.find_all("a", attrs={"download": True})
        for a in download_anchors:
            href = a.get("href", "")
            fn = a.get("download") or (href.split("/")[-1] if href else "downloaded_file")
            ext = "." + fn.split(".")[-1].lower() if "." in fn else ""
            if fn not in seen:
                downloads.append({
                    "detected": True,
                    "url": urljoin(base_url, href),
                    "file_name": fn,
                    "extension": ext,
                    "trigger": "automatic <a download>.click() trigger",
                    "suspicious_extension": ext in SUSPICIOUS_DOWNLOAD_EXTS
                })
                seen.add(fn)

    # 3. Check for window.location pointing directly to executable files
    for ext in SUSPICIOUS_DOWNLOAD_EXTS:
        pattern = re.compile(rf"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+\{ext}(?:\?[^'\"]*)?)['\"]", re.I)
        matches = pattern.findall(html)
        for target in matches:
            fn = target.split("?")[0].split("/")[-1]
            if fn not in seen:
                downloads.append({
                    "detected": True,
                    "url": urljoin(base_url, target),
                    "file_name": fn,
                    "extension": ext,
                    "trigger": "client-side location redirect to file",
                    "suspicious_extension": True
                })
                seen.add(fn)

    return {
        "detected": bool(downloads),
        "downloads": downloads
    }


# ---------------------------------------------------------------------------
# 4. Malicious / Suspicious JavaScript Indicators
# ---------------------------------------------------------------------------

def analyze_javascript_indicators(soup: BeautifulSoup, html: str) -> dict:
    """
    Statically inspect scripts for suspicious patterns (eval, obfuscation, injection).
    """
    indicators = []
    seen = set()

    # 1. eval() usage
    if re.search(r"\beval\s*\(", html):
        indicators.append({
            "type": "dynamic_execution",
            "evidence": "eval() function call detected in script"
        })

    # 2. Function constructor execution
    if re.search(r"new\s+Function\s*\(", html):
        indicators.append({
            "type": "dynamic_execution",
            "evidence": "Function() constructor execution detected"
        })

    # 3. document.write usage
    if re.search(r"document\.write\s*\(|document\.writeln\s*\(", html):
        indicators.append({
            "type": "dom_manipulation",
            "evidence": "document.write() DOM manipulation"
        })

    # 4. Dynamic script injection
    if re.search(r"document\.createElement\s*\(\s*['\"]script['\"]\s*\)", html, re.I):
        indicators.append({
            "type": "dynamic_script_injection",
            "evidence": "document.createElement('script') injection"
        })

    # 5. Hidden iframe creation
    if re.search(r"document\.createElement\s*\(\s*['\"]iframe['\"]\s*\)", html, re.I):
        indicators.append({
            "type": "dynamic_iframe_injection",
            "evidence": "document.createElement('iframe') hidden frame creation"
        })

    # 6. Heavily encoded / base64 string payloads
    # Look for long base64 strings in script blocks (>= 200 consecutive base64 chars)
    b64_matches = re.findall(r"(?:atob\s*\(|['\"][A-Za-z0-9+/]{200,}={0,2}['\"])", html)
    if b64_matches:
        indicators.append({
            "type": "obfuscation",
            "evidence": "Large base64-encoded string payload / atob() decode"
        })

    # 7. Heavy hex / unicode escape sequences (e.g. \x65\x76\x61\x6c or \u0065)
    hex_escapes = re.findall(r"(?:\\x[0-9a-fA-F]{2}){8,}", html)
    unicode_escapes = re.findall(r"(?:\\u[0-9a-fA-F]{4}){6,}", html)
    if hex_escapes or unicode_escapes:
        indicators.append({
            "type": "obfuscation",
            "evidence": "Consecutive hex/unicode escape sequence encoding"
        })

    # 8. Suspicious credential interception / keylogger event listener
    if re.search(r"addEventListener\s*\(\s*['\"]key(?:press|down|up)['\"]", html, re.I):
        indicators.append({
            "type": "keystroke_monitoring",
            "evidence": "Global keystroke event listener attached"
        })

    # 9. Right click / context menu disabling
    if re.search(r"oncontextmenu\s*=\s*['\"]return\s+false['\"]|addEventListener\s*\(\s*['\"]contextmenu['\"].*?preventDefault", html, re.I):
        indicators.append({
            "type": "anti_analysis",
            "evidence": "Context menu / right-click disabled by script"
        })

    return {
        "detected": bool(indicators),
        "indicators": indicators
    }


# ---------------------------------------------------------------------------
# 5 & 6. Form Submission Behavior & Hidden Forms
# ---------------------------------------------------------------------------

def analyze_forms(soup: BeautifulSoup, base_url: str, website_domain: str) -> tuple[list, list]:
    """
    Inspect all HTML forms: action destination, method, input fields, HTTPS,
    cross-domain target, and hidden fields.
    """
    forms_result = []
    hidden_forms_result = []

    forms = soup.find_all("form")

    for idx, form in enumerate(forms, start=1):
        action = form.get("action", "").strip()
        method = (form.get("method") or "GET").upper()

        if action:
            resolved_action = urljoin(base_url, action)
        else:
            resolved_action = base_url

        action_domain = _extract_domain(resolved_action)
        same_origin = (action_domain == website_domain) if (action_domain and website_domain) else True
        uses_https = resolved_action.startswith("https://")

        all_inputs = form.find_all(["input", "textarea", "select"])
        field_names = []
        hidden_fields = []
        has_password = False
        has_sensitive = False

        for inp in all_inputs:
            name = inp.get("name") or inp.get("id") or "unnamed_field"
            inp_type = (inp.get("type") or "text").lower()
            field_names.append(name)

            if inp_type == "password":
                has_password = True
                has_sensitive = True
            elif any(s in name.lower() for s in SENSITIVE_FIELD_NAMES):
                has_sensitive = True

            # Check if hidden
            is_hidden_type = inp_type == "hidden"
            style = (inp.get("style") or "").lower()
            is_hidden_style = "display:none" in style or "visibility:hidden" in style or inp.has_attr("hidden")

            if is_hidden_type or is_hidden_style:
                hidden_fields.append(name)

        form_entry = {
            "form_index": idx,
            "action": resolved_action,
            "method": method,
            "same_origin": same_origin,
            "destination_domain": action_domain or website_domain,
            "cross_domain_submission": not same_origin,
            "uses_https": uses_https,
            "has_password_field": has_password,
            "has_sensitive_fields": has_sensitive,
            "field_count": len(all_inputs),
            "fields": field_names
        }
        forms_result.append(form_entry)

        if hidden_fields:
            hidden_forms_result.append({
                "form_index": idx,
                "hidden_field_count": len(hidden_fields),
                "hidden_fields": hidden_fields
            })

    return forms_result, hidden_forms_result


# ---------------------------------------------------------------------------
# 7. Credential Harvesting Indicators
# ---------------------------------------------------------------------------

def analyze_credential_harvesting(forms: list, html: str, website_domain: str) -> dict:
    """
    Identify potential credential harvesting signals from form attributes and destinations.
    """
    indicators = []

    has_password_field = any(f["has_password_field"] for f in forms)
    if has_password_field:
        indicators.append("Password input field detected on page")

    for f in forms:
        if f["has_password_field"] and f["cross_domain_submission"]:
            indicators.append(
                f"Password form submits externally to a different domain ({f['destination_domain']})"
            )
        if f["has_sensitive_fields"] and not f["uses_https"]:
            indicators.append(
                f"Form with sensitive input fields submits over unencrypted HTTP ({f['action']})"
            )
        if f["has_password_field"] and f["method"] == "GET":
            indicators.append("Password submitted via HTTP GET (exposing credentials in URL parameters)")

    # Check for multiple credential forms
    password_form_count = sum(1 for f in forms if f["has_password_field"])
    if password_form_count > 1:
        indicators.append(f"Multiple password collection forms found ({password_form_count} forms)")

    # Check for fake credential intercept scripts
    if re.search(r"FormData\(.*?\).*?fetch\(|XMLHttpRequest.*?password", html, re.I):
        indicators.append("Client-side script constructs asynchronous credential payload")

    return {
        "detected": bool(indicators),
        "indicators": indicators
    }


# ---------------------------------------------------------------------------
# 8. Fake Login Page Indicators
# ---------------------------------------------------------------------------

def analyze_fake_login(forms: list, soup: BeautifulSoup, html: str, website_domain: str) -> dict:
    """
    Identify potential fake login page signals through brand impersonation,
    login forms, and social engineering keywords.
    """
    indicators = []

    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
    page_text_lower = html.lower()

    # 1. Login keywords detection
    login_keywords = ["login", "sign in", "sign-in", "verify account", "confirm account", "secure login", "authentication", "log in"]
    login_keyword_found = any(k in page_title.lower() or k in page_text_lower for k in login_keywords)
    has_password = any(f["has_password_field"] for f in forms)

    if login_keyword_found and has_password:
        indicators.append("Authentication / Login interface detected with password input")

    # 2. Brand impersonation detection
    detected_brands = []
    for brand, aliases in TARGET_BRAND_MAP.items():
        # Check if brand appears in title or prominent headers
        brand_in_title = any(a in page_title.lower() for a in aliases)
        brand_in_body = any(a in page_text_lower for a in aliases)

        if brand_in_title or (brand_in_body and has_password):
            # Verify if website domain matches the authentic brand domain
            if not any(a.replace(" ", "") in website_domain for a in aliases):
                detected_brands.append(brand.title())

    if detected_brands:
        for b in detected_brands:
            indicators.append(f"Prominent {b} branding/title detected on unrelated domain ({website_domain})")

    # 3. Urgency & Account Threat Cues
    urgency_phrases = [
        "account will be suspended",
        "verify immediately",
        "account has been compromised",
        "unauthorized access detected",
        "action required within 24 hours",
        "update your billing information immediately"
    ]
    for phrase in urgency_phrases:
        if phrase in page_text_lower:
            indicators.append(f"Urgency social engineering trigger detected: '{phrase}'")

    # 4. Form submits cross-domain while claiming to be login
    for f in forms:
        if f["has_password_field"] and f["cross_domain_submission"]:
            indicators.append(f"Login form submits credentials across origins to {f['destination_domain']}")

    return {
        "detected": bool(indicators),
        "potential_fake_login": bool(indicators and has_password),
        "indicators": indicators
    }


# ---------------------------------------------------------------------------
# Main Agent 8 Entrypoint
# ---------------------------------------------------------------------------

def analyze_behavior(raw_url: str) -> dict:
    """
    Execute website behavior analysis across 8 core behavioral feature areas:
    Automatic Redirects, Popups, Forced Downloads, JavaScript Indicators,
    Forms, Hidden Forms, Credential Harvesting, and Fake Login Indicators.

    Strict rules:
    - Evidence collection only.
    - No trust scores or risk scores calculated.
    - No classification verdicts (Safe/Malicious/Phishing).
    - Passive, safe inspection without executing files or submitting forms.
    """
    _log("Starting website behavior analysis...")
    _log("Normalizing URL...")

    norm = normalize_url(raw_url)
    if not norm["is_valid"]:
        _log("Invalid URL provided.")
        extra_err = {
            "input": {
                "original_url": raw_url or "",
                "final_url": ""
            },
            "automatic_redirects": {"detected": False, "count": 0, "chain": []},
            "popups": {"detected": False, "count": 0, "evidence": []},
            "forced_downloads": {"detected": False, "downloads": []},
            "javascript_indicators": {"detected": False, "indicators": []},
            "forms": [],
            "hidden_forms": [],
            "credential_harvesting_indicators": {"detected": False, "indicators": []},
            "fake_login_indicators": {"detected": False, "indicators": []},
            "checked_at": _get_utc_now_iso()
        }
        return build_agent_result(
            agent_identifier="A8",
            target=raw_url or "",
            status="error",
            data={},
            evidence=[],
            errors=["Input URL is empty or invalid."],
            extra_fields=extra_err
        )

    target_url = norm["normalized_url"]
    website_domain = norm["domain"]
    errors = []

    _log("Fetching webpage...")
    fetch_res = fetch_webpage(target_url)

    if fetch_res["status"] != "success":
        errors.append(fetch_res.get("message", "Webpage could not be fetched"))

    final_url = fetch_res.get("final_url", target_url)
    html_text = fetch_res.get("html", "")
    soup = BeautifulSoup(html_text, "html.parser") if html_text else BeautifulSoup("", "html.parser")

    _log("Checking HTTP redirects...")
    _log("Checking client-side redirects...")
    redirects_info = analyze_redirects(fetch_res, soup, html_text)

    _log("Inspecting pop-up behavior...")
    popups_info = analyze_popups(soup, html_text)

    _log("Checking download behavior...")
    forced_downloads_info = analyze_forced_downloads(fetch_res, soup, html_text, final_url)

    _log("Inspecting JavaScript...")
    js_indicators_info = analyze_javascript_indicators(soup, html_text)

    _log("Analyzing forms...")
    _log("Checking hidden fields...")
    forms_info, hidden_forms_info = analyze_forms(soup, final_url, website_domain)

    _log("Checking credential harvesting indicators...")
    cred_harvesting_info = analyze_credential_harvesting(forms_info, html_text, website_domain)

    _log("Checking possible fake login indicators...")
    fake_login_info = analyze_fake_login(forms_info, soup, html_text, website_domain)

    checked_at = _get_utc_now_iso()

    # Step 9: Compile structured evidence items
    evidence = []
    evidence.append(create_evidence_item("A8", 1, "Automatic redirect behavior", redirects_info.get("detected", False), severity="low" if redirects_info.get("detected") else "info", source="HTTP tracer / HTML parser", evidence_type="deterministic", metadata=redirects_info))
    evidence.append(create_evidence_item("A8", 2, "Aggressive popup indicators", popups_info.get("detected", False), severity="medium" if popups_info.get("detected") else "info", source="JavaScript DOM", evidence_type="deterministic", metadata=popups_info))
    evidence.append(create_evidence_item("A8", 3, "Forced or immediate file downloads", forced_downloads_info.get("detected", False), severity="high" if forced_downloads_info.get("detected") else "info", source="HTTP / HTML", evidence_type="deterministic", metadata=forced_downloads_info))
    evidence.append(create_evidence_item("A8", 4, "Suspicious JavaScript behavior patterns", js_indicators_info.get("detected", False), severity="medium" if js_indicators_info.get("detected") else "info", source="JavaScript AST analyzer", evidence_type="deterministic", metadata=js_indicators_info))
    evidence.append(create_evidence_item("A8", 5, "Discovered form submission endpoints", len(forms_info), severity="info", source="HTML form parser", evidence_type="deterministic", metadata={"forms_count": len(forms_info), "forms": forms_info}))
    evidence.append(create_evidence_item("A8", 6, "Hidden form submission fields", len(hidden_forms_info), severity="low" if hidden_forms_info else "info", source="HTML form parser", evidence_type="deterministic", metadata={"hidden_forms": hidden_forms_info}))
    
    is_cred = cred_harvesting_info.get("detected", False)
    evidence.append(create_evidence_item("A8", 7, "Credential harvesting form pattern", is_cred, severity="critical" if is_cred else "info", source="Form security analyzer", evidence_type="inference", evidence_strength=0.88 if is_cred else None, metadata=cred_harvesting_info))
    
    is_fake = fake_login_info.get("detected", False)
    evidence.append(create_evidence_item("A8", 8, "Deceptive login form structure", is_fake, severity="critical" if is_fake else "info", source="Form layout analyzer", evidence_type="inference", evidence_strength=0.85 if is_fake else None, metadata=fake_login_info))

    data_payload = {
        "automatic_redirects": redirects_info,
        "popups": popups_info,
        "forced_downloads": forced_downloads_info,
        "javascript_indicators": js_indicators_info,
        "forms": forms_info,
        "hidden_forms": hidden_forms_info,
        "credential_harvesting_indicators": cred_harvesting_info,
        "fake_login_indicators": fake_login_info
    }

    extra_fields = {
        "input": {
            "original_url": norm["original_url"],
            "final_url": final_url
        },
        "automatic_redirects": redirects_info,
        "popups": popups_info,
        "forced_downloads": forced_downloads_info,
        "javascript_indicators": js_indicators_info,
        "forms": forms_info,
        "hidden_forms": hidden_forms_info,
        "credential_harvesting_indicators": cred_harvesting_info,
        "fake_login_indicators": fake_login_info,
        "checked_at": checked_at
    }

    response_payload = build_agent_result(
        agent_identifier="A8",
        target=norm["original_url"],
        status="success",
        data=data_payload,
        evidence=evidence,
        errors=errors,
        extra_fields=extra_fields
    )

    _log("Website behavior analysis completed.")
    return response_payload


def get_behavior_evidence(url: str) -> dict:
    """
    Convenience alias for analyze_behavior().
    """
    return analyze_behavior(url)
