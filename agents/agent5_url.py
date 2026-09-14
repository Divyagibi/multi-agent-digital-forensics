"""
Agent 5 — URL Structure Analysis
================================
Evidence Collection Agent.

Purpose:
    Inspect the technical structure and lexical characteristics of the submitted
    URL, including length breakdowns, IP-based hostnames, suspicious characters,
    HTTP redirect chains, URL shorteners, Punycode encoding, IDN homograph /
    confusable Unicode spoofing, subdomain depth, query parameters, and percent /
    double encoding.

Features collected (Exactly 10):
    1.  URL Length & Length Analysis
    2.  IP Address Instead of Domain
    3.  Suspicious Characters
    4.  Multiple Redirects
    5.  URL Shortener
    6.  Punycode Domain
    7.  Homograph Attack Detection
    8.  Excessive Subdomains
    9.  Suspicious Query Parameters
    10. Encoded URLs (Percent & Double Encoding)

IMPORTANT:
    This agent is ONLY an evidence collection agent.
    It does NOT calculate trust scores, risk scores, or classify the URL
    as malicious, phishing, or safe.
"""

import re
import idna
import ipaddress
import unicodedata
import requests
from urllib.parse import urlparse, parse_qs, unquote, urljoin

from services.evidence_schema import create_evidence_item, build_agent_result


# ---------------------------------------------------------------------------
# Configurable Constants
# ---------------------------------------------------------------------------

KNOWN_SHORTENERS = {
    "bit.ly": "Bitly",
    "tinyurl.com": "TinyURL",
    "t.co": "Twitter Shortener",
    "goo.gl": "Google Shortener",
    "ow.ly": "Owly",
    "is.gd": "Is.gd",
    "buff.ly": "Buffer",
    "adf.ly": "Adf.ly",
    "bit.do": "Bit.do",
    "rebrand.ly": "Rebrandly",
    "cutt.ly": "Cuttly",
    "shorturl.at": "ShortURL",
    "tiny.cc": "Tiny.cc",
    "qr.net": "QR.net",
    "v.gd": "v.gd"
}

MAX_NORMAL_SUBDOMAINS = 3
MAX_REDIRECTS = 10

# Confusable Unicode look-alikes mapped to their ASCII equivalents
CONFUSABLE_MAP = {
    # Cyrillic small letters
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u0456": "i",
    "\u0458": "j", "\u043e": "o", "\u0440": "p", "\u0455": "s",
    "\u0443": "y", "\u0445": "x", "\u051b": "q", "\u051d": "w",
    # Cyrillic capital letters
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u0406": "I", "\u0408": "J", "\u041a": "K",
    "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0422": "T",
    "\u0425": "X", "\u0423": "Y",
    # Greek small letters
    "\u03b1": "a", "\u03bf": "o", "\u03bd": "v", "\u03c1": "p",
    "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    # Greek capital letters
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a7": "X", "\u03a9": "O"
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# ---------------------------------------------------------------------------
# SSRF Protection Helper
# ---------------------------------------------------------------------------

def is_safe_for_http(url: str) -> bool:
    """Check if the URL is safe to follow via HTTP without risking SSRF."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower()
        if hostname in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
            return False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False
        except ValueError:
            pass
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# FEATURE HELPERS
# ---------------------------------------------------------------------------

def check_ip_instead_of_domain(hostname: str) -> dict:
    """
    Feature 2: Determine whether hostname is an IPv4 or IPv6 address.
    """
    if not hostname:
        return {"detected": False, "ip_version": None, "ip": None}

    clean_host = hostname.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return {
            "detected": True,
            "ip_version": f"IPv{ip_obj.version}",
            "ip": clean_host
        }
    except ValueError:
        return {
            "detected": False,
            "ip_version": None,
            "ip": None
        }


def check_suspicious_characters(raw_url: str, hostname: str, path: str) -> dict:
    """
    Feature 3: Analyze URL for unusual or potentially suspicious characters.
    """
    detected_chars = []
    occurrences = {}

    # Check for @ delimiter
    if "@" in raw_url:
        at_count = raw_url.count("@")
        detected_chars.append("@")
        occurrences["@"] = at_count

    # Check for backslashes
    if "\\" in raw_url:
        slash_count = raw_url.count("\\")
        detected_chars.append("\\")
        occurrences["\\"] = slash_count

    # Check for multiple consecutive slashes in path
    if "//" in path:
        detected_chars.append("//")
        occurrences["//"] = path.count("//")

    # Check for excessive hyphens (> 3 in hostname or > 5 in URL)
    hyphen_count = raw_url.count("-")
    if hyphen_count > 4:
        detected_chars.append("excessive_hyphens")
        occurrences["-"] = hyphen_count

    # Check for excessive dots (> 4 in hostname or > 5 in URL)
    dot_count = raw_url.count(".")
    if dot_count > 5:
        detected_chars.append("excessive_dots")
        occurrences["."] = dot_count

    # Check for unprintable control characters
    unprintable_matches = re.findall(r"[\x00-\x1f\x7f]", raw_url)
    if unprintable_matches:
        detected_chars.append("unprintable_control_chars")
        occurrences["control_chars"] = len(unprintable_matches)

    # Check for zero-width Unicode characters
    zero_width = [zw for zw in ["\u200b", "\u200c", "\u200d", "\ufeff"] if zw in raw_url]
    if zero_width:
        detected_chars.append("zero_width_chars")
        occurrences["zero_width_chars"] = len(zero_width)

    return {
        "detected": len(detected_chars) > 0,
        "characters": detected_chars,
        "occurrences": occurrences
    }


def check_url_shortener(hostname: str) -> dict:
    """
    Feature 5: Check if hostname belongs to a known URL shortening service.
    """
    if not hostname:
        return {"detected": False, "service": None}

    hostname_clean = hostname.lower().strip()
    for short_domain, service_title in KNOWN_SHORTENERS.items():
        if hostname_clean == short_domain or hostname_clean.endswith("." + short_domain):
            return {
                "detected": True,
                "service": short_domain
            }

    return {"detected": False, "service": None}


def check_punycode_domain(hostname: str) -> dict:
    """
    Feature 6: Detect Punycode (xn--) domain labels.
    """
    if not hostname:
        return {"detected": False, "labels": []}

    labels = hostname.lower().split(".")
    puny_labels = [label for label in labels if label.startswith("xn--")]

    return {
        "detected": len(puny_labels) > 0,
        "labels": puny_labels
    }


def check_homograph_attack(hostname: str) -> dict:
    """
    Feature 7: Inspect Unicode character scripts and confusable character look-alikes.
    """
    if not hostname:
        return {
            "detected": False,
            "reason": None,
            "scripts": [],
            "confusable_characters": []
        }

    # Decode Punycode if applicable
    decoded_host = hostname
    if "xn--" in hostname.lower():
        try:
            decoded_host = idna.decode(hostname)
        except Exception:
            decoded_host = hostname

    scripts = set()
    confusables_found = []

    for ch in decoded_host:
        if ch in (".", "-", "_", ":", "/", "?", "&", "=") or ord(ch) < 128:
            if ord(ch) < 128 and ch.isalpha():
                scripts.add("Latin")
            continue

        # Inspect Unicode character script
        try:
            char_name = unicodedata.name(ch, "")
            script_prefix = char_name.split()[0] if char_name else "UNKNOWN"
            # Map script names cleanly
            if "CYRILLIC" in script_prefix:
                scripts.add("Cyrillic")
            elif "GREEK" in script_prefix:
                scripts.add("Greek")
            elif "ARABIC" in script_prefix:
                scripts.add("Arabic")
            elif "HEBREW" in script_prefix:
                scripts.add("Hebrew")
            elif "DEVANAGARI" in script_prefix:
                scripts.add("Devanagari")
            elif "HAN" in script_prefix or "CJK" in script_prefix:
                scripts.add("Chinese/Han")
            elif "HIRAGANA" in script_prefix or "KATAKANA" in script_prefix:
                scripts.add("Japanese")
            elif "HANGUL" in script_prefix:
                scripts.add("Korean")
            else:
                scripts.add(script_prefix.title())
        except Exception:
            pass

        # Check against confusable lookup
        if ch in CONFUSABLE_MAP:
            confusables_found.append({
                "character": ch,
                "unicode": f"U+{ord(ch):04X}",
                "looks_like": CONFUSABLE_MAP[ch]
            })

    # Determine if mixed-script or confusables present
    has_mixed = len(scripts) > 1 and "Latin" in scripts
    has_confusables = len(confusables_found) > 0

    if has_mixed or has_confusables:
        reason = "Mixed-script/confusable Unicode characters detected" if has_mixed else "Confusable Unicode character detected"
        return {
            "detected": True,
            "reason": reason,
            "scripts": sorted(list(scripts)),
            "confusable_characters": confusables_found
        }

    return {
        "detected": False,
        "reason": None,
        "scripts": sorted(list(scripts)),
        "confusable_characters": []
    }


def check_subdomain_analysis(hostname: str, is_ip: bool) -> dict:
    """
    Feature 8: Count and list subdomains excluding registrable domain.
    """
    if not hostname or is_ip:
        return {
            "subdomain_count": 0,
            "subdomains": [],
            "excessive_subdomains": False
        }

    parts = hostname.lower().split(".")
    # Common multi-part TLD suffixes (e.g. .co.uk, .com.au)
    two_part_tlds = {"co.uk", "com.au", "co.nz", "com.br", "co.in", "gov.uk", "edu.au", "ac.uk", "org.uk", "net.au"}

    if len(parts) > 2:
        suffix_check = ".".join(parts[-2:])
        if suffix_check in two_part_tlds and len(parts) > 3:
            subdomains = parts[:-3]
        else:
            subdomains = parts[:-2]
    else:
        subdomains = []

    count = len(subdomains)
    return {
        "subdomain_count": count,
        "subdomains": subdomains,
        "excessive_subdomains": count > MAX_NORMAL_SUBDOMAINS
    }


def check_query_parameters(query_string: str) -> tuple[dict, dict]:
    """
    Feature 9: Parse query parameters and identify potentially suspicious patterns.
    """
    if not query_string:
        return (
            {"present": False, "count": 0, "parameters": []},
            {"detected": False, "parameters": []}
        )

    parsed_params = parse_qs(query_string, keep_blank_values=True)
    param_names = list(parsed_params.keys())
    count = len(param_names)

    suspicious_list = []
    redirect_keys = {"url", "redirect", "redirect_uri", "return", "return_to", "next", "dest", "destination", "target", "goto", "link"}

    for key, values in parsed_params.items():
        key_lower = key.lower()
        val_str = " ".join(values)

        if key_lower in redirect_keys:
            suspicious_list.append({
                "name": key,
                "reason": "Redirect destination parameter detected"
            })
        elif "http://" in val_str or "https://" in val_str:
            suspicious_list.append({
                "name": key,
                "reason": "Contains URL-like value in parameter payload"
            })
        elif len(val_str) > 100:
            suspicious_list.append({
                "name": key,
                "reason": f"Unusually long parameter payload ({len(val_str)} characters)"
            })

    query_parameters = {
        "present": count > 0,
        "count": count,
        "parameters": param_names
    }

    suspicious_query_parameters = {
        "detected": len(suspicious_list) > 0,
        "parameters": suspicious_list
    }

    return query_parameters, suspicious_query_parameters


def check_encoded_url(raw_url: str, path: str, query: str) -> dict:
    """
    Feature 10: Detect percent-encoded sequences and identify double encoding.
    """
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    has_encoding = len(encoded_matches) > 0

    # Double encoding check: %25 followed by hex (e.g. %252F -> %2F)
    double_encoding = bool(re.search(r"%25[0-9a-fA-F]{2}", raw_url, re.IGNORECASE))

    decoded_components = {}
    if has_encoding:
        if path:
            decoded_components["path"] = unquote(path)
        if query:
            decoded_components["query"] = unquote(query)

    return {
        "detected": has_encoding,
        "encoded_sequences": list(set(encoded_matches)),
        "double_encoding": double_encoding,
        "decoded_components": decoded_components
    }


def trace_redirects(start_url: str, max_redirects: int = MAX_REDIRECTS) -> dict:
    """
    Feature 4: Send safe HTTP request with redirect tracking enabled and loop protection.
    """
    redirect_chain = []
    current_url = start_url
    redirect_limit_reached = False
    status_msg = "success"

    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 DigitalForensicsAgent/1.0"
    }

    try:
        for _ in range(max_redirects):
            if not is_safe_for_http(current_url):
                status_msg = "ssrf_protection_triggered"
                break

            # Send single non-redirecting HEAD/GET request to record exact hops
            try:
                resp = session.head(current_url, timeout=3.0, headers=headers, allow_redirects=False)
                if resp.status_code in (405, 400):
                    resp = session.get(current_url, timeout=3.0, headers=headers, allow_redirects=False, stream=True)
            except Exception:
                try:
                    resp = session.get(current_url, timeout=3.0, headers=headers, allow_redirects=False, stream=True)
                except Exception as e:
                    status_msg = f"network_error: {str(e)}"
                    break

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break

                next_url = urljoin(current_url, location)
                redirect_chain.append({
                    "url": current_url,
                    "status_code": resp.status_code,
                    "location": next_url
                })
                # Loop detection
                if any(hop["url"] == next_url for hop in redirect_chain):
                    status_msg = "redirect_loop_detected"
                    current_url = next_url
                    break

                current_url = next_url
            else:
                current_url = resp.url
                break
        else:
            redirect_limit_reached = True
            status_msg = "redirect_limit_reached"

    except Exception as e:
        status_msg = f"error: {str(e)}"

    return {
        "redirect_count": len(redirect_chain),
        "multiple_redirects": len(redirect_chain) > 1,
        "redirect_chain": redirect_chain,
        "final_url": current_url,
        "redirect_limit_reached": redirect_limit_reached,
        "network_status": status_msg
    }


# ---------------------------------------------------------------------------
# MAIN AGENT FUNCTION
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Agent 5 — URL Structure Analysis: Main evidence collection function.

    Collects:
        1. URL Length & Breakdown
        2. IP Address Instead of Domain
        3. Suspicious Characters
        4. Multiple Redirects
        5. URL Shortener
        6. Punycode Domain
        7. Homograph Attack Detection
        8. Excessive Subdomains
        9. Suspicious Query Parameters
        10. Encoded URLs

    This function is an EVIDENCE COLLECTION AGENT only.
    It does NOT calculate trust scores, risk scores, or classify the URL.

    Args:
        url: Raw URL string entered by the user.

    Returns:
        dict: Complete structured URL structure evidence.
    """
    print(f"[Agent 5] Starting URL structure analysis for: {url}")
    errors = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 5] Error: Invalid URL input provided.")
        errors.append("Invalid or empty URL provided")
        empty_data = {
            "original_url": url,
            "url_length": {"value": 0},
            "ip_instead_of_domain": {"detected": False, "ip_version": None, "ip": None},
            "suspicious_characters": {"detected": False, "characters": [], "occurrences": {}},
            "redirect_analysis": {"redirect_count": 0, "multiple_redirects": False, "redirect_chain": [], "final_url": url, "redirect_limit_reached": False},
            "url_shortener": {"detected": False, "service": None},
            "punycode_domain": {"detected": False, "labels": []},
            "homograph_detection": {"detected": False, "reason": None, "scripts": [], "confusable_characters": []},
            "subdomain_analysis": {"subdomain_count": 0, "subdomains": [], "excessive_subdomains": False},
            "query_parameters": {"present": False, "count": 0, "parameters": []},
            "suspicious_query_parameters": {"detected": False, "parameters": []},
            "encoded_url": {"detected": False, "encoded_sequences": [], "double_encoding": False}
        }
        return build_agent_result(
            agent_identifier="A5",
            target=url or "",
            status="error",
            data=empty_data,
            evidence=[],
            errors=errors
        )

    raw_url = url.strip()

    # Step 1: Parse URL with urllib.parse.urlparse
    print(f"[Agent 5] Parsing URL structure...")
    target_with_scheme = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
    try:
        parsed = urlparse(target_with_scheme)
        scheme = parsed.scheme
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path or "/"
        query = parsed.query or ""
        fragment = parsed.fragment or None
    except Exception as e:
        errors.append(f"URL parsing failed: {str(e)}")
        hostname = ""
        scheme = "https"
        port = None
        path = "/"
        query = ""
        fragment = None

    print(f"[Agent 5] Hostname: {hostname or 'None'} (Scheme: {scheme})")

    # Step 2: Feature 1 — URL Length
    print("[Agent 5] Checking URL length...")
    url_len = len(raw_url)
    length_breakdown = {
        "total_length": url_len,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query)
    }

    # Step 3: Feature 2 — IP Address Instead of Domain
    print(f"[Agent 5] Checking IP address hostname...")
    ip_check = check_ip_instead_of_domain(hostname)

    # Step 4: Feature 3 — Suspicious Characters
    print("[Agent 5] Checking suspicious characters...")
    suspicious_chars = check_suspicious_characters(raw_url, hostname, path)

    # Step 5: Feature 5 — URL Shortener
    print("[Agent 5] Checking URL shortener...")
    shortener_info = check_url_shortener(hostname)

    # Step 6: Feature 6 — Punycode Domain
    print("[Agent 5] Checking Punycode...")
    puny_info = check_punycode_domain(hostname)

    # Step 7: Feature 7 — Homograph Attack Detection
    print("[Agent 5] Checking homograph characteristics...")
    homo_info = check_homograph_attack(hostname)

    # Step 8: Feature 8 — Subdomain Analysis
    print("[Agent 5] Analyzing subdomains...")
    sub_info = check_subdomain_analysis(hostname, ip_check["detected"])

    # Step 9: Feature 9 — Query Parameters
    print("[Agent 5] Analyzing query parameters...")
    query_params, susp_params = check_query_parameters(query)

    # Step 10: Feature 10 — Encoded URL
    print("[Agent 5] Checking URL encoding...")
    encoded_info = check_encoded_url(raw_url, path, query)

    # Step 11: Feature 4 — Multiple Redirects
    print("[Agent 5] Checking redirect chain...")
    redirect_info = trace_redirects(target_with_scheme)
    print(f"[Agent 5] Redirect count: {redirect_info['redirect_count']}")

    # Build primary data dictionary adhering strictly to prompt schema
    data = {
        "original_url": raw_url,
        "parsed_url": {
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query": query or None,
            "fragment": fragment
        },
        "url_length": {
            "value": url_len
        },
        "length_analysis": length_breakdown,
        "ip_instead_of_domain": ip_check,
        "suspicious_characters": suspicious_chars,
        "redirect_analysis": {
            "redirect_count": redirect_info["redirect_count"],
            "multiple_redirects": redirect_info["multiple_redirects"],
            "redirect_chain": redirect_info["redirect_chain"],
            "final_url": redirect_info["final_url"],
            "redirect_limit_reached": redirect_info["redirect_limit_reached"]
        },
        "url_shortener": shortener_info,
        "punycode_domain": puny_info,
        "homograph_detection": homo_info,
        "subdomain_analysis": sub_info,
        "query_parameters": query_params,
        "suspicious_query_parameters": susp_params,
        "encoded_url": encoded_info,
        "network_status": redirect_info["network_status"],

        # Compatibility fields for legacy consumers
        "raw_url": raw_url,
        "is_ip_address": ip_check["detected"],
        "ip_version": ip_check["ip_version"],
        "punycode": {
            "is_punycode": puny_info["detected"],
            "decoded_domain": idna.decode(hostname) if puny_info["detected"] else hostname
        },
        "homograph_attack": {
            "potential_homograph": homo_info["detected"],
            "scripts_detected": homo_info["scripts"],
            "details": homo_info["reason"] or "Single script / standard domain"
        },
        "suspicious_query_params": {
            "total_params": query_params["count"],
            "detected_patterns": [p["reason"] for p in susp_params["parameters"]]
        },
        "encoded_characters": {
            "has_percent_encoding": encoded_info["detected"],
            "encoded_count": len(encoded_info["encoded_sequences"]),
            "sequences": encoded_info["encoded_sequences"]
        },
        "redirects": {
            "redirect_count": redirect_info["redirect_count"],
            "redirect_chain": redirect_info["redirect_chain"],
            "final_url": redirect_info["final_url"],
            "cross_domain_redirect": redirect_info["multiple_redirects"]
        }
    }

    # Step 12: Compile structured evidence items
    evidence = []
    tot_len = data["url_length"].get("total_length", 0)
    evidence.append(create_evidence_item("A5", 1, "URL character length", tot_len, severity="low" if tot_len > 100 else "info", source="URL structure", evidence_type="deterministic", metadata=data["url_length"]))
    evidence.append(create_evidence_item("A5", 2, "IP address used as hostname", data["ip_instead_of_domain"].get("detected", False), severity="medium" if data["ip_instead_of_domain"].get("detected") else "info", source="URL structure", evidence_type="deterministic", metadata=data["ip_instead_of_domain"]))
    evidence.append(create_evidence_item("A5", 3, "Suspicious characters in URL", data["suspicious_characters"].get("detected", False), severity="low" if data["suspicious_characters"].get("detected") else "info", source="URL structure", evidence_type="deterministic", metadata=data["suspicious_characters"]))
    evidence.append(create_evidence_item("A5", 4, "HTTP redirect chain length", data["redirect_analysis"].get("redirect_count", 0), severity="medium" if data["redirect_analysis"].get("redirect_count", 0) > 2 else "info", source="HTTP redirect tracer", evidence_type="deterministic", metadata=data["redirect_analysis"]))
    evidence.append(create_evidence_item("A5", 5, "Known URL shortener service", data["url_shortener"].get("detected", False), severity="medium" if data["url_shortener"].get("detected") else "info", source="Domain database", evidence_type="deterministic", metadata=data["url_shortener"]))
    evidence.append(create_evidence_item("A5", 6, "Punycode IDN domain", data["punycode_domain"].get("detected", False), severity="low" if data["punycode_domain"].get("detected") else "info", source="URL structure", evidence_type="deterministic", metadata=data["punycode_domain"]))
    
    is_homo = data["homograph_detection"].get("detected", False)
    evidence.append(create_evidence_item("A5", 7, "Homograph confusable script spoofing", is_homo, severity="high" if is_homo else "info", source="Lexical analyzer", evidence_type="inference", evidence_strength=0.85 if is_homo else None, metadata=data["homograph_detection"]))
    evidence.append(create_evidence_item("A5", 8, "Excessive subdomain hierarchy", data["subdomain_analysis"].get("excessive_subdomains", False), severity="low" if data["subdomain_analysis"].get("excessive_subdomains") else "info", source="URL structure", evidence_type="deterministic", metadata=data["subdomain_analysis"]))
    evidence.append(create_evidence_item("A5", 9, "Suspicious redirect parameters", data["suspicious_query_parameters"].get("detected", False), severity="medium" if data["suspicious_query_parameters"].get("detected") else "info", source="URL query parser", evidence_type="deterministic", metadata=data["suspicious_query_parameters"]))
    evidence.append(create_evidence_item("A5", 10, "Percent-encoded characters in URL", data["encoded_url"].get("detected", False), severity="medium" if data["encoded_url"].get("double_encoding") else "info", source="URL structure", evidence_type="deterministic", metadata=data["encoded_url"]))

    status = "success" if hostname else "partial"
    print(f"[Agent 5] Analysis completed. Status: {status}")

    return build_agent_result(
        agent_identifier="A5",
        target=url,
        status=status,
        data=data,
        evidence=evidence,
        errors=errors
    )


def get_url_structure(url: str) -> dict:
    """
    Compatibility wrapper returning URL structure analysis evidence.
    """
    return analyze_url(url)
