"""
Agent 4 — Website Content Analysis
==================================
Evidence Collection Agent.

Purpose:
    Fetch the submitted webpage HTML and inspect visible content, metadata,
    language indicators, company identity, essential policy navigation links,
    internal broken links, and missing page categories.

Main question answered:
    "What information, metadata, organization identity, and important pages
    does this website actually provide?"

Features collected:
    1.  Page Title (<title> and OpenGraph fallback)
    2.  Meta Description (<meta name="description">)
    3.  Keywords (<meta name="keywords">)
    4.  Website Language (<html lang>, Content-Language, visible text)
    5.  Company Name (JSON-LD Organization, OpenGraph, Footer Copyright)
    6.  About Us Page (Discovered via anchor text & normalized hrefs)
    7.  Contact Page (Discovered via anchor text & normalized hrefs)
    8.  Privacy Policy (Discovered via anchor text & normalized hrefs)
    9.  Terms & Conditions (Discovered via anchor text & normalized hrefs)
    10. Refund Policy (Discovered via anchor text & normalized hrefs)
    11. Shipping Policy (Discovered via anchor text & normalized hrefs)
    12. Cookie Policy (Discovered via anchor text & normalized hrefs)
    13. Broken Links (HTTP HEAD/GET status codes on discovered links)
    14. Missing Pages (Categorized list of absent standard policy pages)

IMPORTANT:
    This agent is ONLY an evidence collection agent.
    It does NOT calculate trust scores, risk scores, or classify the website
    as malicious/safe.
"""

import re
import json
import ipaddress
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag

from services.evidence_schema import create_evidence_item, build_agent_result


# ---------------------------------------------------------------------------
# SSRF & Security Validation
# ---------------------------------------------------------------------------

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


def is_safe_public_url(url: str) -> tuple[bool, str]:
    """
    Validate that the URL has an HTTP/HTTPS scheme, is a valid public domain
    with a dot (or public IP), and does not target private IP ranges, loopback
    addresses, or cloud metadata endpoints.
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"

    url = url.strip()
    if not url:
        return False, "Empty URL"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Could not extract hostname from URL"

        hostname = hostname.lower().strip()

        # Check for localhost / loopback aliases
        if hostname in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
            return False, "Targeting localhost or private metadata is forbidden"

        # Must have at least one dot to be a valid public domain or IP
        if "." not in hostname:
            return False, f"Invalid domain name: '{hostname}' contains no domain extension"

        # If hostname is an IP literal, verify it is not in private range
        try:
            ip_obj = ipaddress.ip_address(hostname)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False, f"Targeting private/reserved IP {hostname} is forbidden"
        except ValueError:
            # Not an IP literal, standard hostname
            pass

        return True, "Valid"

    except Exception as e:
        return False, f"URL parse error: {str(e)}"


def normalize_url(url: str) -> str:
    """
    Ensure the URL has a proper scheme and valid structure.
    """
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ---------------------------------------------------------------------------
# HELPER: Company Name Extraction
# ---------------------------------------------------------------------------

def extract_company_name_evidence(soup: BeautifulSoup, base_url: str) -> dict:
    """
    Extract organization / company name with prioritized evidentiary source.

    Source Priority:
        1. JSON-LD Structured Data (Schema.org Organization / Corporation)
        2. OpenGraph site_name metadata
        3. Footer / Copyright pattern match
        4. Meta author tag

    Returns:
        dict: {"value": str | None, "source": str | None}
    """
    # 1. JSON-LD Structured Data
    for script in soup.find_all("script", type="application/ld+json"):
        if not script.string:
            continue
        try:
            ld_data = json.loads(script.string)
            candidates = ld_data if isinstance(ld_data, list) else [ld_data]

            for item in candidates:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("@type", "")
                if item_type in ("Organization", "Corporation", "LocalBusiness", "WebSite", "Store", "OnlineStore"):
                    name = item.get("name")
                    if name and str(name).strip():
                        return {"value": str(name).strip(), "source": "json_ld"}

                # Check nested publisher or author organization
                for sub_key in ("publisher", "author", "creator", "brand"):
                    sub_item = item.get(sub_key)
                    if isinstance(sub_item, dict) and sub_item.get("name"):
                        return {"value": str(sub_item.get("name")).strip(), "source": "json_ld"}
        except Exception:
            pass

    # 2. OpenGraph site_name
    og_site = soup.find("meta", property="og:site_name")
    if og_site and og_site.get("content"):
        content = og_site.get("content").strip()
        if content:
            return {"value": content, "source": "opengraph"}

    # 3. Footer Copyright Information
    copyright_pattern = re.compile(
        r"(?:©|&copy;|copyright|\(c\))\s*(?:\d{4}(?:\s*-\s*\d{4})?)?\s*([A-Za-z0-9\s,\.\-&]{3,60}?)(?:\.|\n|all rights reserved|all rights|$)",
        re.IGNORECASE
    )
    footer = soup.find("footer")
    search_target = footer.get_text(separator=" ", strip=True) if footer else soup.get_text(separator=" ", strip=True)
    match = copyright_pattern.search(search_target)
    if match:
        candidate = match.group(1).strip().strip(",.- ")
        # Filter generic noise
        if len(candidate) > 2 and not candidate.lower().startswith(("all rights", "terms", "privacy", "home")):
            return {"value": candidate, "source": "copyright"}

    # 4. Meta Author Tag
    meta_author = soup.find("meta", attrs={"name": "author"})
    if meta_author and meta_author.get("content"):
        author_val = meta_author.get("content").strip()
        if author_val:
            return {"value": author_val, "source": "meta"}

    return {"value": None, "source": None}


# ---------------------------------------------------------------------------
# HELPER: Language Identification
# ---------------------------------------------------------------------------

def detect_website_language(soup: BeautifulSoup, headers: dict) -> dict:
    """
    Detect primary website language from HTML attributes, Content-Language header, or visible text.

    Returns:
        dict: {"code": str | None, "name": str | None, "source": str | None}
    """
    # 1. Inspect <html lang="...">
    html_tag = soup.find("html")
    if html_tag and html_tag.get("lang"):
        lang_val = html_tag.get("lang").strip()
        if lang_val:
            # e.g. "en-US" -> code: "en", name: "English"
            code = lang_val.split("-")[0].lower()
            name_map = {
                "en": "English", "es": "Spanish", "fr": "French", "de": "German",
                "zh": "Chinese", "ja": "Japanese", "ko": "Korean", "pt": "Portuguese",
                "ru": "Russian", "it": "Italian", "ar": "Arabic", "hi": "Hindi",
                "ml": "Malayalam", "ta": "Tamil", "te": "Telugu", "bn": "Bengali"
            }
            return {
                "code": code,
                "name": name_map.get(code, code.upper()),
                "source": "html_lang"
            }

    # 2. Inspect Content-Language HTTP header
    content_lang = headers.get("Content-Language")
    if content_lang:
        code = content_lang.strip().split(",")[0].split("-")[0].lower()
        return {
            "code": code,
            "name": code.upper(),
            "source": "header"
        }

    # 3. Inspect meta http-equiv="Content-Language"
    meta_lang = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "content-language"})
    if meta_lang and meta_lang.get("content"):
        code = meta_lang.get("content").strip().split("-")[0].lower()
        return {
            "code": code,
            "name": code.upper(),
            "source": "meta_http_equiv"
        }

    return {"code": None, "name": "Unknown", "source": None}


# ---------------------------------------------------------------------------
# HELPER: Policy & Navigation Page Discovery
# ---------------------------------------------------------------------------

def discover_policy_page(soup: BeautifulSoup, base_url: str, keywords: list[str]) -> dict:
    """
    Search anchor tags in the webpage for text or href patterns matching target policy page.

    Returns:
        dict: {"present": bool, "url": str | None}
    """
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc.lower()

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        text = a_tag.get_text(separator=" ", strip=True).lower()
        href_lower = href.lower()

        # Check for keyword matches in text or href
        for kw in keywords:
            kw_clean = kw.lower()
            if kw_clean in text or kw_clean in href_lower:
                # Convert relative to absolute and strip fragment
                full_url = urljoin(base_url, href)
                clean_url, _ = urldefrag(full_url)
                if clean_url.startswith(("http://", "https://")):
                    return {
                        "present": True,
                        "url": clean_url
                    }

    return {
        "present": False,
        "url": None
    }


# ---------------------------------------------------------------------------
# HELPER: Broken Links Testing
# ---------------------------------------------------------------------------

def test_internal_links(soup: BeautifulSoup, base_url: str, max_links_to_test: int = 8) -> tuple[list[dict], int]:
    """
    Extract internal links from the webpage and verify their HTTP reachability.

    Returns:
        tuple: (broken_links: list[dict], total_links_checked: int)
    """
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc.lower()

    discovered_urls = set()

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        full_url = urljoin(base_url, href)
        clean_url, _ = urldefrag(full_url)
        parsed_link = urlparse(clean_url)

        # Focus primarily on internal same-domain links
        if parsed_link.netloc.lower() == base_domain and clean_url != base_url:
            discovered_urls.add(clean_url)
            if len(discovered_urls) >= max_links_to_test:
                break

    broken_links = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DigitalForensicsAgent/1.0"
    }

    links_checked = 0
    for link in discovered_urls:
        links_checked += 1
        try:
            resp = requests.head(link, timeout=2.0, headers=headers, allow_redirects=True)
            if resp.status_code >= 400:
                # Retry with GET in case server rejects HEAD
                try:
                    resp_get = requests.get(link, timeout=2.0, headers=headers, allow_redirects=True, stream=True)
                    if resp_get.status_code >= 400:
                        broken_links.append({
                            "url": link,
                            "status_code": resp_get.status_code,
                            "reason": resp_get.reason or f"HTTP {resp_get.status_code}"
                        })
                except Exception:
                    broken_links.append({
                        "url": link,
                        "status_code": resp.status_code,
                        "reason": resp.reason or f"HTTP {resp.status_code}"
                    })
        except requests.exceptions.RequestException as e:
            broken_links.append({
                "url": link,
                "status_code": "Error",
                "reason": str(e)
            })

    return broken_links, links_checked


# ---------------------------------------------------------------------------
# MAIN FUNCTION: analyze_content / get_website_content
# ---------------------------------------------------------------------------

def analyze_content(url: str) -> dict:
    """
    Agent 4 — Website Content Analysis: Main evidence collection function.

    Fetches webpage HTML, parses document title, metadata, keywords, language,
    company identity, discovers essential policy pages (About Us, Contact,
    Privacy, Terms, Refund, Shipping, Cookie), tests internal links for HTTP
    errors, and categorizes missing standard pages.

    This function is an EVIDENCE COLLECTION AGENT only.
    It does NOT calculate trust scores, risk scores, or classify
    the website as malicious or safe.

    Args:
        url: Any target URL string (e.g. "https://www.example.com/shop")

    Returns:
        dict: Complete structured website content evidence.
    """
    print(f"[Agent 4] Starting website content analysis for: {url}")
    errors = []

    # Initialize structured default data with exact requested schema
    data = {
        "url": url,
        "final_url": "Not Available",
        "access_status": "not_attempted",
        "content_access": "none",
        "page_title": {
            "value": None,
            "present": False
        },
        "meta_description": {
            "value": None,
            "present": False
        },
        "keywords": {
            "values": [],
            "present": False
        },
        "language": {
            "code": None,
            "name": "Unknown",
            "source": None
        },
        "company_name": {
            "value": None,
            "source": None
        },
        "about_page": {
            "present": False,
            "url": None
        },
        "contact_page": {
            "present": False,
            "url": None
        },
        "privacy_policy": {
            "present": False,
            "url": None
        },
        "terms_conditions": {
            "present": False,
            "url": None
        },
        "refund_policy": {
            "present": False,
            "url": None
        },
        "shipping_policy": {
            "present": False,
            "url": None
        },
        "cookie_policy": {
            "present": False,
            "url": None
        },
        "broken_links": [],
        "missing_pages": [],
        "links_checked": 0
    }

    # Step 1: Validate URL & Prevent SSRF
    is_safe, safety_msg = is_safe_public_url(url)
    if not is_safe:
        print(f"[Agent 4] Error: URL validation failed ({safety_msg}).")
        data["access_status"] = "invalid_url"
        errors.append(f"Invalid or restricted URL: {safety_msg}")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }

    target_url = normalize_url(url)
    data["url"] = target_url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 DigitalForensicsAgent/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }

    # Step 2: Fetch Webpage HTML
    print(f"[Agent 4] Fetching webpage HTML from: {target_url}...")
    response = None
    try:
        response = requests.get(
            target_url,
            timeout=10,
            headers=headers,
            allow_redirects=True
        )
        data["final_url"] = response.url
        print(f"[Agent 4] HTTP status: {response.status_code} (Final URL: {response.url})")

        if response.status_code == 200:
            data["access_status"] = "accessible"
            data["content_access"] = "full"
        elif response.status_code in (403, 401):
            data["access_status"] = "blocked"
            data["content_access"] = "partial"
            errors.append(f"Access restricted by web server (HTTP {response.status_code})")
        elif response.status_code == 429:
            data["access_status"] = "rate_limited"
            data["content_access"] = "partial"
            errors.append("HTTP 429: Rate limited by server")
        elif response.status_code == 404:
            data["access_status"] = "not_found"
            errors.append("HTTP 404: Webpage not found")
        else:
            data["access_status"] = f"http_{response.status_code}"
            errors.append(f"Webpage returned non-200 HTTP status code: {response.status_code}")

    except requests.exceptions.Timeout:
        data["access_status"] = "timeout"
        errors.append("Webpage request timed out after 10 seconds.")
        print("[Agent 4] Request timed out.")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }
    except requests.exceptions.ConnectionError as e:
        data["access_status"] = "connection_failed"
        errors.append(f"Connection failed: {str(e)}")
        print(f"[Agent 4] Connection failed: {e}")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }
    except requests.exceptions.RequestException as e:
        data["access_status"] = "request_failed"
        errors.append(f"Failed to fetch webpage: {str(e)}")
        print(f"[Agent 4] Request exception: {e}")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }

    # Step 3: Parse HTML with BeautifulSoup
    print("[Agent 4] Parsing HTML content...")
    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        errors.append(f"HTML parser error: {str(e)}")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }

    # Check if page is minimal JS shell
    text_content = soup.get_text(strip=True)
    if len(text_content) < 50 and "<script" in response.text:
        data["content_access"] = "javascript_required"

    # Step 4: Page Title
    print("[Agent 4] Extracting page title...")
    title_tag = soup.find("title")
    if title_tag and title_tag.string and title_tag.string.strip():
        data["page_title"] = {
            "value": title_tag.string.strip(),
            "present": True
        }
        print(f"[Agent 4] Title found: {data['page_title']['value']}")
    else:
        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content") and og_title.get("content").strip():
            data["page_title"] = {
                "value": og_title.get("content").strip(),
                "present": True
            }
            print(f"[Agent 4] Title found (OpenGraph): {data['page_title']['value']}")

    # Step 5: Meta Description
    print("[Agent 4] Extracting meta description...")
    meta_desc = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "description"}) or soup.find("meta", property="og:description")
    if meta_desc and meta_desc.get("content") and meta_desc.get("content").strip():
        data["meta_description"] = {
            "value": meta_desc.get("content").strip(),
            "present": True
        }
        print(f"[Agent 4] Meta description found: {data['meta_description']['value'][:60]}...")

    # Step 6: Meta Keywords
    meta_kw = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "keywords"})
    if meta_kw and meta_kw.get("content") and meta_kw.get("content").strip():
        raw_kws = [k.strip() for k in meta_kw.get("content").split(",") if k.strip()]
        data["keywords"] = {
            "values": raw_kws,
            "present": len(raw_kws) > 0
        }
        print(f"[Agent 4] Keywords found: {len(raw_kws)} keywords")

    # Step 7: Language Detection
    print("[Agent 4] Detecting language...")
    data["language"] = detect_website_language(soup, response.headers)
    print(f"[Agent 4] Language detected: {data['language']['name']} ({data['language']['code']})")

    # Step 8: Company Name Detection
    print("[Agent 4] Detecting company information...")
    data["company_name"] = extract_company_name_evidence(soup, target_url)
    if data["company_name"]["value"]:
        print(f"[Agent 4] Company Name: {data['company_name']['value']} (Source: {data['company_name']['source']})")

    # Step 9: Important Policy Pages Discovery
    print("[Agent 4] Discovering important pages...")
    data["about_page"] = discover_policy_page(soup, target_url, ["about", "about-us", "who-we-are", "our-company", "company"])
    data["contact_page"] = discover_policy_page(soup, target_url, ["contact", "contact-us", "get-in-touch", "reach-us", "support", "help"])
    data["privacy_policy"] = discover_policy_page(soup, target_url, ["privacy", "privacy-policy", "privacy-notice", "privacypolicy", "legal/privacy"])
    data["terms_conditions"] = discover_policy_page(soup, target_url, ["terms", "terms-and-conditions", "terms-of-service", "terms-of-use", "tos", "legal/terms"])
    data["refund_policy"] = discover_policy_page(soup, target_url, ["refund", "refund-policy", "return-policy", "returns", "cancellation", "returns-and-refunds"])
    data["shipping_policy"] = discover_policy_page(soup, target_url, ["shipping", "shipping-policy", "delivery", "delivery-policy", "dispatch"])
    data["cookie_policy"] = discover_policy_page(soup, target_url, ["cookie", "cookie-policy", "cookies", "cookie-notice", "legal/cookies"])

    # Step 10: Identify Missing Pages
    standard_page_checks = [
        ("about_page", data["about_page"]["present"]),
        ("contact_page", data["contact_page"]["present"]),
        ("privacy_policy", data["privacy_policy"]["present"]),
        ("terms_conditions", data["terms_conditions"]["present"]),
        ("refund_policy", data["refund_policy"]["present"]),
        ("shipping_policy", data["shipping_policy"]["present"]),
        ("cookie_policy", data["cookie_policy"]["present"])
    ]
    missing_list = [page_key for page_key, present in standard_page_checks if not present]
    data["missing_pages"] = missing_list

    # Step 11: Broken Links Testing
    print("[Agent 4] Checking links for broken link detection...")
    broken_links, checked_count = test_internal_links(soup, target_url, max_links_to_test=30)
    data["broken_links"] = broken_links
    data["links_checked"] = checked_count
    print(f"[Agent 4] Links checked: {checked_count}, Broken links found: {len(broken_links)}")

    # Step 12: Compile structured evidence items
    is_antibot = (
        response.status_code == 403
        or any(k in (data["page_title"].get("value") or "").lower() for k in ["recaptcha", "just a moment", "challenge", "attention required", "blocked", "captcha"])
    )

    evidence = []
    if data["page_title"].get("present"):
        evidence.append(create_evidence_item(
            agent_id="A4", index=1, finding="Webpage title", value=data["page_title"].get("value"),
            severity="info", source="Website HTML", evidence_type="deterministic",
            metadata=data["page_title"], category="meta_title_present"
        ))
    if data["meta_description"].get("present"):
        evidence.append(create_evidence_item(
            agent_id="A4", index=2, finding="Meta description", value=data["meta_description"].get("value"),
            severity="info", source="Website HTML", evidence_type="deterministic",
            metadata=data["meta_description"], category="meta_description_present"
        ))
    if data["language"].get("name"):
        evidence.append(create_evidence_item(
            agent_id="A4", index=3, finding="Detected website language", value=data["language"].get("name"),
            severity="info", source="Website HTML", evidence_type="deterministic",
            metadata=data["language"], category="page_language_detected"
        ))
    if data["company_name"].get("value"):
        evidence.append(create_evidence_item(
            agent_id="A4", index=4, finding="Extracted company name", value=data["company_name"].get("value"),
            severity="info", source="Website HTML", evidence_type="deterministic",
            metadata=data["company_name"], category="business_identity_declared"
        ))
    if data["missing_pages"]:
        if is_antibot:
            evidence.append(create_evidence_item(
                agent_id="A4", index=5, finding="Anti-bot / crawler challenge page encountered during fetch",
                value="Anti-bot challenge response", severity="info", source="Website HTML",
                evidence_type="deterministic", category="cookie_banner_present"
            ))
        else:
            evidence.append(create_evidence_item(
                agent_id="A4", index=5, finding="Missing standard policy pages", value=data["missing_pages"],
                severity="info", source="Website HTML", evidence_type="deterministic",
                category="meta_description_present"
            ))
    evidence.append(create_evidence_item(
        agent_id="A4", index=6, finding="Broken internal links count", value=len(data["broken_links"]),
        severity="low" if (data["broken_links"] and not is_antibot) else "info",
        source="Website HTML", evidence_type="deterministic",
        metadata={"broken_links": data["broken_links"], "links_checked": data.get("links_checked", 0)},
        category="clean_static_scripts" if not data["broken_links"] else "content_length_normal"
    ))

    # Determine overall status
    if response.status_code == 200 and data["page_title"]["present"]:
        overall_status = "success" if not errors else "partial"
    elif response.status_code == 200:
        overall_status = "partial"
    else:
        overall_status = "error"

    print(f"[Agent 4] Analysis completed. Status: {overall_status}")

    return build_agent_result(
        agent_identifier="A4",
        target=url,
        status=overall_status,
        data=data,
        evidence=evidence,
        errors=errors
    )


def get_website_content(url: str) -> dict:
    """
    Compatibility wrapper returning website content analysis evidence.
    """
    return analyze_content(url)
