"""
Agent 13 — External Presence / OSINT Agent
Evidence collection and OSINT correlation module for investigating
publicly available information outside the target website.

Collects and correlates:
1. LinkedIn Company / Profile Presence
2. Facebook Public Page
3. X / Twitter Presence
4. Instagram Public Account
5. GitHub Presence (when relevant)
6. Reddit Mentions & Sentiment Context
7. News Articles & Media Coverage
8. Public Reviews (Trustpilot, BBB, etc.)
9. Forum Discussions & Consumer Threads

Strictly passive forensic evidence collection.
DO NOT calculate final Trust Score or declare legitimate/scam.
"""

import datetime
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlparse
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable constants & limits
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2MB HTML limit
REQUEST_TIMEOUT = 10                   # 10 seconds timeout
SEARCH_TIMEOUT = 8                     # 8 seconds for OSINT search queries

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Software / tech keywords for GitHub relevance
TECH_RELEVANCE_KEYWORDS = {
    "software", "github", "api", "sdk", "developer", "open source",
    "code", "programming", "python", "javascript", "cloud", "saas",
    "devops", "platform", "framework", "library", "repository"
}

# Context classification patterns for mentions and discussions
CONTEXT_PATTERNS = {
    "scam_allegation": [
        r"\b(?:scam|fraud|phishing|fake|stole|rip[\s-]?off|con\s+artist|counterfeit|impersonator)\b",
        r"\b(?:beware\s+of|avoid\s+this|do\s+not\s+buy|scammed\s+me)\b"
    ],
    "complaint": [
        r"\b(?:complaint|terrible|awful|poor\s+service|delayed|broken|never\s+arrived|bad\s+experience|refund\s+denied)\b",
        r"\b(?:horrible|unresponsive|worst|damaged|overcharged)\b"
    ],
    "warning": [
        r"\b(?:warning|caution|suspicious|shady|red\s+flag|heads\s+up|be\s+careful)\b"
    ],
    "recommendation": [
        r"\b(?:recommend|excellent|great\s+experience|love\s+it|legit|amazing|top\s+notch|reliable|trusted)\b",
        r"\b(?:best\s+service|works\s+great|satisfied|positive\s+review)\b"
    ],
    "question": [
        r"\b(?:is\s+it\s+legit|anyone\s+used|has\s+anyone\s+tried|is\s+this\s+safe|thoughts\s+on|legit\?|safe\?)\b"
    ],
    "review": [
        r"\b(?:review|rated|stars|feedback|rating|score|testimonial)\b"
    ],
}


# =====================================================================
# 1. HELPER UTILITIES & TARGET IDENTITY RESOLVER
# =====================================================================

def _normalize_url(url: str) -> str:
    """Normalize input URL to include scheme."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def _extract_registered_domain(url: str) -> str:
    """Safely extract registered domain name."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
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


def _fetch_webpage_safe(url: str, session: requests.Session) -> Tuple[Optional[str], Optional[str], Optional[BeautifulSoup], List[str]]:
    """Fetch target webpage safely to extract base identity signals."""
    errors = []
    try:
        resp = session.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            verify=True,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        try:
            resp = session.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            errors.append(f"HTTP connection failed: {str(e)}")
            return None, url, None, errors
    except requests.exceptions.Timeout:
        errors.append(f"Webpage request timed out after {REQUEST_TIMEOUT}s")
        return None, url, None, errors
    except Exception as e:
        errors.append(f"Failed to fetch webpage: {str(e)}")
        return None, url, None, errors

    final_url = resp.url or url
    try:
        content_chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=8192):
            content_chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded >= MAX_HTML_SIZE:
                errors.append(f"HTML response exceeded {MAX_HTML_SIZE} bytes; truncated")
                break
        html_bytes = b"".join(content_chunks)
        encoding = resp.encoding or "utf-8"
        html_text = html_bytes.decode(encoding, errors="replace")
        soup = BeautifulSoup(html_text, "html.parser")
        return html_text, final_url, soup, errors
    except Exception as e:
        errors.append(f"Error reading HTML response: {str(e)}")
        return None, final_url, None, errors


def _extract_target_identity(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str],
    domain: str,
    final_url: str
) -> Tuple[Dict[str, Any], Dict[str, str], bool]:
    """
    Extract declared website identity, on-page social links, and tech relevance.
    Returns (identity_dict, on_page_socials_dict, is_tech_relevant).
    """
    identity = {
        "company_name": None,
        "brand_name": None,
        "domain": domain,
        "website_title": None,
        "country": None,
        "location": None,
        "email_domains": [domain] if domain else [],
    }
    on_page_socials: Dict[str, str] = {}
    is_tech_relevant = False

    if not soup:
        # Fallback to domain root as brand
        parts = domain.split(".") if domain else []
        if parts:
            identity["brand_name"] = parts[0].capitalize()
            identity["company_name"] = parts[0].capitalize()
        return identity, on_page_socials, is_tech_relevant

    # 1. Page Title
    if soup.title and soup.title.string:
        clean_title = soup.title.string.strip()
        identity["website_title"] = clean_title
        parts = re.split(r"[-|•–—]", clean_title)
        if len(parts) >= 2:
            candidate = parts[-1].strip() if len(parts[-1].strip()) < len(parts[0].strip()) else parts[0].strip()
            if len(candidate) > 2:
                identity["company_name"] = candidate
        else:
            identity["company_name"] = clean_title

    # 2. Schema.org JSON-LD
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            raw_json = script.string or script.get_text()
            if not raw_json:
                continue
            data = json.loads(raw_json)
            items = data if isinstance(data, list) else data.get("@graph", [data]) if isinstance(data, dict) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                stype = str(item.get("@type") or "").lower()
                if any(t in stype for t in ["organization", "corporation", "localbusiness"]):
                    name = item.get("name") or item.get("legalName")
                    if name and isinstance(name, str) and len(name.strip()) > 2:
                        identity["company_name"] = name.strip()
                        identity["brand_name"] = name.strip()
                    addr = item.get("address")
                    if isinstance(addr, dict):
                        country = addr.get("addressCountry")
                        locality = addr.get("addressLocality")
                        region = addr.get("addressRegion")
                        if country:
                            identity["country"] = str(country)
                        loc_parts = [p for p in [locality, region, country] if p]
                        if loc_parts:
                            identity["location"] = ", ".join(loc_parts)
                    # Also check sameAs social links
                    same_as = item.get("sameAs")
                    if isinstance(same_as, list):
                        for sa in same_as:
                            if isinstance(sa, str):
                                _map_social_url(sa, on_page_socials)
                    elif isinstance(same_as, str):
                        _map_social_url(same_as, on_page_socials)
        except Exception:
            pass

    # 3. Footer Copyright
    footer = soup.find("footer")
    if footer:
        footer_text = footer.get_text(separator=" ", strip=True)
        m = re.search(r"(?:©|copyright|&copy;)\s*(?:\d{4})?\s*([A-Za-z0-9\s.,&-]+?)(?:\.|\s+all\s+rights|\s+inc|\s+ltd|\s+pvt|\s*$)", footer_text, re.IGNORECASE)
        if m and not identity["company_name"]:
            cand = m.group(1).strip().rstrip(".,")
            if 2 < len(cand) < 60:
                identity["company_name"] = cand

    # 4. OpenGraph Site Name / Meta Brand
    og_name = soup.find("meta", property="og:site_name")
    if og_name and og_name.get("content"):
        identity["brand_name"] = og_name["content"].strip()
        if not identity["company_name"]:
            identity["company_name"] = identity["brand_name"]

    # 5. Extract On-Page Social Links
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        _map_social_url(href, on_page_socials)

    # 6. Fallback brand if None
    if not identity["brand_name"] and identity["company_name"]:
        identity["brand_name"] = identity["company_name"]
    elif not identity["company_name"] and domain:
        root_name = domain.split(".")[0].replace("-", " ").capitalize()
        identity["company_name"] = root_name
        identity["brand_name"] = root_name

    # 7. Check Tech Relevance
    full_text = (html_text or "").lower()
    tech_count = sum(1 for kw in TECH_RELEVANCE_KEYWORDS if kw in full_text)
    is_tech_relevant = tech_count >= 2

    return identity, on_page_socials, is_tech_relevant


def _map_social_url(url: str, socials_dict: Dict[str, str]) -> None:
    """Classify and record public social media URLs."""
    if not url or not isinstance(url, str):
        return
    low = url.lower()
    if "linkedin.com/company/" in low or "linkedin.com/in/" in low:
        socials_dict.setdefault("linkedin", url)
    elif "facebook.com/" in low and not any(x in low for x in ["sharer", "share.php"]):
        socials_dict.setdefault("facebook", url)
    elif ("twitter.com/" in low or "x.com/" in low) and "intent/" not in low:
        socials_dict.setdefault("x_twitter", url)
    elif "instagram.com/" in low and not any(x in low for x in ["/p/", "/reel/"]):
        socials_dict.setdefault("instagram", url)
    elif "github.com/" in low:
        socials_dict.setdefault("github", url)


# =====================================================================
# 2. PUBLIC OSINT SEARCH ENGINE INTERFACE
# =====================================================================

def execute_public_search(query: str, session: Optional[requests.Session] = None) -> List[Dict[str, str]]:
    """
    Safely execute a public search query and extract result links, titles, and snippets.
    Provides structured results for OSINT correlation without violating TOS or logging in.
    """
    results: List[Dict[str, str]] = []
    if not query or not query.strip():
        return results

    if session is None:
        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)

    # Use DuckDuckGo HTML endpoint for passive public OSINT
    search_url = "https://html.duckduckgo.com/html/"
    try:
        resp = session.post(
            search_url,
            data={"q": query.strip()},
            headers={
                **DEFAULT_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://html.duckduckgo.com/",
            },
            timeout=SEARCH_TIMEOUT,
        )
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for result_div in soup.find_all("div", class_=re.compile(r"result\b|results_links")):
                link_tag = result_div.find("a", class_=re.compile(r"result__snippet|result__url|result__title"))
                title_tag = result_div.find("a", class_="result__a") or result_div.find("h2")
                snippet_tag = result_div.find("a", class_="result__snippet") or result_div.find("div", class_="result__snippet")

                if title_tag and title_tag.get("href"):
                    raw_href = title_tag["href"]
                    # Unpack DDG redirect wrapper if present
                    if "uddg=" in raw_href:
                        parsed_href = parse_qs(urlparse(raw_href).query)
                        actual_url = unquote(parsed_href.get("uddg", [raw_href])[0])
                    else:
                        actual_url = raw_href

                    title_text = title_tag.get_text(separator=" ", strip=True)
                    snippet_text = snippet_tag.get_text(separator=" ", strip=True) if snippet_tag else ""

                    results.append({
                        "url": actual_url,
                        "title": title_text,
                        "snippet": snippet_text,
                    })
    except Exception:
        # Gracefully handle search timeouts/blocks in passive mode
        pass

    return results


# =====================================================================
# 3. IDENTITY CORRELATION & DISAMBIGUATION ENGINE
# =====================================================================

def _correlate_identity_match(
    target_name: Optional[str],
    target_domain: str,
    target_country: Optional[str],
    candidate_name: Optional[str],
    candidate_url: Optional[str],
    candidate_snippet: Optional[str] = ""
) -> Tuple[str, bool, Optional[bool]]:
    """
    Evaluate how strongly an external OSINT candidate matches the claimed identity.
    Returns (identity_match: 'high'|'medium'|'low'|'mismatch'|'unknown', website_match: bool, location_match: bool|None).
    """
    if not candidate_url and not candidate_name:
        return "unknown", False, None

    website_match = False
    location_match = None
    full_text = f"{candidate_name or ''} {candidate_snippet or ''} {candidate_url or ''}".lower()

    # 1. Domain match check
    if target_domain and target_domain in (candidate_snippet or "").lower():
        website_match = True
    elif target_domain and candidate_url and target_domain in candidate_url.lower():
        website_match = True

    # 2. Location match check
    if target_country:
        if target_country.lower() in full_text:
            location_match = True
        elif any(c in full_text for c in ["usa", "united states", "india", "uk", "germany", "singapore", "canada", "australia"]):
            # Detected another specific country differing from target country
            location_match = False

    # 3. Name similarity check
    clean_target = re.sub(r"[^a-zA-Z0-9\s]", "", (target_name or "").lower()).strip()
    clean_cand = re.sub(r"[^a-zA-Z0-9\s]", "", (candidate_name or "").lower()).strip()

    name_matched = False
    if clean_target and clean_cand:
        if clean_target in clean_cand or clean_cand in clean_target:
            name_matched = True
        else:
            target_words = set(clean_target.split())
            cand_words = set(clean_cand.split())
            if target_words and len(target_words & cand_words) >= min(len(target_words), 2):
                name_matched = True

    # 4. Final Disambiguation & Match Classification
    if website_match and name_matched:
        if location_match is False:
            return "medium", website_match, location_match
        return "high", website_match, location_match
    elif website_match and not name_matched:
        return "medium", website_match, location_match
    elif name_matched and not website_match:
        if location_match is True:
            return "medium", website_match, location_match
        elif location_match is False:
            return "mismatch", website_match, location_match
        return "low", website_match, location_match
    elif not name_matched and not website_match:
        if candidate_url:
            return "mismatch", False, location_match
        return "unknown", False, location_match

    return "unknown", False, location_match


# =====================================================================
# 4. PLATFORM-SPECIFIC OSINT SEARCH MODULES
# =====================================================================

def _investigate_linkedin(
    identity: Dict[str, Any],
    on_page_socials: Dict[str, str],
    search_fn: Any
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Search and correlate LinkedIn company/profile presence."""
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    res = {
        "detected": False,
        "profile_url": None,
        "name": None,
        "website_match": False,
        "location_match": None,
        "identity_match": "unknown",
        "source": "public search",
    }

    # 1. On-page seed link
    if "linkedin" in on_page_socials:
        url = on_page_socials["linkedin"]
        res["detected"] = True
        res["profile_url"] = url
        res["source"] = "official_social_profile"
        match_level, web_m, loc_m = _correlate_identity_match(
            identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
            identity.get("company_name"), url, ""
        )
        res["identity_match"] = "mismatch" if match_level == "mismatch" else "high"
        res["website_match"] = True
        res["location_match"] = loc_m
        evidence_list.append(f"LinkedIn presence verified via website social profile link: {url}")
        trace_evidence.append({
            "type": "linkedin_presence",
            "claim": f"{identity.get('company_name', 'Website')} links to LinkedIn profile",
            "source_url": url,
            "source_type": "official_social_profile",
            "identity_match": res["identity_match"],
            "domain_match": True,
        })
        return res, trace_evidence, evidence_list

    # 2. Public OSINT Search
    query = f"site:linkedin.com/company \"{identity.get('company_name') or identity.get('domain')}\""
    search_results = search_fn(query)
    if not search_results and identity.get("domain"):
        search_results = search_fn(f"site:linkedin.com {identity.get('domain')}")

    for cand in search_results:
        url = cand.get("url", "")
        if "linkedin.com/company/" in url or "linkedin.com/in/" in url:
            res["detected"] = True
            res["profile_url"] = url
            res["name"] = cand.get("title", "").split("|")[0].replace("- LinkedIn", "").strip()
            match_level, web_m, loc_m = _correlate_identity_match(
                identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
                res["name"], url, cand.get("snippet", "")
            )
            res["identity_match"] = match_level
            res["website_match"] = web_m
            res["location_match"] = loc_m
            evidence_list.append(f"LinkedIn public company result found: {url} (Identity match: {match_level})")
            trace_evidence.append({
                "type": "linkedin_presence",
                "claim": f"LinkedIn page discovered for {res['name']}",
                "source_url": url,
                "source_type": "search_result",
                "identity_match": match_level,
                "domain_match": web_m,
            })
            break

    return res, trace_evidence, evidence_list


def _investigate_facebook(
    identity: Dict[str, Any],
    on_page_socials: Dict[str, str],
    search_fn: Any
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Search and correlate Facebook public page."""
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    res = {
        "detected": False,
        "page_url": None,
        "page_name": None,
        "website_match": False,
        "identity_match": "unknown",
    }

    if "facebook" in on_page_socials:
        url = on_page_socials["facebook"]
        res["detected"] = True
        res["page_url"] = url
        res["page_name"] = identity.get("company_name")
        res["website_match"] = True
        res["identity_match"] = "high"
        evidence_list.append(f"Facebook page verified via website link: {url}")
        trace_evidence.append({
            "type": "facebook_presence",
            "claim": f"Official Facebook page linked: {url}",
            "source_url": url,
            "source_type": "official_social_profile",
            "identity_match": "high",
            "domain_match": True,
        })
        return res, trace_evidence, evidence_list

    query = f"site:facebook.com \"{identity.get('company_name') or identity.get('domain')}\""
    search_results = search_fn(query)
    for cand in search_results:
        url = cand.get("url", "")
        if "facebook.com/" in url and not any(x in url for x in ["/sharer", "/share", "/dialog/"]):
            res["detected"] = True
            res["page_url"] = url
            res["page_name"] = cand.get("title", "").replace("- Facebook", "").replace("| Facebook", "").strip()
            match_level, web_m, _ = _correlate_identity_match(
                identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
                res["page_name"], url, cand.get("snippet", "")
            )
            res["identity_match"] = match_level
            res["website_match"] = web_m
            evidence_list.append(f"Facebook public page discovered: {url} (Identity match: {match_level})")
            trace_evidence.append({
                "type": "facebook_presence",
                "claim": f"Facebook page candidate: {res['page_name']}",
                "source_url": url,
                "source_type": "search_result",
                "identity_match": match_level,
                "domain_match": web_m,
            })
            break

    return res, trace_evidence, evidence_list


def _investigate_twitter(
    identity: Dict[str, Any],
    on_page_socials: Dict[str, str],
    search_fn: Any
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Search and correlate X / Twitter public presence."""
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    res = {
        "detected": False,
        "username": None,
        "profile_url": None,
        "website_match": False,
        "identity_match": "unknown",
    }

    if "x_twitter" in on_page_socials:
        url = on_page_socials["x_twitter"]
        m = re.search(r"(?:twitter|x)\.com/([^/?#\s]+)", url)
        username = m.group(1) if m else None
        res["detected"] = True
        res["profile_url"] = url
        res["username"] = username
        res["website_match"] = True
        res["identity_match"] = "high"
        evidence_list.append(f"X / Twitter profile verified via website link: @{username or url}")
        trace_evidence.append({
            "type": "x_twitter_presence",
            "claim": f"Official X/Twitter account linked: @{username}",
            "source_url": url,
            "source_type": "official_social_profile",
            "identity_match": "high",
            "domain_match": True,
        })
        return res, trace_evidence, evidence_list

    query = f"site:twitter.com \"{identity.get('company_name') or identity.get('domain')}\""
    search_results = search_fn(query)
    for cand in search_results:
        url = cand.get("url", "")
        if "twitter.com/" in url or "x.com/" in url:
            m = re.search(r"(?:twitter|x)\.com/([^/?#\s]+)", url)
            username = m.group(1) if m else None
            if username and username.lower() not in ["home", "search", "explore", "hashtag"]:
                res["detected"] = True
                res["profile_url"] = url
                res["username"] = username
                match_level, web_m, _ = _correlate_identity_match(
                    identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
                    cand.get("title", ""), url, cand.get("snippet", "")
                )
                res["identity_match"] = match_level
                res["website_match"] = web_m
                evidence_list.append(f"X / Twitter account found: @{username} (Identity match: {match_level})")
                trace_evidence.append({
                    "type": "x_twitter_presence",
                    "claim": f"X/Twitter candidate found: @{username}",
                    "source_url": url,
                    "source_type": "search_result",
                    "identity_match": match_level,
                    "domain_match": web_m,
                })
                break

    return res, trace_evidence, evidence_list


def _investigate_instagram(
    identity: Dict[str, Any],
    on_page_socials: Dict[str, str],
    search_fn: Any
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Search and correlate Instagram public profile."""
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    res = {
        "detected": False,
        "username": None,
        "profile_url": None,
        "website_match": False,
        "identity_match": "unknown",
    }

    if "instagram" in on_page_socials:
        url = on_page_socials["instagram"]
        m = re.search(r"instagram\.com/([^/?#\s]+)", url)
        username = m.group(1) if m else None
        res["detected"] = True
        res["profile_url"] = url
        res["username"] = username
        res["website_match"] = True
        res["identity_match"] = "high"
        evidence_list.append(f"Instagram account verified via website link: @{username or url}")
        trace_evidence.append({
            "type": "instagram_presence",
            "claim": f"Official Instagram profile linked: @{username}",
            "source_url": url,
            "source_type": "official_social_profile",
            "identity_match": "high",
            "domain_match": True,
        })
        return res, trace_evidence, evidence_list

    query = f"site:instagram.com \"{identity.get('company_name') or identity.get('domain')}\""
    search_results = search_fn(query)
    for cand in search_results:
        url = cand.get("url", "")
        if "instagram.com/" in url and not any(x in url for x in ["/p/", "/reel/", "/explore/"]):
            m = re.search(r"instagram\.com/([^/?#\s]+)", url)
            username = m.group(1) if m else None
            if username:
                res["detected"] = True
                res["profile_url"] = url
                res["username"] = username
                match_level, web_m, _ = _correlate_identity_match(
                    identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
                    cand.get("title", ""), url, cand.get("snippet", "")
                )
                res["identity_match"] = match_level
                res["website_match"] = web_m
                evidence_list.append(f"Instagram profile discovered: @{username} (Identity match: {match_level})")
                trace_evidence.append({
                    "type": "instagram_presence",
                    "claim": f"Instagram profile candidate: @{username}",
                    "source_url": url,
                    "source_type": "search_result",
                    "identity_match": match_level,
                    "domain_match": web_m,
                })
                break

    return res, trace_evidence, evidence_list


def _investigate_github(
    identity: Dict[str, Any],
    on_page_socials: Dict[str, str],
    is_tech_relevant: bool,
    search_fn: Any
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Search and correlate GitHub public organization/repository presence."""
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    res = {
        "relevant": is_tech_relevant,
        "detected": False,
        "organization_url": None,
        "website_match": False,
        "identity_match": "unknown",
    }

    if "github" in on_page_socials:
        url = on_page_socials["github"]
        res["relevant"] = True
        res["detected"] = True
        res["organization_url"] = url
        res["website_match"] = True
        res["identity_match"] = "high"
        evidence_list.append(f"GitHub organization verified via website link: {url}")
        trace_evidence.append({
            "type": "github_presence",
            "claim": f"Official GitHub repository/org linked: {url}",
            "source_url": url,
            "source_type": "official_social_profile",
            "identity_match": "high",
            "domain_match": True,
        })
        return res, trace_evidence, evidence_list

    if not is_tech_relevant:
        return res, trace_evidence, evidence_list

    query = f"site:github.com \"{identity.get('company_name') or identity.get('domain')}\""
    search_results = search_fn(query)
    for cand in search_results:
        url = cand.get("url", "")
        if "github.com/" in url and not any(x in url for x in ["/site/", "/topics/", "/explore"]):
            res["detected"] = True
            res["organization_url"] = url
            match_level, web_m, _ = _correlate_identity_match(
                identity.get("company_name"), identity.get("domain", ""), identity.get("country"),
                cand.get("title", ""), url, cand.get("snippet", "")
            )
            res["identity_match"] = match_level
            res["website_match"] = web_m
            evidence_list.append(f"GitHub organization found: {url} (Identity match: {match_level})")
            trace_evidence.append({
                "type": "github_presence",
                "claim": f"GitHub org found for {identity.get('company_name')}",
                "source_url": url,
                "source_type": "search_result",
                "identity_match": match_level,
                "domain_match": web_m,
            })
            break

    return res, trace_evidence, evidence_list


def _investigate_reddit(
    identity: Dict[str, Any],
    search_fn: Any
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Search and extract Reddit public mentions, subreddits, and context."""
    reddit_mentions: List[Dict[str, Any]] = []
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    domain = identity.get("domain", "")
    company = identity.get("company_name") or ""
    query = f"site:reddit.com \"{domain}\"" if domain else f"site:reddit.com \"{company}\""

    search_results = search_fn(query)
    if not search_results and company and company != domain:
        search_results = search_fn(f"site:reddit.com \"{company}\"")

    for cand in search_results[:8]:
        url = cand.get("url", "")
        if "reddit.com/r/" in url:
            title = cand.get("title", "").replace("- Reddit", "").replace("| Reddit", "").strip()
            snippet = cand.get("snippet", "")
            full_text = f"{title} {snippet}".lower()

            # Extract subreddit name
            m_sub = re.search(r"reddit\.com/r/([^/?#\s]+)", url)
            subreddit = m_sub.group(1) if m_sub else "reddit"

            # Classify context
            context = "discussion"
            for ctx_name, patterns in CONTEXT_PATTERNS.items():
                if any(re.search(p, full_text) for p in patterns):
                    context = ctx_name
                    break

            # Attempt date extraction from snippet
            date_match = re.search(r"\b(20[12]\d[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))\b", snippet)
            pub_date = date_match.group(1) if date_match else None

            mention_obj = {
                "platform": "Reddit",
                "subreddit": f"r/{subreddit}",
                "url": url,
                "title": title,
                "date": pub_date,
                "context": context,
                "summary": snippet[:180] + ("..." if len(snippet) > 180 else "") if snippet else title,
                "evidence_type": "user_generated_content",
            }
            reddit_mentions.append(mention_obj)
            evidence_list.append(f"Reddit mention in r/{subreddit}: '{title}' [Context: {context}]")
            trace_evidence.append({
                "type": "reddit_mention",
                "claim": f"Discussion observed in r/{subreddit}",
                "source_url": url,
                "source_type": "user_generated_content",
                "context": context,
                "date": pub_date,
            })

    return reddit_mentions, trace_evidence, evidence_list


def _investigate_news(
    identity: Dict[str, Any],
    search_fn: Any
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Search and extract public news articles and media coverage."""
    news_articles: List[Dict[str, Any]] = []
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    company = identity.get("company_name") or identity.get("domain", "")
    query = f"\"{company}\" news media article"

    search_results = search_fn(query)
    for cand in search_results[:6]:
        url = cand.get("url", "")
        title = cand.get("title", "")
        snippet = cand.get("snippet", "")

        # Exclude official domain itself or basic social sites
        if identity.get("domain") and identity.get("domain") in url:
            continue
        if any(soc in url for soc in ["facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com"]):
            continue

        publisher = urlparse(url).netloc.replace("www.", "")

        # Classify context
        full_text = f"{title} {snippet}".lower()
        context = "business coverage"
        if any(re.search(p, full_text) for p in CONTEXT_PATTERNS["scam_allegation"]):
            context = "investigation / controversy"
        elif "acquisition" in full_text or "funding" in full_text or "launch" in full_text:
            context = "corporate announcement"
        elif "review" in full_text or "analysis" in full_text:
            context = "industry analysis"

        # Extract date if present
        date_match = re.search(r"\b(20[12]\d[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))\b", snippet)
        pub_date = date_match.group(1) if date_match else None

        news_item = {
            "title": title,
            "publisher": publisher,
            "url": url,
            "published_date": pub_date,
            "relevance": "high" if company.lower() in title.lower() else "medium",
            "context": context,
        }
        news_articles.append(news_item)
        evidence_list.append(f"News article from {publisher}: '{title}' (Context: {context})")
        trace_evidence.append({
            "type": "news_article",
            "claim": f"Article published by {publisher}",
            "source_url": url,
            "source_type": "news_media",
            "context": context,
            "date": pub_date,
        })

    return news_articles, trace_evidence, evidence_list


def _investigate_public_reviews(
    identity: Dict[str, Any],
    search_fn: Any
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Search and extract public reviews from platforms like Trustpilot, Sitejabber, BBB."""
    public_reviews: List[Dict[str, Any]] = []
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    domain = identity.get("domain", "")
    company = identity.get("company_name") or domain
    query = f"site:trustpilot.com/review \"{domain}\"" if domain else f"site:trustpilot.com \"{company}\""

    search_results = search_fn(query)
    if not search_results:
        search_results = search_fn(f"\"{company}\" customer reviews rating sitejabber trustpilot")

    for cand in search_results[:5]:
        url = cand.get("url", "")
        title = cand.get("title", "")
        snippet = cand.get("snippet", "")
        full_text = f"{title} {snippet}"

        platform = "Public Review Platform"
        if "trustpilot.com" in url:
            platform = "Trustpilot"
        elif "sitejabber.com" in url:
            platform = "Sitejabber"
        elif "bbb.org" in url:
            platform = "Better Business Bureau (BBB)"
        elif "google.com" in url or "maps.google" in url:
            platform = "Google Reviews"

        # Rating extraction
        rating = None
        m_rate = re.search(r"(\d(?:\.\d)?)\s*(?:out of 5|/5|stars|\★)", full_text, re.IGNORECASE)
        if m_rate:
            try:
                rating = float(m_rate.group(1))
            except Exception:
                pass

        # Review count extraction
        review_count = None
        m_count = re.search(r"(\d+(?:,\d+)?)\s*(?:reviews|ratings|customer reviews)", full_text, re.IGNORECASE)
        if m_count:
            try:
                review_count = int(m_count.group(1).replace(",", ""))
            except Exception:
                pass

        # General sentiment
        sentiment = "mixed"
        if rating:
            if rating >= 4.0:
                sentiment = "positive"
            elif rating <= 2.5:
                sentiment = "negative"
            else:
                sentiment = "mixed"
        else:
            low_text = full_text.lower()
            if any(re.search(p, low_text) for p in CONTEXT_PATTERNS["recommendation"]):
                sentiment = "positive"
            elif any(re.search(p, low_text) for p in CONTEXT_PATTERNS["complaint"] + CONTEXT_PATTERNS["scam_allegation"]):
                sentiment = "negative"

        review_entry = {
            "platform": platform,
            "rating": rating,
            "review_count": review_count,
            "url": url,
            "general_sentiment": sentiment,
        }
        public_reviews.append(review_entry)
        rate_str = f"Rated {rating}/5" if rating else "Reviews identified"
        evidence_list.append(f"{platform} review profile: {rate_str} (Sentiment: {sentiment})")
        trace_evidence.append({
            "type": "public_reviews",
            "claim": f"{platform} reviews available",
            "source_url": url,
            "source_type": "review_platform",
            "context": sentiment,
        })

    return public_reviews, trace_evidence, evidence_list


def _investigate_forums(
    identity: Dict[str, Any],
    search_fn: Any
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Search and extract public forum discussions."""
    forum_discussions: List[Dict[str, Any]] = []
    evidence_list: List[str] = []
    trace_evidence: List[Dict[str, Any]] = []

    domain = identity.get("domain", "")
    company = identity.get("company_name") or domain
    query = f"\"{domain}\" forum discussion experience"

    search_results = search_fn(query)
    for cand in search_results[:6]:
        url = cand.get("url", "")
        title = cand.get("title", "")
        snippet = cand.get("snippet", "")

        # Exclude major social networks or target domain
        if any(ex in url for ex in ["reddit.com", "facebook.com", "twitter.com", "linkedin.com", "instagram.com", "youtube.com"]):
            continue
        if domain and domain in url:
            continue

        forum_name = urlparse(url).netloc.replace("www.", "")
        full_text = f"{title} {snippet}".lower()

        # Classify context & discussion type
        context = "neutral"
        for ctx_name, patterns in CONTEXT_PATTERNS.items():
            if any(re.search(p, full_text) for p in patterns):
                context = ctx_name
                break

        date_match = re.search(r"\b(20[12]\d[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01]))\b", snippet)
        pub_date = date_match.group(1) if date_match else None

        forum_item = {
            "forum_name": forum_name,
            "url": url,
            "title": title,
            "date": pub_date,
            "context": context,
            "discussion_type": "customer experience" if context in ["complaint", "recommendation"] else "technical discussion"
        }
        forum_discussions.append(forum_item)
        evidence_list.append(f"Forum thread on {forum_name}: '{title}' [Context: {context}]")
        trace_evidence.append({
            "type": "forum_discussion",
            "claim": f"Discussion on {forum_name}",
            "source_url": url,
            "source_type": "forum",
            "context": context,
            "date": pub_date,
        })

    return forum_discussions, trace_evidence, evidence_list


# =====================================================================
# 5. CROSS-PLATFORM IDENTITY CONSISTENCY EVALUATION
# =====================================================================

def _evaluate_external_consistency(
    linkedin: Dict[str, Any],
    facebook: Dict[str, Any],
    twitter: Dict[str, Any],
    instagram: Dict[str, Any],
    github: Dict[str, Any],
    news: List[Dict[str, Any]],
    reviews: List[Dict[str, Any]],
    reddit: List[Dict[str, Any]],
    forums: List[Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[str, int], Dict[str, int], List[str]]:
    """
    Synthesize all external OSINT observations to assess cross-platform consistency.
    Returns (external_identity_consistency, presence_summary, context_summary, evidence_list).
    """
    matched_sources: List[str] = []
    conflicts: List[str] = []
    evidence_list: List[str] = []

    social_matches = [
        ("LinkedIn", linkedin),
        ("Facebook", facebook),
        ("X / Twitter", twitter),
        ("Instagram", instagram),
        ("GitHub", github),
    ]

    for name, s in social_matches:
        if s.get("detected"):
            if s.get("identity_match") in ["high", "medium"]:
                matched_sources.append(name)
            elif s.get("identity_match") == "mismatch":
                conflicts.append(f"{name} profile links to conflicting identity / mismatched domain")

    # Presence counts
    social_count = sum(1 for _, s in social_matches if s.get("detected"))
    news_count = len(news)
    review_count = len(reviews)
    reddit_count = len(reddit)
    forum_count = len(forums)

    presence_summary = {
        "social_profiles_found": social_count,
        "news_sources_found": news_count,
        "review_platforms_found": review_count,
        "reddit_mentions_found": reddit_count,
        "forum_mentions_found": forum_count,
    }

    # Context sentiment summary
    context_summary = {
        "positive": 0,
        "negative": 0,
        "neutral": 0,
        "mixed": 0,
        "unknown": 0,
    }

    all_mentions = reddit + forums + [{"context": r.get("general_sentiment")} for r in reviews]
    for m in all_mentions:
        ctx = str(m.get("context") or "unknown").lower()
        if ctx in ["recommendation", "positive"]:
            context_summary["positive"] += 1
        elif ctx in ["complaint", "scam_allegation", "negative"]:
            context_summary["negative"] += 1
        elif ctx in ["discussion", "question", "neutral"]:
            context_summary["neutral"] += 1
        elif ctx == "mixed":
            context_summary["mixed"] += 1
        else:
            context_summary["unknown"] += 1

    # Overall consistency status
    if len(conflicts) > 0:
        status = "inconsistent"
        evidence_list.append(f"External identity correlation identified {len(conflicts)} conflict(s) across OSINT sources")
    elif len(matched_sources) >= 2:
        status = "consistent"
        evidence_list.append(f"External identity shows consistent alignment across {len(matched_sources)} platforms ({', '.join(matched_sources)})")
    elif len(matched_sources) == 1:
        status = "partially_consistent"
        evidence_list.append(f"External identity partially confirmed on {matched_sources[0]}")
    elif social_count == 0 and news_count == 0 and review_count == 0:
        status = "unknown"
        evidence_list.append("No discoverable external public profiles or OSINT footprints found")
    else:
        status = "partially_consistent"

    external_consistency = {
        "status": status,
        "matched_sources": matched_sources,
        "conflicts": conflicts,
    }

    return external_consistency, presence_summary, context_summary, evidence_list


# =====================================================================
# 6. MAIN ENTRYPOINT
# =====================================================================

def analyze_osint(url: str, search_override: Optional[Any] = None) -> Dict[str, Any]:
    """
    Main entry point for Agent 13: External Presence / OSINT Agent.
    Collects passive forensic evidence regarding external brand footprints,
    social profiles, Reddit discussions, news, public reviews, and forum threads.
    """
    print("[Agent 13] Starting external presence & OSINT investigation...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    forensic_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 13] Invalid URL provided.")
        extra = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "identity": {"company_name": None, "brand_name": None, "domain": None},
            "linkedin": {"detected": False, "company_found": False, "url": None},
            "facebook": {"detected": False, "url": None},
            "x_twitter": {"detected": False, "url": None},
            "instagram": {"detected": False, "url": None},
            "github": {"detected": False, "relevant": False, "url": None},
            "reddit_mentions": [],
            "news_articles": [],
            "public_reviews": [],
            "forum_discussions": [],
            "external_identity_consistency": {"status": "unknown", "matched_sources": [], "conflicts": []},
            "presence_summary": {
                "social_profiles_found": 0, "news_sources_found": 0,
                "review_platforms_found": 0, "reddit_mentions_found": 0, "forum_mentions_found": 0
            },
            "context_summary": {"positive": 0, "negative": 0, "neutral": 0, "mixed": 0, "unknown": 0},
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A13",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra,
        )

    print("[Agent 13] Normalizing URL & extracting domain...")
    normalized_url = _normalize_url(url)
    submitted_domain = _extract_registered_domain(normalized_url)

    # Initialize session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    # Search function interface
    search_fn = search_override if search_override is not None else lambda q: execute_public_search(q, session)

    print("[Agent 13] Extracting website identity & on-page links...")
    html_text, final_url, soup, fetch_errors = _fetch_webpage_safe(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    final_domain = _extract_registered_domain(final_url) if final_url else submitted_domain

    identity, on_page_socials, is_tech_relevant = _extract_target_identity(
        soup, html_text, final_domain, final_url or normalized_url
    )

    print(f"[Agent 13] Identity resolved: '{identity.get('company_name')}' (Domain: {identity.get('domain')})")
    forensic_evidence.append(f"Target identity extracted: Company='{identity.get('company_name')}', Brand='{identity.get('brand_name')}', Domain='{identity.get('domain')}'")

    print("[Agent 13] Investigating LinkedIn presence...")
    linkedin_res, li_traces, li_ev = _investigate_linkedin(identity, on_page_socials, search_fn)
    forensic_evidence.extend(li_ev)

    print("[Agent 13] Investigating Facebook presence...")
    facebook_res, fb_traces, fb_ev = _investigate_facebook(identity, on_page_socials, search_fn)
    forensic_evidence.extend(fb_ev)

    print("[Agent 13] Investigating X/Twitter presence...")
    twitter_res, tw_traces, tw_ev = _investigate_twitter(identity, on_page_socials, search_fn)
    forensic_evidence.extend(tw_ev)

    print("[Agent 13] Investigating Instagram presence...")
    instagram_res, ig_traces, ig_ev = _investigate_instagram(identity, on_page_socials, search_fn)
    forensic_evidence.extend(ig_ev)

    print("[Agent 13] Investigating GitHub presence...")
    github_res, gh_traces, gh_ev = _investigate_github(identity, on_page_socials, is_tech_relevant, search_fn)
    forensic_evidence.extend(gh_ev)

    print("[Agent 13] Searching Reddit public mentions...")
    reddit_mentions, rd_traces, rd_ev = _investigate_reddit(identity, search_fn)
    forensic_evidence.extend(rd_ev)

    print("[Agent 13] Searching public news & media articles...")
    news_articles, nw_traces, nw_ev = _investigate_news(identity, search_fn)
    forensic_evidence.extend(nw_ev)

    print("[Agent 13] Searching public reviews & ratings...")
    public_reviews, rv_traces, rv_ev = _investigate_public_reviews(identity, search_fn)
    forensic_evidence.extend(rv_ev)

    print("[Agent 13] Searching forum discussions...")
    forum_discussions, fm_traces, fm_ev = _investigate_forums(identity, search_fn)
    forensic_evidence.extend(fm_ev)

    print("[Agent 13] Evaluating cross-platform identity consistency...")
    external_consistency, presence_summary, context_summary, cons_ev = _evaluate_external_consistency(
        linkedin_res, facebook_res, twitter_res, instagram_res, github_res,
        news_articles, public_reviews, reddit_mentions, forum_discussions
    )
    forensic_evidence.extend(cons_ev)

    print("[Agent 13] Generating evidence...")
    # Build structured evidence items
    structured_evidence = []

    # E13-01: Target Identity
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=1,
        finding="Resolved brand and company identity for OSINT querying",
        value=identity.get("company_name"),
        severity="info",
        source="DOM Identity Resolver",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=identity
    ))

    # E13-02: LinkedIn Presence
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=2,
        finding="LinkedIn corporate page presence and employee footprint",
        value=linkedin_res.get("detected", False),
        severity="info",
        source="LinkedIn OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata=linkedin_res
    ))

    # E13-03: Facebook Presence
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=3,
        finding="Facebook official public page presence",
        value=facebook_res.get("detected", False),
        severity="info",
        source="Facebook OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata=facebook_res
    ))

    # E13-04: X/Twitter Presence
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=4,
        finding="X / Twitter account verification and handle corroboration",
        value=twitter_res.get("detected", False),
        severity="info",
        source="Twitter OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata=twitter_res
    ))

    # E13-05: Instagram Presence
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=5,
        finding="Instagram public profile presence",
        value=instagram_res.get("detected", False),
        severity="info",
        source="Instagram OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata=instagram_res
    ))

    # E13-06: GitHub Software Repositories
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=6,
        finding="GitHub organization repository footprint",
        value=github_res.get("detected", False),
        severity="info",
        source="GitHub OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata=github_res
    ))

    # E13-07: Reddit Mentions & Sentiment
    has_scam_mentions = any(m.get("context") in ("scam_allegation", "warning") for m in reddit_mentions)
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=7,
        finding="Reddit public community discussions and consumer mentions",
        value=len(reddit_mentions),
        severity="high" if has_scam_mentions else "info",
        source="Reddit Public OSINT",
        evidence_type="external_source",
        evidence_strength=0.75 if has_scam_mentions else 0.1,
        metadata={"mentions": reddit_mentions}
    ))

    # E13-08: News & Media Articles
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=8,
        finding="Independent news articles and mainstream media coverage",
        value=len(news_articles),
        severity="info",
        source="Public News Indices",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata={"news": news_articles}
    ))

    # E13-09: Public Consumer Reviews
    has_bad_reviews = any(r.get("context") in ("scam_allegation", "complaint") for r in public_reviews)
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=9,
        finding="Third-party consumer review platforms (Trustpilot, BBB)",
        value=len(public_reviews),
        severity="high" if has_bad_reviews else "info",
        source="Review Aggregator OSINT",
        evidence_type="external_source",
        evidence_strength=0.8 if has_bad_reviews else 0.1,
        metadata={"reviews": public_reviews}
    ))

    # E13-10: Forum Discussions
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=10,
        finding="Online community forum discussions and consumer queries",
        value=len(forum_discussions),
        severity="info",
        source="Web Forums OSINT",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata={"forums": forum_discussions}
    ))

    # E13-11: External OSINT Consistency
    is_inconsistent = external_consistency.get("status") == "inconsistent"
    structured_evidence.append(create_evidence_item(
        agent_id="A13",
        index=11,
        finding="Cross-platform identity consistency and public corroboration",
        value=external_consistency.get("status", "unknown"),
        severity="high" if is_inconsistent else "info",
        source="OSINT Cross-Corroboration Analyzer",
        evidence_type="inference",
        evidence_strength=0.75 if is_inconsistent else 0.1,
        metadata={"consistency": external_consistency, "presence": presence_summary, "context": context_summary}
    ))

    print("[Agent 13] External presence & OSINT investigation completed.")

    data_payload = {
        "identity": identity,
        "linkedin": linkedin_res,
        "facebook": facebook_res,
        "x_twitter": twitter_res,
        "instagram": instagram_res,
        "github": github_res,
        "reddit_mentions": reddit_mentions,
        "news_articles": news_articles,
        "public_reviews": public_reviews,
        "forum_discussions": forum_discussions,
        "external_identity_consistency": external_consistency,
        "presence_summary": presence_summary,
        "context_summary": context_summary,
        "evidence": forensic_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url or normalized_url,
            "domain": final_domain or submitted_domain,
        },
        **data_payload,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A13",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
