"""
Agent 14 — Historical Evidence Agent
Investigates the historical development and temporal evolution of a submitted
domain and website.

Collects and analyzes:
1. Wayback Machine & CDX Snapshot History
2. Website Content & Business Identity Evolution
3. Domain Ownership & Registrar Changes
4. Historical DNS & Infrastructure Transitions (IP, NS, MX)
5. Previous Public Reputation & Past Security Reports
6. Domain Reuse & Parked / Inactive Periods
7. Historical Inconsistency Detection (Claims vs Historical Record)
8. Chronological Event Timeline

Strictly passive forensic evidence collection.
DO NOT calculate final Trust/Risk score or declare legitimate/scam.
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
WAYBACK_TIMEOUT = 8                    # 8 seconds for Wayback API

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Domain parking and inactivity indicators
PARKING_INDICATORS = [
    r"\b(?:domain\s+(?:for\s+sale|is\s+parked|has\s+expired|may\s+be\s+for\s+sale))\b",
    r"\b(?:buy\s+this\s+domain|inquire\s+about\s+this\s+domain|renew\s+now|under\s+construction)\b",
    r"\b(?:sedo|godaddy\s+parking|dan\.com|afternic|hugedomains|bodis|parkingcrew)\b",
    r"\b(?:website\s+coming\s+soon|future\s+home\s+of|page\s+is\s+under\s+development)\b",
]

# Claimed establishment patterns
ESTABLISHED_PATTERNS = [
    r"\b(?:established|est\.?|founded|since|operating\s+since)\s*(?:in\s*)?([12][90]\d{2})\b",
    r"\b([12][90]\d{2})\s*[-–—]\s*(?:present|202[0-9])\b",
    r"\b(?:over|more\s+than)\s*(\d{1,2})\s*years\s+of\s+experience\b",
]


# =====================================================================
# 1. HELPER UTILITIES & DOMAIN PARSING
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


def _fetch_current_page_and_claims(
    url: str,
    session: requests.Session
) -> Tuple[Optional[str], Optional[str], Optional[BeautifulSoup], Optional[int], List[str]]:
    """Fetch current webpage to extract claimed founding years and current identity."""
    errors = []
    claimed_year = None

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
            return None, url, None, None, errors
    except Exception as e:
        errors.append(f"Failed to fetch current webpage: {str(e)}")
        return None, url, None, None, errors

    final_url = resp.url or url
    try:
        content_chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=8192):
            content_chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded >= MAX_HTML_SIZE:
                break
        html_bytes = b"".join(content_chunks)
        encoding = resp.encoding or "utf-8"
        html_text = html_bytes.decode(encoding, errors="replace")
        soup = BeautifulSoup(html_text, "html.parser")

        # Extract claimed founding year
        full_text = soup.get_text(separator=" ", strip=True)
        for pat in ESTABLISHED_PATTERNS:
            m = re.search(pat, full_text, re.IGNORECASE)
            if m:
                val = m.group(1)
                if len(val) == 4 and val.isdigit():
                    yr = int(val)
                    if 1900 <= yr <= datetime.datetime.now().year:
                        claimed_year = yr
                        break

        return html_text, final_url, soup, claimed_year, errors
    except Exception as e:
        errors.append(f"Error parsing current HTML: {str(e)}")
        return None, final_url, None, None, errors


# =====================================================================
# 2. WAYBACK MACHINE & CDX API QUERY ENGINE
# =====================================================================

def _query_wayback_cdx(
    domain: str,
    session: requests.Session,
    override_fn: Optional[Any] = None
) -> Tuple[List[List[str]], int, List[str]]:
    """
    Query the Wayback Machine CDX API for historical snapshot records.
    Returns (cdx_rows, snapshot_count, errors).
    """
    errors: List[str] = []
    if override_fn is not None:
        try:
            rows, count = override_fn(domain)
            return rows, count, errors
        except Exception as e:
            errors.append(f"Wayback override query failed: {str(e)}")
            return [], 0, errors

    if not domain:
        return [], 0, errors

    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest",
        "collapse": "timestamp:4",  # One capture per year roughly
        "limit": 100,
    }

    try:
        resp = session.get(
            cdx_url,
            params=params,
            headers=DEFAULT_HEADERS,
            timeout=WAYBACK_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                # Row 0 is headers: ["timestamp", "original", "mimetype", "statuscode", "digest"]
                return data[1:], len(data) - 1, errors
            return [], 0, errors
        elif resp.status_code == 404:
            return [], 0, errors
        else:
            errors.append(f"Wayback CDX API returned HTTP {resp.status_code}")
            return [], 0, errors
    except requests.exceptions.Timeout:
        errors.append("Wayback CDX API request timed out (safe fallback enabled)")
        return [], 0, errors
    except Exception as e:
        errors.append(f"Wayback CDX query failed: {str(e)}")
        return [], 0, errors


def _parse_wayback_snapshots(
    cdx_rows: List[List[str]],
    domain: str
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """
    Parse raw CDX rows into structured snapshot objects and pick milestone snapshots.
    Returns (wayback_history_dict, selected_snapshots_list, evidence_list).
    """
    evidence_list: List[str] = []
    wayback_history = {
        "available": False,
        "snapshot_count": 0,
        "earliest_snapshot": None,
        "latest_snapshot": None,
        "selected_snapshots": [],
    }
    selected_snapshots: List[Dict[str, Any]] = []

    if not cdx_rows:
        evidence_list.append("Wayback Machine: No historical archived snapshots discoverable for this domain")
        return wayback_history, selected_snapshots, evidence_list

    wayback_history["available"] = True
    wayback_history["snapshot_count"] = len(cdx_rows)

    parsed_captures: List[Dict[str, Any]] = []

    for row in cdx_rows:
        if len(row) < 4:
            continue
        ts = str(row[0])
        orig = str(row[1])
        mime = str(row[2]) if len(row) > 2 else "text/html"
        status = int(row[3]) if str(row[3]).isdigit() else 200
        digest = str(row[4]) if len(row) > 4 else ""

        # Format date YYYY-MM-DD
        if len(ts) >= 8:
            formatted_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
            year_str = ts[0:4]
        else:
            formatted_date = ts
            year_str = "Unknown"

        snapshot_url = f"https://web.archive.org/web/{ts}/{orig}"

        parsed_captures.append({
            "timestamp": ts,
            "date": formatted_date,
            "year": year_str,
            "url": orig,
            "status": status,
            "mime_type": mime,
            "digest": digest,
            "snapshot_url": snapshot_url,
            "title": None,
            "company_name": None,
            "business_category": "General Website",
            "is_parked": False,
            "redirect_url": None,
        })

    if not parsed_captures:
        return wayback_history, selected_snapshots, evidence_list

    # Sort chronologically
    parsed_captures.sort(key=lambda x: x["timestamp"])

    earliest = parsed_captures[0]
    latest = parsed_captures[-1]

    wayback_history["earliest_snapshot"] = {
        "timestamp": earliest["timestamp"],
        "date": earliest["date"],
        "url": earliest["snapshot_url"],
    }
    wayback_history["latest_snapshot"] = {
        "timestamp": latest["timestamp"],
        "date": latest["date"],
        "url": latest["snapshot_url"],
    }

    # Group by year to select representative snapshots
    by_year: Dict[str, List[Dict[str, Any]]] = {}
    for cap in parsed_captures:
        by_year.setdefault(cap["year"], []).append(cap)

    # Pick 1 per year, up to 10 milestone snapshots
    for yr, caps in sorted(by_year.items()):
        # Prefer HTTP 200 status
        ok_caps = [c for c in caps if c["status"] == 200]
        chosen = ok_caps[0] if ok_caps else caps[0]
        selected_snapshots.append(chosen)

    wayback_history["selected_snapshots"] = selected_snapshots[:10]

    evidence_list.append(
        f"Wayback Machine: Found {len(parsed_captures)} snapshot(s) spanning {earliest['date']} to {latest['date']}"
    )

    return wayback_history, selected_snapshots, evidence_list


# =====================================================================
# 3. WEBSITE EVOLUTION & HISTORICAL CONTENT COMPARISON
# =====================================================================

def _analyze_historical_content(
    selected_snapshots: List[Dict[str, Any]],
    current_company_name: Optional[str],
    current_domain: str,
    snapshot_fetcher: Optional[Any] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Examine historical snapshots for company identity shifts, parking periods, and redesigns.
    Returns (website_history, inactive_periods, redirect_history, evidence_list).
    """
    website_history = {
        "timeline": [],
        "major_changes": [],
        "identity_changes": [],
        "business_category_changes": [],
    }
    inactive_periods: List[Dict[str, Any]] = []
    redirect_history: List[Dict[str, Any]] = []
    evidence_list: List[str] = []

    if not selected_snapshots:
        return website_history, inactive_periods, redirect_history, evidence_list

    previous_identity: Optional[str] = None
    previous_category: Optional[str] = None
    previous_digest: Optional[str] = None

    for snap in selected_snapshots:
        date_str = snap["date"]
        year_str = snap.get("year", date_str[:4])
        status = snap.get("status", 200)

        # 1. Check HTTP redirects (301/302)
        if status in [301, 302, 307, 308]:
            redirect_obj = {
                "date": date_str,
                "status_code": status,
                "source_url": snap["url"],
                "destination_url": snap.get("redirect_url") or "External Location",
                "snapshot_url": snap["snapshot_url"],
            }
            redirect_history.append(redirect_obj)
            website_history["timeline"].append({
                "date": year_str,
                "event": f"HTTP {status} Redirect observed in archive",
            })
            continue

        # 2. Check snapshot content / metadata if fetcher provided
        snap_title = snap.get("title")
        snap_company = snap.get("company_name")
        snap_cat = snap.get("business_category", "General Website")
        is_parked = snap.get("is_parked", False)

        if snapshot_fetcher is not None:
            try:
                fetched_info = snapshot_fetcher(snap["snapshot_url"])
                if isinstance(fetched_info, dict):
                    snap_title = fetched_info.get("title", snap_title)
                    snap_company = fetched_info.get("company_name", snap_company)
                    snap_cat = fetched_info.get("business_category", snap_cat)
                    is_parked = fetched_info.get("is_parked", is_parked)
            except Exception:
                pass

        # Check parking / inactive status
        if is_parked:
            inactive_obj = {
                "period": year_str,
                "date": date_str,
                "status": "parked_or_inactive",
                "evidence": "Domain parking or under-construction indicators observed in snapshot",
                "snapshot_url": snap["snapshot_url"],
            }
            inactive_periods.append(inactive_obj)
            website_history["timeline"].append({
                "date": year_str,
                "event": "Domain observed parked or inactive",
            })
            evidence_list.append(f"Historical period {year_str}: Domain was parked or under development")
            continue

        # Identify changes
        if snap_company and previous_identity and snap_company.lower() != previous_identity.lower():
            change_entry = {
                "change_type": "business_identity_change",
                "from": previous_identity,
                "to": snap_company,
                "approximate_date": year_str,
                "evidence": f"Company name shifted from '{previous_identity}' to '{snap_company}'",
                "snapshot_url": snap["snapshot_url"],
            }
            website_history["identity_changes"].append(change_entry)
            website_history["major_changes"].append(change_entry)
            website_history["timeline"].append({
                "date": year_str,
                "event": f"Business identity shifted to '{snap_company}'",
            })
            evidence_list.append(f"Historical change ({year_str}): Business identity changed from '{previous_identity}' to '{snap_company}'")

        if snap_cat and previous_category and snap_cat.lower() != previous_category.lower() and snap_cat != "General Website":
            cat_entry = {
                "change_type": "business_category_change",
                "from": previous_category,
                "to": snap_cat,
                "approximate_date": year_str,
                "evidence": f"Website category shifted from '{previous_category}' to '{snap_cat}'",
                "snapshot_url": snap["snapshot_url"],
            }
            website_history["business_category_changes"].append(cat_entry)
            website_history["major_changes"].append(cat_entry)
            website_history["timeline"].append({
                "date": year_str,
                "event": f"Business category changed to '{snap_cat}'",
            })
            evidence_list.append(f"Historical change ({year_str}): Website content category shifted to '{snap_cat}'")

        # Check digest change (redesign)
        if previous_digest and snap.get("digest") and snap["digest"] != previous_digest:
            website_history["timeline"].append({
                "date": year_str,
                "event": "Website content/design updated",
            })

        if snap_company:
            previous_identity = snap_company
        if snap_cat and snap_cat != "General Website":
            previous_category = snap_cat
        if snap.get("digest"):
            previous_digest = snap["digest"]

    return website_history, inactive_periods, redirect_history, evidence_list


# =====================================================================
# 4. DOMAIN OWNERSHIP & REGISTRAR HISTORY
# =====================================================================

def _analyze_historical_ownership(
    domain: str,
    history_override: Optional[Any] = None
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Examine historical WHOIS / RDAP ownership and registrar transitions.
    Returns (historical_ownership_dict, evidence_list).
    """
    evidence_list: List[str] = []
    ownership = {
        "available": False,
        "records": [],
        "possible_ownership_changes": [],
    }

    if history_override is not None:
        try:
            records, changes = history_override(domain)
            ownership["available"] = bool(records)
            ownership["records"] = records
            ownership["possible_ownership_changes"] = changes
            if changes:
                for ch in changes:
                    evidence_list.append(
                        f"Ownership history: Possible registrant transition from '{ch.get('previous_entity')}' to '{ch.get('new_entity')}' ({ch.get('date', 'past period')})"
                    )
            return ownership, evidence_list
        except Exception:
            pass

    # Passive public fallback: mark as not_available without data fabrication
    ownership["available"] = False
    return ownership, evidence_list


# =====================================================================
# 5. HISTORICAL DNS & INFRASTRUCTURE CHANGES
# =====================================================================

def _analyze_historical_dns(
    domain: str,
    dns_override: Optional[Any] = None
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """
    Examine historical DNS records (A, NS, MX) and hosting/IP infrastructure transitions.
    Returns (historical_dns, infrastructure_history, evidence_list).
    """
    evidence_list: List[str] = []
    historical_dns = {
        "available": False,
        "records": [],
        "changes": [],
    }
    infrastructure_history = {
        "ip_changes": [],
        "nameserver_changes": [],
        "hosting_changes": [],
    }

    if dns_override is not None:
        try:
            records, changes, ip_ch, ns_ch = dns_override(domain)
            historical_dns["available"] = bool(records)
            historical_dns["records"] = records
            historical_dns["changes"] = changes
            infrastructure_history["ip_changes"] = ip_ch
            infrastructure_history["nameserver_changes"] = ns_ch
            for ch in ip_ch:
                evidence_list.append(f"Historical IP change: {ch.get('from')} → {ch.get('to')} ({ch.get('date')})")
            for ch in ns_ch:
                evidence_list.append(f"Historical NS change: {ch.get('from')} → {ch.get('to')} ({ch.get('date')})")
            return historical_dns, infrastructure_history, evidence_list
        except Exception:
            pass

    return historical_dns, infrastructure_history, evidence_list


# =====================================================================
# 6. HISTORICAL REPUTATION & PAST INCIDENTS
# =====================================================================

def _analyze_historical_reputation(
    domain: str,
    company_name: Optional[str],
    session: requests.Session,
    search_override: Optional[Any] = None
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Search and contextualize historical reputation reports, past complaints, and security disclosures.
    Returns (historical_reputation, evidence_list).
    """
    evidence_list: List[str] = []
    rep_data = {
        "reports": [],
        "negative_reports": [],
        "positive_reports": [],
        "neutral_reports": [],
    }

    if search_override is not None:
        try:
            raw_reports = search_override(domain)
            for r in raw_reports:
                sentiment = r.get("sentiment", "neutral").lower()
                rep_data["reports"].append(r)
                if sentiment == "negative":
                    rep_data["negative_reports"].append(r)
                elif sentiment == "positive":
                    rep_data["positive_reports"].append(r)
                else:
                    rep_data["neutral_reports"].append(r)
            if rep_data["reports"]:
                evidence_list.append(
                    f"Historical reputation: Found {len(rep_data['reports'])} historical report(s) ({len(rep_data['negative_reports'])} negative, {len(rep_data['positive_reports'])} positive)"
                )
            return rep_data, evidence_list
        except Exception:
            pass

    return rep_data, evidence_list


# =====================================================================
# 7. DOMAIN REUSE & HISTORICAL INCONSISTENCY DETECTION
# =====================================================================

def _detect_domain_reuse(
    website_history: Dict[str, Any],
    inactive_periods: List[Dict[str, Any]],
    ownership: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Determine if historical patterns indicate the domain was repurposed across different owners/industries.
    Returns (domain_reuse_dict, evidence_list).
    """
    evidence_list: List[str] = []
    domain_reuse = {
        "possible": False,
        "evidence": [],
    }

    reasons: List[str] = []

    # 1. Identity changes
    if len(website_history.get("identity_changes", [])) > 0:
        domain_reuse["possible"] = True
        for ch in website_history["identity_changes"]:
            reasons.append(f"Business identity shifted from '{ch.get('from')}' to '{ch.get('to')}' ({ch.get('approximate_date')})")

    # 2. Category shifts after parked period
    if len(inactive_periods) > 0 and len(website_history.get("business_category_changes", [])) > 0:
        domain_reuse["possible"] = True
        reasons.append("Website underwent a parked/inactive period followed by a business category shift")

    # 3. Ownership shifts
    if len(ownership.get("possible_ownership_changes", [])) > 0:
        domain_reuse["possible"] = True
        for ow in ownership["possible_ownership_changes"]:
            reasons.append(f"Possible registrant ownership transition observed in {ow.get('date', 'past records')}")

    domain_reuse["evidence"] = reasons

    if domain_reuse["possible"]:
        evidence_list.append(f"Domain lifecycle analysis: Evidence indicates possible domain reuse ({len(reasons)} observation(s))")

    return domain_reuse, evidence_list


def _evaluate_historical_inconsistencies(
    claimed_founding_year: Optional[int],
    earliest_snapshot: Optional[Dict[str, Any]],
    domain_reuse: Dict[str, Any],
    timeline: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Compare claimed website founding year/tenure against earliest discoverable archive records.
    Returns (inconsistencies_list, evidence_list).
    """
    inconsistencies: List[Dict[str, Any]] = []
    evidence_list: List[str] = []

    if claimed_founding_year and earliest_snapshot:
        earliest_date_str = earliest_snapshot.get("date", "")
        if len(earliest_date_str) >= 4 and earliest_date_str[:4].isdigit():
            earliest_yr = int(earliest_date_str[:4])
            # If claimed year is significantly earlier than first archive capture (e.g. 5+ years)
            if earliest_yr - claimed_founding_year >= 5:
                entry = {
                    "type": "historical_claim_comparison",
                    "claim": f"Website states establishment in {claimed_founding_year}",
                    "historical_evidence": f"Earliest available Wayback Machine archive snapshot is {earliest_date_str}",
                    "assessment": "not_verifiable_from_wayback",
                    "notes": "Company may have existed offline before digital domain registration, or acquired the domain later.",
                }
                inconsistencies.append(entry)
                evidence_list.append(
                    f"Historical claim evaluation: Website states established in {claimed_founding_year}; earliest discoverable archive capture is {earliest_yr} (neutral observation)"
                )

    return inconsistencies, evidence_list


# =====================================================================
# 8. MASTER TIMELINE SYNTHESIS
# =====================================================================

def _build_master_timeline(
    wayback_history: Dict[str, Any],
    website_history: Dict[str, Any],
    ownership: Dict[str, Any],
    historical_dns: Dict[str, Any],
    reputation: Dict[str, Any],
    inactive_periods: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Combine temporal events from all historical sources into a unified chronological timeline."""
    events: List[Dict[str, Any]] = []

    # 1. Earliest snapshot
    earliest = wayback_history.get("earliest_snapshot")
    if earliest:
        events.append({
            "date": earliest.get("date", "Earliest Archive"),
            "source": "Wayback Machine",
            "event": "First archived website capture recorded",
            "url": earliest.get("url"),
        })

    # 2. Website timeline events
    for ev in website_history.get("timeline", []):
        events.append({
            "date": ev.get("date", ""),
            "source": "Website Archive Analysis",
            "event": ev.get("event", "Website update"),
        })

    # 3. Inactive / parked periods
    for inact in inactive_periods:
        events.append({
            "date": inact.get("date", inact.get("period", "")),
            "source": "Wayback Archive",
            "event": "Domain observed parked or under construction",
            "url": inact.get("snapshot_url"),
        })

    # 4. Ownership changes
    for ow in ownership.get("possible_ownership_changes", []):
        events.append({
            "date": ow.get("date", ""),
            "source": "WHOIS / Registration History",
            "event": f"Registrant transition: {ow.get('previous_entity')} → {ow.get('new_entity')}",
        })

    # 5. DNS / IP changes
    for ch in historical_dns.get("changes", []):
        events.append({
            "date": ch.get("date", ""),
            "source": "Historical DNS",
            "event": f"Infrastructure change: {ch.get('type', 'DNS')} update ({ch.get('from')} → {ch.get('to')})",
        })

    # 6. Reputation reports
    for rep in reputation.get("reports", []):
        events.append({
            "date": rep.get("date", "Historical Record"),
            "source": rep.get("source", "Public Media / Report"),
            "event": f"Public report noted: '{rep.get('title', 'Historical report')}' [{rep.get('sentiment', 'neutral').upper()}]",
            "url": rep.get("url"),
        })

    # 7. Latest snapshot
    latest = wayback_history.get("latest_snapshot")
    if latest and latest != earliest:
        events.append({
            "date": latest.get("date", "Latest Archive"),
            "source": "Wayback Machine",
            "event": "Latest historical archive snapshot captured",
            "url": latest.get("url"),
        })

    # Sort events by date if possible
    def _sort_key(e: Dict[str, Any]) -> str:
        d = str(e.get("date") or "")
        return d if d else "9999"

    events.sort(key=_sort_key)
    return events


# =====================================================================
# 9. MAIN FORENSIC ENTRYPOINT
# =====================================================================

def analyze_history(
    url: str,
    cdx_override: Optional[Any] = None,
    snapshot_fetcher: Optional[Any] = None,
    ownership_override: Optional[Any] = None,
    dns_override: Optional[Any] = None,
    reputation_override: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Main entry point for Agent 14: Historical Evidence Agent.
    Collects passive forensic evidence regarding domain history, snapshot evolution,
    previous ownership, DNS records, domain reuse, and temporal inconsistencies.
    """
    print("[Agent 14] Starting historical evidence investigation...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    forensic_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 14] Invalid URL provided.")
        extra = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "wayback_history": {
                "available": False,
                "snapshot_count": 0,
                "earliest_snapshot": None,
                "latest_snapshot": None,
                "selected_snapshots": [],
            },
            "website_history": {
                "timeline": [],
                "major_changes": [],
                "identity_changes": [],
                "business_category_changes": [],
            },
            "historical_ownership": {"available": False, "records": [], "possible_ownership_changes": []},
            "historical_screenshots": [],
            "historical_reputation": {"reports": [], "negative_reports": [], "positive_reports": [], "neutral_reports": []},
            "historical_dns": {"available": False, "records": [], "changes": []},
            "infrastructure_history": {"ip_changes": [], "nameserver_changes": [], "hosting_changes": []},
            "domain_reuse": {"possible": False, "evidence": []},
            "inactive_periods": [],
            "redirect_history": [],
            "historical_inconsistencies": [],
            "timeline": [],
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A14",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra,
        )

    print("[Agent 14] Normalizing URL & extracting domain...")
    normalized_url = _normalize_url(url)
    domain = _extract_registered_domain(normalized_url)

    # Initialize session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    # 1. Fetch current webpage to extract claimed founding years
    print("[Agent 14] Fetching current webpage & analyzing tenure claims...")
    html_text, final_url, soup, claimed_founding_year, fetch_errors = _fetch_current_page_and_claims(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    current_company = None
    if soup and soup.title and soup.title.string:
        current_company = soup.title.string.strip()

    # 2. Query Wayback Machine CDX API
    print("[Agent 14] Querying Wayback Machine CDX archives...")
    cdx_rows, snapshot_count, cdx_errors = _query_wayback_cdx(domain, session, cdx_override)
    if cdx_errors:
        errors.extend(cdx_errors)

    wayback_history, selected_snapshots, wb_ev = _parse_wayback_snapshots(cdx_rows, domain)
    forensic_evidence.extend(wb_ev)

    # 3. Analyze website changes over time
    print("[Agent 14] Analyzing historical website changes & identity shifts...")
    website_history, inactive_periods, redirect_history, hist_ev = _analyze_historical_content(
        selected_snapshots, current_company, domain, snapshot_fetcher
    )
    forensic_evidence.extend(hist_ev)

    # 4. Query historical ownership
    print("[Agent 14] Checking historical domain ownership records...")
    ownership, ow_ev = _analyze_historical_ownership(domain, ownership_override)
    forensic_evidence.extend(ow_ev)

    # 5. Query historical DNS
    print("[Agent 14] Checking historical DNS & infrastructure transitions...")
    historical_dns, infrastructure_history, dns_ev = _analyze_historical_dns(domain, dns_override)
    forensic_evidence.extend(dns_ev)

    # 6. Query historical reputation
    print("[Agent 14] Searching historical public reputation & reports...")
    historical_reputation, rep_ev = _analyze_historical_reputation(domain, current_company, session, reputation_override)
    forensic_evidence.extend(rep_ev)

    # 7. Evaluate domain reuse
    print("[Agent 14] Evaluating domain reuse patterns...")
    domain_reuse, reuse_ev = _detect_domain_reuse(website_history, inactive_periods, ownership)
    forensic_evidence.extend(reuse_ev)

    # 8. Check historical inconsistencies
    print("[Agent 14] Checking historical claim consistency...")
    historical_inconsistencies, inc_ev = _evaluate_historical_inconsistencies(
        claimed_founding_year, wayback_history.get("earliest_snapshot"), domain_reuse, website_history.get("timeline", [])
    )
    forensic_evidence.extend(inc_ev)

    # 9. Format historical screenshots list
    historical_screenshots = [
        {
            "date": s.get("date"),
            "year": s.get("year"),
            "snapshot_url": s.get("snapshot_url"),
            "screenshot_available": True,
        }
        for s in selected_snapshots[:8]
    ]

    # 10. Build master chronological timeline
    print("[Agent 14] Assembling chronological lifecycle timeline...")
    master_timeline = _build_master_timeline(
        wayback_history, website_history, ownership, historical_dns, historical_reputation, inactive_periods
    )

    print("[Agent 14] Generating evidence...")
    # Build structured evidence items
    structured_evidence = []

    # E14-01: Wayback Machine Archive
    has_archive = wayback_history.get("available", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=1,
        finding="Wayback Machine historical snapshot availability",
        value=wayback_history.get("snapshot_count", 0),
        severity="info" if has_archive else "low",
        source="Internet Archive CDX API",
        evidence_type="historical",
        evidence_strength=0.1,
        metadata=wayback_history
    ))

    # E14-02: Content Evolution & Identity Changes
    id_changes = website_history.get("identity_changes", [])
    cat_changes = website_history.get("business_category_changes", [])
    has_shift = bool(id_changes or cat_changes)
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=2,
        finding="Historical content evolution and identity transformation",
        value=len(id_changes) + len(cat_changes),
        severity="high" if has_shift else "info",
        source="Wayback Content Analyzer",
        evidence_type="historical",
        evidence_strength=0.75 if has_shift else 0.1,
        metadata={"identity_changes": id_changes, "category_changes": cat_changes}
    ))

    # E14-03: Historical Ownership Changes
    ow_changes = ownership.get("possible_ownership_changes", [])
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=3,
        finding="Historical domain registration and ownership transfer records",
        value=len(ow_changes),
        severity="medium" if len(ow_changes) > 0 else "info",
        source="Historical WHOIS Archive",
        evidence_type="historical",
        evidence_strength=0.6 if len(ow_changes) > 0 else 0.1,
        metadata=ownership
    ))

    # E14-04: Historical DNS Infrastructure
    ip_changes = infrastructure_history.get("ip_changes", [])
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=4,
        finding="Historical DNS records and infrastructure transitions",
        value=len(ip_changes),
        severity="info",
        source="Passive DNS History",
        evidence_type="historical",
        evidence_strength=0.1,
        metadata={"dns": historical_dns, "infrastructure": infrastructure_history}
    ))

    # E14-05: Historical Security Reputation
    neg_reps = historical_reputation.get("negative_reports", [])
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=5,
        finding="Historical cybersecurity incident and blacklisting records",
        value=len(neg_reps),
        severity="critical" if len(neg_reps) > 0 else "info",
        source="Historical Threat Feeds",
        evidence_type="historical",
        evidence_strength=0.9 if len(neg_reps) > 0 else 0.1,
        metadata=historical_reputation
    ))

    # E14-06: Domain Reuse & Inactivity
    reuse_possible = domain_reuse.get("possible", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=6,
        finding="Domain repurposing and parked/inactive periods",
        value=reuse_possible,
        severity="high" if reuse_possible else "info",
        source="Lifecycle Heuristics",
        evidence_type="historical",
        evidence_strength=0.8 if reuse_possible else 0.1,
        metadata={"domain_reuse": domain_reuse, "inactive_periods": inactive_periods}
    ))

    # E14-07: Historical Inconsistencies
    has_inconsistencies = bool(historical_inconsistencies)
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=7,
        finding="Discrepancies between claimed founding claims and historical archive",
        value=len(historical_inconsistencies),
        severity="high" if has_inconsistencies else "info",
        source="Temporal Consistency Engine",
        evidence_type="inference",
        evidence_strength=0.85 if has_inconsistencies else 0.05,
        metadata={"inconsistencies": historical_inconsistencies}
    ))

    # E14-08: Master Lifecycle Timeline
    structured_evidence.append(create_evidence_item(
        agent_id="A14",
        index=8,
        finding="Chronological domain lifecycle event timeline",
        value=len(master_timeline),
        severity="info",
        source="Integrated Timeline Assembler",
        evidence_type="historical",
        evidence_strength=0.1,
        metadata={"timeline_events": master_timeline}
    ))

    print("[Agent 14] Historical evidence investigation completed.")

    data_payload = {
        "wayback_history": wayback_history,
        "website_history": website_history,
        "historical_ownership": ownership,
        "historical_screenshots": historical_screenshots,
        "historical_reputation": historical_reputation,
        "historical_dns": historical_dns,
        "infrastructure_history": infrastructure_history,
        "domain_reuse": domain_reuse,
        "inactive_periods": inactive_periods,
        "redirect_history": redirect_history,
        "historical_inconsistencies": historical_inconsistencies,
        "timeline": master_timeline,
        "evidence": forensic_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url or normalized_url,
            "domain": domain,
        },
        **data_payload,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A14",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
