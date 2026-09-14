"""
Agent 6 — Reputation & Threat Intelligence
===========================================
Evidence Collection Agent.

Purpose:
    Query external reputation and threat-intelligence sources and collect
    available reputation evidence for the submitted URL, domain, or IP address.

Features / Sources collected (Exactly 10):
    1.  VirusTotal Reputation
    2.  Google Safe Browsing
    3.  PhishTank
    4.  OpenPhish
    5.  AbuseIPDB
    6.  URLHaus
    7.  Spamhaus
    8.  ScamAdviser
    9.  Public Blacklists
    10. Community Reputation

IMPORTANT ARCHITECTURAL RULES:
    - This is strictly an EVIDENCE COLLECTION AGENT.
    - Do NOT calculate the final Trust Score.
    - Do NOT calculate the final phishing probability.
    - Do NOT classify the URL as Safe, Malicious, or Phishing.
    - Do NOT assign the final risk score.
    - Do NOT assign the final confidence score.
    - Never hardcode or leak API keys in source code or responses.
    - Missing or unconfigured APIs return status="not_configured" or status="unavailable".
    - Do NOT fabricate results or return fake zeroes for unqueried services.
"""

import os
import sys
import time
import socket
import base64
import ipaddress
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import dns.resolver
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 10  # Seconds
CACHE_TTL = 300       # Seconds (5 minutes)

# In-memory thread-safe cache
_CACHE_LOCK = threading.Lock()
_CACHE = {}

# OpenPhish in-memory feed cache
_OPENPHISH_CACHE_LOCK = threading.Lock()
_OPENPHISH_CACHE = {
    "feed": set(),
    "fetched_at": 0.0,
    "timestamp_str": None
}


# ---------------------------------------------------------------------------
# Helpers: Time & Logging
# ---------------------------------------------------------------------------

def _get_utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str):
    """Log Agent 6 actions to console cleanly without leaking credentials."""
    print(f"[Agent 6] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Input Normalization & Resolution
# ---------------------------------------------------------------------------

def extract_domain_info(raw_url: str) -> dict:
    """
    Parse input URL and normalize components:
    - original_url
    - scheme
    - hostname
    - domain (root/registered domain)
    - path
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "original_url": "",
            "scheme": "",
            "hostname": "",
            "domain": "",
            "path": "",
            "is_valid": False
        }

    trimmed = raw_url.strip()
    if not trimmed.startswith(("http://", "https://")):
        parsed = urlparse("https://" + trimmed)
        scheme = "https"
    else:
        parsed = urlparse(trimmed)
        scheme = parsed.scheme.lower()

    hostname = (parsed.hostname or "").strip().lower()

    # Extract registrable domain
    domain = hostname
    if _TLDEXTRACT_AVAILABLE and hostname:
        ext = tldextract.extract(hostname)
        if ext.registered_domain:
            domain = ext.registered_domain.lower()
    elif hostname:
        # Fallback split
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])

    return {
        "original_url": trimmed,
        "scheme": scheme,
        "hostname": hostname,
        "domain": domain,
        "path": parsed.path or "/",
        "is_valid": bool(hostname)
    }


def resolve_ip(hostname: str) -> str:
    """
    Resolve hostname to an IPv4 address safely.
    Returns None if resolution fails or if already an IP address.
    """
    if not hostname:
        return None

    # Check if already an IP
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Try DNS resolution
    try:
        if _DNSPYTHON_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                return rdata.to_text()
        else:
            return socket.gethostbyname(hostname)
    except Exception:
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    return None


# ---------------------------------------------------------------------------
# 1. VirusTotal Reputation
# ---------------------------------------------------------------------------

def query_virustotal(original_url: str) -> dict:
    """
    Query the VirusTotal v3 URL analysis endpoint if VIRUSTOTAL_API_KEY is configured.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "message": "API key not configured"
        }

    checked_at = _get_utc_now_iso()

    try:
        # VirusTotal v3 URL identifier is base64 urlsafe encoded without '=' padding
        url_id = base64.urlsafe_b64encode(original_url.encode("utf-8")).decode("utf-8").strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "DigitalForensics-Agent6/1.0"
        }

        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            return {
                "status": "not_found",
                "message": "URL not found in VirusTotal database",
                "checked_at": checked_at
            }
        elif resp.status_code == 429:
            return {
                "status": "rate_limited",
                "message": "VirusTotal API rate limit reached",
                "checked_at": checked_at
            }
        elif resp.status_code == 401 or resp.status_code == 403:
            return {
                "status": "unavailable",
                "message": "Invalid or unauthorized VirusTotal API key",
                "checked_at": checked_at
            }
        elif resp.status_code != 200:
            return {
                "status": "error",
                "message": f"VirusTotal returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }

        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = sum(stats.values()) if stats else 0
        reputation = attributes.get("reputation", 0)
        last_analysis_ts = attributes.get("last_analysis_date")

        last_analysis_str = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).isoformat()
            if last_analysis_ts else "Not Available"
        )

        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines,
            "reputation": reputation,
            "last_analysis": last_analysis_str,
            "report_available": True,
            "checked_at": checked_at
        }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"VirusTotal request timed out after {REQUEST_TIMEOUT}s",
            "checked_at": checked_at
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"VirusTotal query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 2. Google Safe Browsing
# ---------------------------------------------------------------------------

def query_google_safe_browsing(original_url: str) -> dict:
    """
    Query Google Safe Browsing v4 ThreatMatches API if configured.
    """
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") or os.environ.get("SAFE_BROWSING_API_KEY", "")
    api_key = api_key.strip() if api_key else ""

    if not api_key:
        return {
            "status": "not_configured",
            "message": "API key not configured"
        }

    checked_at = _get_utc_now_iso()

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "digital-forensics-agent6",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": original_url}]
            }
        }

        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {
                "status": "rate_limited",
                "message": "Google Safe Browsing rate limit exceeded",
                "checked_at": checked_at
            }
        elif resp.status_code in (401, 403):
            return {
                "status": "unavailable",
                "message": "Invalid Google Safe Browsing API key",
                "checked_at": checked_at
            }
        elif resp.status_code != 200:
            return {
                "status": "error",
                "message": f"Google Safe Browsing returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }

        result_data = resp.json()
        matches = result_data.get("matches", [])

        if matches:
            threat_types = sorted(list(set([m.get("threatType") for m in matches if m.get("threatType")])))
            return {
                "status": "success",
                "threat_detected": True,
                "threat_types": threat_types,
                "checked_at": checked_at
            }
        else:
            return {
                "status": "success",
                "threat_detected": False,
                "threat_types": [],
                "checked_at": checked_at
            }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"Google Safe Browsing request timed out after {REQUEST_TIMEOUT}s",
            "checked_at": checked_at
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Google Safe Browsing query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 3. PhishTank
# ---------------------------------------------------------------------------

def query_phishtank(original_url: str) -> dict:
    """
    Check whether the URL appears in PhishTank database via checkurl API.
    """
    api_key = os.environ.get("PHISHTANK_API_KEY", "").strip()
    checked_at = _get_utc_now_iso()

    try:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        data = {
            "url": original_url,
            "format": "json"
        }
        if api_key:
            data["app_key"] = api_key

        headers = {
            "User-Agent": "phishtank/digital-forensics-agent6"
        }

        resp = requests.post(endpoint, data=data, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429 or resp.status_code == 509:
            return {
                "status": "rate_limited",
                "message": "PhishTank API rate limit exceeded",
                "checked_at": checked_at
            }
        elif resp.status_code != 200:
            return {
                "status": "unavailable",
                "message": f"PhishTank service returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }

        res_json = resp.json()
        results_data = res_json.get("results", {})

        in_database = results_data.get("in_database", False)
        if in_database:
            verified = results_data.get("verified", False)
            verified_at = results_data.get("verified_at")
            return {
                "status": "success",
                "found": True,
                "verified_phishing": bool(verified),
                "verification_date": verified_at or "Not Available",
                "details_available": bool(results_data.get("phish_detail_page")),
                "checked_at": checked_at
            }
        else:
            return {
                "status": "success",
                "found": False,
                "verified_phishing": False,
                "checked_at": checked_at
            }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"PhishTank query timed out after {REQUEST_TIMEOUT}s",
            "checked_at": checked_at
        }
    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"PhishTank lookup unavailable: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 4. OpenPhish
# ---------------------------------------------------------------------------

def _get_openphish_feed() -> tuple[set, str]:
    """
    Fetch or retrieve cached OpenPhish community feed.
    Cached for 10 minutes (600s).
    """
    global _OPENPHISH_CACHE
    now = time.time()

    with _OPENPHISH_CACHE_LOCK:
        if _OPENPHISH_CACHE["feed"] and (now - _OPENPHISH_CACHE["fetched_at"] < 600):
            return _OPENPHISH_CACHE["feed"], _OPENPHISH_CACHE["timestamp_str"]

    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "DigitalForensics-Agent6/1.0"},
            timeout=REQUEST_TIMEOUT
        )
        if resp.status_code == 200 and resp.text:
            lines = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
            ts_str = _get_utc_now_iso()
            with _OPENPHISH_CACHE_LOCK:
                _OPENPHISH_CACHE["feed"] = lines
                _OPENPHISH_CACHE["fetched_at"] = now
                _OPENPHISH_CACHE["timestamp_str"] = ts_str
            return lines, ts_str
    except Exception:
        pass

    with _OPENPHISH_CACHE_LOCK:
        return _OPENPHISH_CACHE["feed"], _OPENPHISH_CACHE["timestamp_str"]


def query_openphish(original_url: str, hostname: str) -> dict:
    """
    Check if the URL or host matches the OpenPhish threat feed.
    """
    checked_at = _get_utc_now_iso()

    try:
        feed, feed_ts = _get_openphish_feed()

        if not feed:
            return {
                "status": "unavailable",
                "message": "OpenPhish feed temporarily unavailable",
                "checked_at": checked_at
            }

        # Check exact URL or variations
        norm_url = original_url.strip().rstrip("/")
        matched_url = None

        for item in feed:
            item_norm = item.strip().rstrip("/")
            if norm_url == item_norm or (hostname and hostname in item):
                matched_url = item
                break

        if matched_url:
            return {
                "status": "success",
                "found": True,
                "matched_url": matched_url,
                "feed_timestamp": feed_ts or checked_at,
                "checked_at": checked_at
            }
        else:
            return {
                "status": "success",
                "found": False,
                "checked_at": checked_at
            }

    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"OpenPhish query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 5. AbuseIPDB
# ---------------------------------------------------------------------------

def query_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB API v2 for IP address reputation if ABUSEIPDB_API_KEY is configured.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "message": "API key not configured"
        }

    if not ip:
        return {
            "status": "error",
            "message": "No IP address available to query AbuseIPDB"
        }

    checked_at = _get_utc_now_iso()

    try:
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        headers = {
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "DigitalForensics-Agent6/1.0"
        }

        resp = requests.get(endpoint, params=params, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {
                "status": "rate_limited",
                "message": "AbuseIPDB API rate limit exceeded",
                "checked_at": checked_at
            }
        elif resp.status_code in (401, 403):
            return {
                "status": "unavailable",
                "message": "Invalid or unauthorized AbuseIPDB API key",
                "checked_at": checked_at
            }
        elif resp.status_code != 200:
            return {
                "status": "error",
                "message": f"AbuseIPDB returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }

        data = resp.json().get("data", {})

        return {
            "status": "success",
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode") or "Unknown",
            "isp": data.get("isp") or "Unknown",
            "domain": data.get("domain") or "Unknown",
            "usage_type": data.get("usageType") or "Unknown",
            "last_reported_at": data.get("lastReportedAt") or "Not Reported",
            "checked_at": checked_at
        }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"AbuseIPDB request timed out after {REQUEST_TIMEOUT}s",
            "checked_at": checked_at
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"AbuseIPDB query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 6. URLHaus
# ---------------------------------------------------------------------------

def query_urlhaus(original_url: str, hostname: str) -> dict:
    """
    Check URLHaus public API (abuse.ch) for malware URLs and hosts.
    """
    checked_at = _get_utc_now_iso()

    try:
        headers = {"User-Agent": "DigitalForensics-Agent6/1.0"}
        api_key = os.environ.get("URLHAUS_API_KEY", "").strip()
        if api_key:
            headers["Auth-Key"] = api_key

        url_found = False
        host_found = False
        threat = None
        date_added = None
        status_from_source = None

        # 1. Query URL endpoint
        url_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        url_resp = requests.post(url_endpoint, data={"url": original_url}, headers=headers, timeout=REQUEST_TIMEOUT)

        if url_resp.status_code == 200:
            url_json = url_resp.json()
            q_status = url_json.get("query_status")
            if q_status == "ok":
                url_found = True
                threat = url_json.get("threat")
                date_added = url_json.get("date_added")
                status_from_source = url_json.get("url_status")
            elif q_status == "no_results":
                url_found = False

        # 2. Query Host endpoint if hostname exists
        if hostname:
            host_endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            host_resp = requests.post(host_endpoint, data={"host": hostname}, headers=headers, timeout=REQUEST_TIMEOUT)
            if host_resp.status_code == 200:
                host_json = host_resp.json()
                q_status = host_json.get("query_status")
                if q_status == "ok":
                    host_found = True
                    if not threat:
                        threat = host_json.get("threat")
                    if not date_added:
                        date_added = host_json.get("firstseen")

        return {
            "status": "success",
            "url_found": url_found,
            "host_found": host_found,
            "threat": threat or "None",
            "date_added": date_added or "Not Listed",
            "status_from_source": status_from_source or "Not Listed",
            "checked_at": checked_at
        }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"URLHaus query timed out after {REQUEST_TIMEOUT}s",
            "checked_at": checked_at
        }
    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"URLHaus query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 7. Spamhaus
# ---------------------------------------------------------------------------

def query_spamhaus(ip: str, domain: str) -> dict:
    """
    Check Spamhaus reputation and blocklists where authorized / permitted.
    Spamhaus requires Data Query Service (DQS) key for automated DNSBL queries.
    Never scrape or bypass access restrictions.
    """
    dqs_key = os.environ.get("SPAMHAUS_DQS_KEY") or os.environ.get("SPAMHAUS_API_KEY", "")
    dqs_key = dqs_key.strip() if dqs_key else ""

    checked_at = _get_utc_now_iso()

    if not dqs_key:
        return {
            "status": "not_configured",
            "message": "Spamhaus DQS API key not configured (required for automated queries under Spamhaus ToS)",
            "checked_at": checked_at
        }

    try:
        listed_lists = []
        is_listed = False

        if _DNSPYTHON_AVAILABLE and ip:
            # Reverse IP for DNSBL: a.b.c.d -> d.c.b.a.<dqs_key>.zen.dq.spamhaus.net
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    rev_ip = ".".join(reversed(ip.split(".")))
                    query_host = f"{rev_ip}.{dqs_key}.zen.dq.spamhaus.net"

                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3.0
                    resolver.lifetime = 3.0
                    answers = resolver.resolve(query_host, "A")

                    for rdata in answers:
                        r_ip = rdata.to_text()
                        if r_ip.startswith("127.0.0."):
                            is_listed = True
                            subcode = r_ip.split(".")[-1]
                            reason_map = {
                                "2": "SBL (Spamhaus Block List)",
                                "3": "CSS (Spamhaus CSS)",
                                "4": "XBL (Exploits Block List)",
                                "10": "PBL (Policy Block List)",
                                "11": "PBL (Policy Block List)"
                            }
                            listed_lists.append({
                                "name": reason_map.get(subcode, f"Spamhaus ZEN ({r_ip})"),
                                "reason": f"Listed on Spamhaus ZEN return code {r_ip}"
                            })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                pass

        return {
            "status": "success",
            "listed": is_listed,
            "lists": listed_lists,
            "checked_at": checked_at
        }

    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"Spamhaus query failed: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 8. ScamAdviser
# ---------------------------------------------------------------------------

def query_scamadviser(domain: str) -> dict:
    """
    Check ScamAdviser reputation only through permitted / official API.
    Does NOT scrape aggressively. If no API key configured, returns status unavailable.
    """
    api_key = os.environ.get("SCAMADVISER_API_KEY", "").strip()
    checked_at = _get_utc_now_iso()

    if not api_key:
        return {
            "status": "unavailable",
            "reason": "No permitted API configured",
            "checked_at": checked_at
        }

    try:
        endpoint = "https://api.scamadviser.com/v1/domain/check"
        params = {"domain": domain}
        headers = {
            "x-api-key": api_key,
            "Accept": "application/json",
            "User-Agent": "DigitalForensics-Agent6/1.0"
        }

        resp = requests.get(endpoint, params=params, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "success",
                "domain": domain,
                "trust_score_indicator": data.get("trust_score"),
                "domain_age_days": data.get("domain_age_days"),
                "warning_flags": data.get("flags", []),
                "checked_at": checked_at
            }
        else:
            return {
                "status": "unavailable",
                "reason": f"ScamAdviser API returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }

    except Exception as e:
        return {
            "status": "unavailable",
            "reason": f"ScamAdviser lookup unavailable: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# 9. Public Blacklists (Modular Architecture)
# ---------------------------------------------------------------------------

class PublicBlacklistChecker:
    """
    Modular engine for inspecting domain and IP public reputation blocklists.
    """
    DNSBL_IP_SOURCES = [
        {"name": "Spamcop BL", "zone": "bl.spamcop.net", "category": "spam_reputation"},
        {"name": "Barracuda BRBL", "zone": "b.barracudacentral.org", "category": "reputation"},
        {"name": "Blocklist.de", "zone": "bl.blocklist.de", "category": "bruteforce_attacks"},
        {"name": "SORBS DNSBL", "zone": "dnsbl.sorbs.net", "category": "spam_aggregate"}
    ]

    DNSBL_DOMAIN_SOURCES = [
        {"name": "SURBL", "zone": "multi.surbl.org", "category": "phishing_uri"},
        {"name": "URIBL", "zone": "black.uribl.com", "category": "malicious_domains"}
    ]

    @classmethod
    def check_ip_dnsbl(cls, ip: str) -> list:
        results = []
        if not ip or not _DNSPYTHON_AVAILABLE:
            return results

        try:
            ip_obj = ipaddress.ip_address(ip)
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return results
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return results

            rev_ip = ".".join(reversed(ip.split(".")))
        except ValueError:
            return results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for src in cls.DNSBL_IP_SOURCES:
            query_target = f"{rev_ip}.{src['zone']}"
            ts = _get_utc_now_iso()
            try:
                answers = resolver.resolve(query_target, "A")
                results.append({
                    "source": src["name"],
                    "query": ip,
                    "type": "ip",
                    "listed": True,
                    "category": src["category"],
                    "response": [r.to_text() for r in answers],
                    "timestamp": ts,
                    "source_status": "success"
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results.append({
                    "source": src["name"],
                    "query": ip,
                    "type": "ip",
                    "listed": False,
                    "category": src["category"],
                    "timestamp": ts,
                    "source_status": "success"
                })
            except Exception as ex:
                results.append({
                    "source": src["name"],
                    "query": ip,
                    "type": "ip",
                    "listed": False,
                    "category": src["category"],
                    "timestamp": ts,
                    "source_status": "unavailable"
                })

        return results

    @classmethod
    def check_domain_dnsbl(cls, domain: str) -> list:
        results = []
        if not domain or not _DNSPYTHON_AVAILABLE:
            return results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for src in cls.DNSBL_DOMAIN_SOURCES:
            query_target = f"{domain}.{src['zone']}"
            ts = _get_utc_now_iso()
            try:
                answers = resolver.resolve(query_target, "A")
                results.append({
                    "source": src["name"],
                    "query": domain,
                    "type": "domain",
                    "listed": True,
                    "category": src["category"],
                    "response": [r.to_text() for r in answers],
                    "timestamp": ts,
                    "source_status": "success"
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results.append({
                    "source": src["name"],
                    "query": domain,
                    "type": "domain",
                    "listed": False,
                    "category": src["category"],
                    "timestamp": ts,
                    "source_status": "success"
                })
            except Exception as ex:
                results.append({
                    "source": src["name"],
                    "query": domain,
                    "type": "domain",
                    "listed": False,
                    "category": src["category"],
                    "timestamp": ts,
                    "source_status": "unavailable"
                })

        return results


def query_public_blacklists(ip: str, domain: str) -> list:
    """
    Execute modular blacklist checks across configured DNSBL sources.
    """
    entries = []
    if ip:
        entries.extend(PublicBlacklistChecker.check_ip_dnsbl(ip))
    if domain:
        entries.extend(PublicBlacklistChecker.check_domain_dnsbl(domain))
    return entries


# ---------------------------------------------------------------------------
# 10. Community Reputation
# ---------------------------------------------------------------------------

def query_community_reputation(domain: str, ip: str) -> dict:
    """
    Query community-contributed threat feeds (e.g., AlienVault OTX) if configured.
    Does NOT invent fake community reputation or use unscientific search hits.
    """
    otx_key = os.environ.get("ALIENVAULT_OTX_API_KEY", "").strip()
    checked_at = _get_utc_now_iso()

    if not otx_key:
        return {
            "status": "unavailable",
            "reason": "No configured community reputation source",
            "checked_at": checked_at
        }

    try:
        # If AlienVault OTX is configured
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {
            "X-OTX-API-KEY": otx_key,
            "Accept": "application/json",
            "User-Agent": "DigitalForensics-Agent6/1.0"
        }
        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            return {
                "status": "success",
                "source": "AlienVault OTX",
                "pulse_count": pulse_info.get("count", 0),
                "community_references": len(pulse_info.get("pulses", [])),
                "checked_at": checked_at
            }
        else:
            return {
                "status": "unavailable",
                "reason": f"Community source returned HTTP {resp.status_code}",
                "checked_at": checked_at
            }
    except Exception as e:
        return {
            "status": "unavailable",
            "reason": f"Community lookup error: {str(e)}",
            "checked_at": checked_at
        }


# ---------------------------------------------------------------------------
# Main Agent 6 Entrypoint
# ---------------------------------------------------------------------------

def analyze_reputation(raw_url: str) -> dict:
    """
    Execute comprehensive reputation and threat intelligence evidence collection
    across 10 external security sources.

    Strict rules:
    - Evidence collection only.
    - No final Trust Score or Risk Score calculation.
    - No Safe/Malicious/Phishing classifications.
    - Concurrency and timeouts for high performance and resilience.
    - Result caching for identical URLs within CACHE_TTL.
    """
    _log("Starting reputation analysis...")
    _log(f"Input URL: {raw_url}")

    # Validate input URL
    norm = extract_domain_info(raw_url)
    if not norm["is_valid"]:
        _log("Invalid URL provided.")
        extra = {
            "input": {
                "url": raw_url,
                "domain": "",
                "ip": None
            },
            "virustotal": {"status": "error", "message": "Invalid URL provided"},
            "google_safe_browsing": {"status": "error", "message": "Invalid URL provided"},
            "phishtank": {"status": "error", "message": "Invalid URL provided"},
            "openphish": {"status": "error", "message": "Invalid URL provided"},
            "abuseipdb": {"status": "error", "message": "Invalid URL provided"},
            "urlhaus": {"status": "error", "message": "Invalid URL provided"},
            "spamhaus": {"status": "error", "message": "Invalid URL provided"},
            "scamadviser": {"status": "unavailable", "reason": "Invalid URL provided"},
            "public_blacklists": [],
            "community_reputation": {"status": "unavailable", "reason": "Invalid URL provided"}
        }
        return build_agent_result(
            agent_identifier="A6",
            target=raw_url or "",
            status="error",
            data={},
            evidence=[],
            errors=["Input URL is empty or invalid."],
            extra_fields=extra
        )

    original_url = norm["original_url"]
    hostname = norm["hostname"]
    domain = norm["domain"]

    # Check in-memory cache
    cache_key = original_url.lower()
    now_time = time.time()
    with _CACHE_LOCK:
        if cache_key in _CACHE:
            cached_item, cache_ts = _CACHE[cache_key]
            if now_time - cache_ts < CACHE_TTL:
                _log("Returning cached reputation analysis result.")
                return cached_item

    _log("Extracting domain...")
    _log(f"Extracted domain: {domain}, hostname: {hostname}")

    _log("Resolving IP...")
    resolved_ip = resolve_ip(hostname)
    _log(f"Resolved IP: {resolved_ip or 'None'}")

    errors = []

    # Parallel Execution of all 10 independent threat intelligence sources
    results = {}

    def _run_vt():
        _log("Querying VirusTotal...")
        return "virustotal", query_virustotal(original_url)

    def _run_gsb():
        _log("Querying Google Safe Browsing...")
        return "google_safe_browsing", query_google_safe_browsing(original_url)

    def _run_pt():
        _log("Querying PhishTank...")
        return "phishtank", query_phishtank(original_url)

    def _run_op():
        _log("Querying OpenPhish...")
        return "openphish", query_openphish(original_url, hostname)

    def _run_abuse():
        _log("Querying AbuseIPDB...")
        return "abuseipdb", query_abuseipdb(resolved_ip)

    def _run_uh():
        _log("Querying URLHaus...")
        return "urlhaus", query_urlhaus(original_url, hostname)

    def _run_sh():
        _log("Querying Spamhaus...")
        return "spamhaus", query_spamhaus(resolved_ip, domain)

    def _run_sa():
        return "scamadviser", query_scamadviser(domain)

    def _run_bl():
        _log("Checking public blacklists...")
        return "public_blacklists", query_public_blacklists(resolved_ip, domain)

    def _run_cr():
        _log("Collecting community reputation...")
        return "community_reputation", query_community_reputation(domain, resolved_ip)

    tasks = [
        _run_vt,
        _run_gsb,
        _run_pt,
        _run_op,
        _run_abuse,
        _run_uh,
        _run_sh,
        _run_sa,
        _run_bl,
        _run_cr
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fn) for fn in tasks]
        for future in as_completed(futures):
            try:
                src_key, src_data = future.result()
                results[src_key] = src_data
            except Exception as e:
                errors.append(f"Unexpected source runner exception: {str(e)}")

    # Ensure all required keys exist
    vt_res = results.get("virustotal", {"status": "unavailable"})
    gsb_res = results.get("google_safe_browsing", {"status": "unavailable"})
    pt_res = results.get("phishtank", {"status": "unavailable"})
    op_res = results.get("openphish", {"status": "unavailable"})
    abuse_res = results.get("abuseipdb", {"status": "unavailable"})
    uh_res = results.get("urlhaus", {"status": "unavailable"})
    sh_res = results.get("spamhaus", {"status": "unavailable"})
    sa_res = results.get("scamadviser", {"status": "unavailable"})
    bl_res = results.get("public_blacklists", [])
    cr_res = results.get("community_reputation", {"status": "unavailable"})

    # Structured data object
    data_payload = {
        "url": original_url,
        "hostname": hostname,
        "domain": domain,
        "ip": resolved_ip,
        "virustotal": vt_res,
        "google_safe_browsing": gsb_res,
        "phishtank": pt_res,
        "openphish": op_res,
        "abuseipdb": abuse_res,
        "urlhaus": uh_res,
        "spamhaus": sh_res,
        "scamadviser": sa_res,
        "public_blacklists": bl_res,
        "community_reputation": cr_res
    }

    # Step 11: Compile structured evidence items
    evidence = []
    
    vt_mal = vt_res.get("malicious", 0) if isinstance(vt_res, dict) else 0
    vt_sev = "critical" if vt_mal > 0 else "info"
    evidence.append(create_evidence_item("A6", 1, "VirusTotal malicious detection count", vt_mal, severity=vt_sev, source="VirusTotal", evidence_type="threat_intelligence", evidence_strength=0.95 if vt_mal > 0 else None, metadata=vt_res if isinstance(vt_res, dict) else {}))
    
    gsb_match = gsb_res.get("threat_detected", False) if isinstance(gsb_res, dict) else False
    evidence.append(create_evidence_item("A6", 2, "Google Safe Browsing threat match", gsb_match, severity="critical" if gsb_match else "info", source="Google Safe Browsing", evidence_type="threat_intelligence", evidence_strength=0.98 if gsb_match else None, metadata=gsb_res if isinstance(gsb_res, dict) else {}))
    
    pt_match = pt_res.get("in_database", False) if isinstance(pt_res, dict) else False
    evidence.append(create_evidence_item("A6", 3, "PhishTank phishing verified match", pt_match, severity="critical" if pt_match else "info", source="PhishTank", evidence_type="threat_intelligence", evidence_strength=0.95 if pt_match else None, metadata=pt_res if isinstance(pt_res, dict) else {}))
    
    op_match = op_res.get("in_feed", False) if isinstance(op_res, dict) else False
    evidence.append(create_evidence_item("A6", 4, "OpenPhish feed detection match", op_match, severity="critical" if op_match else "info", source="OpenPhish", evidence_type="threat_intelligence", evidence_strength=0.95 if op_match else None, metadata=op_res if isinstance(op_res, dict) else {}))
    
    abuse_score = abuse_res.get("abuse_confidence_score", 0) if isinstance(abuse_res, dict) else 0
    abuse_sev = "high" if (isinstance(abuse_score, (int, float)) and abuse_score > 50) else "info"
    evidence.append(create_evidence_item("A6", 5, "AbuseIPDB IP confidence score", abuse_score, severity=abuse_sev, source="AbuseIPDB", evidence_type="threat_intelligence", evidence_strength=0.90 if (isinstance(abuse_score, (int, float)) and abuse_score > 50) else None, metadata=abuse_res if isinstance(abuse_res, dict) else {}))
    
    uh_match = uh_res.get("threat_detected", False) if isinstance(uh_res, dict) else False
    evidence.append(create_evidence_item("A6", 6, "URLhaus malware URL listing", uh_match, severity="critical" if uh_match else "info", source="URLhaus", evidence_type="threat_intelligence", evidence_strength=0.95 if uh_match else None, metadata=uh_res if isinstance(uh_res, dict) else {}))
    
    sh_match = sh_res.get("listed", False) if isinstance(sh_res, dict) else False
    evidence.append(create_evidence_item("A6", 7, "Spamhaus blocklist listing", sh_match, severity="high" if sh_match else "info", source="Spamhaus", evidence_type="threat_intelligence", evidence_strength=0.90 if sh_match else None, metadata=sh_res if isinstance(sh_res, dict) else {}))
    
    bl_count = len(bl_res) if isinstance(bl_res, list) else 0
    evidence.append(create_evidence_item("A6", 8, "Public DNSBL blacklists matches", bl_count, severity="medium" if bl_count > 0 else "info", source="DNSBL Blacklists", evidence_type="threat_intelligence", metadata={"blacklists": bl_res} if isinstance(bl_res, list) else {}))
    
    evidence.append(create_evidence_item("A6", 9, "Scamadviser reputation analysis", sa_res.get("status") if isinstance(sa_res, dict) else "unavailable", severity="info", source="Scamadviser", evidence_type="external_source", metadata=sa_res if isinstance(sa_res, dict) else {}))
    evidence.append(create_evidence_item("A6", 10, "Community reputation telemetry", cr_res.get("status") if isinstance(cr_res, dict) else "unavailable", severity="info", source="Community telemetry", evidence_type="external_source", metadata=cr_res if isinstance(cr_res, dict) else {}))

    extra_fields = {
        "input": {
            "url": original_url,
            "domain": domain,
            "ip": resolved_ip
        },
        "virustotal": vt_res,
        "google_safe_browsing": gsb_res,
        "phishtank": pt_res,
        "openphish": op_res,
        "abuseipdb": abuse_res,
        "urlhaus": uh_res,
        "spamhaus": sh_res,
        "scamadviser": sa_res,
        "public_blacklists": bl_res,
        "community_reputation": cr_res
    }

    final_response = build_agent_result(
        agent_identifier="A6",
        target=original_url,
        status="success",
        data=data_payload,
        evidence=evidence,
        errors=errors,
        extra_fields=extra_fields
    )

    # Store in memory cache
    with _CACHE_LOCK:
        _CACHE[cache_key] = (final_response, time.time())

    _log("Reputation analysis completed.")
    return final_response


def get_reputation_evidence(url: str) -> dict:
    """
    Convenience alias for analyze_reputation().
    """
    return analyze_reputation(url)
