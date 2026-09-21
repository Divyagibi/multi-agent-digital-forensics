"""
Agent 2 — DNS & Infrastructure
==============================
Evidence Collection Agent.

Purpose:
    Determine and collect reliable DNS resolution records and server infrastructure
    evidence associated with the given domain or URL.

Main question answered:
    "How does this domain resolve on the Internet, what DNS records does it have,
    what IP/network is associated with it, and whether there is evidence of a
    hosting provider or CDN?"

Features collected:
    1.  DNS Records (overall structured summary)
    2.  A Record (IPv4 addresses)
    3.  AAAA Record (IPv6 addresses)
    4.  MX Record (Mail exchange servers with priority)
    5.  NS Record (Authoritative nameservers)
    6.  TXT Record (Text / SPF / verification records)
    7.  CNAME Record (Canonical name aliases)
    8.  Reverse DNS (PTR hostnames for resolved IPs)
    9.  DNSSEC (DS / DNSKEY record status)
    10. Hosting Provider (Organization, ASN, Network name)
    11. Server IP Address (Primary resolved IP and all server IPs)
    12. CDN Detection (Multi-signal CDN identification & evidence)

IMPORTANT:
    This agent is ONLY an evidence collection agent.
    It does NOT calculate trust scores, risk scores, or classify the domain
    as malicious/safe.
"""

import dns.resolver
import dns.rdatatype
import socket
import requests
from urllib.parse import urlparse

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# HELPER: Domain and Hostname Extraction
# ---------------------------------------------------------------------------

def extract_host_and_domain(url: str):
    """
    Extract the specific hostname and registrable domain from a URL or raw string.

    Examples:
        "https://www.example.com/login"          -> hostname: "www.example.com", registrable: "example.com"
        "https://login.shop.example.co.uk/page"  -> hostname: "login.shop.example.co.uk", registrable: "example.co.uk"
        "example.com"                            -> hostname: "example.com", registrable: "example.com"

    Returns:
        tuple: (hostname, registrable_domain) or (None, None) on failure.
    """
    if not url or not isinstance(url, str):
        return None, None

    url = url.strip()
    if not url:
        return None, None

    # Prepend scheme if missing so urlparse works reliably
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None, None

        hostname = hostname.lower()

        # Extract registrable domain using tldextract
        if _TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(hostname)
            if extracted.domain and extracted.suffix:
                registrable = f"{extracted.domain}.{extracted.suffix}".lower()
            elif extracted.domain:
                registrable = extracted.domain.lower()
            else:
                registrable = hostname
        else:
            # Fallback: strip www if present
            registrable = hostname[4:] if hostname.startswith("www.") else hostname

        return hostname, registrable

    except Exception:
        return None, None


def extract_domain(url: str) -> str:
    """
    Legacy helper extracting the primary domain / hostname for DNS lookup.
    """
    hostname, registrable = extract_host_and_domain(url)
    return hostname or ""


# ---------------------------------------------------------------------------
# HELPER: DNS Query Resolver Setup
# ---------------------------------------------------------------------------

def _get_configured_resolver(timeout: float = 5.0, lifetime: float = 8.0) -> dns.resolver.Resolver:
    """
    Instantiate a dns.resolver.Resolver with robust timeout and fallback nameservers.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    # Standard public DNS fallbacks if system resolver has trouble
    # Default nameservers are retained from system configuration
    return resolver


# ---------------------------------------------------------------------------
# HELPER: DNS Records Resolution (A, AAAA, MX, NS, TXT, CNAME)
# ---------------------------------------------------------------------------

def query_a_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[str], str | None]:
    """Query IPv4 A records."""
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "A")
        for rdata in answers:
            records.append(str(rdata))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"A record query timed out for {target}"
    except Exception as e:
        error = f"A record query error for {target}: {str(e)}"
    return records, error


def query_aaaa_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[str], str | None]:
    """Query IPv6 AAAA records."""
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "AAAA")
        for rdata in answers:
            records.append(str(rdata))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"AAAA record query timed out for {target}"
    except Exception as e:
        error = f"AAAA record query error for {target}: {str(e)}"
    return records, error


def query_mx_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[dict], str | None]:
    """
    Query MX records, preserving preference / priority.
    Returns: list of {"priority": int, "exchange": str}
    """
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "MX")
        for rdata in answers:
            records.append({
                "priority": int(rdata.preference),
                "exchange": str(rdata.exchange).rstrip(".")
            })
        # Sort MX records by priority ascending
        records.sort(key=lambda x: x["priority"])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"MX record query timed out for {target}"
    except Exception as e:
        error = f"MX record query error for {target}: {str(e)}"
    return records, error


def query_ns_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[str], str | None]:
    """Query authoritative NS records."""
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "NS")
        for rdata in answers:
            records.append(str(rdata.target).rstrip("."))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"NS record query timed out for {target}"
    except Exception as e:
        error = f"NS record query error for {target}: {str(e)}"
    return records, error


def query_txt_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[str], str | None]:
    """Query TXT records."""
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "TXT")
        for rdata in answers:
            # Join multiple byte strings if rdata.strings contains chunks
            txt_content = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt_content)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"TXT record query timed out for {target}"
    except Exception as e:
        error = f"TXT record query error for {target}: {str(e)}"
    return records, error


def query_cname_records(resolver: dns.resolver.Resolver, target: str) -> tuple[list[str], str | None]:
    """Query CNAME records."""
    records = []
    error = None
    try:
        answers = resolver.resolve(target, "CNAME")
        for rdata in answers:
            records.append(str(rdata.target).rstrip("."))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout:
        error = f"CNAME record query timed out for {target}"
    except Exception as e:
        error = f"CNAME record query error for {target}: {str(e)}"
    return records, error


import dns.reversename


def perform_reverse_dns(ip_addresses: list[str]) -> dict[str, list[str]]:
    """
    Perform PTR reverse DNS lookup for each resolved IP address.

    Returns:
        dict: { "ip_address": ["ptr_hostname.example.com"] }
    """
    results = {}
    rev_resolver = dns.resolver.Resolver()
    rev_resolver.timeout = 2.0
    rev_resolver.lifetime = 3.0

    for ip in ip_addresses:
        results[ip] = []
        if not ip or ip == "Not available":
            continue
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = rev_resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                ptr_clean = str(rdata.target).rstrip(".")
                if ptr_clean and ptr_clean not in results[ip]:
                    results[ip].append(ptr_clean)
        except Exception:
            # Normal: many IPs do not have PTR records
            pass
    return results


# ---------------------------------------------------------------------------
# HELPER: DNSSEC Status Determination
# ---------------------------------------------------------------------------

def check_dnssec_status(resolver: dns.resolver.Resolver, target: str, registrable_domain: str) -> dict:
    """
    Check for DNSSEC records (DS, DNSKEY) and assess deployment status.

    Does NOT classify DNSSEC presence as safe or absent as malicious.
    Evidence collection only.
    """
    ds_present = False
    dnskey_present = False
    status = "Not detected"

    domains_to_check = [target]
    if registrable_domain and registrable_domain != target:
        domains_to_check.append(registrable_domain)

    # 1. Check DS records (Delegation Signer)
    for dom in domains_to_check:
        try:
            ds_answers = resolver.resolve(dom, "DS")
            if len(ds_answers) > 0:
                ds_present = True
                break
        except Exception:
            pass

    # 2. Check DNSKEY records
    for dom in domains_to_check:
        try:
            dnskey_answers = resolver.resolve(dom, "DNSKEY")
            if len(dnskey_answers) > 0:
                dnskey_present = True
                break
        except Exception:
            pass

    if ds_present and dnskey_present:
        status = "Enabled"
    elif ds_present or dnskey_present:
        status = "Enabled"
    else:
        status = "Not detected"

    return {
        "status": status,
        "ds_present": ds_present,
        "dnskey_present": dnskey_present
    }


# ---------------------------------------------------------------------------
# HELPER: Hosting Provider & ASN Identification
# ---------------------------------------------------------------------------

def get_hosting_provider_info(server_ip: str) -> dict:
    """
    Query IP/ASN ownership information for the primary resolved server IP via RDAP.

    Returns:
        dict: {
            "organization": str,
            "asn": str,
            "network": str,
            "country": str
        }
    """
    default_info = {
        "organization": "Not Available",
        "asn": "Not Available",
        "network": "Not Available",
        "country": "Not Available"
    }

    if not server_ip or server_ip == "Not available":
        return default_info

    try:
        rdap_url = f"https://rdap.org/ip/{server_ip}"
        resp = requests.get(
            rdap_url,
            timeout=5,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "DigitalForensicsAgent/1.0 (EvidenceCollection)"
            }
        )

        if resp.status_code == 200:
            data = resp.json()
            net_name = data.get("name") or "Not Available"
            country = data.get("country") or "Not Available"
            org_name = "Not Available"
            asn_str = "Not Available"

            # Check handle or autnums
            autnums = data.get("autnums", [])
            if autnums and isinstance(autnums, list):
                asn_str = f"AS{autnums[0]}"
            elif data.get("handle"):
                handle = str(data.get("handle"))
                if handle.upper().startswith("AS"):
                    asn_str = handle

            # Search entities for organization/owner name
            entities = data.get("entities", [])
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                vcard_array = entity.get("vcardArray")
                if vcard_array and len(vcard_array) > 1:
                    for field in vcard_array[1]:
                        if isinstance(field, list) and len(field) >= 4:
                            if field[0] in ("fn", "org") and field[3]:
                                candidate = str(field[3]).strip()
                                if candidate and candidate.lower() != "noc":
                                    org_name = candidate
                                    break
                if org_name != "Not Available":
                    break

            if org_name == "Not Available" and net_name != "Not Available":
                org_name = net_name

            return {
                "organization": org_name,
                "asn": asn_str,
                "network": str(net_name),
                "country": str(country)
            }

    except Exception:
        pass

    return default_info


# ---------------------------------------------------------------------------
# HELPER: CDN Multi-Signal Detection
# ---------------------------------------------------------------------------

def detect_cdn(
    domain: str,
    cname_records: list[str],
    ns_records: list[str],
    reverse_dns_dict: dict[str, list[str]],
    server_ips: list[str],
    hosting_org: str
) -> dict:
    """
    Detect CDN / reverse-proxy infrastructure using multiple corroborating signals:
    1. CNAME records
    2. NS nameservers
    3. Reverse DNS hostnames
    4. Hosting Organization / ASN
    5. HTTP response headers (lightweight HEAD request)

    Returns:
        dict: {
            "detected": bool,
            "provider": str | null,
            "evidence": list[str]
        }
    """
    cdn_signatures = {
        "Cloudflare": ["cloudflare.com", "cloudflare.net", "cloudflare"],
        "Amazon CloudFront": ["cloudfront.net", "amazonaws.com", "awsdns"],
        "Akamai": ["akamai.net", "akamaiedge.net", "akamai.com", "akamaitechnologies", "akadns.net"],
        "Fastly": ["fastly.net", "fastlylb.net", "fastly"],
        "Google Cloud CDN": ["1e100.net", "googlehosted.com", "googleusercontent.com"],
        "Microsoft Azure CDN": ["azureedge.net", "azurewebsites.net", "trafficmanager.net", "azurefd.net"],
        "Imperva Incapsula": ["incapdns.net", "impervadns.net", "incapsula"],
        "Sucuri": ["sucuri.net", "sucuridns.com"]
    }

    detected_provider = None
    evidence = []

    # 1. Check CNAME records
    for cname in cname_records:
        cname_lower = cname.lower()
        for provider, sigs in cdn_signatures.items():
            if any(sig in cname_lower for sig in sigs):
                detected_provider = provider
                evidence.append(f"CNAME alias points to {provider} infrastructure ({cname})")
                break
        if detected_provider:
            break

    # 2. Check Name Servers (NS)
    for ns in ns_records:
        ns_lower = ns.lower()
        for provider, sigs in cdn_signatures.items():
            if any(sig in ns_lower for sig in sigs):
                if not detected_provider:
                    detected_provider = provider
                evidence.append(f"Authoritative nameserver matches {provider} ({ns})")
                break

    # 3. Check Reverse DNS (PTR)
    for ip, ptr_list in reverse_dns_dict.items():
        for ptr in ptr_list:
            ptr_lower = ptr.lower()
            for provider, sigs in cdn_signatures.items():
                if any(sig in ptr_lower for sig in sigs):
                    if not detected_provider:
                        detected_provider = provider
                    evidence.append(f"Reverse DNS PTR for {ip} indicates {provider} ({ptr})")
                    break

    # 4. Check Hosting Provider / ASN Organization
    if hosting_org and hosting_org != "Not Available":
        h_lower = hosting_org.lower()
        for provider, sigs in cdn_signatures.items():
            if any(sig in h_lower for sig in sigs) or provider.lower() in h_lower:
                if not detected_provider:
                    detected_provider = provider
                evidence.append(f"Network / ASN organization identifies as {hosting_org}")
                break

    # 5. Check HTTP Response Headers
    if domain:
        try:
            resp = requests.head(
                f"https://{domain}",
                timeout=4,
                headers={"User-Agent": "DigitalForensicsAgent/1.0 (EvidenceCollection)"},
                allow_redirects=True
            )
            headers = resp.headers
            server_hdr = headers.get("Server", "").strip()

            if "cloudflare" in server_hdr.lower() or "cf-ray" in headers:
                if not detected_provider:
                    detected_provider = "Cloudflare"
                evidence.append(f"HTTP response header: Server={server_hdr or 'cloudflare'}, CF-RAY present")
            elif "x-amz-cf-id" in headers or "cloudfront" in server_hdr.lower():
                if not detected_provider:
                    detected_provider = "Amazon CloudFront"
                evidence.append(f"HTTP response contains CloudFront header (X-Amz-Cf-Id)")
            elif "akamai" in server_hdr.lower() or "x-akamai-transformed" in headers:
                if not detected_provider:
                    detected_provider = "Akamai"
                evidence.append(f"HTTP response contains Akamai header")
            elif "fastly" in server_hdr.lower() or "x-fastly-request-id" in headers:
                if not detected_provider:
                    detected_provider = "Fastly"
                evidence.append(f"HTTP response contains Fastly header")
            elif "x-sucuri-id" in headers:
                if not detected_provider:
                    detected_provider = "Sucuri"
                evidence.append(f"HTTP response contains Sucuri protection header")
        except Exception:
            pass

    if detected_provider:
        return {
            "detected": True,
            "provider": detected_provider,
            "evidence": evidence
        }
    else:
        return {
            "detected": False,
            "provider": None,
            "evidence": []
        }


# ---------------------------------------------------------------------------
# MAIN FUNCTION: analyze_dns / get_dns_records
# ---------------------------------------------------------------------------

def analyze_dns(url: str) -> dict:
    """
    Agent 2 — DNS & Infrastructure: Main evidence collection function.

    Accepts a URL or hostname, performs comprehensive DNS queries,
    resolves server IPs, performs reverse DNS, checks DNSSEC,
    and identifies hosting/CDN infrastructure.

    This function is an EVIDENCE COLLECTION AGENT only.
    It does NOT calculate trust scores, risk scores, or classify
    the domain as malicious or safe.

    Args:
        url: Any URL string (e.g. "https://www.example.com/login?id=5")

    Returns:
        dict:
            {
                "status": "success" | "partial" | "error",
                "data": {
                    "domain":           str,
                    "a_records":        list[str],
                    "aaaa_records":     list[str],
                    "mx_records":       list[dict],
                    "ns_records":       list[str],
                    "txt_records":      list[str],
                    "cname_records":    list[str],
                    "reverse_dns":      dict[str, list[str]],
                    "dnssec":           dict,
                    "server_ips":       list[str],
                    "server_ip":        str,
                    "hosting_provider": dict,
                    "cdn":              dict
                },
                "errors": list[str]
            }
    """
    print(f"[Agent 2] Starting DNS & Infrastructure analysis for: {url}")
    errors = []

    # Initialize default data structure with empty/safe values
    data = {
        "domain":           "Not Available",
        "a_records":        [],
        "aaaa_records":     [],
        "mx_records":       [],
        "ns_records":       [],
        "txt_records":      [],
        "cname_records":    [],
        "reverse_dns":      {},
        "dnssec":           {
            "status": "Unable to determine",
            "ds_present": False,
            "dnskey_present": False
        },
        "server_ips":       [],
        "server_ip":        "Not Available",
        "hosting_provider": {
            "organization": "Not Available",
            "asn": "Not Available",
            "network": "Not Available",
            "country": "Not Available"
        },
        "cdn": {
            "detected": False,
            "provider": None,
            "evidence": []
        }
    }

    # Step 1: Extract hostname and registrable domain
    hostname, registrable_domain = extract_host_and_domain(url)
    if not hostname or not ("." in hostname or hostname.replace(".", "").isdigit()):
        print("[Agent 2] Error: Invalid URL or hostname provided.")
        errors.append("Invalid URL or domain — could not identify a valid hostname.")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }

    data["domain"] = hostname
    print(f"[Agent 2] Hostname: {hostname} (Registrable domain: {registrable_domain})")

    resolver = _get_configured_resolver(timeout=5.0, lifetime=8.0)

    # Step 2: Query A Records (IPv4)
    print(f"[Agent 2] Querying A records for {hostname}...")
    a_recs, a_err = query_a_records(resolver, hostname)
    data["a_records"] = a_recs
    if a_err:
        errors.append(a_err)
    if a_recs:
        print(f"[Agent 2] A records found: {a_recs}")
    else:
        # If hostname had no A record, check registrable domain as fallback
        if registrable_domain and registrable_domain != hostname:
            apex_a, _ = query_a_records(resolver, registrable_domain)
            if apex_a:
                print(f"[Agent 2] Apex A records found: {apex_a}")
                # We retain hostname records in data['a_records'] but note apex in logging

    # Step 3: Query AAAA Records (IPv6)
    print(f"[Agent 2] Querying AAAA records for {hostname}...")
    aaaa_recs, aaaa_err = query_aaaa_records(resolver, hostname)
    data["aaaa_records"] = aaaa_recs
    if aaaa_err:
        errors.append(aaaa_err)
    if aaaa_recs:
        print(f"[Agent 2] AAAA records found: {aaaa_recs}")
    else:
        print("[Agent 2] No AAAA records found.")

    # Step 4: Query MX Records (Check target then registrable domain)
    print(f"[Agent 2] Querying MX records...")
    mx_recs, mx_err = query_mx_records(resolver, hostname)
    if not mx_recs and registrable_domain and registrable_domain != hostname:
        mx_recs, mx_err = query_mx_records(resolver, registrable_domain)
    data["mx_records"] = mx_recs
    if mx_err:
        errors.append(mx_err)
    if mx_recs:
        print(f"[Agent 2] MX records found: {len(mx_recs)} mail servers")
    else:
        print("[Agent 2] No MX records found.")

    # Step 5: Query NS Records (Authoritative Nameservers usually on registrable domain)
    print(f"[Agent 2] Querying NS records...")
    ns_recs, ns_err = query_ns_records(resolver, hostname)
    if not ns_recs and registrable_domain:
        ns_recs, ns_err = query_ns_records(resolver, registrable_domain)
    data["ns_records"] = ns_recs
    if ns_err:
        errors.append(ns_err)
    if ns_recs:
        print(f"[Agent 2] NS records found: {ns_recs}")
    else:
        print("[Agent 2] No NS records found.")

    # Step 6: Query TXT Records (Check hostname then registrable domain)
    print(f"[Agent 2] Querying TXT records...")
    txt_recs, txt_err = query_txt_records(resolver, hostname)
    if registrable_domain and registrable_domain != hostname:
        reg_txt, _ = query_txt_records(resolver, registrable_domain)
        for t in reg_txt:
            if t not in txt_recs:
                txt_recs.append(t)
    data["txt_records"] = txt_recs
    if txt_err:
        errors.append(txt_err)
    if txt_recs:
        print(f"[Agent 2] TXT records found: {len(txt_recs)} records")
    else:
        print("[Agent 2] No TXT records found.")

    # Step 7: Query CNAME Records
    print(f"[Agent 2] Querying CNAME records for {hostname}...")
    cname_recs, cname_err = query_cname_records(resolver, hostname)
    data["cname_records"] = cname_recs
    if cname_err:
        errors.append(cname_err)
    if cname_recs:
        print(f"[Agent 2] CNAME records found: {cname_recs}")
    else:
        print("[Agent 2] No CNAME record found.")

    # Step 8: Resolved Server IP Addresses
    print(f"[Agent 2] Resolving server IP addresses...")
    server_ips = list(data["a_records"])
    if not server_ips:
        try:
            fallback_ip = socket.gethostbyname(hostname)
            if fallback_ip and fallback_ip not in server_ips:
                server_ips.append(fallback_ip)
        except Exception:
            pass

    data["server_ips"] = server_ips
    if server_ips:
        data["server_ip"] = server_ips[0]
        print(f"[Agent 2] Primary server IP: {data['server_ip']} (All: {server_ips})")
    else:
        data["server_ip"] = "Not Available"
        print("[Agent 2] Server IP resolution unavailable.")

    # Step 9: Reverse DNS (PTR)
    print(f"[Agent 2] Checking reverse DNS (PTR)...")
    reverse_dns_dict = perform_reverse_dns(data["server_ips"])
    data["reverse_dns"] = reverse_dns_dict
    for ip, ptrs in reverse_dns_dict.items():
        if ptrs:
            print(f"[Agent 2] Reverse DNS for {ip}: {ptrs}")

    # Step 10: DNSSEC Check
    print(f"[Agent 2] Checking DNSSEC status...")
    dnssec_info = check_dnssec_status(resolver, hostname, registrable_domain or hostname)
    data["dnssec"] = dnssec_info
    print(f"[Agent 2] DNSSEC: {dnssec_info['status']} (DS: {dnssec_info['ds_present']}, DNSKEY: {dnssec_info['dnskey_present']})")

    # Step 11: Hosting Provider & ASN Lookup
    print(f"[Agent 2] Checking IP/ASN hosting information...")
    hosting_info = get_hosting_provider_info(data["server_ip"])
    data["hosting_provider"] = hosting_info
    print(f"[Agent 2] Hosting Provider: {hosting_info.get('organization')} (ASN: {hosting_info.get('asn')})")

    # Step 12: Multi-Signal CDN Detection
    print(f"[Agent 2] Checking CDN indicators...")
    cdn_info = detect_cdn(
        domain=hostname,
        cname_records=data["cname_records"],
        ns_records=data["ns_records"],
        reverse_dns_dict=data["reverse_dns"],
        server_ips=data["server_ips"],
        hosting_org=hosting_info.get("organization", "")
    )
    data["cdn"] = cdn_info
    if cdn_info["detected"]:
        print(f"[Agent 2] CDN Detected: {cdn_info['provider']}")
    else:
        print("[Agent 2] No CDN detected.")

    # Step 13: Compile structured evidence items
    evidence = []
    if data["a_records"]:
        evidence.append(create_evidence_item("A2", 1, "DNS A records", data["a_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["aaaa_records"]:
        evidence.append(create_evidence_item("A2", 2, "DNS AAAA records", data["aaaa_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["mx_records"]:
        evidence.append(create_evidence_item("A2", 3, "DNS MX records", data["mx_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["ns_records"]:
        evidence.append(create_evidence_item("A2", 4, "DNS NS records", data["ns_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["txt_records"]:
        evidence.append(create_evidence_item("A2", 5, "DNS TXT records", data["txt_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["cname_records"]:
        evidence.append(create_evidence_item("A2", 6, "DNS CNAME records", data["cname_records"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    if data["reverse_dns"]:
        evidence.append(create_evidence_item("A2", 7, "Reverse DNS PTR records", data["reverse_dns"], severity="info", source="DNS resolver", evidence_type="deterministic"))
    evidence.append(create_evidence_item("A2", 8, "DNSSEC record status", data["dnssec"].get("status"), severity="info", source="DNS resolver", evidence_type="deterministic", metadata=data["dnssec"]))
    if data.get("server_ip") not in ("Not Available", None):
        evidence.append(create_evidence_item("A2", 9, "Primary resolved IP", data["server_ip"], severity="info", source="DNS resolver", evidence_type="deterministic", metadata={"server_ips": data["server_ips"]}))
    if hosting_info.get("organization") not in ("Not Available", None):
        evidence.append(create_evidence_item("A2", 10, "Hosting provider organization", hosting_info.get("organization"), severity="info", source="BGP / IP Geolocation", evidence_type="deterministic", metadata={"asn": hosting_info.get("asn"), "country": hosting_info.get("country")}))
    evidence.append(create_evidence_item("A2", 11, "CDN provider detected", cdn_info.get("provider"), severity="info", source="DNS / HTTP headers", evidence_type="deterministic", metadata={"detected": cdn_info.get("detected"), "evidence": cdn_info.get("evidence")}))

    # Step 14: Overall Status
    has_records = bool(data["a_records"] or data["aaaa_records"] or data["ns_records"] or data["server_ips"])
    if has_records:
        overall_status = "success" if not errors else "partial"
    else:
        overall_status = "error" if not errors else "partial"

    print(f"[Agent 2] Analysis completed. Status: {overall_status}")

    return build_agent_result(
        agent_identifier="A2",
        target=url,
        status=overall_status,
        data=data,
        evidence=evidence,
        errors=errors
    )


def get_dns_records(domain_or_url: str) -> dict:
    """
    Compatibility wrapper returning the structured evidence result dictionary.
    """
    return analyze_dns(domain_or_url)