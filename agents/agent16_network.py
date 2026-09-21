"""
Agent 16 — Network Security Analysis Agent
Multi-Agent Digital Forensics System

Strictly an EVIDENCE COLLECTION module for gathering, organizing, and
analyzing technical network and HTTP security information about the target.

Investigates:
1. Open Ports (safe web ports: 80, 443, 8080, 8443)
2. HTTP Headers & Status Code
3. Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.)
4. CORS Configuration & Safe Origin Reflection Check
5. Content Security Policy (CSP) Directives & Observations
6. X-Frame-Options & Framing Defenses
7. X-XSS-Protection Analysis
8. Server & Technology Fingerprinting

DO NOT calculate final Trust Score or Risk Score.
DO NOT declare the website safe or malicious.
DO NOT exploit vulnerabilities or perform aggressive scanning.
"""

import datetime
import ipaddress
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import urllib3
import requests

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure HTTPS warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Network Constants & Safe Limits
PORT_TIMEOUT = 1.2                     # 1.2s timeout for safe port connection check
HTTP_TIMEOUT = 8.0                     # 8s timeout for HTTP requests
USER_AGENT = "DigitalForensicsAgent/1.0"

SAFE_WEB_PORTS = {
    80: {"service": "HTTP", "protocol": "tcp"},
    443: {"service": "HTTPS", "protocol": "tcp"},
    8080: {"service": "HTTP-alt", "protocol": "tcp"},
    8443: {"service": "HTTPS-alt", "protocol": "tcp"}
}


# =====================================================================
# 1. TARGET NORMALIZATION & PRIVATE IP VALIDATION
# =====================================================================

def _normalize_target(url: str) -> Dict[str, Any]:
    """
    Normalize target URL and extract components: scheme, hostname, domain, port.
    """
    url = url.strip()
    if not url:
        return {"original_url": "", "scheme": "", "hostname": "", "domain": "", "port": None}
    
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "https").lower()
        hostname = (parsed.hostname or "").lower()
        explicit_port = parsed.port
        
        domain = hostname
        if _TLDEXTRACT_AVAILABLE and hostname:
            ext = tldextract.extract(hostname)
            reg_dom = getattr(ext, 'top_domain_under_public_suffix', '')
            if reg_dom:
                domain = reg_dom.lower()
            elif ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}".lower()
        elif hostname:
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])

        return {
            "original_url": url,
            "scheme": scheme,
            "hostname": hostname,
            "domain": domain,
            "port": explicit_port
        }
    except Exception:
        return {"original_url": url, "scheme": "https", "hostname": "", "domain": "", "port": None}


def _is_private_or_restricted_ip(ip_str: str) -> bool:
    """
    Verify if an IP address belongs to private, loopback, link-local,
    multicast, or reserved address spaces (SSRF protection).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified
        )
    except Exception:
        return False


def _resolve_target_ip(hostname: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely resolve hostname to IPv4 address and validate against restricted ranges.
    """
    if not hostname:
        return None, "Invalid or empty hostname."
    
    # Check if hostname itself is an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        ip_str = str(ip_obj)
        if _is_private_or_restricted_ip(ip_str):
            return ip_str, "target_restricted"
        return ip_str, None
    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(hostname)
        if _is_private_or_restricted_ip(resolved_ip):
            return resolved_ip, "target_restricted"
        return resolved_ip, None
    except socket.gaierror as e:
        return None, f"DNS resolution failure: {str(e)}"
    except Exception as e:
        return None, f"Resolution error: {str(e)}"


# =====================================================================
# 2. SAFE OPEN PORTS CHECK
# =====================================================================

def check_open_ports(hostname: str, target_ip: str) -> Dict[str, Any]:
    """
    Check safe, standard web ports only (80, 443, 8080, 8443) using safe TCP socket connect.
    Non-destructive; does not perform vulnerability exploitation or aggressive port scanning.
    """
    results = {}
    if not hostname and not target_ip:
        return results

    dest = target_ip or hostname

    for port, meta in SAFE_WEB_PORTS.items():
        port_key = str(port)
        state = "closed"
        latency_ms = None
        error_msg = None

        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)

        try:
            conn_res = sock.connect_ex((dest, port))
            latency_ms = round((time.time() - start_time) * 1000, 2)

            if conn_res == 0:
                state = "open"
            elif conn_res in (10060, 110, 111):
                # WSAETIMEDOUT / ETIMEDOUT / ECONNREFUSED
                state = "closed" if conn_res == 111 else "filtered"
            else:
                state = "closed"
        except socket.timeout:
            state = "filtered"
            latency_ms = round(PORT_TIMEOUT * 1000, 2)
        except Exception as e:
            state = "unknown"
            error_msg = str(e)
        finally:
            sock.close()

        port_entry = {
            "port": port,
            "state": state,
            "protocol": meta["protocol"],
            "service_guess": meta["service"]
        }
        if latency_ms is not None:
            port_entry["response_time_ms"] = latency_ms
        if error_msg:
            port_entry["error"] = error_msg

        results[port_key] = port_entry

    return results


# =====================================================================
# 3. HTTP HEADERS & REDIRECT INSPECTION
# =====================================================================

def fetch_http_headers(target_url: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """
    Retrieve HTTP response headers using HEAD request (falling back to GET if needed).
    Collects status code, headers dictionary, redirect chain, and reachability indicators.
    """
    http_data = {
        "status_code": None,
        "final_url": target_url,
        "headers": {},
        "redirect_count": 0,
        "redirect_chain": [],
        "https_reachable": False,
        "http_reachable": False,
        "http_to_https_redirect": False
    }
    errors = []

    req_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*"
    }

    # 1. Main request to target URL
    try:
        # Try HEAD first
        resp = requests.head(
            target_url,
            headers=req_headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False
        )
        
        # If HEAD returned 405 (Method Not Allowed) or empty headers, retry with GET
        if resp.status_code in (405, 501) or not resp.headers:
            resp = requests.get(
                target_url,
                headers=req_headers,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                stream=True,
                verify=False
            )

        http_data["status_code"] = resp.status_code
        http_data["final_url"] = resp.url
        http_data["headers"] = dict(resp.headers)
        http_data["redirect_count"] = len(resp.history)
        http_data["redirect_chain"] = [r.url for r in resp.history] + [resp.url]

        if resp.url.startswith("https://"):
            http_data["https_reachable"] = True
        elif resp.url.startswith("http://"):
            http_data["http_reachable"] = True

    except requests.exceptions.SSLError as e:
        errors.append({"component": "http_request", "error": f"SSL connection error: {str(e)}"})
    except requests.exceptions.Timeout:
        errors.append({"component": "http_request", "error": "HTTP request timed out."})
    except requests.exceptions.ConnectionError as e:
        errors.append({"component": "http_request", "error": f"HTTP connection failed: {str(e)}"})
    except Exception as e:
        errors.append({"component": "http_request", "error": f"HTTP request error: {str(e)}"})

    # 2. Check HTTP to HTTPS redirect behavior
    parsed = urlparse(target_url)
    if parsed.hostname:
        http_test_url = f"http://{parsed.hostname}/"
        try:
            http_resp = requests.head(
                http_test_url,
                headers=req_headers,
                timeout=5.0,
                allow_redirects=False,
                verify=False
            )
            http_data["http_reachable"] = True
            loc = http_resp.headers.get("Location", "")
            if http_resp.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                http_data["http_to_https_redirect"] = True
        except Exception:
            pass

    return http_data, errors


# =====================================================================
# 4. SECURITY HEADERS NORMALIZATION & PARSING
# =====================================================================

def parse_hsts_header(hsts_val: Optional[str]) -> Dict[str, Any]:
    """Parse Strict-Transport-Security header directives."""
    if not hsts_val:
        return {
            "present": False,
            "value": None,
            "max_age": None,
            "include_subdomains": False,
            "preload": False
        }

    max_age = None
    include_subdomains = "includesubdomains" in hsts_val.lower()
    preload = "preload" in hsts_val.lower()

    m = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.IGNORECASE)
    if m:
        try:
            max_age = int(m.group(1))
        except ValueError:
            pass

    return {
        "present": True,
        "value": hsts_val,
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload
    }


def parse_csp_header(csp_val: Optional[str]) -> Dict[str, Any]:
    """Parse Content-Security-Policy header into directives and observations."""
    if not csp_val:
        return {
            "present": False,
            "value": None,
            "directives": {},
            "observations": ["Content-Security-Policy header is absent."]
        }

    directives = {}
    observations = ["Content-Security-Policy header is present."]
    
    # Directives are separated by semicolons
    raw_directives = [d.strip() for d in csp_val.split(";") if d.strip()]
    for d in raw_directives:
        parts = d.split()
        if parts:
            d_name = parts[0].lower()
            d_values = parts[1:] if len(parts) > 1 else []
            directives[d_name] = d_values

    # Check for notable CSP properties (Evidence collection, not vulnerability declaration)
    csp_lower = csp_val.lower()
    if "'unsafe-inline'" in csp_lower:
        observations.append("CSP contains 'unsafe-inline' in directive source list.")
    if "'unsafe-eval'" in csp_lower:
        observations.append("CSP contains 'unsafe-eval' in directive source list.")
    if "*" in csp_val.split():
        observations.append("CSP uses wildcard '*' in source definitions.")
    if "frame-ancestors" in directives:
        observations.append("CSP includes 'frame-ancestors' directive for framing control.")
    if "upgrade-insecure-requests" in directives or "upgrade-insecure-requests" in csp_lower:
        observations.append("CSP enforces 'upgrade-insecure-requests'.")

    return {
        "present": True,
        "value": csp_val,
        "directives": directives,
        "observations": observations
    }


def parse_x_frame_options(xfo_val: Optional[str], csp_frame_ancestors: bool = False) -> Dict[str, Any]:
    """Parse X-Frame-Options header and normalize interpretation."""
    if not xfo_val:
        interp = "Header not present."
        if csp_frame_ancestors:
            interp += " (Note: CSP frame-ancestors directive provides equivalent/superseding framing defense)."
        return {
            "present": False,
            "value": None,
            "interpretation": interp
        }

    xfo_upper = xfo_val.strip().upper()
    if xfo_upper == "DENY":
        interp = "Completely prevents the webpage from being rendered in a frame/iframe."
    elif xfo_upper == "SAMEORIGIN":
        interp = "Restricts framing of the webpage to the same origin."
    elif xfo_upper.startswith("ALLOW-FROM"):
        interp = "Allows framing only from the specified URI origin."
    else:
        interp = f"Observed non-standard X-Frame-Options value: '{xfo_val}'."

    return {
        "present": True,
        "value": xfo_val,
        "interpretation": interp
    }


def parse_x_xss_protection(xxss_val: Optional[str]) -> Dict[str, Any]:
    """Parse legacy X-XSS-Protection header."""
    if not xxss_val:
        return {
            "present": False,
            "value": None,
            "interpretation": "Header not present (modern browsers primarily rely on CSP for XSS defense)."
        }

    xxss_clean = xxss_val.strip()
    if xxss_clean == "0":
        interp = "Filter disabled by header configuration."
    elif xxss_clean == "1":
        interp = "Filter enabled; browser sanitizes the page if cross-site scripting attack detected."
    elif "mode=block" in xxss_clean.lower():
        interp = "Filter enabled with mode=block; browser stops rendering the page if attack detected."
    else:
        interp = f"Observed X-XSS-Protection value: '{xxss_val}'."

    return {
        "present": True,
        "value": xxss_val,
        "interpretation": interp
    }


def extract_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Extract, normalize, and interpret standard security HTTP response headers.
    """
    # Normalize header keys to lowercase
    h_lower = {k.lower(): v for k, v in headers.items()}

    hsts_raw = h_lower.get("strict-transport-security")
    csp_raw = h_lower.get("content-security-policy")
    xfo_raw = h_lower.get("x-frame-options")
    xcto_raw = h_lower.get("x-content-type-options")
    ref_raw = h_lower.get("referrer-policy")
    perm_raw = h_lower.get("permissions-policy")
    xxss_raw = h_lower.get("x-xss-protection")

    csp_parsed = parse_csp_header(csp_raw)
    has_frame_ancestors = "frame-ancestors" in csp_parsed.get("directives", {})

    return {
        "strict_transport_security": parse_hsts_header(hsts_raw),
        "content_security_policy": csp_parsed,
        "x_frame_options": parse_x_frame_options(xfo_raw, has_frame_ancestors),
        "x_content_type_options": {
            "present": bool(xcto_raw),
            "value": xcto_raw,
            "interpretation": "Prevents MIME-sniffing" if (xcto_raw and "nosniff" in xcto_raw.lower()) else ("Header present" if xcto_raw else "Header not present.")
        },
        "referrer_policy": {
            "present": bool(ref_raw),
            "value": ref_raw
        },
        "permissions_policy": {
            "present": bool(perm_raw),
            "value": perm_raw
        },
        "x_xss_protection": parse_x_xss_protection(xxss_raw)
    }


# =====================================================================
# 5. CORS CONFIGURATION & SAFE REFLECTION PROBE
# =====================================================================

def analyze_cors_configuration(target_url: str, base_headers: Dict[str, str]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """
    Analyze CORS response headers and optionally perform a safe origin reflection check.
    Does not exploit or attempt credential theft.
    """
    errors = []
    h_lower = {k.lower(): v for k, v in base_headers.items()}

    allow_origin = h_lower.get("access-control-allow-origin")
    allow_credentials = h_lower.get("access-control-allow-credentials")
    allow_methods = h_lower.get("access-control-allow-methods")
    allow_headers = h_lower.get("access-control-allow-headers")
    expose_headers = h_lower.get("access-control-expose-headers")
    max_age = h_lower.get("access-control-max-age")

    mode = "not_present"
    origin_reflected = False

    # Send a safe CORS check probe with a harmless synthetic Origin
    test_origin = "https://example-origin.invalid"
    try:
        probe_resp = requests.get(
            target_url,
            headers={
                "User-Agent": USER_AGENT,
                "Origin": test_origin
            },
            timeout=5.0,
            verify=False
        )
        probe_h = {k.lower(): v for k, v in probe_resp.headers.items()}
        probe_acao = probe_h.get("access-control-allow-origin")
        probe_acac = probe_h.get("access-control-allow-credentials")

        if probe_acao:
            allow_origin = probe_acao
            if probe_acac:
                allow_credentials = probe_acac

        if probe_acao == test_origin:
            origin_reflected = True
            mode = "origin_reflected"
        elif probe_acao == "*":
            mode = "wildcard"
        elif probe_acao:
            mode = "specific_origin"
    except Exception as e:
        errors.append({"component": "cors_probe", "error": f"CORS origin probe failed: {str(e)}"})

    if mode == "not_present" and allow_origin:
        if allow_origin == "*":
            mode = "wildcard"
        else:
            mode = "specific_origin"

    # Identify potential CORS misconfiguration flag (Wildcard + Credentials)
    is_misconfigured = False
    notes = []
    if allow_origin == "*" and allow_credentials and allow_credentials.lower() == "true":
        is_misconfigured = True
        notes.append("Potential CORS misconfiguration: Wildcard origin combined with Allow-Credentials: true.")
    elif origin_reflected and allow_credentials and allow_credentials.lower() == "true":
        notes.append("Dynamic origin reflection observed with Allow-Credentials: true.")
    elif allow_origin == "*":
        notes.append("Wildcard CORS (Access-Control-Allow-Origin: *) permits cross-origin reading of public resources.")
    elif allow_origin:
        notes.append(f"CORS permits specific origin: '{allow_origin}'.")
    else:
        notes.append("No explicit CORS Access-Control-Allow-Origin headers returned.")

    return {
        "present": bool(allow_origin),
        "mode": mode,
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "allow_methods": allow_methods,
        "allow_headers": allow_headers,
        "expose_headers": expose_headers,
        "max_age": max_age,
        "origin_reflected": origin_reflected,
        "potential_cors_misconfiguration": is_misconfigured,
        "notes": notes
    }, errors


# =====================================================================
# 6. SERVER FINGERPRINTING & INFORMATION DISCLOSURE
# =====================================================================

def fingerprint_server_technologies(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Inspect passive HTTP headers to identify web server, technologies, and version disclosures.
    """
    h_lower = {k.lower(): v for k, v in headers.items()}

    server_header = h_lower.get("server")
    powered_by = h_lower.get("x-powered-by")
    via_header = h_lower.get("via")
    aspnet_ver = h_lower.get("x-aspnet-version")
    generator = h_lower.get("x-generator")

    technologies = []
    version_disclosures = []

    # Server Header Analysis
    if server_header:
        technologies.append(server_header)
        # Check if version number is disclosed e.g. "nginx/1.24.0", "Apache/2.4.57"
        if re.search(r"/\d+(?:\.\d+)+", server_header):
            version_disclosures.append(f"Server header exposes version: {server_header}")

    # X-Powered-By Analysis
    if powered_by:
        technologies.append(f"X-Powered-By: {powered_by}")
        if re.search(r"/\d+(?:\.\d+)+", powered_by):
            version_disclosures.append(f"X-Powered-By exposes version: {powered_by}")

    # Via Header Analysis (Proxies / CDNs)
    if via_header:
        technologies.append(f"Via: {via_header}")

    # ASP.NET version
    if aspnet_ver:
        technologies.append(f"ASP.NET {aspnet_ver}")
        version_disclosures.append(f"X-AspNet-Version exposes version: {aspnet_ver}")

    # Generator header
    if generator:
        technologies.append(f"Generator: {generator}")

    # Deduplicate technologies list
    clean_techs = []
    seen = set()
    for t in technologies:
        t_clean = t.strip()
        if t_clean and t_clean.lower() not in seen:
            seen.add(t_clean.lower())
            clean_techs.append(t_clean)

    return {
        "server": server_header,
        "powered_by": powered_by,
        "via": via_header,
        "aspnet_version": aspnet_ver,
        "generator": generator,
        "technologies": clean_techs,
        "information_disclosure": bool(version_disclosures),
        "version_disclosures": version_disclosures
    }


# =====================================================================
# 7. STANDARDIZED EVIDENCE COMPILATION
# =====================================================================

def compile_network_evidence(
    open_ports: Dict[str, Any],
    http_data: Dict[str, Any],
    sec_headers: Dict[str, Any],
    cors_data: Dict[str, Any],
    server_data: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Compile structured, source-traceable forensic evidence observations.
    """
    evidence = []

    # 1. Port Evidence
    for p_str, p_info in open_ports.items():
        if p_info.get("state") == "open":
            evidence.append({
                "evidence_type": "open_port",
                "category": "network_services",
                "observation": f"Port {p_str} ({p_info.get('service_guess')}) is open and accepting TCP connections.",
                "value": f"{p_str}/tcp",
                "source": "TCP connection check",
                "confidence": "high"
            })

    # 2. TLS / HTTP Reachability
    if http_data.get("https_reachable"):
        evidence.append({
            "evidence_type": "network_reachability",
            "category": "transport_security",
            "observation": "Target website is reachable over HTTPS.",
            "value": "https",
            "source": "HTTP client",
            "confidence": "high"
        })
    if http_data.get("http_to_https_redirect"):
        evidence.append({
            "evidence_type": "http_redirect",
            "category": "transport_security",
            "observation": "Plaintext HTTP requests are automatically redirected to HTTPS.",
            "value": "http_to_https",
            "source": "HTTP redirect chain",
            "confidence": "high"
        })

    # 3. Security Headers Evidence
    hsts = sec_headers.get("strict_transport_security", {})
    if hsts.get("present"):
        evidence.append({
            "evidence_type": "security_header",
            "category": "HSTS",
            "observation": f"Strict-Transport-Security header is present (max-age={hsts.get('max_age')}, includeSubDomains={hsts.get('include_subdomains')}).",
            "value": hsts.get("value"),
            "source": "HTTP response headers",
            "confidence": "high"
        })
    else:
        evidence.append({
            "evidence_type": "missing_security_header",
            "category": "HSTS",
            "observation": "Strict-Transport-Security header is absent.",
            "value": None,
            "source": "HTTP response headers",
            "confidence": "high"
        })

    csp = sec_headers.get("content_security_policy", {})
    if csp.get("present"):
        evidence.append({
            "evidence_type": "security_header",
            "category": "CSP",
            "observation": "Content-Security-Policy header is present and configured.",
            "value": csp.get("value"),
            "source": "HTTP response headers",
            "confidence": "high"
        })
        for obs in csp.get("observations", []):
            if "unsafe" in obs or "wildcard" in obs:
                evidence.append({
                    "evidence_type": "csp_configuration",
                    "category": "CSP",
                    "observation": obs,
                    "value": csp.get("value"),
                    "source": "CSP header parsing",
                    "confidence": "high"
                })
    else:
        evidence.append({
            "evidence_type": "missing_security_header",
            "category": "CSP",
            "observation": "Content-Security-Policy header is absent.",
            "value": None,
            "source": "HTTP response headers",
            "confidence": "high"
        })

    xfo = sec_headers.get("x_frame_options", {})
    if xfo.get("present"):
        evidence.append({
            "evidence_type": "security_header",
            "category": "framing_defense",
            "observation": f"X-Frame-Options is configured: {xfo.get('value')}.",
            "value": xfo.get("value"),
            "source": "HTTP response headers",
            "confidence": "high"
        })

    # 4. CORS Evidence
    if cors_data.get("present"):
        evidence.append({
            "evidence_type": "cors_configuration",
            "category": "CORS",
            "observation": f"CORS Access-Control-Allow-Origin is configured as '{cors_data.get('allow_origin')}'.",
            "value": cors_data.get("allow_origin"),
            "source": "HTTP response headers",
            "confidence": "high"
        })
        if cors_data.get("potential_cors_misconfiguration"):
            evidence.append({
                "evidence_type": "cors_misconfiguration",
                "category": "CORS",
                "observation": "Access-Control-Allow-Origin: * is configured alongside Access-Control-Allow-Credentials: true.",
                "value": "wildcard_with_credentials",
                "source": "CORS header audit",
                "confidence": "high"
            })

    # 5. Server Fingerprinting & Disclosure Evidence
    if server_data.get("server"):
        evidence.append({
            "evidence_type": "server_disclosure",
            "category": "server_fingerprinting",
            "observation": f"Server header reveals: '{server_data.get('server')}'.",
            "value": server_data.get("server"),
            "source": "HTTP response headers",
            "confidence": "high"
        })

    for v_disc in server_data.get("version_disclosures", []):
        evidence.append({
            "evidence_type": "version_disclosure",
            "category": "server_fingerprinting",
            "observation": v_disc,
            "value": server_data.get("server") or server_data.get("powered_by"),
            "source": "HTTP response headers",
            "confidence": "high"
        })

    return evidence


# =====================================================================
# 8. MAIN FORENSIC ENTRYPOINT: analyze_network_security(url)
# =====================================================================

def analyze_network_security(url: str) -> Dict[str, Any]:
    """
    Main forensic entrypoint for Agent 16: Network Security Analysis Agent.
    Collects open ports, HTTP headers, security headers, CORS settings, CSP,
    X-Frame-Options, and server fingerprinting observations.
    """
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[Dict[str, str]] = []

    # 1. Normalize Input Target
    norm = _normalize_target(url)
    if not norm["hostname"]:
        extra = {
            "input": norm,
            "open_ports": {},
            "http_headers": {"status_code": None, "final_url": url, "headers": {}},
            "security_headers": {},
            "cors": {"allow_origin": None, "allow_credentials": None, "allow_methods": None, "allow_headers": None},
            "csp": {"present": False, "value": None, "directives": {}},
            "x_frame_options": {"present": False, "value": None},
            "x_xss_protection": {"present": False, "value": None},
            "server_fingerprinting": {"server": None, "powered_by": None, "technologies": []},
            "checked_at": checked_at
        }
        return build_agent_result(
            agent_identifier="A16",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=[{"component": "input", "error": "Invalid URL or hostname provided."}],
            extra_fields=extra,
        )

    # 2. DNS & Private IP Check (SSRF Protection)
    resolved_ip, ip_err = _resolve_target_ip(norm["hostname"])
    if ip_err == "target_restricted":
        extra = {
            "error": "Target resolved to a private or restricted IP address range.",
            "input": norm,
            "open_ports": {},
            "http_headers": {"status_code": None, "final_url": norm["original_url"], "headers": {}},
            "security_headers": {},
            "cors": {"allow_origin": None, "allow_credentials": None, "allow_methods": None, "allow_headers": None},
            "csp": {"present": False, "value": None, "directives": {}},
            "x_frame_options": {"present": False, "value": None},
            "x_xss_protection": {"present": False, "value": None},
            "server_fingerprinting": {"server": None, "powered_by": None, "technologies": []},
            "checked_at": checked_at
        }
        rest_ev = [create_evidence_item(
            agent_id="A16",
            index=1,
            finding="Target hostname resolved to restricted IP address",
            value=resolved_ip,
            severity="high",
            source="DNS resolution validation",
            evidence_type="deterministic",
            evidence_strength=0.9,
            metadata={"hostname": norm["hostname"], "resolved_ip": resolved_ip},
            category="open_sensitive_port"
        )]
        return build_agent_result(
            agent_identifier="A16",
            target=url or "",
            status="restricted",
            data=extra,
            evidence=rest_ev,
            errors=[{"component": "dns", "error": f"Target resolved to private IP ({resolved_ip}). Scanning restricted."}],
            extra_fields=extra,
        )
    elif ip_err:
        errors.append({"component": "dns", "error": ip_err})

    # 3. Check Open Ports
    open_ports = {}
    try:
        open_ports = check_open_ports(norm["hostname"], resolved_ip)
    except Exception as e:
        errors.append({"component": "open_ports", "error": f"Port checking error: {str(e)}"})

    # 4. Retrieve HTTP Headers
    http_data, http_errors = fetch_http_headers(norm["original_url"])
    errors.extend(http_errors)

    raw_headers = http_data.get("headers", {})

    # 5. Extract & Normalize Security Headers
    sec_headers = extract_security_headers(raw_headers)

    # 6. Analyze CORS Configuration
    cors_data, cors_errors = analyze_cors_configuration(norm["original_url"], raw_headers)
    errors.extend(cors_errors)

    # 7. Fingerprint Server Technologies
    server_data = fingerprint_server_technologies(raw_headers)

    # 8. Compile Standardized Evidence Model
    evidence = compile_network_evidence(open_ports, http_data, sec_headers, cors_data, server_data)

    # 9. Structured Evidence Items for Common Schema
    structured_evidence = []

    # E16-01: Open Ports
    open_list = [p for p, info in open_ports.items() if info.get("state") == "open"]
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=1,
        finding="Network web services open port inspection",
        value=open_list,
        severity="info",
        source="TCP Socket Inspection",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata={"ports": open_ports},
        category="standard_port_open"
    ))

    # E16-02: HTTP Headers & Reachability
    has_redirect = http_data.get("http_to_https_redirect", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=2,
        finding="HTTP protocol reachability and HTTPS redirection",
        value=f"Status: {http_data.get('status_code')}, HTTPS redirect: {has_redirect}",
        severity="info",
        source="HTTP Head Inspection",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=http_data,
        category="hsts_preloaded" if has_redirect else "clean_http_route"
    ))

    # E16-03: HSTS Header
    hsts = sec_headers.get("strict_transport_security", {})
    hsts_present = hsts.get("present", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=3,
        finding="Strict-Transport-Security (HSTS) header configured" if hsts_present else "Strict-Transport-Security (HSTS) header absent",
        value=hsts.get("value") if hsts_present else "Missing",
        severity="info" if hsts_present else "low",
        source="HTTP Response Headers",
        evidence_type="deterministic",
        evidence_strength=0.1 if hsts_present else 0.2,
        metadata=hsts,
        category="hsts_preloaded" if hsts_present else "missing_security_headers"
    ))

    # E16-04: CSP Header
    csp = sec_headers.get("content_security_policy", {})
    csp_present = csp.get("present", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=4,
        finding="Content Security Policy (CSP) header configured" if csp_present else "Content Security Policy (CSP) header absent",
        value=csp.get("value") if csp_present else "Missing",
        severity="info" if csp_present else "low",
        source="HTTP Response Headers",
        evidence_type="deterministic",
        evidence_strength=0.1 if csp_present else 0.2,
        metadata=csp,
        category="strict_csp_configured" if csp_present else "missing_security_headers"
    ))

    # E16-05: X-Frame-Options
    xfo = sec_headers.get("x_frame_options", {})
    xfo_present = xfo.get("present", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=5,
        finding="X-Frame-Options framing protection configured" if xfo_present else "X-Frame-Options framing protection header absent",
        value=xfo.get("value") if xfo_present else "Missing",
        severity="info" if xfo_present else "low",
        source="HTTP Response Headers",
        evidence_type="deterministic",
        evidence_strength=0.1 if xfo_present else 0.2,
        metadata=xfo,
        category="strict_csp_configured" if xfo_present else "missing_security_headers"
    ))

    # E16-06: MIME Sniffing Protection
    xcto = sec_headers.get("x_content_type_options", {})
    xcto_present = xcto.get("present", False)
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=6,
        finding="X-Content-Type-Options nosniff directive",
        value=xcto.get("value") if xcto_present else "Missing",
        severity="info",
        source="HTTP Response Headers",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=xcto,
        category="meta_description_present" if xcto_present else "missing_security_headers"
    ))

    # E16-07: CORS Configuration
    cors_risk = cors_data.get("risk")
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=7,
        finding="CORS Access-Control policy and origin reflection",
        value=cors_data.get("allow_origin") or "Standard",
        severity="high" if cors_risk == "high" else "info",
        source="CORS Inspection",
        evidence_type="deterministic",
        evidence_strength=0.8 if cors_risk == "high" else 0.1,
        metadata=cors_data,
        category="missing_security_headers" if (cors_risk == "high" or cors_data.get("potential_cors_misconfiguration")) else ("strict_cors_configured" if cors_data.get("present") else "meta_description_present")
    ))

    # E16-08: Server Fingerprinting
    structured_evidence.append(create_evidence_item(
        agent_id="A16",
        index=8,
        finding="Server technology disclosure and fingerprinting",
        value=server_data.get("technologies", []),
        severity="info",
        source="Server Banner Headers",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=server_data,
        category="server_banner_detected"
    ))

    data_payload = {
        "open_ports": open_ports,
        "http_headers": {
            "status_code": http_data.get("status_code"),
            "final_url": http_data.get("final_url"),
            "headers": raw_headers,
            "redirect_count": http_data.get("redirect_count", 0),
            "redirect_chain": http_data.get("redirect_chain", []),
            "https_reachable": http_data.get("https_reachable", False),
            "http_reachable": http_data.get("http_reachable", False),
            "http_to_https_redirect": http_data.get("http_to_https_redirect", False)
        },
        "security_headers": sec_headers,
        "cors": cors_data,
        "csp": sec_headers.get("content_security_policy", {}),
        "x_frame_options": sec_headers.get("x_frame_options", {}),
        "x_xss_protection": sec_headers.get("x_xss_protection", {}),
        "server_fingerprinting": server_data,
        "evidence": evidence,
    }

    extra_fields = {
        "input": {
            "original_url": norm["original_url"],
            "hostname": norm["hostname"],
            "domain": norm["domain"],
            "scheme": norm["scheme"],
            "port": norm["port"],
            "resolved_ip": resolved_ip
        },
        **data_payload,
        "checked_at": checked_at
    }

    return build_agent_result(
        agent_identifier="A16",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
