"""
Agent 3 — SSL / HTTPS Security
==============================
Evidence Collection Agent.

Purpose:
    Inspect the HTTPS / TLS security configuration of the submitted URL
    and collect factual technical evidence regarding the TLS connection,
    presented X.509 certificate, Certificate Authority, expiration, validity,
    certificate chain, Certificate Transparency, HSTS, TLS protocol version,
    and negotiated cipher suite.

Main question answered:
    "Does this website support HTTPS, what certificate does it present, who
    issued it, is it currently valid, is it trusted, what TLS version and
    cipher suite are negotiated, and does it enforce HSTS?"

Features collected:
    1.  HTTPS Availability
    2.  SSL Certificate (Subject, Issuer, Serial, Version, Validity, SANs)
    3.  Certificate Authority (CA)
    4.  Certificate Expiration (Expiration date & days remaining)
    5.  Certificate Validity (Temporal validity against UTC)
    6.  Certificate Chain (Leaf, intermediate, and root certificates)
    7.  Certificate Transparency (CT / SCT logs)
    8.  HSTS Enabled (HTTP Strict-Transport-Security header & directives)
    9.  TLS Version (Actual negotiated version: TLSv1.2, TLSv1.3, etc.)
    10. Cipher Suites (Negotiated cipher suite name, protocol, bits)
    11. Certificate Validation (Trust store verification & hostname match)

IMPORTANT:
    This agent is ONLY an evidence collection agent.
    It does NOT calculate trust scores, risk scores, or classify the domain
    as malicious/safe.
"""

import ssl
import socket
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from services.evidence_schema import create_evidence_item, build_agent_result


# ---------------------------------------------------------------------------
# HELPER: URL & Hostname Parsing
# ---------------------------------------------------------------------------

def extract_domain_and_port(url: str):
    """
    Extract scheme, hostname, and port from a URL or raw input string.

    For SSL/HTTPS inspection, the TLS connection defaults to port 443 unless
    an explicit custom port is specified in the URL (e.g. https://example.com:8443).

    Examples:
        "https://example.com/login"          -> ("example.com", 443, "https")
        "http://example.com"                 -> ("example.com", 443, "http")
        "https://example.com:8443/test"      -> ("example.com", 8443, "https")
        "www.example.com"                    -> ("www.example.com", 443, "https")

    Returns:
        tuple: (hostname: str | None, port: int, scheme: str)
    """
    if not url or not isinstance(url, str):
        return None, 443, "https"

    url = url.strip()
    if not url:
        return None, 443, "https"

    scheme = "https"
    if url.startswith("http://"):
        scheme = "http"
    elif url.startswith("https://"):
        scheme = "https"
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname:
            hostname = hostname.lower().strip()
        # Default to 443 for HTTPS/TLS connection unless explicitly provided
        port = parsed.port if parsed.port else 443
        return hostname, port, scheme
    except Exception:
        return None, 443, scheme


# ---------------------------------------------------------------------------
# HELPER: Certificate Parsing & Feature Extraction
# ---------------------------------------------------------------------------

def parse_certificate_metadata(der_cert: bytes, requested_hostname: str) -> dict:
    """
    Parse a DER-encoded X.509 certificate using cryptography for detailed evidence.

    Extracts:
        - Subject & Issuer (RFC 4514 format + friendly names)
        - Certificate Authority (CA) identification
        - Serial Number (Hex)
        - Version
        - Validity period (NotBefore, NotAfter)
        - Expiration countdown in days
        - Temporal validity status
        - Signature Algorithm
        - Public Key Algorithm & bit size
        - Subject Alternative Names (SAN)
        - Hostname match evaluation
        - Embedded Certificate Transparency (SCT) extensions

    Returns:
        dict: Complete structured certificate metadata
    """
    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    # 1. Subject & Issuer
    subject_rfc4514 = cert.subject.rfc4514_string()
    issuer_rfc4514 = cert.issuer.rfc4514_string()

    subject_cn = "Not Available"
    subject_org = "Not Available"
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            subject_cn = str(attr.value)
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            subject_org = str(attr.value)

    issuer_cn = "Not Available"
    issuer_org = "Not Available"
    for attr in cert.issuer:
        if attr.oid == NameOID.COMMON_NAME:
            issuer_cn = str(attr.value)
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            issuer_org = str(attr.value)

    # Friendly CA Identification
    ca_name = issuer_org if issuer_org != "Not Available" else (issuer_cn if issuer_cn != "Not Available" else issuer_rfc4514)

    # 2. Validity Dates (Timezone-aware UTC)
    try:
        valid_from_dt = cert.not_valid_before_utc
        valid_to_dt = cert.not_valid_after_utc
    except AttributeError:
        valid_from_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
        valid_to_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    is_temporally_valid = (valid_from_dt <= now <= valid_to_dt)
    days_remaining = (valid_to_dt - now).days

    if now > valid_to_dt:
        validity_status = "expired"
        expiration_status = "expired"
    elif now < valid_from_dt:
        validity_status = "not_yet_valid"
        expiration_status = "valid"
    else:
        validity_status = "valid"
        expiration_status = "expiring_soon" if days_remaining <= 14 else "valid"

    # 3. Serial Number & Version
    serial_hex = f"{cert.serial_number:X}"
    cert_version = cert.version.value if hasattr(cert.version, "value") else str(cert.version)

    # 4. Signature Algorithm
    try:
        sig_algo = cert.signature_algorithm_oid._name
    except AttributeError:
        sig_algo = str(cert.signature_algorithm_oid)

    # 5. Public Key Info
    pub_key = cert.public_key()
    pub_key_type = pub_key.__class__.__name__.replace("_", "").replace("PublicKey", "")
    pub_key_bits = getattr(pub_key, "key_size", "Not Available")

    # 6. Subject Alternative Names (SAN)
    san_names = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            san_names.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    # 7. Hostname Verification against SAN & CN
    hostname_match = False
    if requested_hostname:
        req_h = requested_hostname.lower().strip()
        names_to_check = [s.lower().strip() for s in san_names]
        if subject_cn != "Not Available":
            names_to_check.append(subject_cn.lower().strip())

        for pattern in names_to_check:
            if pattern == req_h:
                hostname_match = True
                break
            # Wildcard matching (e.g. *.example.com)
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if req_h.endswith(suffix) and req_h.count(".") == pattern.count("."):
                    hostname_match = True
                    break

    # 8. Certificate Transparency Logs (SCT extension OID 1.3.6.1.4.1.11129.2.4.2)
    sct_present = False
    sct_count = 0
    try:
        sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
        sct_ext = cert.extensions.get_extension_for_oid(sct_oid)
        if sct_ext:
            sct_present = True
            # Embedded SCT lists in DER format typically contain 2-4 SCT entries
            raw_len = len(sct_ext.value.value) if hasattr(sct_ext.value, "value") else 100
            sct_count = max(1, raw_len // 100)
    except Exception:
        pass

    return {
        "present": True,
        "subject": subject_rfc4514,
        "subject_cn": subject_cn,
        "subject_org": subject_org,
        "issuer": ca_name,
        "issuer_full": issuer_rfc4514,
        "certificate_authority": ca_name,
        "serial_number": serial_hex,
        "version": cert_version,
        "valid_from": valid_from_dt.isoformat(),
        "valid_to": valid_to_dt.isoformat(),
        "valid": is_temporally_valid,
        "validity_status": validity_status,
        "days_remaining": days_remaining,
        "expiration_status": expiration_status,
        "signature_algorithm": sig_algo,
        "public_key_type": str(pub_key_type),
        "public_key_bits": pub_key_bits,
        "san_names": san_names,
        "hostname_match": hostname_match,
        "sct_present": sct_present,
        "sct_count": sct_count
    }


# ---------------------------------------------------------------------------
# HELPER: HSTS Header Detection
# ---------------------------------------------------------------------------

def check_hsts_header(hostname: str, port: int) -> dict:
    """
    Query the HTTPS endpoint to inspect the HTTP Strict-Transport-Security header.

    Directives parsed:
        - max-age (integer seconds)
        - includeSubDomains (boolean)
        - preload (boolean)

    Returns:
        dict: {
            "enabled": bool,
            "header": str | None,
            "max_age": int | None,
            "include_subdomains": bool,
            "preload": bool
        }
    """
    default_hsts = {
        "enabled": False,
        "header": None,
        "max_age": None,
        "include_subdomains": False,
        "preload": False
    }

    if not hostname:
        return default_hsts

    url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"

    try:
        resp = requests.head(
            url,
            timeout=5,
            headers={"User-Agent": "DigitalForensicsAgent/1.0 (EvidenceCollection)"},
            allow_redirects=True
        )

        hsts_raw = resp.headers.get("Strict-Transport-Security")
        if not hsts_raw:
            return default_hsts

        max_age = None
        include_subdomains = False
        preload = False

        # Parse directives: e.g. "max-age=31536000; includeSubDomains; preload"
        for directive in hsts_raw.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("max-age="):
                try:
                    max_age = int(directive.split("=")[1].strip())
                except ValueError:
                    pass
            elif directive.lower() == "includesubdomains":
                include_subdomains = True
            elif directive.lower() == "preload":
                preload = True

        return {
            "enabled": True,
            "header": hsts_raw.strip(),
            "max_age": max_age,
            "include_subdomains": include_subdomains,
            "preload": preload
        }

    except Exception:
        return default_hsts


# ---------------------------------------------------------------------------
# MAIN FUNCTION: analyze_ssl / get_ssl_certificate
# ---------------------------------------------------------------------------

def analyze_ssl(url: str) -> dict:
    """
    Agent 3 — SSL / HTTPS Security: Main evidence collection function.

    Establishes real TLS connection, verifies certificate trust and hostname,
    extracts X.509 metadata, inspects certificate chain and CT logs,
    and queries HSTS response header.

    This function is an EVIDENCE COLLECTION AGENT only.
    It does NOT calculate trust scores, risk scores, or classify
    the website as malicious or safe.

    Args:
        url: Any URL string (e.g. "https://www.example.com/login?id=5")

    Returns:
        dict: Factual TLS & Certificate Evidence structure.
    """
    print(f"[Agent 3] Starting SSL/TLS analysis for: {url}")
    errors = []

    # Initialize structured default data
    data = {
        "url": url,
        "hostname": "Not Available",
        "https_availability": {
            "available": False,
            "status": "not_available"
        },
        "ssl_certificate": {
            "present": False,
            "subject": "Not Available",
            "issuer": "Not Available",
            "serial_number": "Not Available",
            "version": "Not Available",
            "valid_from": "Not Available",
            "valid_until": "Not Available",
            "signature_algorithm": "Not Available",
            "san_names": []
        },
        # Backward compatibility alias
        "certificate": {
            "present": False,
            "issuer": "Not Available",
            "valid_from": "Not Available",
            "valid_to": "Not Available",
            "valid": False,
            "days_until_expiry": "Not Available",
            "serial_number": "Not Available",
            "signature_algorithm": "Not Available",
            "san_names": []
        },
        "certificate_authority": "Not Available",
        "certificate_expiration": {
            "expires_at": "Not Available",
            "days_remaining": "Not Available",
            "status": "unknown"
        },
        "certificate_validity": {
            "valid": False,
            "not_before": "Not Available",
            "not_after": "Not Available",
            "status": "unknown"
        },
        "certificate_chain": {
            "status": "unavailable",
            "certificates": []
        },
        "certificate_transparency": {
            "status": "unable_to_determine",
            "found": False,
            "log_count": 0,
            "details": "Not detected"
        },
        "hsts": {
            "enabled": False,
            "header": None,
            "max_age": None,
            "include_subdomains": False,
            "preload": False
        },
        "tls_version": "Not Available",
        "cipher_suite": {
            "name": "Not Available",
            "protocol": "Not Available",
            "bits": 0
        },
        "cipher_bits": "Not Available",
        "certificate_validation": {
            "trusted": False,
            "hostname_match": False,
            "error": None
        }
    }

    # Step 1: Extract domain and port
    hostname, port, scheme = extract_domain_and_port(url)
    if not hostname:
        print("[Agent 3] Error: Invalid URL or hostname provided.")
        errors.append("Invalid URL — could not identify a valid hostname.")
        return {
            "status": "error",
            "data": data,
            "errors": errors
        }

    data["hostname"] = hostname
    print(f"[Agent 3] Hostname: {hostname} (Port: {port})")

    # Step 2: Establish TLS Connection
    print(f"[Agent 3] Connecting to {hostname}:{port}...")

    # Standard default verified context
    verified_ctx = ssl.create_default_context()
    # Fallback unverified context to inspect expired/untrusted/self-signed certificates
    unverified_ctx = ssl._create_unverified_context()

    der_cert = None
    chain_der_list = []
    tls_version_negotiated = None
    cipher_negotiated = None
    is_trusted = False
    handshake_error = None

    # 2a. Attempt Verified Handshake
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                data["https_availability"]["available"] = True
                data["https_availability"]["status"] = "available"
                is_trusted = True
                tls_version_negotiated = ssock.version()
                cipher_negotiated = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

                # Attempt peer cert chain retrieval
                try:
                    raw_chain = ssock.get_unverified_chain()
                    if raw_chain:
                        for c in raw_chain:
                            chain_der_list.append(c.public_bytes(ssl.Encoding.DER))
                except Exception:
                    pass

        print(f"[Agent 3] HTTPS connection established & certificate verified (TLS: {tls_version_negotiated})")

    except ssl.SSLCertVerificationError as e:
        handshake_error = str(e)
        is_trusted = False
        data["https_availability"]["available"] = True
        data["https_availability"]["status"] = "available"
        print(f"[Agent 3] SSL Verification notice: {e}. Falling back to inspect certificate metadata...")
        errors.append(f"Certificate trust verification failed: {handshake_error}")

        # Attempt unverified connection to retrieve certificate for inspection
        try:
            with socket.create_connection((hostname, port), timeout=6) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version_negotiated = ssock.version()
                    cipher_negotiated = ssock.cipher()
                    der_cert = ssock.getpeercert(binary_form=True)
                    try:
                        raw_chain = ssock.get_unverified_chain()
                        if raw_chain:
                            for c in raw_chain:
                                chain_der_list.append(c.public_bytes(ssl.Encoding.DER))
                    except Exception:
                        pass
        except Exception as unv_e:
            errors.append(f"Unverified TLS connection error: {str(unv_e)}")

    except (socket.timeout, TimeoutError):
        data["https_availability"]["status"] = "timeout"
        errors.append(f"HTTPS connection to {hostname}:{port} timed out after 6 seconds.")
        print("[Agent 3] Connection timed out.")

    except (ConnectionRefusedError, socket.gaierror, OSError) as e:
        data["https_availability"]["status"] = "connection_failed"
        errors.append(f"Could not establish HTTPS connection to {hostname}:{port}: {str(e)}")
        print(f"[Agent 3] Connection failed: {e}")

    except Exception as e:
        data["https_availability"]["status"] = "connection_failed"
        errors.append(f"Unexpected TLS connection error: {str(e)}")
        print(f"[Agent 3] Error: {e}")

    # Step 3: Record TLS Version & Cipher Suite
    if tls_version_negotiated:
        data["tls_version"] = tls_version_negotiated
        print(f"[Agent 3] TLS Version: {tls_version_negotiated}")

    if cipher_negotiated:
        data["cipher_suite"] = {
            "name": cipher_negotiated[0],
            "protocol": cipher_negotiated[1],
            "bits": cipher_negotiated[2]
        }
        data["cipher_bits"] = cipher_negotiated[2]
        print(f"[Agent 3] Cipher Suite: {cipher_negotiated[0]} ({cipher_negotiated[2]} bits)")

    # Step 4: Parse Certificate Details if retrieved
    if der_cert:
        print("[Agent 3] Parsing X.509 server certificate...")
        try:
            cert_meta = parse_certificate_metadata(der_cert, hostname)

            data["ssl_certificate"] = {
                "present": True,
                "subject": cert_meta["subject"],
                "subject_cn": cert_meta["subject_cn"],
                "subject_org": cert_meta["subject_org"],
                "issuer": cert_meta["issuer"],
                "issuer_full": cert_meta["issuer_full"],
                "serial_number": cert_meta["serial_number"],
                "version": cert_meta["version"],
                "valid_from": cert_meta["valid_from"],
                "valid_until": cert_meta["valid_to"],
                "signature_algorithm": cert_meta["signature_algorithm"],
                "public_key_type": cert_meta["public_key_type"],
                "public_key_bits": cert_meta["public_key_bits"],
                "san_names": cert_meta["san_names"]
            }

            # Compatibility object
            data["certificate"] = {
                "present": True,
                "issuer": cert_meta["issuer"],
                "issuer_full": cert_meta["issuer_full"],
                "subject": cert_meta["subject"],
                "valid_from": cert_meta["valid_from"],
                "valid_to": cert_meta["valid_to"],
                "valid": cert_meta["valid"] and is_trusted,
                "days_until_expiry": cert_meta["days_remaining"],
                "serial_number": cert_meta["serial_number"],
                "signature_algorithm": cert_meta["signature_algorithm"],
                "san_names": cert_meta["san_names"]
            }

            data["certificate_authority"] = cert_meta["certificate_authority"]
            print(f"[Agent 3] Certificate Authority: {cert_meta['certificate_authority']}")

            data["certificate_expiration"] = {
                "expires_at": cert_meta["valid_to"],
                "days_remaining": cert_meta["days_remaining"],
                "status": cert_meta["expiration_status"]
            }
            print(f"[Agent 3] Expiration: {cert_meta['valid_to']} ({cert_meta['days_remaining']} days remaining)")

            data["certificate_validity"] = {
                "valid": cert_meta["valid"],
                "not_before": cert_meta["valid_from"],
                "not_after": cert_meta["valid_to"],
                "status": cert_meta["validity_status"]
            }

            data["certificate_validation"] = {
                "trusted": is_trusted,
                "hostname_match": cert_meta["hostname_match"],
                "error": handshake_error
            }

            # Step 5: Certificate Transparency Evidence
            if cert_meta["sct_present"]:
                data["certificate_transparency"] = {
                    "status": "found",
                    "found": True,
                    "log_count": cert_meta["sct_count"],
                    "details": f"Embedded SCT list found ({cert_meta['sct_count']} log entries)"
                }
                print(f"[Agent 3] Certificate Transparency: Embedded SCTs found ({cert_meta['sct_count']} logs)")
            else:
                data["certificate_transparency"] = {
                    "status": "not_found",
                    "found": False,
                    "log_count": 0,
                    "details": "No embedded SCT extension detected in certificate"
                }

        except Exception as e:
            errors.append(f"Failed parsing X.509 certificate: {str(e)}")
            print(f"[Agent 3] Error parsing certificate: {e}")

    # Step 6: Certificate Chain Processing
    if chain_der_list:
        try:
            chain_certs = []
            for idx, c_bytes in enumerate(chain_der_list):
                c_obj = x509.load_der_x509_certificate(c_bytes, default_backend())
                c_type = "leaf" if idx == 0 else ("root" if idx == len(chain_der_list) - 1 and len(chain_der_list) > 2 else "intermediate")
                chain_certs.append({
                    "position": idx,
                    "subject": c_obj.subject.rfc4514_string(),
                    "issuer": c_obj.issuer.rfc4514_string(),
                    "type": c_type
                })
            data["certificate_chain"] = {
                "status": "available",
                "certificates": chain_certs
            }
            print(f"[Agent 3] Certificate Chain: {len(chain_certs)} certificates collected")
        except Exception as e:
            data["certificate_chain"] = {"status": "partial", "certificates": []}
            errors.append(f"Failed decoding certificate chain: {str(e)}")
    elif der_cert:
        data["certificate_chain"] = {
            "status": "available",
            "certificates": [
                {
                    "position": 0,
                    "subject": data["ssl_certificate"]["subject"],
                    "issuer": data["ssl_certificate"]["issuer_full"],
                    "type": "leaf"
                }
            ]
        }

    # Step 7: HSTS Header Inspection
    if data["https_availability"]["available"]:
        print("[Agent 3] Checking HTTP Strict-Transport-Security (HSTS)...")
        try:
            hsts_info = check_hsts_header(hostname, port)
            data["hsts"] = hsts_info
            if hsts_info["enabled"]:
                print(f"[Agent 3] HSTS Enabled (max-age: {hsts_info['max_age']}, subdomains: {hsts_info['include_subdomains']})")
            else:
                print("[Agent 3] HSTS header not detected.")
        except Exception as e:
            errors.append(f"Failed inspecting HSTS: {str(e)}")

    # Step 8: Compile structured evidence items
    evidence = []
    is_https = data["https_availability"].get("available", False)
    evidence.append(create_evidence_item("A3", 1, "HTTPS availability", is_https, severity="info" if is_https else "high", source="TLS handshake", evidence_type="deterministic", metadata=data["https_availability"], category="standard_tls_version" if is_https else "missing_security_headers"))
    
    tls_ver = data.get("tls_version")
    if tls_ver and tls_ver != "Not Available":
        is_modern_tls = tls_ver in ("TLSv1.2", "TLSv1.3")
        t_sev = "info" if is_modern_tls else "medium"
        evidence.append(create_evidence_item("A3", 2, "Negotiated TLS version", tls_ver, severity=t_sev, source="TLS handshake", evidence_type="deterministic", category="standard_tls_version"))
    
    cipher_info = data.get("cipher_suite", {})
    if isinstance(cipher_info, dict) and cipher_info.get("name") not in ("Not Available", None):
        evidence.append(create_evidence_item("A3", 3, "Negotiated cipher suite", cipher_info.get("name"), severity="info", source="TLS handshake", evidence_type="deterministic", metadata=cipher_info, category="standard_tls_version"))
        
    if data["ssl_certificate"].get("issuer"):
        evidence.append(create_evidence_item("A3", 4, "Certificate authority issuer", data["ssl_certificate"]["issuer"], severity="info", source="TLS certificate", evidence_type="deterministic", metadata={"issuer_full": data["ssl_certificate"].get("issuer_full")}, category="standard_tls_version"))
        
    if data["certificate_validity"].get("status"):
        is_valid_cert = bool(data["certificate_validity"].get("valid"))
        val_sev = "low" if is_valid_cert else "high"
        val_cat = "valid_ca_signed_certificate" if is_valid_cert else "invalid_certificate_chain"
        evidence.append(create_evidence_item("A3", 5, "Certificate validity status", data["certificate_validity"]["status"], severity=val_sev, source="TLS certificate", evidence_type="deterministic", evidence_strength=0.85 if is_valid_cert else 0.85, metadata=data["certificate_validity"], category=val_cat))
        
    if data["certificate_expiration"].get("days_remaining") not in ("Not Available", None):
        d_rem = data["certificate_expiration"]["days_remaining"]
        exp_sev = "high" if (isinstance(d_rem, (int, float)) and d_rem < 0) else ("medium" if (isinstance(d_rem, (int, float)) and d_rem < 15) else "info")
        exp_cat = "expired_certificate" if (isinstance(d_rem, (int, float)) and d_rem < 0) else "standard_tls_version"
        evidence.append(create_evidence_item("A3", 6, "Certificate expiration days remaining", d_rem, severity=exp_sev, source="TLS certificate", evidence_type="deterministic", metadata=data["certificate_expiration"], category=exp_cat))
        
    evidence.append(create_evidence_item("A3", 7, "Certificate Transparency SCT logging", data["certificate_transparency"].get("found", False), severity="info", source="TLS certificate", evidence_type="deterministic", metadata=data["certificate_transparency"], category="standard_tls_version"))
    
    is_hsts = bool(data["hsts"].get("enabled", False))
    evidence.append(create_evidence_item("A3", 8, "HTTP Strict Transport Security (HSTS)", is_hsts, severity="low" if is_hsts else "info", source="HTTP headers", evidence_type="deterministic", metadata=data["hsts"], category="hsts_preloaded" if is_hsts else "missing_security_headers"))

    # Step 9: Determine overall status
    if data["https_availability"]["available"] and data["ssl_certificate"]["present"]:
        overall_status = "success" if not errors else "partial"
    elif data["https_availability"]["available"]:
        overall_status = "partial"
    else:
        overall_status = "error"

    print(f"[Agent 3] Analysis completed. Status: {overall_status}")

    return build_agent_result(
        agent_identifier="A3",
        target=url,
        status=overall_status,
        data=data,
        evidence=evidence,
        errors=errors
    )


def get_ssl_certificate(domain_or_url: str) -> dict:
    """
    Compatibility wrapper returning structured TLS / SSL evidence.
    """
    return analyze_ssl(domain_or_url)
