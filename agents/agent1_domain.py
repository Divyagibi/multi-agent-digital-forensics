"""
Agent 1 — Domain Identity
=========================
Evidence Collection Agent.

Purpose:
    Determine and collect publicly available registration and identity
    information about the domain associated with the given URL.

Main question answered:
    "Who is this domain, when was it registered, when does it expire,
    who is its registrar, and what public registration information
    is available?"

Features collected:
    1.  Domain Name
    2.  Domain Age (days + years)
    3.  Domain Registration Date
    4.  Domain Expiry Date
    5.  Domain Registrar
    6.  WHOIS / RDAP Information (structured)
    7.  Registrant Organization
    8.  Registrant Country
    9.  Domain Status

Data source:
    RDAP (rdap.org) — primary
    WHOIS may be added as fallback if needed.

IMPORTANT:
    This agent is ONLY an evidence collection agent.
    It does NOT calculate trust scores, risk scores, or
    classify the domain as malicious/safe.
"""

import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# HELPER: Domain Extraction
# ---------------------------------------------------------------------------

def extract_domain(url: str):
    """
    Extract the registrable domain name from a URL.

    Handles:
        - http:// and https:// prefixes
        - www and arbitrary subdomain prefixes
        - paths, query parameters, fragments
        - multi-part TLDs such as example.co.uk

    Examples:
        "https://www.example.com/login"          → "example.com"
        "https://login.shop.example.com/account" → "example.com"
        "https://example.co.uk/page?id=10"       → "example.co.uk"
        "http://192.168.1.1/admin"               → "192.168.1.1"

    Returns:
        str: Registrable domain (or IP), or None if extraction fails.
    """
    if not url:
        return None

    url = url.strip()

    # Ensure scheme is present for urlparse to work correctly
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname  # strips port, lowercases
        if not hostname:
            return None

        # Use tldextract to get the registrable domain
        if _TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(hostname)
            # extracted.domain  = "example"
            # extracted.suffix  = "co.uk" / "com"
            # extracted.subdomain = "www" / "login.shop"
            if extracted.domain and extracted.suffix:
                registrable = f"{extracted.domain}.{extracted.suffix}"
                return registrable.lower()
            elif extracted.domain:
                # No known TLD — return the raw hostname (could be IP or local)
                return hostname.lower()
            else:
                return hostname.lower()
        else:
            # Fallback: strip leading "www." only
            if hostname.startswith("www."):
                hostname = hostname[4:]
            return hostname.lower()

    except Exception:
        return None


# ---------------------------------------------------------------------------
# HELPER: RDAP Date Parsing
# ---------------------------------------------------------------------------

def parse_rdap_date(events: list, action: str):
    """
    Extract a specific date string from the RDAP events array.

    Args:
        events: List of RDAP event dicts, each with "eventAction" and "eventDate".
        action: The eventAction to look for
                ("registration", "expiration", "last changed", etc.)

    Returns:
        str: ISO 8601 date string, or None if not found.
    """
    if not events or not isinstance(events, list):
        return None

    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == action:
            date_value = event.get("eventDate")
            if date_value:
                return str(date_value)
    return None


# ---------------------------------------------------------------------------
# HELPER: Domain Age Calculation
# ---------------------------------------------------------------------------

def calculate_domain_age(registration_date: str):
    """
    Calculate domain age in days and years from an ISO 8601 registration date.

    Uses: current_date - registration_date

    Args:
        registration_date: ISO 8601 date string (e.g. "2018-04-12T00:00:00Z")

    Returns:
        Tuple (age_days: int, age_years: float), or (None, None) on failure.
    """
    if not registration_date:
        return None, None

    try:
        # Normalize "Z" suffix to "+00:00" for fromisoformat compatibility
        iso_str = registration_date.replace("Z", "+00:00")
        registered = datetime.fromisoformat(iso_str)

        # Ensure both datetimes are timezone-aware
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - registered).days
        age_years = round(age_days / 365.25, 2)
        return age_days, age_years

    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# HELPER: Entity Extraction (Registrar, Registrant)
# ---------------------------------------------------------------------------

def extract_entity_information(rdap_data: dict) -> dict:
    """
    Extract registrar name, registrant organization, and registrant country
    from the RDAP entities array.

    RDAP entities carry vCard arrays with structured contact information.
    Roles of interest:
        "registrar"   → domain registrar name
        "registrant"  → registrant contact details (often redacted for privacy)

    Returns:
        dict with keys: registrar, registrant_organization, registrant_country
    """
    registrar = None
    registrant_country = None
    registrant_organization = None

    entities = rdap_data.get("entities", [])
    if not isinstance(entities, list):
        return {
            "registrar": registrar,
            "registrant_country": registrant_country,
            "registrant_organization": registrant_organization,
        }

    for entity in entities:
        if not isinstance(entity, dict):
            continue

        roles = entity.get("roles", [])

        # --- Registrar ---
        if "registrar" in roles and registrar is None:
            # Try vcardArray first
            vcard_name = _extract_vcard_fn(entity)
            if vcard_name:
                registrar = vcard_name
            else:
                # Fallback: publicIds, handle, or nested entity name field
                handle = entity.get("handle", "")
                if handle:
                    registrar = handle

        # --- Registrant ---
        if "registrant" in roles:
            vcard_fields = _parse_vcard(entity)
            if vcard_fields.get("org") and registrant_organization is None:
                registrant_organization = vcard_fields["org"]
            if vcard_fields.get("country") and registrant_country is None:
                registrant_country = vcard_fields["country"]
            if vcard_fields.get("adr_country") and registrant_country is None:
                registrant_country = vcard_fields["adr_country"]

        # Also check nested entities (registrar sometimes nests registrant)
        nested = entity.get("entities", [])
        if isinstance(nested, list):
            for nested_entity in nested:
                if not isinstance(nested_entity, dict):
                    continue
                nested_roles = nested_entity.get("roles", [])
                if "registrant" in nested_roles:
                    nested_fields = _parse_vcard(nested_entity)
                    if nested_fields.get("org") and registrant_organization is None:
                        registrant_organization = nested_fields["org"]
                    if nested_fields.get("country") and registrant_country is None:
                        registrant_country = nested_fields["country"]
                    if nested_fields.get("adr_country") and registrant_country is None:
                        registrant_country = nested_fields["adr_country"]

    return {
        "registrar": registrar,
        "registrant_organization": registrant_organization,
        "registrant_country": registrant_country,
    }


def _extract_vcard_fn(entity: dict):
    """Extract the 'fn' (formatted name) field from an entity's vcardArray."""
    vcard_array = entity.get("vcardArray")
    if not vcard_array or len(vcard_array) < 2:
        return None
    vcard = vcard_array[1]
    for field in vcard:
        if isinstance(field, list) and len(field) >= 4:
            if field[0] == "fn" and field[3]:
                return str(field[3]).strip() or None
    return None


def _parse_vcard(entity: dict) -> dict:
    """
    Parse a vCard from an RDAP entity and return a flat dict of relevant fields.

    Extracted fields: fn, org, country, adr_country
    """
    result = {}
    vcard_array = entity.get("vcardArray")
    if not vcard_array or len(vcard_array) < 2:
        return result

    vcard = vcard_array[1]
    for field in vcard:
        if not isinstance(field, list) or len(field) < 4:
            continue

        field_name = field[0]
        field_params = field[1] if len(field) > 1 else {}
        field_value = field[3]

        if field_name == "fn" and field_value:
            result["fn"] = str(field_value).strip()

        elif field_name == "org" and field_value:
            # org value can be a list like ["Example Corp"] or a plain string
            if isinstance(field_value, list):
                result["org"] = " ".join(str(v) for v in field_value).strip()
            else:
                result["org"] = str(field_value).strip()

        elif field_name == "country" and field_value:
            result["country"] = str(field_value).strip()

        elif field_name == "adr" and field_value:
            # ADR is structured: [POBox, Extended, Street, Locality, Region, PostalCode, Country]
            if isinstance(field_value, list) and len(field_value) >= 7:
                country_part = field_value[6]
                if country_part and str(country_part).strip():
                    result["adr_country"] = str(country_part).strip()

    return result


# ---------------------------------------------------------------------------
# HELPER: Domain Status Extraction
# ---------------------------------------------------------------------------

def extract_domain_status(rdap_data: dict) -> list:
    """
    Extract domain status codes from RDAP response.

    The raw status values are preserved exactly as returned by the
    registration service (e.g. "clientTransferProhibited").

    Returns:
        List of status strings.
    """
    raw_status = rdap_data.get("status", [])
    if isinstance(raw_status, list):
        return [str(s) for s in raw_status if s]
    elif raw_status:
        return [str(raw_status)]
    return []


# ---------------------------------------------------------------------------
# HELPER: RDAP Query
# ---------------------------------------------------------------------------

def query_rdap(domain: str) -> dict:
    """
    Query the RDAP protocol for domain registration data.

    Uses rdap.org as the RDAP bootstrap resolver.
    Timeout: 10 seconds (per the specification).

    Args:
        domain: Registrable domain name (e.g. "example.com")

    Returns:
        dict with keys:
            success (bool): Whether the query succeeded.
            data    (dict): Parsed RDAP JSON response (if success).
            error   (str):  Error description (if not success).
    """
    rdap_url = f"https://rdap.org/domain/{domain}"
    print(f"[Agent 1] RDAP URL: {rdap_url}")

    try:
        response = requests.get(
            rdap_url,
            timeout=10,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "DigitalForensicsAgent/1.0 (EvidenceCollection)"
            },
            allow_redirects=True
        )

        if response.status_code == 200:
            return {
                "success": True,
                "data": response.json(),
            }
        elif response.status_code == 404:
            return {
                "success": False,
                "error": f"Domain '{domain}' not found in RDAP (HTTP 404 — "
                         f"domain may not exist or TLD may be unsupported)"
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "RDAP request rate-limited (HTTP 429). Try again later."
            }
        else:
            return {
                "success": False,
                "error": f"RDAP returned HTTP {response.status_code}"
            }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "RDAP request timed out (10-second limit exceeded)"
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "success": False,
            "error": f"RDAP connection error: {str(e)}"
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"RDAP network error: {str(e)}"
        }
    except ValueError:
        return {
            "success": False,
            "error": "Failed to parse RDAP JSON response (malformed data)"
        }


# ---------------------------------------------------------------------------
# HELPER: Format date string for display
# ---------------------------------------------------------------------------

def _format_date(raw_date: str) -> str:
    """
    Format an ISO 8601 date string to a clean YYYY-MM-DD representation.

    If parsing fails, the original string is returned unchanged.
    """
    if not raw_date:
        return "Not Available"
    try:
        iso_str = raw_date.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return raw_date


# ---------------------------------------------------------------------------
# HELPER: Validate URL
# ---------------------------------------------------------------------------

def _is_valid_url_input(url: str) -> bool:
    """
    Perform a basic sanity check on the URL input.

    Accepts bare domains (e.g. "example.com") because extract_domain
    will prepend "https://" before parsing.

    Returns False for inputs that cannot possibly contain a valid hostname.
    """
    if not url or not isinstance(url, str):
        return False

    url = url.strip()
    if not url:
        return False

    # Must contain at least one dot to be a domain or URL
    # (local hostnames without dots are not valid public domains)
    test_url = url if url.startswith(("http://", "https://")) else "https://" + url
    try:
        parsed = urlparse(test_url)
        return bool(parsed.hostname and "." in parsed.hostname)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# MAIN FUNCTION: analyze_domain
# ---------------------------------------------------------------------------

def analyze_domain(url: str) -> dict:
    """
    Agent 1 — Domain Identity: Main evidence collection function.

    Accepts a URL (any form), extracts the registrable domain, queries
    RDAP for registration data, and returns all available evidence in a
    structured dictionary.

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
                    "domain_name":             str,
                    "domain_age_days":         int | "Not Available",
                    "domain_age_years":        float | "Not Available",
                    "registration_date":       str | "Not Available",
                    "expiry_date":             str | "Not Available",
                    "registrar":               str | "Not Available",
                    "whois_available":         bool,
                    "whois_information":       dict,
                    "registrant_organization": str | "Not Available",
                    "registrant_country":      str | "Not Available",
                    "domain_status":           list[str]
                },
                "errors": list[str]
            }
    """
    print(f"[Agent 1] Starting domain analysis for: {url}")

    errors = []

    # Initialize data with "Not Available" defaults for every field
    data = {
        "domain_name":             "Not Available",
        "domain_age_days":         "Not Available",
        "domain_age_years":        "Not Available",
        "registration_date":       "Not Available",
        "expiry_date":             "Not Available",
        "registrar":               "Not Available",
        "whois_available":         False,
        "whois_information":       {
            "whois_available":         False,
            "raw_information":         "Not Available",
            "registration_date":       "Not Available",
            "expiry_date":             "Not Available",
            "registrar":               "Not Available",
            "registrant_organization": "Not Available",
            "registrant_country":      "Not Available",
            "domain_status":           []
        },
        "registrant_organization": "Not Available",
        "registrant_country":      "Not Available",
        "domain_status":           []
    }

    # ------------------------------------------------------------------
    # Step 1: Validate input
    # ------------------------------------------------------------------
    if not _is_valid_url_input(url):
        print("[Agent 1] Error: Invalid URL input.")
        errors.append(
            "Invalid URL — could not identify a valid domain name. "
            "Provide a full URL such as https://example.com"
        )
        return build_agent_result(
            agent_identifier="A1",
            target=url or "",
            status="error",
            data=data,
            evidence=[],
            errors=errors
        )

    # ------------------------------------------------------------------
    # Step 2: Extract registrable domain
    # ------------------------------------------------------------------
    print("[Agent 1] Extracting registrable domain...")
    domain = extract_domain(url)

    if not domain:
        print("[Agent 1] Error: Could not extract domain.")
        errors.append("Could not extract a valid registrable domain from the URL.")
        return build_agent_result(
            agent_identifier="A1",
            target=url or "",
            status="error",
            data=data,
            evidence=[],
            errors=errors
        )

    data["domain_name"] = domain
    print(f"[Agent 1] Domain: {domain}")

    # ------------------------------------------------------------------
    # Step 3: Query RDAP (single request covers all fields)
    # ------------------------------------------------------------------
    print(f"[Agent 1] Querying RDAP for: {domain}...")
    rdap_result = query_rdap(domain)

    if not rdap_result["success"]:
        rdap_error = rdap_result.get("error", "RDAP query failed")
        print(f"[Agent 1] RDAP unavailable: {rdap_error}")
        errors.append(f"RDAP query failed: {rdap_error}")

        # Return partial result — domain name is known but RDAP data is not
        data["whois_information"] = {
            "whois_available": False,
            "raw_information": "Not Available",
            "registration_date": "Not Available",
            "expiry_date": "Not Available",
            "registrar": "Not Available",
            "registrant_organization": "Not Available",
            "registrant_country": "Not Available",
            "domain_status": []
        }
        evidence = [
            create_evidence_item("A1", 1, "Domain name", domain, severity="info", source="RDAP", evidence_type="deterministic"),
            create_evidence_item("A1", 2, "WHOIS/RDAP availability", False, severity="info", source="RDAP", evidence_type="deterministic", metadata={"availability": "unavailable", "error": rdap_error})
        ]
        return build_agent_result(
            agent_identifier="A1",
            target=url,
            status="partial",
            data=data,
            evidence=evidence,
            errors=errors
        )

    # RDAP succeeded — parse all fields independently
    rdap_data = rdap_result["data"]
    data["whois_available"] = True
    print("[Agent 1] RDAP data received. Parsing fields...")

    # ------------------------------------------------------------------
    # Step 4a: Domain Status
    # ------------------------------------------------------------------
    try:
        domain_status = extract_domain_status(rdap_data)
        data["domain_status"] = domain_status
        if domain_status:
            print(f"[Agent 1] Domain status found: {domain_status}")
        else:
            print("[Agent 1] Domain status not present in RDAP response")
            errors.append("Domain status not present in RDAP response")
    except Exception as e:
        print(f"[Agent 1] Warning: Failed to parse domain status: {e}")
        errors.append(f"Failed to parse domain status: {str(e)}")

    # ------------------------------------------------------------------
    # Step 4b: Registration and Expiry Dates
    # ------------------------------------------------------------------
    try:
        events = rdap_data.get("events", [])

        # Registration date
        reg_raw = parse_rdap_date(events, "registration")
        if reg_raw:
            data["registration_date"] = _format_date(reg_raw)
            print(f"[Agent 1] Registration date found: {data['registration_date']}")
        else:
            print("[Agent 1] Registrant registration date unavailable")
            errors.append("Registration date not available in RDAP response")

        # Expiry date
        exp_raw = parse_rdap_date(events, "expiration")
        if exp_raw:
            data["expiry_date"] = _format_date(exp_raw)
            print(f"[Agent 1] Expiry date found: {data['expiry_date']}")
        else:
            print("[Agent 1] Expiry date unavailable")
            errors.append("Expiry date not available in RDAP response")

    except Exception as e:
        print(f"[Agent 1] Warning: Failed to parse dates: {e}")
        errors.append(f"Failed to parse registration/expiry dates: {str(e)}")

    # ------------------------------------------------------------------
    # Step 4c: Domain Age (derived from registration date)
    # ------------------------------------------------------------------
    try:
        if data["registration_date"] and data["registration_date"] != "Not Available":
            age_days, age_years = calculate_domain_age(data["registration_date"])
            if age_days is not None:
                data["domain_age_days"] = age_days
                data["domain_age_years"] = age_years
                print(f"[Agent 1] Domain age: {age_days} days ({age_years} years)")
            else:
                print("[Agent 1] Could not calculate domain age from registration date")
                errors.append("Could not calculate domain age from registration date")
        else:
            print("[Agent 1] Domain age cannot be calculated — registration date unavailable")
    except Exception as e:
        print(f"[Agent 1] Warning: Failed to calculate domain age: {e}")
        errors.append(f"Failed to calculate domain age: {str(e)}")

    # ------------------------------------------------------------------
    # Step 4d: Registrar and Registrant Information
    # ------------------------------------------------------------------
    try:
        entity_info = extract_entity_information(rdap_data)

        # Registrar
        registrar_val = entity_info.get("registrar")
        if registrar_val and registrar_val.strip():
            data["registrar"] = registrar_val.strip()
            print(f"[Agent 1] Registrar found: {data['registrar']}")
        else:
            print("[Agent 1] Registrar information unavailable")
            errors.append("Registrar information not available in RDAP response")

        # Registrant Organization
        org_val = entity_info.get("registrant_organization")
        if org_val and org_val.strip():
            data["registrant_organization"] = org_val.strip()
            print(f"[Agent 1] Registrant organization found: {data['registrant_organization']}")
        else:
            print("[Agent 1] Registrant organization unavailable (may be privacy-protected)")
            errors.append(
                "Registrant organization not publicly available "
                "(privacy protection or not provided)"
            )

        # Registrant Country
        country_val = entity_info.get("registrant_country")
        if country_val and country_val.strip():
            data["registrant_country"] = country_val.strip()
            print(f"[Agent 1] Registrant country found: {data['registrant_country']}")
        else:
            print("[Agent 1] Registrant country unavailable (may be privacy-protected)")
            errors.append(
                "Registrant country not publicly available "
                "(privacy protection or not provided)"
            )

    except Exception as e:
        print(f"[Agent 1] Warning: Failed to parse entity information: {e}")
        errors.append(f"Failed to parse registrar/registrant information: {str(e)}")

    # ------------------------------------------------------------------
    # Step 5: Build structured WHOIS information block
    # ------------------------------------------------------------------
    data["whois_information"] = {
        "whois_available":         True,
        "raw_information":         f"RDAP data retrieved from rdap.org for {domain}",
        "registration_date":       data["registration_date"],
        "expiry_date":             data["expiry_date"],
        "registrar":               data["registrar"],
        "registrant_organization": data["registrant_organization"],
        "registrant_country":      data["registrant_country"],
        "domain_status":           data["domain_status"]
    }

    # ------------------------------------------------------------------
    # Step 6: Compile structured evidence items
    # ------------------------------------------------------------------
    evidence = []
    evidence.append(create_evidence_item("A1", 1, "Domain name", domain, severity="info", source="RDAP", evidence_type="deterministic"))
    
    age_days = data.get("domain_age_days")
    if age_days not in ("Not Available", None):
        age_sev = "medium" if isinstance(age_days, (int, float)) and age_days < 30 else "info"
        evidence.append(create_evidence_item("A1", 2, "Domain age", age_days, severity=age_sev, source="RDAP", evidence_type="deterministic", metadata={"domain_age_years": data.get("domain_age_years")}))
    
    if data.get("registration_date") not in ("Not Available", None):
        evidence.append(create_evidence_item("A1", 3, "Domain registration date", data["registration_date"], severity="info", source="RDAP", evidence_type="deterministic"))
    
    if data.get("expiry_date") not in ("Not Available", None):
        evidence.append(create_evidence_item("A1", 4, "Domain expiration date", data["expiry_date"], severity="info", source="RDAP", evidence_type="deterministic"))
        
    if data.get("registrar") not in ("Not Available", None):
        evidence.append(create_evidence_item("A1", 5, "Domain registrar", data["registrar"], severity="info", source="RDAP", evidence_type="deterministic"))
        
    evidence.append(create_evidence_item("A1", 6, "WHOIS/RDAP availability", data.get("whois_available", False), severity="info", source="RDAP", evidence_type="deterministic"))
    
    if data.get("registrant_organization") not in ("Not Available", None):
        evidence.append(create_evidence_item("A1", 7, "Registrant organization", data["registrant_organization"], severity="info", source="RDAP", evidence_type="deterministic"))
        
    if data.get("registrant_country") not in ("Not Available", None):
        evidence.append(create_evidence_item("A1", 8, "Registrant country", data["registrant_country"], severity="info", source="RDAP", evidence_type="deterministic"))
        
    if data.get("domain_status"):
        evidence.append(create_evidence_item("A1", 9, "Domain status codes", data["domain_status"], severity="info", source="RDAP", evidence_type="deterministic"))

    # ------------------------------------------------------------------
    # Step 7: Determine overall status and build result
    # ------------------------------------------------------------------
    if not errors:
        overall_status = "success"
    else:
        overall_status = "partial"

    print(f"[Agent 1] Analysis completed. Status: {overall_status}")

    return build_agent_result(
        agent_identifier="A1",
        target=url,
        status=overall_status,
        data=data,
        evidence=evidence,
        errors=errors
    )