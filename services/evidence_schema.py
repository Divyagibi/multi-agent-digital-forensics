"""
services/evidence_schema.py
===========================
Common Evidence Schema & Validation Framework for Multi-Agent Digital Forensics System.

Architectural Rule:
    Agents collect evidence. They do NOT calculate final trust scores, risk scores,
    or final website verdicts. Those responsibilities are decoupled and delegated
    to the future Trust Calculation Engine and AI Reasoning Engine.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union


# =====================================================================
# 1. CANONICAL AGENT REGISTRY
# =====================================================================

CANONICAL_AGENT_METADATA = {
    1: {"id": "A1", "number": 1, "name": "Domain Identity", "desc": "Domain registration, RDAP/WHOIS, age & registrar"},
    2: {"id": "A2", "number": 2, "name": "DNS & Infrastructure", "desc": "A, AAAA, MX, NS, TXT, CNAME, DNSSEC, CDN & IP"},
    3: {"id": "A3", "number": 3, "name": "SSL/HTTPS", "desc": "TLS version, X509 certificates, cipher suites & HSTS"},
    4: {"id": "A4", "number": 4, "name": "Website Content", "desc": "Metadata, company detection, policy pages & broken links"},
    5: {"id": "A5", "number": 5, "name": "URL Structure", "desc": "Lexical features, Punycode, homograph & redirects"},
    6: {"id": "A6", "number": 6, "name": "Reputation & Threat Intelligence", "desc": "VirusTotal, Safe Browsing, PhishTank, OpenPhish, AbuseIPDB, URLHaus & Blocklists"},
    7: {"id": "A7", "number": 7, "name": "Technical Fingerprinting", "desc": "Web server, CMS, frameworks, JS libraries, analytics, trackers, admin panels & directories"},
    8: {"id": "A8", "number": 8, "name": "Website Behavior", "desc": "Automatic redirects, popups, forced downloads, JS indicators, forms & fake login"},
    9: {"id": "A9", "number": 9, "name": "Brand Verification", "desc": "Logo, favicon, brand name, trademark references, color theme, layout & official domain comparison"},
    10: {"id": "A10", "number": 10, "name": "Visual/UI Analysis", "desc": "Screenshot, OCR text, trust badges, payment logos, reviews & suspicious UI patterns"},
    11: {"id": "A11", "number": 11, "name": "Content Quality", "desc": "Grammar, spelling, AI-generated indicators, duplicate text, unrealistic claims, urgency & scam keywords"},
    12: {"id": "A12", "number": 12, "name": "Contact Verification", "desc": "Email, phone, physical address, Google Maps, social media, GSTIN/VAT & business registry verification"},
    13: {"id": "A13", "number": 13, "name": "External Presence / OSINT", "desc": "LinkedIn, Facebook, X/Twitter, Instagram, GitHub, Reddit, News, Reviews & Forums"},
    14: {"id": "A14", "number": 14, "name": "Historical Evidence", "desc": "Wayback Machine archives, content evolution, ownership & DNS infrastructure timeline"},
    15: {"id": "A15", "number": 15, "name": "User Trust Signals", "desc": "Trustpilot, Google Reviews, Reddit discussions, scam complaints, consumer forums, testimonials & cross-source corroboration"},
    16: {"id": "A16", "number": 16, "name": "Network Security", "desc": "Open ports, HTTP & security headers, CSP, CORS configuration, X-Frame-Options & server fingerprinting"},
    17: {"id": "A17", "number": 17, "name": "Malware Indicators", "desc": "Malicious downloads, suspicious scripts, drive-by patterns, cryptomining & obfuscated JavaScript"},
    18: {"id": "A18", "number": 18, "name": "QR Analysis", "desc": "Decodes QR payloads, extracts embedded URLs, inspects redirect chains, shorteners & parameters"},
}

# String ID to integer mapping
AGENT_ID_MAP = {f"A{i}": i for i in range(1, 19)}
for i in range(1, 19):
    AGENT_ID_MAP[str(i)] = i


# =====================================================================
# 2. CONTROLLED VOCABULARIES & VALIDATION CONSTANTS
# =====================================================================

VALID_EVIDENCE_TYPES = {
    "deterministic",       # Directly observed or measured
    "inference",           # Analytical conclusion derived from observations (must have strength)
    "threat_intelligence", # Evidence from threat intelligence databases/feeds
    "external_source",     # Evidence from public external sources (OSINT, reviews, registries)
    "historical",          # Historical timeline/archive evidence
    "subjective"           # Qualitative review or consumer sentiment assessments
}

VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical"
}

VALID_STATUSES = {
    "success",
    "partial",
    "error",
    "skipped",
    "unavailable",
    "completed",
    "restricted"
}

EVIDENCE_ID_PATTERN = re.compile(r"^E(1[0-8]|[1-9])-\d{2,}$")


# =====================================================================
# 3. EVIDENCE ITEM BUILDER & VALIDATOR
# =====================================================================

def create_evidence_item(
    agent_id: Union[int, str],
    index: int,
    finding: str,
    value: Any,
    severity: str = "info",
    source: str = "Unknown",
    evidence_type: str = "deterministic",
    evidence_strength: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None,
    category: Optional[str] = None
) -> Dict[str, Any]:
    """
    Factory function to construct a validated evidence item.

    Format of evidence_id: E<agent_number>-<index:02d>
    Example: E1-01, E2-03, E18-05
    """
    # Normalize agent number
    if isinstance(agent_id, str):
        if agent_id.startswith("A") and agent_id[1:].isdigit():
            agent_num = int(agent_id[1:])
        elif agent_id.isdigit():
            agent_num = int(agent_id)
        else:
            agent_num = 1
    else:
        agent_num = int(agent_id)

    ev_id = f"E{agent_num}-{index:02d}"

    # Validate type
    norm_type = str(evidence_type).strip().lower()
    if norm_type not in VALID_EVIDENCE_TYPES:
        norm_type = "deterministic"

    # Validate severity
    norm_sev = str(severity).strip().lower()
    if norm_sev not in VALID_SEVERITIES:
        norm_sev = "info"

    # Validate evidence_strength
    clean_strength = None
    if evidence_strength is not None:
        try:
            strength_val = float(evidence_strength)
            if 0.0 <= strength_val <= 1.0:
                clean_strength = round(strength_val, 4)
        except (ValueError, TypeError):
            clean_strength = None

    item = {
        "evidence_id": ev_id,
        "type": norm_type,
        "finding": str(finding).strip(),
        "value": value,
        "severity": norm_sev,
        "source": str(source).strip(),
        "evidence_strength": clean_strength,
        "metadata": metadata if isinstance(metadata, dict) else {}
    }
    if category:
        item["category"] = category

    return item


def validate_evidence_item(item: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate an individual evidence item against the schema specification.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    if not isinstance(item, dict):
        return False, ["Evidence item must be a dictionary."]

    # 1. evidence_id
    ev_id = item.get("evidence_id")
    if not ev_id or not isinstance(ev_id, str):
        errors.append("Evidence item must have a non-empty string 'evidence_id'.")
    elif not EVIDENCE_ID_PATTERN.match(ev_id):
        errors.append(f"Invalid evidence_id format: '{ev_id}'. Expected 'E<1-18>-<index:02d>'.")

    # 2. type
    ev_type = item.get("type")
    if not ev_type or ev_type not in VALID_EVIDENCE_TYPES:
        errors.append(f"Invalid evidence type: '{ev_type}'. Must be one of {sorted(VALID_EVIDENCE_TYPES)}.")

    # 3. finding
    finding = item.get("finding")
    if not finding or not isinstance(finding, str) or not finding.strip():
        errors.append("Evidence item must have a non-empty string 'finding'.")

    # 4. severity
    severity = item.get("severity")
    if not severity or severity not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}.")

    # 5. source
    source = item.get("source")
    if not source or not isinstance(source, str) or not source.strip():
        errors.append("Evidence item must have a non-empty string 'source'.")

    # 6. evidence_strength (optional, but if present must be float 0.0 - 1.0)
    strength = item.get("evidence_strength")
    if strength is not None:
        if not isinstance(strength, (int, float)) or isinstance(strength, bool) or not (0.0 <= strength <= 1.0):
            errors.append(f"Invalid evidence_strength: {strength}. Must be float in range [0.0, 1.0] or None.")

    # 7. metadata (must be dict)
    meta = item.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        errors.append(f"Metadata must be a dictionary, got {type(meta).__name__}.")

    return len(errors) == 0, errors


# =====================================================================
# 4. AGENT RESULT BUILDER & VALIDATOR
# =====================================================================

def build_agent_result(
    agent_identifier: Union[int, str],
    target: str,
    status: str,
    data: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    errors: Optional[List[Any]] = None,
    extra_fields: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Standardizes the final output envelope for an agent.
    Guarantees consistent top-level fields, status reporting, and evidence embedding.
    """
    # Resolve agent metadata
    agent_num = 1
    if isinstance(agent_identifier, str):
        if agent_identifier.startswith("A") and agent_identifier[1:].isdigit():
            agent_num = int(agent_identifier[1:])
        elif agent_identifier.isdigit():
            agent_num = int(agent_identifier)
        else:
            # Match by name
            for k, v in CANONICAL_AGENT_METADATA.items():
                if v["name"].lower() == agent_identifier.lower() or f"agent {k}".lower() == agent_identifier.lower():
                    agent_num = k
                    break
    elif isinstance(agent_identifier, int):
        agent_num = agent_identifier

    meta = CANONICAL_AGENT_METADATA.get(agent_num, {
        "id": f"A{agent_num}",
        "number": agent_num,
        "name": f"Agent {agent_num}",
        "desc": "Forensic analysis agent"
    })

    # Normalize status
    norm_status = str(status).strip().lower()
    if norm_status not in VALID_STATUSES:
        norm_status = "error" if errors else "success"

    # Normalize errors
    clean_errors = []
    if errors:
        for err in errors:
            if isinstance(err, (str, dict)):
                clean_errors.append(err)
            else:
                clean_errors.append(str(err))

    # Standardized legacy block
    legacy_block = {
        "trust_score": None,
        "risk_score": None,
        "verdict": "not_calculated",
        "notice": "Agent-level scores are legacy/preliminary. Final trust calculation is handled by the Trust Calculation Engine."
    }

    result = {
        "agent": meta["name"],
        "agent_id": meta["id"],
        "agent_name": meta["name"],
        "agent_number": meta["number"],
        "status": norm_status,
        "target": target or "",
        "data": data if isinstance(data, dict) else {},
        "evidence": evidence if isinstance(evidence, list) else [],
        "errors": clean_errors,
        "legacy": legacy_block
    }

    # If caller provided extra agent-specific root attributes (like input, virustotal, etc.)
    if extra_fields and isinstance(extra_fields, dict):
        for k, v in extra_fields.items():
            result[k] = v

    return result


def validate_agent_result(result: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a complete agent result against the common schema.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    if not isinstance(result, dict):
        return False, ["Agent result must be a dictionary."]

    # Required top-level keys
    for req_key in ["agent", "agent_id", "status", "target", "data", "evidence", "errors"]:
        if req_key not in result:
            errors.append(f"Missing required top-level key: '{req_key}'.")

    # Status check
    status = result.get("status")
    if status not in VALID_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of {sorted(list(VALID_STATUSES))}.")

    # Data check
    if not isinstance(result.get("data"), dict):
        errors.append("'data' must be a dictionary.")

    # Errors check
    if not isinstance(result.get("errors"), list):
        errors.append("'errors' must be a list.")

    # Evidence list check
    evidence_list = result.get("evidence")
    if not isinstance(evidence_list, list):
        errors.append("'evidence' must be a list.")
    else:
        for i, ev in enumerate(evidence_list):
            is_valid_item, item_errors = validate_evidence_item(ev)
            if not is_valid_item:
                for ie in item_errors:
                    errors.append(f"Evidence item [{i}] ({ev.get('evidence_id', 'unknown')}): {ie}")

    return len(errors) == 0, errors
