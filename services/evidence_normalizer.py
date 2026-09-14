"""
services/evidence_normalizer.py
===============================
Evidence Normalization Layer for Multi-Agent Digital Forensics System.

Normalizes forensic evidence items, entity targets, and provenance metadata
into a unified, loss-minimizing, and traceable structure for the Evidence Ledger.

Architectural Guarantees:
- Deterministic & Reproducible: Same inputs always yield identical normalized records.
- Provenance Preservation: Retains originating agent, component, and source feed.
- Loss-Minimizing: Raw observations and agent metadata are preserved in the payload.
- Scoring Independence: Does NOT calculate trust scores, risk scores, or verdicts.
- Missing Data Integrity: Unavailable or missing telemetry remains missing (None),
  never converted into artificial zeros or assumed to be negative evidence.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from services.evidence_schema import (
    CANONICAL_AGENT_METADATA,
    VALID_EVIDENCE_TYPES,
    VALID_SEVERITIES,
    VALID_STATUSES,
    EVIDENCE_ID_PATTERN,
)


# =====================================================================
# 1. TARGET / ENTITY NORMALIZATION
# =====================================================================

def normalize_target(target_input: Optional[str]) -> Dict[str, Any]:
    """
    Produce a canonical entity target representation from a URL, domain, or IP.
    
    Preserves missing fields as None without fabricating default values.
    
    Returns:
        Dict with keys:
            - original_url: string as provided
            - normalized_url: canonicalized URL or None
            - scheme: 'http', 'https', etc. or None
            - hostname: canonical lowercase hostname
            - registrable_domain: base domain (e.g. 'example.com') or None
            - port: integer port if specified or None
            - path: request path or None
    """
    if not target_input or not isinstance(target_input, str):
        return {
            "original_url": "",
            "normalized_url": None,
            "scheme": None,
            "hostname": None,
            "registrable_domain": None,
            "port": None,
            "path": None
        }

    raw = target_input.strip()
    original_url = raw

    # Detect if raw input already has a scheme
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw))
    parse_target = raw if has_scheme else f"http://{raw}"

    try:
        parsed = urllib.parse.urlparse(parse_target)
        scheme = parsed.scheme.lower() if has_scheme else None
        netloc = parsed.netloc or parsed.path.split("/")[0]
        
        # Split port if present
        hostname = None
        port = None
        if ":" in netloc:
            parts = netloc.split(":")
            hostname = parts[0].lower()
            try:
                port = int(parts[1])
            except (ValueError, TypeError):
                port = None
        else:
            hostname = netloc.lower() if netloc else None

        # Clean hostname
        if hostname:
            hostname = hostname.rstrip(".")

        # Extract path
        path = None
        if has_scheme:
            path = parsed.path if parsed.path else "/"
        else:
            # If plain domain with path
            if "/" in raw:
                path = "/" + raw.split("/", 1)[1]
            else:
                path = None

        # Determine registrable domain
        registrable_domain = None
        if hostname:
            if _HAS_TLDEXTRACT:
                try:
                    extracted = tldextract.extract(hostname)
                    reg_dom = getattr(extracted, "top_domain_under_public_suffix", None) or getattr(extracted, "registered_domain", None)
                    if reg_dom:
                        registrable_domain = reg_dom.lower()
                    else:
                        registrable_domain = hostname
                except Exception:
                    registrable_domain = _fallback_registrable_domain(hostname)
            else:
                registrable_domain = _fallback_registrable_domain(hostname)

        # Build normalized URL
        normalized_url = None
        if hostname:
            used_scheme = scheme if scheme else "http"
            port_part = f":{port}" if port and port not in (80, 443) else ""
            path_part = path if path else ""
            normalized_url = f"{used_scheme}://{hostname}{port_part}{path_part}"

        return {
            "original_url": original_url,
            "normalized_url": normalized_url,
            "scheme": scheme,
            "hostname": hostname,
            "registrable_domain": registrable_domain,
            "port": port,
            "path": path
        }
    except Exception:
        return {
            "original_url": original_url,
            "normalized_url": None,
            "scheme": None,
            "hostname": None,
            "registrable_domain": None,
            "port": None,
            "path": None
        }


def _fallback_registrable_domain(hostname: str) -> str:
    """Fallback parser for registrable domain when tldextract is unavailable."""
    if not hostname:
        return ""
    # Check if IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return hostname
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # Simple two-part TLD check (co.uk, com.au, org.in, etc.)
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "org.in", "co.in", "com.br"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# =====================================================================
# 2. EVIDENCE NORMALIZATION
# =====================================================================

def normalize_evidence_item(
    evidence_item: Dict[str, Any],
    agent_identifier: Union[int, str],
    agent_result: Optional[Dict[str, Any]] = None,
    canonical_target: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Normalize an individual evidence item into a research-grade ledger entry.
    
    Preserves:
    - Identity: Traceable evidence_id (e.g. E1-01)
    - Provenance: Originating agent number, name, source component/feed
    - Target: Canonical entity reference
    - Meaning: Observation description/finding, raw value, severity, type, strength
    - Data: Full metadata and observation context
    - Status: Execution state of originating agent
    - Relationships: Placeholder list for cross-agent correlation
    """
    if not isinstance(evidence_item, dict):
        evidence_item = {}

    # 1. Resolve agent metadata
    agent_num = 1
    if isinstance(agent_identifier, str):
        if agent_identifier.startswith("A") and agent_identifier[1:].isdigit():
            agent_num = int(agent_identifier[1:])
        elif agent_identifier.isdigit():
            agent_num = int(agent_identifier)
        else:
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

    # 2. Traceable Evidence ID
    raw_ev_id = evidence_item.get("evidence_id")
    if raw_ev_id and isinstance(raw_ev_id, str) and EVIDENCE_ID_PATTERN.match(raw_ev_id):
        evidence_id = raw_ev_id
    else:
        # Fallback to deterministic ID if missing
        evidence_id = f"E{agent_num}-01"

    # 3. Evidence Type
    raw_type = str(evidence_item.get("type", "deterministic")).strip().lower()
    evidence_type = raw_type if raw_type in VALID_EVIDENCE_TYPES else "deterministic"

    # 4. Severity
    raw_sev = str(evidence_item.get("severity", "info")).strip().lower()
    severity = raw_sev if raw_sev in VALID_SEVERITIES else "info"

    # 5. Finding & Description
    finding = str(evidence_item.get("finding") or evidence_item.get("description") or "").strip()
    description = finding

    # 6. Observed Value
    value = evidence_item.get("value")

    # 7. Evidence Strength
    raw_strength = evidence_item.get("evidence_strength")
    evidence_strength = None
    if raw_strength is not None:
        try:
            s_val = float(raw_strength)
            if 0.0 <= s_val <= 1.0:
                evidence_strength = round(s_val, 4)
        except (ValueError, TypeError):
            evidence_strength = None

    # 8. Data / Metadata context
    raw_meta = evidence_item.get("metadata")
    item_data = raw_meta if isinstance(raw_meta, dict) else {}
    if "category" in evidence_item:
        item_data["category"] = evidence_item["category"]

    # 9. Target Normalization
    if canonical_target and isinstance(canonical_target, dict):
        target_info = canonical_target
    else:
        target_str = agent_result.get("target") if isinstance(agent_result, dict) else None
        target_info = normalize_target(target_str)

    # 10. Agent Status & Provenance
    agent_status = "success"
    if agent_result and isinstance(agent_result, dict):
        raw_status = agent_result.get("status", "success")
        if raw_status in VALID_STATUSES:
            agent_status = raw_status

    source_detail = str(evidence_item.get("source", "Unknown")).strip()
    provenance = {
        "source_agent": meta["id"],
        "source_name": meta["name"],
        "source_number": meta["number"],
        "source_function": f"analyze_{meta['name'].lower().replace(' ', '_').replace('/', '_')}",
        "source_type": "agent_output",
        "source_detail": source_detail,
        "agent_status": agent_status
    }

    # 11. Entry status
    # Distinguish unavailable / error / skipped from negative evidence
    if agent_status in ("unavailable", "restricted"):
        entry_status = "unavailable"
    elif agent_status == "error":
        entry_status = "error"
    elif agent_status == "skipped":
        entry_status = "skipped"
    elif agent_status == "partial":
        entry_status = "partial"
    else:
        entry_status = "success"

    return {
        "evidence_id": evidence_id,
        "agent_id": meta["number"],
        "agent_name": meta["name"],
        "evidence_type": evidence_type,
        "severity": severity,
        "description": description,
        "finding": finding,
        "value": value,
        "evidence_strength": evidence_strength,
        "data": item_data,
        "target": target_info,
        "provenance": provenance,
        "status": entry_status,
        "relationships": []
    }
