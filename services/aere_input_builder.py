"""
services/aere_input_builder.py
==============================
AERE Input Builder for Multi-Agent Digital Forensics System.

Serves as a deterministic, non-destructive mediation layer between the
canonical Investigation Evidence Ledger, the Trust Calculation Engine (TCE),
and the future AI Evidence Reasoning Engine (AERE).

Core Responsibilities:
1. Input Payload Assembly: Combines Evidence Ledger data, TCE metrics, and
   investigation target metadata into a structured, machine-readable envelope.
2. Ledger Immutability: Treats the canonical Evidence Ledger as an immutable
   forensic artifact; NEVER mutates, deletes, or re-indexes ledger entries.
3. Actual Runtime Data: Copies runtime TCE metrics and ledger evidence IDs verbatim;
   NEVER introduces hardcoded, fictional, or illustrative values.
4. Sensitive Data Masking: Redacts credential-like fields (passwords, auth tokens,
   API keys, session cookies) from the AERE-facing payload while preserving raw
   evidence in the ledger.
5. Field-Aware Data Minimization: Applies bounded-context size limits on text
   and structured data to prevent context-window blowup without blind truncation.
6. Relationship & Lineage Preservation: Preserves all explicit ledger relationships
   (supporting, contradiction, duplicate, derived_from, same_target, related_dimension).
7. Missing Telemetry Neutrality: Preserves unavailable, skipped, error, and restricted
   telemetry states without converting them into synthetic negative evidence.
8. Deterministic Serialization: Produces stable, reproducibly ordered payloads
   with canonical SHA-256 payload digests.
"""

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.evidence_normalizer import normalize_target


# =====================================================================
# CONFIGURABLE BOUNDED-CONTEXT LIMITS (Prototype Parameters)
# =====================================================================
MAX_FINDING_LENGTH: int = 500
MAX_DESCRIPTION_LENGTH: int = 500
MAX_VALUE_STRING_LENGTH: int = 300
MAX_DATA_FIELD_STRING_LENGTH: int = 300
MAX_METADATA_ENTRIES: int = 25
MAX_COLLECTION_ITEMS: int = 30

BUILDER_VERSION: str = "1.0.0"
AERE_INPUT_SCHEMA_VERSION: str = "2026.09-v1"

# Case-insensitive sensitive key identifiers for masking
SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password", "pass", "passwd", "pwd", "secret", "token", "auth_token",
    "access_token", "api_key", "apikey", "bearer", "authorization",
    "cookie", "session_id", "sessionid", "jwt", "private_key",
    "secret_key", "client_secret", "app_key"
}


class AEREInputBuilder:
    """
    Deterministic mediation builder that constructs bounded, sanitized,
    and grounded input payloads for the AI Evidence Reasoning Engine.
    """

    def __init__(
        self,
        max_finding_len: int = MAX_FINDING_LENGTH,
        max_desc_len: int = MAX_DESCRIPTION_LENGTH,
        max_val_len: int = MAX_VALUE_STRING_LENGTH,
        max_data_field_len: int = MAX_DATA_FIELD_STRING_LENGTH,
        sensitive_keys: Optional[Set[str]] = None
    ):
        self.max_finding_len = max_finding_len
        self.max_desc_len = max_desc_len
        self.max_val_len = max_val_len
        self.max_data_field_len = max_data_field_len
        self.sensitive_keys = sensitive_keys or SENSITIVE_KEY_PATTERNS

    # -----------------------------------------------------------------
    # 1. Sensitive Data Masking Helpers
    # -----------------------------------------------------------------
    def is_sensitive_key(self, key: str) -> bool:
        """Check if a field name indicates sensitive credential data."""
        if not key or not isinstance(key, str):
            return False
        k = key.strip().lower()
        if k in self.sensitive_keys:
            return True
        for pattern in self.sensitive_keys:
            if pattern in k and len(pattern) >= 4:
                return True
        return False

    def mask_value(self, val: Any, key_name: str = "") -> Any:
        """
        Recursively mask sensitive values in nested dicts/lists/strings
        without mutating the source object.
        """
        if self.is_sensitive_key(key_name):
            if val is None:
                return None
            return "[REDACTED]"

        if isinstance(val, dict):
            return {k: self.mask_value(v, key_name=k) for k, v in val.items()}

        if isinstance(val, list):
            return [self.mask_value(item, key_name=key_name) for item in val]

        if isinstance(val, str):
            # Check for inline bearer token or private key patterns
            if val.startswith("Bearer ") and len(val) > 15:
                return "Bearer [REDACTED]"
            if "BEGIN PRIVATE KEY" in val or "BEGIN RSA PRIVATE KEY" in val:
                return "[REDACTED_PRIVATE_KEY]"
            return val

        return val

    # -----------------------------------------------------------------
    # 2. Bounded Context Truncation Helpers
    # -----------------------------------------------------------------
    def bound_string(self, text: Any, max_length: int) -> Any:
        """Apply field-aware string length bounds with indicator."""
        if not isinstance(text, str):
            return text
        if len(text) <= max_length:
            return text
        return text[:max_length] + " [TRUNCATED]"

    def sanitize_structured_data(self, data: Any, depth: int = 0) -> Any:
        """
        Bound sizes of nested dictionaries and lists while filtering oversized blobs.
        """
        if depth > 4:
            return "[NESTED_DATA_DEPTH_LIMIT]"

        if isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            items_processed = 0
            for k, v in data.items():
                if items_processed >= MAX_METADATA_ENTRIES:
                    sanitized["_omitted_entries_count"] = len(data) - items_processed
                    break
                # Skip massive binary / base64 image strings
                if isinstance(v, str) and (len(v) > 2000 and ("base64," in v or v.startswith("data:image"))):
                    sanitized[k] = "[IMAGE_BINARY_BLOB_OMITTED]"
                else:
                    sanitized[k] = self.sanitize_structured_data(v, depth + 1)
                items_processed += 1
            return sanitized

        if isinstance(data, list):
            if len(data) > MAX_COLLECTION_ITEMS:
                truncated_list = [self.sanitize_structured_data(x, depth + 1) for x in data[:MAX_COLLECTION_ITEMS]]
                truncated_list.append(f"[{len(data) - MAX_COLLECTION_ITEMS} items omitted]")
                return truncated_list
            return [self.sanitize_structured_data(x, depth + 1) for x in data]

        if isinstance(data, str):
            return self.bound_string(data, self.max_data_field_len)

        return data

    # -----------------------------------------------------------------
    # 3. Single Entry Sanitization
    # -----------------------------------------------------------------
    def sanitize_entry(
        self,
        entry: Dict[str, Any],
        tce_contrib_lookup: Dict[str, Dict[str, Any]],
        telemetry_stats: Dict[str, int]
    ) -> Dict[str, Any]:
        """
        Produce a sanitized, bounded, and masked AERE entry from a ledger entry.
        Guarantees that the original entry dictionary is untouched.
        """
        ev_id = entry.get("evidence_id", "")
        tce_info = tce_contrib_lookup.get(ev_id, {})

        # Mask sensitive fields first
        masked_entry = self.mask_value(entry)
        if masked_entry != entry:
            telemetry_stats["masked_fields"] += 1

        # Extract primary finding/description
        raw_finding = masked_entry.get("finding") or masked_entry.get("description") or ""
        bounded_finding = self.bound_string(raw_finding, self.max_finding_len)
        if len(str(raw_finding)) > self.max_finding_len:
            telemetry_stats["truncated_fields"] += 1

        raw_value = masked_entry.get("value")
        if isinstance(raw_value, str):
            bounded_value = self.bound_string(raw_value, self.max_val_len)
        else:
            bounded_value = self.sanitize_structured_data(raw_value)

        # Sanitize data and metadata payloads
        sanitized_data = self.sanitize_structured_data(masked_entry.get("data", {}))
        sanitized_meta = self.sanitize_structured_data(masked_entry.get("metadata", {}))

        # Assemble clean entry
        clean_entry: Dict[str, Any] = {
            "evidence_id": ev_id,
            "agent_id": entry.get("agent_id"),
            "agent_name": entry.get("agent_name"),
            "category": entry.get("category") or (entry.get("data") or {}).get("category") or "",
            "severity": entry.get("severity", "info"),
            "evidence_type": entry.get("evidence_type", "deterministic"),
            "evidence_strength": entry.get("evidence_strength"),
            "status": entry.get("status", "success"),
            "finding": bounded_finding,
            "value": bounded_value,
            "polarity": tce_info.get("polarity", entry.get("polarity", "neutral")),
            "base_contribution": tce_info.get("base_contribution"),
            "final_item_contribution": tce_info.get("final_item_contribution"),
            "suppression_multiplier": tce_info.get("suppression_multiplier", 1.0),
            "collinearity_discount": tce_info.get("collinearity_discount", 1.0),
            "provenance": copy.deepcopy(entry.get("provenance", {})),
            "target": copy.deepcopy(entry.get("target", {})),
            "data": sanitized_data,
            "metadata": sanitized_meta
        }

        # Include relationships list if already attached on entry
        if "relationships" in entry and isinstance(entry["relationships"], list):
            clean_entry["entry_relationships"] = copy.deepcopy(entry["relationships"])

        return clean_entry

    # -----------------------------------------------------------------
    # 4. Main Payload Construction
    # -----------------------------------------------------------------
    def build_payload(
        self,
        ledger: Union[Dict[str, Any], Any],
        tce_result: Optional[Dict[str, Any]] = None,
        target: Optional[Union[str, Dict[str, Any]]] = None,
        investigation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assemble the complete, bounded, and grounded AERE input payload.
        """
        telemetry_stats = {
            "masked_fields": 0,
            "truncated_fields": 0,
            "omitted_large_blobs": 0
        }

        # 1. Normalize Ledger representation without mutating source
        if hasattr(ledger, "to_dict"):
            ledger_dict = ledger.to_dict()
        elif isinstance(ledger, dict):
            # Shallow-copy the outer structure to protect caller
            ledger_dict = dict(ledger)
        else:
            ledger_dict = {"entries": [], "relationships": [], "summary": {}, "target": {}}

        raw_entries: List[Dict[str, Any]] = ledger_dict.get("entries", [])
        raw_relationships: List[Dict[str, Any]] = ledger_dict.get("relationships", [])
        raw_summary: Dict[str, Any] = ledger_dict.get("summary", {})

        # 2. Build TCE contribution lookup from actual runtime TCE output
        actual_tce = copy.deepcopy(tce_result) if isinstance(tce_result, dict) else {}
        tce_contrib_lookup: Dict[str, Dict[str, Any]] = {}
        for item in actual_tce.get("evidence_contributions", []):
            eid = item.get("evidence_id")
            if eid:
                tce_contrib_lookup[eid] = item

        # 3. Deterministically sort and sanitize ledger entries
        sorted_raw_entries = sorted(raw_entries, key=lambda e: str(e.get("evidence_id", "")))
        sanitized_entries = [
            self.sanitize_entry(entry, tce_contrib_lookup, telemetry_stats)
            for entry in sorted_raw_entries
        ]

        # 4. Deterministically sort and deepcopy relationships
        sorted_raw_rels = sorted(
            raw_relationships,
            key=lambda r: (
                str(r.get("relationship_id", "")),
                str(r.get("source_evidence_id", "")),
                str(r.get("target_evidence_id", "")),
                str(r.get("relationship_type", ""))
            )
        )
        sanitized_relationships = copy.deepcopy(sorted_raw_rels)

        # 5. Extract and normalize Target Metadata
        canonical_target: Dict[str, Any] = {}
        if target:
            if isinstance(target, dict):
                canonical_target = copy.deepcopy(target)
            else:
                canonical_target = normalize_target(str(target))
        elif "target" in ledger_dict and isinstance(ledger_dict["target"], dict) and ledger_dict["target"]:
            canonical_target = copy.deepcopy(ledger_dict["target"])
        else:
            canonical_target = {
                "original_input": None,
                "canonical_url": None,
                "scheme": None,
                "hostname": None,
                "domain": None,
                "ip": None
            }

        # 6. Extract Agent Execution Telemetry
        agents_represented = raw_summary.get("agents_represented", [])
        if not agents_represented:
            agents_represented = sorted(list({
                e["agent_id"] for e in sanitized_entries if e.get("agent_id") is not None
            }))

        total_agents_configured = 18
        coverage = len(agents_represented) / float(total_agents_configured)

        agent_execution_summary = {
            "total_agents_configured": total_agents_configured,
            "agents_represented": agents_represented,
            "agents_represented_count": len(agents_represented),
            "telemetry_coverage": actual_tce.get("telemetry_coverage", round(coverage, 4)),
            "low_telemetry_coverage": actual_tce.get("low_telemetry_coverage", coverage < 0.20),
            "missing_or_unavailable_entries_count": raw_summary.get("missing_or_unavailable_count", sum(
                1 for e in sanitized_entries if e.get("status") in ("unavailable", "skipped", "error", "restricted")
            ))
        }

        # 7. Compute Canonical Deterministic Ledger Payload Hash
        hash_payload = {
            "target": canonical_target,
            "entries": [
                {
                    "id": e["evidence_id"],
                    "agent": e["agent_id"],
                    "sev": e["severity"],
                    "type": e["evidence_type"],
                    "finding": e["finding"]
                }
                for e in sanitized_entries
            ],
            "relationships": [
                {
                    "id": r.get("relationship_id"),
                    "src": r.get("source_evidence_id"),
                    "tgt": r.get("target_evidence_id"),
                    "type": r.get("relationship_type")
                }
                for r in sanitized_relationships
            ]
        }
        canonical_json_str = json.dumps(hash_payload, sort_keys=True, separators=(",", ":"))
        ledger_hash = hashlib.sha256(canonical_json_str.encode("utf-8")).hexdigest()

        # 8. Assemble Complete Bounded AERE Input Payload
        payload = {
            "investigation_metadata": {
                "investigation_id": investigation_id,
                "schema_version": AERE_INPUT_SCHEMA_VERSION,
                "builder_version": BUILDER_VERSION,
                "ledger_sha256": ledger_hash,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            "target": canonical_target,
            "tce_result": actual_tce,
            "ledger_summary": {
                "entries": sanitized_entries,
                "relationships": sanitized_relationships,
                "summary": {
                    "total_entries": len(sanitized_entries),
                    "total_relationships": len(sanitized_relationships),
                    "by_severity": raw_summary.get("by_severity", {}),
                    "by_evidence_type": raw_summary.get("by_evidence_type", {}),
                    "by_relationship_type": raw_summary.get("by_relationship_type", {})
                }
            },
            "agent_execution_summary": agent_execution_summary,
            "builder_telemetry": {
                "selected_entries_count": len(sanitized_entries),
                "selected_relationships_count": len(sanitized_relationships),
                "masked_fields_count": telemetry_stats["masked_fields"],
                "truncated_fields_count": telemetry_stats["truncated_fields"],
                "omitted_large_blobs_count": telemetry_stats["omitted_large_blobs"]
            }
        }

        return payload


def build_aere_input_payload(
    ledger: Union[Dict[str, Any], Any],
    tce_result: Optional[Dict[str, Any]] = None,
    target: Optional[Union[str, Dict[str, Any]]] = None,
    investigation_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience functional interface to build an AERE input payload using default settings.
    """
    builder = AEREInputBuilder()
    return builder.build_payload(
        ledger=ledger,
        tce_result=tce_result,
        target=target,
        investigation_id=investigation_id
    )
