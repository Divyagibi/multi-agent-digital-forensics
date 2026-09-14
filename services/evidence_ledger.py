"""
services/evidence_ledger.py
===========================
Investigation Evidence Ledger for Multi-Agent Digital Forensics System.

Serves as the canonical, investigation-level repository of normalized forensic evidence.
Enables cross-agent correlation, provenance tracking, and relationship modeling.

Core Design Principles:
1. Canonical Repository: Centralized collection of all agent observations for an investigation.
2. Cross-Agent Correlation: Deterministically links evidence across multiple agents using canonical targets.
3. Provenance Retention: Every entry traces back to its source agent, component, and evidence ID.
4. Loss-Minimizing: Preserves raw values, metadata, severity, and strength without alteration.
5. Strict Scoring Separation:
   - Does NOT compute risk scores.
   - Does NOT compute trust scores.
   - Does NOT compute confidence scores for website verdicts.
   - Does NOT emit maliciousness verdicts.
6. Missing Data Neutrality: Missing/unavailable telemetry remains neutral, never converted into risk.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from services.evidence_normalizer import normalize_target, normalize_evidence_item
from services.evidence_schema import CANONICAL_AGENT_METADATA


# Supported relationship types
RELATIONSHIP_TYPES = {
    "same_target",         # Evidence items refer to the same domain/entity target
    "supporting",          # Independent observations corroborating a forensic fact
    "contradiction",       # Incompatible or conflicting observations across agents
    "duplicate",           # Repeated observations across processing stages
    "derived_from",        # Evidence derived from another agent's initial extraction (e.g., QR -> URL)
    "related_dimension"    # Complementary forensic vectors on the same subject
}


class EvidenceLedger:
    """
    Centralized Investigation Evidence Ledger.
    """

    def __init__(self, target: Optional[Union[str, Dict[str, Any]]] = None):
        if isinstance(target, dict):
            self.target = target
        else:
            self.target = normalize_target(target)
        
        self.entries: List[Dict[str, Any]] = []
        self._entries_by_id: Dict[str, Dict[str, Any]] = {}
        self.relationships: List[Dict[str, Any]] = []
        self._rel_counter = 0

    def add_entry(self, entry: Dict[str, Any]) -> None:
        """
        Add a normalized evidence entry to the ledger.
        """
        if not isinstance(entry, dict):
            return

        ev_id = entry.get("evidence_id")
        if not ev_id:
            return

        # If duplicate ID within ledger, assign a unique suffixed identifier while retaining original
        if ev_id in self._entries_by_id:
            entry_copy = dict(entry)
            entry_copy["original_evidence_id"] = ev_id
            ev_id = f"{ev_id}-DUP{len(self.entries) + 1}"
            entry_copy["evidence_id"] = ev_id
            self.entries.append(entry_copy)
            self._entries_by_id[ev_id] = entry_copy
        else:
            self.entries.append(entry)
            self._entries_by_id[ev_id] = entry

    def add_entries_from_agent(self, agent_result: Dict[str, Any]) -> None:
        """
        Extract and normalize all evidence items from an agent result payload.
        """
        if not isinstance(agent_result, dict):
            return

        agent_id = agent_result.get("agent_id") or agent_result.get("agent_number") or agent_result.get("agent", 1)
        raw_evidence = agent_result.get("evidence", [])
        
        if not isinstance(raw_evidence, list):
            return

        for item in raw_evidence:
            if isinstance(item, dict):
                norm_entry = normalize_evidence_item(
                    evidence_item=item,
                    agent_identifier=agent_id,
                    agent_result=agent_result,
                    canonical_target=self.target
                )
                self.add_entry(norm_entry)

    def add_relationship(
        self,
        source_evidence_id: str,
        target_evidence_id: str,
        relationship_type: str,
        description: str = "",
        details: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Record a relationship between two evidence items in the ledger.
        """
        if relationship_type not in RELATIONSHIP_TYPES:
            relationship_type = "related_dimension"

        if source_evidence_id not in self._entries_by_id or target_evidence_id not in self._entries_by_id:
            return None

        # Avoid redundant duplicate relationship entries
        for r in self.relationships:
            if (
                r["source_evidence_id"] == source_evidence_id
                and r["target_evidence_id"] == target_evidence_id
                and r["relationship_type"] == relationship_type
            ):
                return r

        self._rel_counter += 1
        rel_id = f"REL-{self._rel_counter:03d}"

        rel = {
            "relationship_id": rel_id,
            "source_evidence_id": source_evidence_id,
            "target_evidence_id": target_evidence_id,
            "relationship_type": relationship_type,
            "description": description or f"{relationship_type.replace('_', ' ').capitalize()} relationship",
            "details": details if isinstance(details, dict) else {}
        }
        self.relationships.append(rel)

        # Update entry relationship pointers
        source_entry = self._entries_by_id.get(source_evidence_id)
        if source_entry is not None:
            if "relationships" not in source_entry or not isinstance(source_entry["relationships"], list):
                source_entry["relationships"] = []
            source_entry["relationships"].append({
                "relationship_id": rel_id,
                "target_evidence_id": target_evidence_id,
                "relationship_type": relationship_type
            })

        target_entry = self._entries_by_id.get(target_evidence_id)
        if target_entry is not None:
            if "relationships" not in target_entry or not isinstance(target_entry["relationships"], list):
                target_entry["relationships"] = []
            target_entry["relationships"].append({
                "relationship_id": rel_id,
                "target_evidence_id": source_evidence_id,
                "relationship_type": relationship_type
            })

        return rel

    def correlate_relationships(self) -> List[Dict[str, Any]]:
        """
        Deterministically discover and establish relationships across ledger entries.
        
        Cross-agent correlation logic:
        1. same_target: Evidence items sharing identical registrable_domain or hostname.
        2. supporting: Independent agents corroborating suspicious or positive indicators.
        3. contradiction: Mutually conflicting factual claims (e.g. declared vs IP location).
        4. duplicate: Identical findings repeated across stages, maintaining separate provenance.
        5. derived_from: QR payload extraction -> URL pipeline analysis.
        6. related_dimension: Complementary forensic vectors on the same target.
        """
        n = len(self.entries)
        for i in range(n):
            for j in range(i + 1, n):
                e1 = self.entries[i]
                e2 = self.entries[j]

                # Check 1: Duplicate detection
                if self._is_duplicate(e1, e2):
                    self.add_relationship(
                        source_evidence_id=e1["evidence_id"],
                        target_evidence_id=e2["evidence_id"],
                        relationship_type="duplicate",
                        description=f"Duplicate observation detected between {e1['provenance']['source_agent']} and {e2['provenance']['source_agent']} with distinct provenance preserved."
                    )
                    continue

                # Check 2: Contradiction detection
                contradiction_desc = self._detect_contradiction(e1, e2)
                if contradiction_desc:
                    self.add_relationship(
                        source_evidence_id=e1["evidence_id"],
                        target_evidence_id=e2["evidence_id"],
                        relationship_type="contradiction",
                        description=contradiction_desc
                    )
                    continue

                # Check 3: Supporting corroboration
                supporting_desc = self._detect_supporting(e1, e2)
                if supporting_desc:
                    self.add_relationship(
                        source_evidence_id=e1["evidence_id"],
                        target_evidence_id=e2["evidence_id"],
                        relationship_type="supporting",
                        description=supporting_desc
                    )
                    continue

                # Check 4: Derived from (e.g. Agent 18 QR to downstream URL agents)
                if e1["agent_id"] == 18 and e2["agent_id"] in (1, 2, 3, 5):
                    self.add_relationship(
                        source_evidence_id=e2["evidence_id"],
                        target_evidence_id=e1["evidence_id"],
                        relationship_type="derived_from",
                        description=f"Agent {e2['agent_id']} target URL was extracted/derived from Agent 18 QR payload."
                    )
                    continue

                # Check 5: Related dimension (same target + complementary forensic domains)
                if self._is_same_target(e1, e2):
                    if self._is_related_dimension(e1, e2):
                        self.add_relationship(
                            source_evidence_id=e1["evidence_id"],
                            target_evidence_id=e2["evidence_id"],
                            relationship_type="related_dimension",
                            description=f"Complementary forensic dimensions: {e1['agent_name']} and {e2['agent_name']} on {e1['target'].get('registrable_domain')}."
                        )
                    else:
                        self.add_relationship(
                            source_evidence_id=e1["evidence_id"],
                            target_evidence_id=e2["evidence_id"],
                            relationship_type="same_target",
                            description=f"Both evidence items reference target: {e1['target'].get('registrable_domain') or e1['target'].get('hostname')}."
                        )

        return self.relationships

    def _is_same_target(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> bool:
        """Check if two evidence items refer to the same target domain or hostname."""
        t1 = e1.get("target") or {}
        t2 = e2.get("target") or {}
        
        reg1 = t1.get("registrable_domain")
        reg2 = t2.get("registrable_domain")
        if reg1 and reg2 and reg1.lower() == reg2.lower():
            return True

        host1 = t1.get("hostname")
        host2 = t2.get("hostname")
        if host1 and host2 and host1.lower() == host2.lower():
            return True

        return False

    def _is_duplicate(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> bool:
        """Check if two evidence items represent duplicate findings."""
        if e1["agent_id"] == e2["agent_id"]:
            f1 = (e1.get("finding") or "").strip().lower()
            f2 = (e2.get("finding") or "").strip().lower()
            v1 = str(e1.get("value") or "").strip().lower()
            v2 = str(e2.get("value") or "").strip().lower()
            if f1 and f1 == f2 and v1 == v2:
                return True
        return False

    def _detect_contradiction(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> Optional[str]:
        """
        Deterministically identify factual contradictions between cross-agent observations.
        Does NOT assign risk or penalize scores.
        """
        # Contradiction Case 1: Contact location (A12) vs Server IP geolocation (A2)
        if (e1["agent_id"] == 12 and e2["agent_id"] == 2) or (e1["agent_id"] == 2 and e2["agent_id"] == 12):
            contact_ev = e1 if e1["agent_id"] == 12 else e2
            dns_ev = e2 if e1["agent_id"] == 12 else e1
            c_country = (contact_ev.get("data") or {}).get("country") or (contact_ev.get("metadata") or {}).get("country")
            s_country = (dns_ev.get("data") or {}).get("country") or (dns_ev.get("metadata") or {}).get("country")
            if c_country and s_country and str(c_country).upper() != str(s_country).upper():
                return f"Factual location discrepancy: Agent 12 declared entity country '{c_country}' differs from Agent 2 server infrastructure country '{s_country}'."

        # Contradiction Case 2: Domain creation date (A1) vs Archive historical tenure (A14)
        if (e1["agent_id"] == 1 and e2["agent_id"] == 14) or (e1["agent_id"] == 14 and e2["agent_id"] == 1):
            a1_ev = e1 if e1["agent_id"] == 1 else e2
            a14_ev = e2 if e1["agent_id"] == 1 else e1
            a1_age_days = (a1_ev.get("data") or {}).get("domain_age_days")
            a14_tenure_years = (a14_ev.get("data") or {}).get("archive_tenure_years")
            if a1_age_days is not None and a14_tenure_years is not None:
                # If domain is < 60 days old but archive claims > 5 years tenure
                if float(a1_age_days) < 60 and float(a14_tenure_years) > 5.0:
                    return f"Timeline discrepancy: Agent 1 WHOIS reports recent registration ({a1_age_days} days) whereas Agent 14 records {a14_tenure_years} years of historical archives (possible domain reuse/drop-catch)."

        # Contradiction Case 3: Legitimate business registry verified (A12) vs Confirmed active malicious blacklist (A6)
        if (e1["agent_id"] == 12 and e2["agent_id"] == 6) or (e1["agent_id"] == 6 and e2["agent_id"] == 12):
            a12_ev = e1 if e1["agent_id"] == 12 else e2
            a6_ev = e2 if e1["agent_id"] == 12 else e1
            if a12_ev.get("severity") == "info" and a6_ev.get("severity") in ("high", "critical"):
                if "verified" in str(a12_ev.get("finding", "")).lower() and "blacklist" in str(a6_ev.get("finding", "")).lower():
                    return f"Reputational conflict: Agent 12 found valid corporate registration while Agent 6 detected active security blacklist entries."

        return None

    def _detect_supporting(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> Optional[str]:
        """
        Deterministically identify cross-agent corroboration.
        """
        if e1["agent_id"] == e2["agent_id"]:
            return None

        # Supporting Case 1: Multi-Agent Threat Intelligence & Malware corroboration (A6 & A17)
        if (e1["agent_id"] == 6 and e2["agent_id"] == 17) or (e1["agent_id"] == 17 and e2["agent_id"] == 6):
            if e1.get("severity") in ("high", "critical") and e2.get("severity") in ("high", "critical"):
                return f"Cross-agent corroboration: Reputation agent (A6) and Malware agent (A17) independently detected high-severity threats."

        # Supporting Case 2: Phishing behavior (A8) and Brand Impersonation (A9)
        if (e1["agent_id"] == 8 and e2["agent_id"] == 9) or (e1["agent_id"] == 9 and e2["agent_id"] == 8):
            if e1.get("severity") in ("medium", "high", "critical") and e2.get("severity") in ("medium", "high", "critical"):
                return f"Cross-agent corroboration: Behavioral agent (A8) login/form flags corroborated by Brand agent (A9) impersonation signals."

        # Supporting Case 3: Content Quality (A11) and Contact Verification (A12) missing signals
        if (e1["agent_id"] == 11 and e2["agent_id"] == 12) or (e1["agent_id"] == 12 and e2["agent_id"] == 11):
            if e1.get("severity") in ("medium", "high") and e2.get("severity") in ("medium", "high"):
                return f"Cross-agent corroboration: Content quality anomalies (A11) corroborated by entity contact verification anomalies (A12)."

        # Supporting Case 4: SSL anomalies (A3) and Network Security anomalies (A16)
        if (e1["agent_id"] == 3 and e2["agent_id"] == 16) or (e1["agent_id"] == 16 and e2["agent_id"] == 3):
            if e1.get("severity") in ("medium", "high", "critical") and e2.get("severity") in ("medium", "high", "critical"):
                return f"Cross-agent corroboration: SSL certificate issues (A3) corroborated by network security header deficiencies (A16)."

        # Supporting Case 5: Domain age (A1) and Archive history (A14) newness
        if (e1["agent_id"] == 1 and e2["agent_id"] == 14) or (e1["agent_id"] == 14 and e2["agent_id"] == 1):
            if e1.get("severity") in ("medium", "high") and e2.get("severity") in ("medium", "high"):
                if "new" in str(e1.get("finding", "")).lower() or "young" in str(e1.get("finding", "")).lower():
                    return f"Cross-agent corroboration: Recent domain registration (A1) corroborated by lack of historical archive footprint (A14)."

        return None

    def _is_related_dimension(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> bool:
        """Identify complementary forensic dimensions between agents."""
        related_pairs = {
            (1, 14),   # Domain & History
            (2, 16),   # DNS & Network Security
            (3, 16),   # SSL & Network Security
            (4, 11),   # Website Content & Content Quality
            (5, 18),   # URL Structure & QR analysis
            (6, 17),   # Reputation & Malware Indicators
            (8, 9),    # Website Behavior & Brand Verification
            (10, 9),   # Visual UI & Brand Verification
            (12, 13),  # Contact Verification & External Presence OSINT
            (13, 15)   # External OSINT & User Trust / Consumer Sentiment
        }
        pair = (min(e1["agent_id"], e2["agent_id"]), max(e1["agent_id"], e2["agent_id"]))
        return pair in related_pairs

    # =====================================================================
    # QUERY & EXPORT INTERFACES
    # =====================================================================

    def get_entries(
        self,
        agent_id: Optional[int] = None,
        severity: Optional[str] = None,
        evidence_type: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Filter ledger entries by criteria."""
        results = self.entries
        if agent_id is not None:
            results = [e for e in results if e.get("agent_id") == agent_id]
        if severity is not None:
            results = [e for e in results if e.get("severity") == severity]
        if evidence_type is not None:
            results = [e for e in results if e.get("evidence_type") == evidence_type]
        if status is not None:
            results = [e for e in results if e.get("status") == status]
        return results

    def get_relationships(
        self,
        relationship_type: Optional[str] = None,
        evidence_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Filter ledger relationships by type or involved evidence ID."""
        results = self.relationships
        if relationship_type is not None:
            results = [r for r in results if r.get("relationship_type") == relationship_type]
        if evidence_id is not None:
            results = [
                r for r in results
                if r.get("source_evidence_id") == evidence_id or r.get("target_evidence_id") == evidence_id
            ]
        return results

    def get_contradictions(self) -> List[Dict[str, Any]]:
        """Return all contradictory evidence relationships."""
        return self.get_relationships(relationship_type="contradiction")

    def get_supporting_chains(self) -> List[Dict[str, Any]]:
        """Return all corroborating supporting evidence relationships."""
        return self.get_relationships(relationship_type="supporting")

    def get_provenance(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full provenance for a specific evidence item."""
        entry = self._entries_by_id.get(evidence_id)
        if entry:
            return entry.get("provenance")
        return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the complete Investigation Evidence Ledger to a dictionary.
        
        Strictly guarantees absence of trust_score, risk_score, confidence_score, or verdicts.
        """
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        agents_set: Set[int] = set()
        missing_count = 0

        for entry in self.entries:
            sev = entry.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

            ev_type = entry.get("evidence_type", "deterministic")
            by_type[ev_type] = by_type.get(ev_type, 0) + 1

            if "agent_id" in entry:
                agents_set.add(entry["agent_id"])

            if entry.get("status") in ("unavailable", "skipped", "error", "restricted"):
                missing_count += 1

        by_rel_type: Dict[str, int] = {}
        for rel in self.relationships:
            rtype = rel.get("relationship_type", "related_dimension")
            by_rel_type[rtype] = by_rel_type.get(rtype, 0) + 1

        return {
            "target": self.target,
            "entries": self.entries,
            "relationships": self.relationships,
            "summary": {
                "total_entries": len(self.entries),
                "total_relationships": len(self.relationships),
                "agents_represented": sorted(list(agents_set)),
                "by_severity": by_severity,
                "by_evidence_type": by_type,
                "by_relationship_type": by_rel_type,
                "missing_or_unavailable_count": missing_count
            }
        }
