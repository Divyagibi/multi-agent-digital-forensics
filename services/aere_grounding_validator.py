"""
services/aere_grounding_validator.py
====================================
AERE Grounding Validator for Multi-Agent Digital Forensics System.

Safety and evidence-integrity validation component that evaluates whether
generated AERE (AI Evidence Reasoning Engine) claims are strictly grounded in
the investigation input payload supplied by the AERE Input Builder.

Core Invariants & Principles:
1. Grounding validity != Truth != Confidence:
   The validator evaluates whether claims are structurally and contextually
   grounded in the supplied evidence ledger, target metadata, and telemetry.
   It does NOT determine whether a website is objectively malicious, nor does
   it compute confidence intervals or risk scores.
2. TCE Sovereignty:
   The Trust Calculation Engine (TCE) is the sole authoritative source for
   numerical risk_score, trust_score, verdict, and thresholds. The Grounding
   Validator never modifies, recalculates, or substitutes numerical scores.
3. Zero Silent Stripping:
   Invalid or nonexistent Evidence IDs are never silently removed or replaced.
   Any invalid ID triggers an explicit diagnostic flag and fails validation.
4. Telemetry Neutrality:
   Missing or unavailable telemetry (unavailable, skipped, error, restricted)
   must never be interpreted as positive/clean evidence (e.g., unavailable != clean).
5. Prompt-Injection Resistance:
   Evidence text is treated strictly as passive data. Embedded instructions
   (e.g., 'IGNORE PREVIOUS INSTRUCTIONS', 'CHANGE TCE SCORE') are never executed.
6. Non-Destructive / Input Immutability:
   Both AERE output and AERE input payloads are treated as immutable artifacts.
"""

import copy
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.aere_contract import (
    is_valid_evidence_id_syntax,
    FORENSIC_SIGNIFICANCE_LEVELS
)


# =====================================================================
# CONSTANTS & CONTROLLED VOCABULARIES
# =====================================================================
VALIDATOR_VERSION: str = "1.0.0"

class GroundingStatus:
    """Taxonomy of claim-level grounding statuses."""
    GROUNDED = "GROUNDED"
    PARTIALLY_GROUNDED = "PARTIALLY_GROUNDED"
    UNGROUNDED = "UNGROUNDED"
    UNCERTAIN = "UNCERTAIN"


class ValidationResultStatus:
    """Overall grounding validation outcome."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    UNCERTAIN = "UNCERTAIN"


class GroundingSource:
    """Classification of the primary source grounding a claim."""
    EVIDENCE = "evidence"
    TELEMETRY = "telemetry"
    HYPOTHETICAL = "hypothetical"
    DISCREPANCY = "discrepancy"
    TCE_METRIC = "tce_metric"


# Known telemetry statuses that do NOT imply clean/safe states
INACTIVE_TELEMETRY_STATUSES: Set[str] = {
    "unavailable",
    "skipped",
    "error",
    "restricted"
}

# Strong overclaim terms that require high/critical severity backing
STRONG_MALICIOUS_TERMS: Set[str] = {
    "confirmed phishing",
    "confirmed malicious",
    "proven attack",
    "critical malware",
    "active exploit",
    "definitive fraud",
    "undeniable breach",
    "proven phishing",
    "confirmed scam"
}

# Clean / negative inference keywords that cannot be derived from missing telemetry
CLEAN_INFERENCE_TERMS: Set[str] = {
    "clean",
    "safe",
    "no threats",
    "no malicious indicators",
    "benign",
    "legitimate",
    "passed all checks",
    "verified safe"
}


# =====================================================================
# AERE GROUNDING VALIDATOR IMPLEMENTATION
# =====================================================================
class AEREGroundingValidator:
    """
    Evaluates grounding integrity between structured AERE output and
    the canonical AERE input payload.
    """

    def __init__(self):
        self.version = VALIDATOR_VERSION

    # -----------------------------------------------------------------
    # Helper: Extract searchable text corpora from input
    # -----------------------------------------------------------------
    def _extract_input_index(self, aere_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build index lookups of ledger entries, relationships, agent statuses,
        target tokens, and TCE metrics from the input payload.
        """
        ledger_summary = aere_input.get("ledger_summary", {})
        entries_list = ledger_summary.get("entries", [])
        rels_list = ledger_summary.get("relationships", [])
        agent_exec = aere_input.get("agent_execution_summary", {})
        target = aere_input.get("target", {})
        tce = aere_input.get("tce_result", {})

        entries_by_id: Dict[str, Dict[str, Any]] = {}
        for entry in entries_list:
            eid = entry.get("evidence_id")
            if eid:
                entries_by_id[eid] = entry

        # Build target text representation
        target_tokens: Set[str] = set()
        for k, v in target.items():
            if isinstance(v, str) and v.strip():
                # Add normalized word tokens
                words = re.findall(r"[A-Za-z0-9_\-\.]+", v.lower())
                target_tokens.update(words)
                target_tokens.add(v.lower().strip())

        # Relationships by source and target
        rels_by_pair: Set[Tuple[str, str, str]] = set()
        duplicate_eids: Set[str] = set()
        derived_eids: Set[str] = set()
        for r in rels_list:
            src = r.get("source_evidence_id", "")
            tgt = r.get("target_evidence_id", "")
            rtype = r.get("relationship_type", "")
            rels_by_pair.add((src, tgt, rtype))
            if rtype == "duplicate":
                duplicate_eids.add(src)
                duplicate_eids.add(tgt)
            elif rtype == "derived_from":
                derived_eids.add(src)

        return {
            "entries_by_id": entries_by_id,
            "rels_by_pair": rels_by_pair,
            "duplicate_eids": duplicate_eids,
            "derived_eids": derived_eids,
            "agent_exec": agent_exec,
            "target": target,
            "target_tokens": target_tokens,
            "tce": tce
        }

    # -----------------------------------------------------------------
    # Helper: Check Evidence ID Validity & Membership
    # -----------------------------------------------------------------
    def _check_evidence_ids(
        self,
        eids: List[str],
        entries_by_id: Dict[str, Dict[str, Any]],
        claim_id: str
    ) -> Tuple[List[str], List[str]]:
        """
        Validate a list of evidence IDs for syntax and existence in ledger.
        Returns:
            (invalid_or_missing_ids: List[str], issues: List[str])
        """
        bad_ids = []
        issues = []
        for eid in eids:
            if not isinstance(eid, str) or not eid.strip():
                bad_ids.append(str(eid))
                issues.append(f"Claim '{claim_id}' contains empty or non-string Evidence ID.")
                continue

            clean_eid = eid.strip()
            if not is_valid_evidence_id_syntax(clean_eid):
                bad_ids.append(clean_eid)
                issues.append(f"Claim '{claim_id}' contains invalid Evidence ID syntax: '{clean_eid}'.")
            elif clean_eid not in entries_by_id:
                bad_ids.append(clean_eid)
                issues.append(f"Claim '{claim_id}' cites nonexistent Evidence ID in ledger: '{clean_eid}'.")

        return bad_ids, issues

    # -----------------------------------------------------------------
    # Helper: Extract searchable text for an entry
    # -----------------------------------------------------------------
    def _get_entry_text_corpus(self, entry: Dict[str, Any]) -> str:
        """Combine all text fields in an entry for entity/number grounding."""
        parts = [
            str(entry.get("finding", "")),
            str(entry.get("description", "")),
            str(entry.get("value", "")),
            str(entry.get("category", "")),
            str(entry.get("agent_name", "")),
            str(entry.get("severity", ""))
        ]
        data = entry.get("data", {})
        if isinstance(data, dict):
            parts.extend([f"{k} {v}" for k, v in data.items()])
        meta = entry.get("metadata", {})
        if isinstance(meta, dict):
            parts.extend([f"{k} {v}" for k, v in meta.items()])
        return " ".join(parts).lower()

    # -----------------------------------------------------------------
    # Heuristic: Check Unsupported Numerical Literals
    # -----------------------------------------------------------------
    def _find_unsupported_numbers(
        self,
        claim_text: str,
        cited_entries: List[Dict[str, Any]],
        target: Dict[str, Any]
    ) -> List[str]:
        """
        Detect standalone numerical values or quantities in claim text
        that do not appear anywhere in cited entries or target metadata.
        """
        unsupported = []
        # Find explicit numbers (e.g. 10 years, 50%, 8080, 3 days, 99.9)
        # We ignore single digits 0-9 if used generically, but flag multi-digit or specific measurements
        number_patterns = re.findall(r"\b(\d+(?:\.\d+)?(?:\s*(?:days?|years?|months?|hours?|mins?|seconds?|%|percent|ms|kb|mb|gb|bits|bytes))?)\b", claim_text, re.IGNORECASE)
        
        if not number_patterns:
            return unsupported

        combined_evidence_corpus = " ".join([self._get_entry_text_corpus(e) for e in cited_entries])
        combined_target_corpus = " ".join([str(v) for v in target.values() if v is not None]).lower()
        full_corpus = f"{combined_evidence_corpus} {combined_target_corpus}"

        # Digits that might just be section identifiers (e.g. F-01, E1-01)
        for num_str in number_patterns:
            raw_num_match = re.search(r"\d+(?:\.\d+)?", num_str)
            if not raw_num_match:
                continue
            raw_val = raw_num_match.group(0)

            # Skip small digits 0-9 if they appear in structural prefixes or common words
            if len(raw_val) == 1 and raw_val in "0123456789" and not any(unit in num_str.lower() for unit in ["day", "year", "month", "%"]):
                continue

            # Check if num_str or raw_val is present in evidence corpus
            if raw_val not in full_corpus and num_str.lower() not in full_corpus:
                unsupported.append(num_str.strip())

        return list(set(unsupported))

    # -----------------------------------------------------------------
    # Heuristic: Check Unsupported Entities / Brands
    # -----------------------------------------------------------------
    def _find_unsupported_entities(
        self,
        claim_text: str,
        cited_entries: List[Dict[str, Any]],
        target: Dict[str, Any],
        target_tokens: Set[str]
    ) -> List[str]:
        """
        Detect capitalized brand or organization entities asserted in claims
        that have no basis in cited evidence or target metadata.
        """
        unsupported = []
        
        # Common forensic / technical abbreviations and structural terms
        common_terms = {
            "the", "this", "that", "these", "those", "an", "a", "in", "on", "at",
            "for", "with", "by", "from", "as", "if", "when", "while", "because",
            "however", "therefore", "furthermore", "additionally", "overall",
            "evidence", "agent", "investigation", "finding", "chain", "primary",
            "tce", "aere", "dns", "ssl", "tls", "http", "https", "url", "ip",
            "html", "dom", "api", "whois", "mx", "txt", "cname", "ns", "soa",
            "spf", "dkim", "dmarc", "note", "status", "summary", "interpretation",
            "assessment", "grounded", "suspicious", "malicious", "benign",
            "domain", "registrar", "form", "login", "credential", "action",
            "extremely", "young", "fresh", "recent", "recently", "active", "created"
        }

        # Known major brands frequently targeted in phishing / impersonation
        known_impersonation_targets = {
            "google", "paypal", "microsoft", "apple", "netflix", "amazon",
            "facebook", "meta", "chase", "wellsfargo", "bankofamerica",
            "ebay", "adobe", "dropbox", "dhl", "fedex", "ups", "usps", "instagram"
        }

        combined_evidence_corpus = " ".join([self._get_entry_text_corpus(e) for e in cited_entries])
        combined_target_corpus = " ".join([str(v) for v in target.values() if v is not None]).lower()
        full_evidence_text = f"{combined_evidence_corpus} {combined_target_corpus}"

        # 1. Check for specific known brand targets
        claim_lower = claim_text.lower()
        for brand in known_impersonation_targets:
            # Word boundary search for brand
            if re.search(r"\b" + re.escape(brand) + r"\b", claim_lower):
                if brand not in target_tokens and brand not in full_evidence_text:
                    unsupported.append(brand.capitalize())

        # 2. Extract mid-sentence capitalized words (e.g. "targets BrandName")
        # Matches capitalized words not immediately following sentence-ending punctuation (.!?)
        mid_sentence_candidates = re.findall(r"(?<=[a-z0-9,;]\s)([A-Z][a-zA-Z0-9_\-\.]{2,})\b", claim_text)
        for cand in mid_sentence_candidates:
            cand_lower = cand.lower()
            if cand_lower in common_terms:
                continue
            if cand_lower in target_tokens:
                continue
            if cand_lower in full_evidence_text:
                continue
            unsupported.append(cand)

        return list(set(unsupported))

    # -----------------------------------------------------------------
    # Heuristic: Overclaim Detection
    # -----------------------------------------------------------------
    def _check_overclaiming(
        self,
        claim_text: str,
        cited_entries: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Flag claims making absolute high-severity assertions when cited evidence
        only contains informational or low-severity findings.
        """
        flags = []
        claim_lower = claim_text.lower()
        
        has_strong_term = any(term in claim_lower for term in STRONG_MALICIOUS_TERMS)
        if has_strong_term:
            # Check maximum severity among cited entries
            severities = [str(e.get("severity", "info")).lower() for e in cited_entries]
            has_high_or_critical = any(s in ("high", "critical", "medium") for s in severities)
            if not has_high_or_critical and cited_entries:
                flags.append(
                    f"Claim asserts definitive maliciousness ('{claim_text[:60]}...') "
                    f"but cited evidence has low/info severity: {severities}."
                )
        return flags

    # -----------------------------------------------------------------
    # Telemetry / Status Invariant Check
    # -----------------------------------------------------------------
    def _check_telemetry_invariants(
        self,
        gap_claim: Dict[str, Any],
        agent_exec: Dict[str, Any]
    ) -> List[str]:
        """
        Ensure unobserved/missing telemetry is not treated as negative/clean evidence.
        """
        issues = []
        reason = str(gap_claim.get("reason", "")).lower()
        dim = str(gap_claim.get("unobserved_dimension", "")).lower()
        rec = str(gap_claim.get("recommended_action", "")).lower()
        full_text = f"{dim} {reason} {rec}"

        # If claim asserts clean/safe because telemetry was missing/unavailable
        for clean_term in CLEAN_INFERENCE_TERMS:
            if clean_term in full_text and any(status in full_text for status in INACTIVE_TELEMETRY_STATUSES):
                issues.append(
                    f"Investigative gap incorrectly conflates inactive telemetry with clean verdict: '{clean_term}'."
                )
        return issues

    # -----------------------------------------------------------------
    # MAIN VALIDATION PIPELINE
    # -----------------------------------------------------------------
    def validate(
        self,
        aere_output: Any,
        aere_input: Any
    ) -> Dict[str, Any]:
        """
        Perform comprehensive grounding validation of AERE output against AERE input.
        
        Does NOT mutate aere_output or aere_input.
        Does NOT recalculate or replace TCE metrics.
        """
        # Defensive validation
        if not isinstance(aere_output, dict):
            return {
                "grounding_validation_status": ValidationResultStatus.FAILED,
                "claim_results": [],
                "invalid_evidence_ids": [],
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": [],
                "telemetry_status_issues": [],
                "affected_claims": [],
                "grounding_errors": ["AERE output payload must be a dictionary."],
                "validation_metadata": {"error": "Invalid output type"}
            }

        if not isinstance(aere_input, dict):
            return {
                "grounding_validation_status": ValidationResultStatus.FAILED,
                "claim_results": [],
                "invalid_evidence_ids": [],
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": [],
                "telemetry_status_issues": [],
                "affected_claims": [],
                "grounding_errors": ["AERE input payload must be a dictionary."],
                "validation_metadata": {"error": "Invalid input type"}
            }

        # Extract indexed input lookups
        input_index = self._extract_input_index(aere_input)
        entries_by_id = input_index["entries_by_id"]
        target = input_index["target"]
        target_tokens = input_index["target_tokens"]
        agent_exec = input_index["agent_exec"]
        tce = input_index["tce"]
        duplicate_eids = input_index["duplicate_eids"]

        all_invalid_ids: Set[str] = set()
        all_unsupported_entities: Set[str] = set()
        all_unsupported_numbers: Set[str] = set()
        all_overclaim_flags: List[str] = []
        all_telemetry_issues: List[str] = []
        affected_claims: Set[str] = set()
        grounding_errors: List[str] = []
        claim_results: List[Dict[str, Any]] = []

        total_claims_evaluated = 0
        grounded_claims_count = 0
        ungrounded_claims_count = 0
        partially_grounded_count = 0
        uncertain_claims_count = 0

        # -------------------------------------------------------------
        # 1. Validate Primary Findings (Evidence-Grounded)
        # -------------------------------------------------------------
        for idx, finding in enumerate(aere_output.get("primary_findings", [])):
            if not isinstance(finding, dict):
                continue
            total_claims_evaluated += 1
            fid = finding.get("finding_id", f"PF-{idx+1}")
            eids = finding.get("grounded_evidence_ids", [])
            summary = finding.get("summary", "")
            interp = finding.get("interpretation", "")
            claim_text = f"{summary} {interp}"
            issues: List[str] = []

            # Check evidence IDs
            bad_eids, eid_issues = self._check_evidence_ids(eids, entries_by_id, fid)
            issues.extend(eid_issues)
            if bad_eids:
                all_invalid_ids.update(bad_eids)
                affected_claims.add(fid)

            # Substantive claim must cite at least one evidence ID
            if not eids:
                issues.append(f"Primary finding '{fid}' has empty 'grounded_evidence_ids'.")
                affected_claims.add(fid)

            # Retrieve active entry dicts for valid cited IDs
            cited_entries = [entries_by_id[eid] for eid in eids if eid in entries_by_id]

            # Check numbers
            unsupported_nums = self._find_unsupported_numbers(claim_text, cited_entries, target)
            if unsupported_nums:
                all_unsupported_numbers.update(unsupported_nums)
                issues.append(f"Unsupported numerical assertions: {unsupported_nums}")
                affected_claims.add(fid)

            # Check entities
            unsupported_ents = self._find_unsupported_entities(claim_text, cited_entries, target, target_tokens)
            if unsupported_ents:
                all_unsupported_entities.update(unsupported_ents)
                issues.append(f"Unsupported brand/entity assertions: {unsupported_ents}")
                affected_claims.add(fid)

            # Check overclaiming
            overclaims = self._check_overclaiming(claim_text, cited_entries)
            if overclaims:
                all_overclaim_flags.extend(overclaims)
                issues.extend(overclaims)
                affected_claims.add(fid)

            # Determine claim status
            if bad_eids or not eids or (unsupported_ents and unsupported_nums):
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
            elif unsupported_ents or unsupported_nums or overclaims:
                c_status = GroundingStatus.PARTIALLY_GROUNDED
                partially_grounded_count += 1
            elif not issues:
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1
            else:
                c_status = GroundingStatus.UNCERTAIN
                uncertain_claims_count += 1

            claim_results.append({
                "claim_id": fid,
                "section": "primary_findings",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.EVIDENCE,
                "evidence_ids": eids,
                "issues": issues,
                "unsupported_entities": unsupported_ents,
                "unsupported_numbers": unsupported_nums,
                "overclaim_flags": overclaims
            })

        # -------------------------------------------------------------
        # 2. Validate Evidence Chains (Evidence-Grounded)
        # -------------------------------------------------------------
        for idx, chain in enumerate(aere_output.get("evidence_chains", [])):
            if not isinstance(chain, dict):
                continue
            total_claims_evaluated += 1
            cid = chain.get("chain_id", f"EC-{idx+1}")
            eids = chain.get("evidence_ids", [])
            narrative = chain.get("narrative", "")
            issues = []

            bad_eids, eid_issues = self._check_evidence_ids(eids, entries_by_id, cid)
            issues.extend(eid_issues)
            if bad_eids:
                all_invalid_ids.update(bad_eids)
                affected_claims.add(cid)

            if not eids:
                issues.append(f"Evidence chain '{cid}' has empty 'evidence_ids'.")
                affected_claims.add(cid)

            cited_entries = [entries_by_id[eid] for eid in eids if eid in entries_by_id]

            # Check if chain only cites duplicate evidence as multiple independent proofs
            if len(eids) > 1 and all(eid in duplicate_eids for eid in eids):
                issues.append(f"Evidence chain '{cid}' cites only duplicate evidence entries without independent corroboration.")

            unsupported_nums = self._find_unsupported_numbers(narrative, cited_entries, target)
            if unsupported_nums:
                all_unsupported_numbers.update(unsupported_nums)
                issues.append(f"Unsupported numerical assertions: {unsupported_nums}")
                affected_claims.add(cid)

            unsupported_ents = self._find_unsupported_entities(narrative, cited_entries, target, target_tokens)
            if unsupported_ents:
                all_unsupported_entities.update(unsupported_ents)
                issues.append(f"Unsupported brand/entity assertions: {unsupported_ents}")
                affected_claims.add(cid)

            overclaims = self._check_overclaiming(narrative, cited_entries)
            if overclaims:
                all_overclaim_flags.extend(overclaims)
                issues.extend(overclaims)
                affected_claims.add(cid)

            if bad_eids or not eids:
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
            elif unsupported_ents or unsupported_nums or overclaims:
                c_status = GroundingStatus.PARTIALLY_GROUNDED
                partially_grounded_count += 1
            elif not issues:
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1
            else:
                c_status = GroundingStatus.UNCERTAIN
                uncertain_claims_count += 1

            claim_results.append({
                "claim_id": cid,
                "section": "evidence_chains",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.EVIDENCE,
                "evidence_ids": eids,
                "issues": issues,
                "unsupported_entities": unsupported_ents,
                "unsupported_numbers": unsupported_nums,
                "overclaim_flags": overclaims
            })

        # -------------------------------------------------------------
        # 3. Validate Contradiction Analyses (Discrepancy-Grounded)
        # -------------------------------------------------------------
        for idx, contra in enumerate(aere_output.get("contradiction_analyses", [])):
            if not isinstance(contra, dict):
                continue
            total_claims_evaluated += 1
            conf_id = contra.get("conflict_id", f"CA-{idx+1}")
            eids = contra.get("conflicting_evidence_ids", [])
            analysis = contra.get("analysis", "")
            issues = []

            bad_eids, eid_issues = self._check_evidence_ids(eids, entries_by_id, conf_id)
            issues.extend(eid_issues)
            if bad_eids:
                all_invalid_ids.update(bad_eids)
                affected_claims.add(conf_id)

            if len(eids) < 2:
                issues.append(f"Contradiction '{conf_id}' must reference at least 2 conflicting evidence IDs.")
                affected_claims.add(conf_id)

            cited_entries = [entries_by_id[eid] for eid in eids if eid in entries_by_id]

            if bad_eids or len(eids) < 2:
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
            elif not issues:
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1
            else:
                c_status = GroundingStatus.UNCERTAIN
                uncertain_claims_count += 1

            claim_results.append({
                "claim_id": conf_id,
                "section": "contradiction_analyses",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.DISCREPANCY,
                "evidence_ids": eids,
                "issues": issues,
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": []
            })

        # -------------------------------------------------------------
        # 4. Validate Alternative Explanations (Hypothetical-Grounded)
        # -------------------------------------------------------------
        for idx, alt in enumerate(aere_output.get("alternative_explanations", [])):
            if not isinstance(alt, dict):
                continue
            total_claims_evaluated += 1
            alt_id = f"AE-{idx+1}"
            eids = alt.get("evidence_ids", [])
            counter_eids = alt.get("counter_evidence_ids", [])
            all_alt_eids = eids + counter_eids
            issues = []

            bad_eids, eid_issues = self._check_evidence_ids(all_alt_eids, entries_by_id, alt_id)
            issues.extend(eid_issues)
            if bad_eids:
                all_invalid_ids.update(bad_eids)
                affected_claims.add(alt_id)

            if bad_eids:
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
            else:
                # Formally labeled as alternative hypothesis
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1

            claim_results.append({
                "claim_id": alt_id,
                "section": "alternative_explanations",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.HYPOTHETICAL,
                "evidence_ids": all_alt_eids,
                "issues": issues,
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": []
            })

        # -------------------------------------------------------------
        # 5. Validate Investigative Gaps (Telemetry / Status-Grounded)
        # -------------------------------------------------------------
        for idx, gap in enumerate(aere_output.get("investigative_gaps", [])):
            if not isinstance(gap, dict):
                continue
            total_claims_evaluated += 1
            gid = gap.get("gap_id", f"GAP-{idx+1}")
            issues = []

            telemetry_issues = self._check_telemetry_invariants(gap, agent_exec)
            if telemetry_issues:
                all_telemetry_issues.extend(telemetry_issues)
                issues.extend(telemetry_issues)
                affected_claims.add(gid)

            if telemetry_issues:
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
            else:
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1

            claim_results.append({
                "claim_id": gid,
                "section": "investigative_gaps",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.TELEMETRY,
                "evidence_ids": [],
                "issues": issues,
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": []
            })

        # -------------------------------------------------------------
        # 6. Validate TCE Interpretation Alignment
        # -------------------------------------------------------------
        tce_interp = aere_output.get("tce_interpretation", {})
        if isinstance(tce_interp, dict):
            total_claims_evaluated += 1
            tce_issues = []
            math_align = str(tce_interp.get("mathematical_alignment", ""))
            verdict_supp = str(tce_interp.get("verdict_support", ""))

            # Check if AERE interpretation hallucinates contradicting verdict
            runtime_verdict = str(tce.get("verdict", "")).lower()
            if runtime_verdict:
                # If runtime is Benign/Legitimate but interpretation claims confirmed Malicious
                if runtime_verdict in ("benign", "legitimate", "low_risk") and any(w in math_align.lower() or w in verdict_supp.lower() for w in ["critical malicious", "proven scam", "proven phishing"]):
                    tce_issues.append(f"TCE interpretation contradicts actual TCE verdict '{runtime_verdict}'.")
                    affected_claims.add("TCE_INTERPRETATION")

            if tce_issues:
                c_status = GroundingStatus.UNGROUNDED
                ungrounded_claims_count += 1
                grounding_errors.extend(tce_issues)
            else:
                c_status = GroundingStatus.GROUNDED
                grounded_claims_count += 1

            claim_results.append({
                "claim_id": "TCE_INTERPRETATION",
                "section": "tce_interpretation",
                "grounding_status": c_status,
                "grounding_source": GroundingSource.TCE_METRIC,
                "evidence_ids": [],
                "issues": tce_issues,
                "unsupported_entities": [],
                "unsupported_numbers": [],
                "overclaim_flags": []
            })

        # -------------------------------------------------------------
        # Aggregate Overall Grounding Result Status
        # -------------------------------------------------------------
        if all_invalid_ids or ungrounded_claims_count > 0 or all_telemetry_issues or grounding_errors:
            overall_status = ValidationResultStatus.FAILED
            if all_invalid_ids:
                grounding_errors.append(f"Nonexistent or invalid Evidence IDs cited: {sorted(list(all_invalid_ids))}")
        elif partially_grounded_count > 0 or uncertain_claims_count > 0:
            overall_status = ValidationResultStatus.UNCERTAIN
        else:
            overall_status = ValidationResultStatus.PASSED

        return {
            "grounding_validation_status": overall_status,
            "claim_results": claim_results,
            "invalid_evidence_ids": sorted(list(all_invalid_ids)),
            "unsupported_entities": sorted(list(all_unsupported_entities)),
            "unsupported_numbers": sorted(list(all_unsupported_numbers)),
            "overclaim_flags": all_overclaim_flags,
            "telemetry_status_issues": all_telemetry_issues,
            "affected_claims": sorted(list(affected_claims)),
            "grounding_errors": grounding_errors,
            "validation_metadata": {
                "validator_version": self.version,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_claims_evaluated": total_claims_evaluated,
                "grounded_claims_count": grounded_claims_count,
                "partially_grounded_count": partially_grounded_count,
                "ungrounded_claims_count": ungrounded_claims_count,
                "uncertain_claims_count": uncertain_claims_count,
                "invalid_evidence_ids_count": len(all_invalid_ids),
                "unsupported_entities_count": len(all_unsupported_entities),
                "unsupported_numbers_count": len(all_unsupported_numbers)
            }
        }


# =====================================================================
# FUNCTIONAL API WRAPPER
# =====================================================================
def validate_aere_grounding(
    aere_output: Dict[str, Any],
    aere_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Vendor-neutral functional entrypoint for AERE Grounding Validation.
    
    Accepts:
        aere_output: Structured AERE output dictionary.
        aere_input: Structured AERE Input Builder payload dictionary.
        
    Returns:
        Structured machine-readable grounding validation report.
    """
    validator = AEREGroundingValidator()
    return validator.validate(aere_output=aere_output, aere_input=aere_input)
