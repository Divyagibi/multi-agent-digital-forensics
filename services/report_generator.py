"""
services/report_generator.py
============================
Deterministic Final Investigator Report Assembly Service (Step 5B).

Architectural Principles & Boundaries:
1. Post-Hoc & Additive: Evaluates only after the forensics pipeline, Evidence Ledger,
   Trust Calculation Engine (TCE), AI Evidence Reasoning Engine (AERE), and Confidence Engine complete.
2. Read-Only & Immutability: Pure read-only consumer of completed pipeline sessions.
   NEVER mutates the input session, ledger, or intermediate artifacts.
3. TCE Sovereignty: TCE remains the sole authority for risk_score, trust_score, and verdict.
   TCE outputs are strictly preserved and never recalculated or overridden.
4. Epistemic Decoupling: Risk != Trust != Confidence. Confidence metrics remain epistemically
   separate and are labeled uncalibrated deterministic heuristics.
5. Zero LLM / Zero Network: 100% deterministic Python execution. Zero LLM calls, zero network I/O.
6. Presentation-Only Ordering: Findings are ordered deterministically by severity weight,
   evidence strength, and evidence ID solely for UI rendering.
7. Zero Autonomous Enforcement: The report prohibits automated blocking, takedowns, or suspensions.
"""

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.confidence_contract import (
    CALIBRATION_STATUS,
    AbstentionRecommendation,
    ConfidenceOutputPayload
)
from services.confidence_engine import ConfidenceEngine
from services.evidence_schema import (
    CANONICAL_AGENT_METADATA,
    VALID_SEVERITIES,
    VALID_EVIDENCE_TYPES
)
from services.report_contract import (
    REPORT_CONTRACT_VERSION,
    VALID_TCE_VERDICTS,
    ReportOverviewSection,
    ReportAssessmentSection,
    KeyFindingItem,
    GroundedClaimItem,
    ContradictionReportItem,
    EvidenceLineageItem,
    InvestigatorReportPayload,
    validate_investigator_report
)
from services.tce_config import (
    SEVERITY_WEIGHTS,
    resolve_evidence_polarity
)


class InvestigatorReportGenerator:
    """
    Deterministic Final Investigator Report Assembly Engine.
    """

    def __init__(self, version: str = REPORT_CONTRACT_VERSION):
        self.version = version

    def generate_report(
        self,
        session: Dict[str, Any],
        confidence_payload: Optional[Union[ConfidenceOutputPayload, Dict[str, Any]]] = None
    ) -> InvestigatorReportPayload:
        """
        Assemble a validated InvestigatorReportPayload from a completed pipeline session.

        Args:
            session: Read-only dictionary of the completed pipeline session.
            confidence_payload: Optional pre-computed ConfidenceOutputPayload or dict.

        Returns:
            InvestigatorReportPayload instance conforming to Step 5B contract.
        """
        # 1. Ensure input immutability
        if not isinstance(session, dict):
            raise TypeError("Pipeline session must be a dictionary.")

        # 2. Extract Session Metadata
        session_id = session.get("session_id")
        created_at = session.get("created_at")
        execution_status = session.get("status", "completed")
        generated_at = datetime.now(timezone.utc).isoformat()

        target_meta = self._extract_target_metadata(session)

        # 3. Extract Ledger Components
        ledger_data = session.get("evidence_ledger") or {}
        if hasattr(ledger_data, "to_dict"):
            ledger_data = ledger_data.to_dict()

        raw_entries = ledger_data.get("entries", [])
        raw_relationships = ledger_data.get("relationships", [])

        # Index entries for fast lookup
        entries_by_id: Dict[str, Dict[str, Any]] = {}
        for entry in raw_entries:
            eid = entry.get("evidence_id")
            if eid:
                entries_by_id[eid] = entry

        # 4. Extract TCE Results & Authoritative Contributions
        tce_summary = session.get("tce_summary") or {}
        tce_verdict = str(tce_summary.get("verdict", session.get("verdict", "unknown"))).lower()
        if tce_verdict not in VALID_TCE_VERDICTS:
            tce_verdict = "unknown"

        tce_risk_score = tce_summary.get("risk_score", session.get("risk_score"))
        if tce_risk_score is not None:
            tce_risk_score = round(float(tce_risk_score), 2)

        tce_trust_score = tce_summary.get("trust_score", session.get("trust_score"))
        if tce_trust_score is not None:
            tce_trust_score = round(float(tce_trust_score), 2)

        # Map existing TCE contributions directly by evidence_id
        tce_contributions_map: Dict[str, float] = {}
        for c_item in tce_summary.get("evidence_contributions", []):
            if isinstance(c_item, dict):
                c_eid = c_item.get("evidence_id")
                final_contrib = c_item.get("final_item_contribution")
                if c_eid and final_contrib is not None:
                    try:
                        tce_contributions_map[c_eid] = round(float(final_contrib), 5)
                    except (ValueError, TypeError):
                        pass

        # 5. Extract AERE Results & Grounding Diagnostics
        aere_data = session.get("aere") or {}
        aere_status = str(aere_data.get("status", "unavailable"))
        aere_output = aere_data.get("aere_output") or {}
        grounding_report = aere_data.get("grounding_report") or {}

        investigation_summary = aere_output.get("investigation_summary")
        if not investigation_summary or not str(investigation_summary).strip():
            investigation_summary = self._build_fallback_investigation_summary(
                target_url=target_meta.get("target_url"),
                verdict=tce_verdict,
                risk_score=tce_risk_score,
                trust_score=tce_trust_score,
                active_evidence_count=len(raw_entries)
            )

        detailed_findings = aere_output.get("primary_findings", [])
        if not isinstance(detailed_findings, list):
            detailed_findings = []

        grounded_claims, unsubstantiated_count, invalid_eids_set = self._extract_grounding_claims(
            grounding_report=grounding_report,
            aere_output=aere_output
        )

        # 6. Extract or Evaluate Confidence Diagnostics
        ce_data = self._resolve_confidence_data(
            session=session,
            ledger_data=ledger_data,
            tce_summary=tce_summary,
            aere_data=aere_data,
            confidence_payload=confidence_payload,
            session_id=session_id
        )

        # 7. Polarity Partitioning & Presentation Ordering
        risk_increasing, risk_reducing, neutral_obs, lineage_items = self._partition_and_order_findings(
            entries=raw_entries,
            tce_contributions_map=tce_contributions_map
        )

        # 8. Extract Contradictions from Ledger
        contradictions = self._extract_contradictions(
            relationships=raw_relationships,
            entries_by_id=entries_by_id
        )

        # 9. Build Section Dataclasses
        overview = ReportOverviewSection(
            investigation_id=session_id,
            target=target_meta,
            investigation_timestamp=created_at,
            report_generated_at=generated_at,
            execution_status=execution_status
        )

        assessment = ReportAssessmentSection(
            tce_verdict=tce_verdict,
            tce_risk_score=tce_risk_score,
            tce_trust_score=tce_trust_score,
            composite_confidence=ce_data.get("composite_confidence"),
            evidence_confidence=ce_data.get("evidence_confidence"),
            interpretation_confidence=ce_data.get("interpretation_confidence"),
            abstention_flag=bool(ce_data.get("abstention_flag", False)),
            abstention_reason=str(ce_data.get("abstention_reason", AbstentionRecommendation.REVIEW_REQUIRED_LOW_CONFIDENCE)),
            confidence_calibration_status=CALIBRATION_STATUS,
            epistemic_disclaimer="Risk != Trust != Confidence. Confidence indices are uncalibrated deterministic heuristics."
        )

        # 10. Assemble Final Report Payload
        report_payload = InvestigatorReportPayload(
            report_version=self.version,
            generated_at=generated_at,
            overview=overview,
            assessment=assessment,
            risk_increasing_findings=risk_increasing,
            risk_reducing_findings=risk_reducing,
            neutral_observations=neutral_obs,
            aere_reasoning_status=aere_status,
            investigation_summary=investigation_summary,
            detailed_findings=detailed_findings,
            grounded_claims=grounded_claims,
            unsubstantiated_claims_count=unsubstantiated_count,
            grounded_citation_ratio=float(ce_data.get("grounded_citation_ratio", 1.0)),
            total_active_evidence_items=int(ce_data.get("total_active_evidence_items", len(raw_entries))),
            provenance_gate_passed=bool(ce_data.get("provenance_gate_passed", True)),
            evidence_lineage=lineage_items,
            contradictions=contradictions,
            contradiction_score=float(ce_data.get("contradiction_score", 0.0)),
            observed_dimensions=list(ce_data.get("observed_dimensions", [])),
            inactive_telemetry_gaps=dict(ce_data.get("unobserved_reasons", {})),
            telemetry_coverage_score=float(ce_data.get("telemetry_coverage_score", 0.0)),
            source_reliability_score=float(ce_data.get("source_reliability_score", 0.0)),
            corroboration_score=float(ce_data.get("corroboration_score", 0.0)),
            concordant_cluster_count=int(ce_data.get("concordant_cluster_count", 0)),
            concordant_clusters=list(ce_data.get("concordant_clusters", []))
        )

        # 11. Validate Report Payload
        is_valid, validation_errors = validate_investigator_report(report_payload)
        if not is_valid:
            raise ValueError(f"Generated Investigator Report failed contract validation: {validation_errors}")

        return report_payload

    # -----------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------

    def _extract_target_metadata(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Extract canonical target details from session without mutation."""
        target_field = session.get("target")
        if isinstance(target_field, dict):
            return dict(target_field)

        return {
            "target_url": session.get("target_url"),
            "input_type": session.get("input_type", "url"),
            "original_input": session.get("original_input", "")
        }

    def _build_fallback_investigation_summary(
        self,
        target_url: Optional[str],
        verdict: str,
        risk_score: Optional[float],
        trust_score: Optional[float],
        active_evidence_count: int
    ) -> str:
        """Deterministic, factual fallback summary when AERE reasoning is unavailable."""
        url_str = target_url or "the investigated target"
        r_str = f"{risk_score:.2f}" if risk_score is not None else "N/A"
        t_str = f"{trust_score:.2f}" if trust_score is not None else "N/A"
        return (
            f"Digital forensics analysis of {url_str} yielded {active_evidence_count} active evidence entries. "
            f"The Trust Calculation Engine emitted an authoritative verdict of '{verdict}' "
            f"with Risk Score {r_str}/100.0 and Trust Score {t_str}/100.0. "
            f"All forensic findings and telemetry observations have been cataloged in this report for human investigator review."
        )

    def _extract_grounding_claims(
        self,
        grounding_report: Dict[str, Any],
        aere_output: Dict[str, Any]
    ) -> Tuple[List[GroundedClaimItem], int, Set[str]]:
        """Extract structured grounding claim records and preserve invalid evidence IDs."""
        grounded_claims: List[GroundedClaimItem] = []
        invalid_eids_set: Set[str] = set(grounding_report.get("invalid_evidence_ids", []))
        claim_results = grounding_report.get("claim_results", [])

        unsubstantiated_count = 0

        if isinstance(claim_results, list) and claim_results:
            for cr in claim_results:
                if not isinstance(cr, dict):
                    continue
                cid = cr.get("claim_id", "CLAIM-UNKNOWN")
                sec = cr.get("section", "primary_findings")
                g_status = cr.get("grounding_status", "UNCERTAIN")
                g_source = cr.get("grounding_source", "evidence")
                c_eids = cr.get("evidence_ids", [])
                issues = cr.get("issues", [])

                if g_status == "UNGROUNDED":
                    unsubstantiated_count += 1

                valid_citations = [eid for eid in c_eids if eid not in invalid_eids_set]
                invalid_citations = [eid for eid in c_eids if eid in invalid_eids_set]

                grounded_claims.append(
                    GroundedClaimItem(
                        claim_id=cid,
                        section=sec,
                        grounding_status=g_status,
                        grounding_source=g_source,
                        cited_evidence_ids=c_eids,
                        valid_evidence_ids=valid_citations,
                        invalid_evidence_ids=invalid_citations,
                        issues=issues
                    )
                )
        else:
            # If no grounding report exists (e.g. AERE was skipped or unavailable)
            unsubstantiated_count = 0

        return grounded_claims, unsubstantiated_count, invalid_eids_set

    def _resolve_confidence_data(
        self,
        session: Dict[str, Any],
        ledger_data: Dict[str, Any],
        tce_summary: Dict[str, Any],
        aere_data: Dict[str, Any],
        confidence_payload: Optional[Union[ConfidenceOutputPayload, Dict[str, Any]]],
        session_id: Optional[str]
    ) -> Dict[str, Any]:
        """Resolve confidence metrics from pre-computed payload, session, or on-the-fly CE."""
        if confidence_payload is not None:
            if isinstance(confidence_payload, ConfidenceOutputPayload):
                return confidence_payload.to_dict()
            elif isinstance(confidence_payload, dict):
                return dict(confidence_payload)

        # Check if already embedded in session
        for key in ["confidence", "confidence_summary", "confidence_result"]:
            if session.get(key) and isinstance(session.get(key), dict):
                return dict(session[key])

        # Evaluate deterministically using ConfidenceEngine
        ce = ConfidenceEngine()
        payload = ce.evaluate_confidence(
            ledger=ledger_data,
            aere_result=aere_data,
            tce_result=tce_summary,
            pipeline_session=session,
            investigation_id=session_id
        )
        return payload.to_dict()

    def _partition_and_order_findings(
        self,
        entries: List[Dict[str, Any]],
        tce_contributions_map: Dict[str, float]
    ) -> Tuple[List[KeyFindingItem], List[KeyFindingItem], List[KeyFindingItem], List[EvidenceLineageItem]]:
        """
        Group active evidence into risk_increasing, risk_reducing, and neutral groups,
        applying PRESENTATION-ONLY DETERMINISTIC ORDERING:
        (-SEVERITY_WEIGHTS[severity], -evidence_strength, evidence_id).
        """
        risk_increasing: List[KeyFindingItem] = []
        risk_reducing: List[KeyFindingItem] = []
        neutral_obs: List[KeyFindingItem] = []
        lineage_items: List[EvidenceLineageItem] = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ev_id = entry.get("evidence_id")
            if not ev_id:
                continue

            aid = entry.get("agent_id") or 1
            try:
                aid_int = int(aid)
            except (ValueError, TypeError):
                aid_int = 1

            aname = entry.get("agent_name") or CANONICAL_AGENT_METADATA.get(aid_int, {}).get("name", f"Agent {aid_int}")
            finding = entry.get("finding") or entry.get("description") or ""
            cat = entry.get("category") or (entry.get("data") or {}).get("category") or ""
            status = entry.get("status", "success")

            sev = str(entry.get("severity", "info")).lower()
            if sev not in VALID_SEVERITIES:
                sev = "info"

            etype = str(entry.get("evidence_type", "deterministic")).lower()
            if etype not in VALID_EVIDENCE_TYPES:
                etype = "deterministic"

            raw_str = entry.get("evidence_strength")
            try:
                estrength = float(raw_str) if raw_str is not None else 1.0
                estrength = max(0.0, min(1.0, round(estrength, 4)))
            except (ValueError, TypeError):
                estrength = 1.0

            # Polarity resolution via authoritative TCE taxonomy
            if status in ("unavailable", "restricted", "skipped", "error"):
                polarity = "neutral"
            else:
                polarity = resolve_evidence_polarity(cat, finding)

            tce_contrib = tce_contributions_map.get(ev_id)
            orig_ev_id = entry.get("original_evidence_id")
            is_dup = bool(orig_ev_id)

            key_item = KeyFindingItem(
                evidence_id=ev_id,
                agent_id=aid_int,
                agent_name=aname,
                finding=finding,
                category=cat,
                severity=sev,
                evidence_type=etype,
                evidence_strength=estrength,
                polarity=polarity,
                tce_contribution=tce_contrib,
                is_duplicate=is_dup,
                original_evidence_id=orig_ev_id
            )

            if polarity == "risk_increasing":
                risk_increasing.append(key_item)
            elif polarity == "risk_reducing":
                risk_reducing.append(key_item)
            else:
                neutral_obs.append(key_item)

            lineage_items.append(
                EvidenceLineageItem(
                    evidence_id=ev_id,
                    agent_id=aid_int,
                    agent_name=aname,
                    finding=finding,
                    raw_value=entry.get("value"),
                    evidence_type=etype,
                    severity=sev,
                    evidence_strength=estrength,
                    polarity=polarity,
                    provenance=entry.get("provenance") or {},
                    status=status,
                    tce_final_contribution=tce_contrib
                )
            )

        # Presentation-Only Deterministic Ordering
        # Order by: severity weight descending, strength descending, evidence_id ascending
        sort_key = lambda item: (
            -SEVERITY_WEIGHTS.get(item.severity, 0.0),
            -item.evidence_strength,
            item.evidence_id
        )

        risk_increasing.sort(key=sort_key)
        risk_reducing.sort(key=sort_key)
        neutral_obs.sort(key=sort_key)

        return risk_increasing, risk_reducing, neutral_obs, lineage_items

    def _extract_contradictions(
        self,
        relationships: List[Dict[str, Any]],
        entries_by_id: Dict[str, Dict[str, Any]]
    ) -> List[ContradictionReportItem]:
        """Extract authoritative contradiction relationships from the ledger."""
        contradictions: List[ContradictionReportItem] = []

        for rel in relationships:
            if not isinstance(rel, dict):
                continue
            if rel.get("relationship_type") != "contradiction":
                continue

            rel_id = rel.get("relationship_id", "")
            src_id = rel.get("source_evidence_id", "")
            tgt_id = rel.get("target_evidence_id", "")
            desc = rel.get("description", "Contradiction detected across forensic observations.")

            src_entry = entries_by_id.get(src_id, {})
            tgt_entry = entries_by_id.get(tgt_id, {})

            src_aname = src_entry.get("agent_name", "")
            tgt_aname = tgt_entry.get("agent_name", "")
            src_finding = src_entry.get("finding", "")
            tgt_finding = tgt_entry.get("finding", "")

            contradictions.append(
                ContradictionReportItem(
                    relationship_id=rel_id,
                    source_evidence_id=src_id,
                    target_evidence_id=tgt_id,
                    source_agent_name=src_aname,
                    target_agent_name=tgt_aname,
                    source_finding=src_finding,
                    target_finding=tgt_finding,
                    description=desc
                )
            )

        return contradictions


# =====================================================================
# FUNCTIONAL PUBLIC API ENTRYPOINT
# =====================================================================
def generate_investigator_report(
    session: Dict[str, Any],
    confidence_payload: Optional[Union[ConfidenceOutputPayload, Dict[str, Any]]] = None
) -> InvestigatorReportPayload:
    """
    Public API entrypoint for generating a Final Investigator Report.

    Args:
        session: Completed pipeline session dictionary.
        confidence_payload: Optional pre-computed ConfidenceOutputPayload or dictionary.

    Returns:
        InvestigatorReportPayload: Fully validated report contract dataclass instance.
    """
    generator = InvestigatorReportGenerator()
    return generator.generate_report(session=session, confidence_payload=confidence_payload)
