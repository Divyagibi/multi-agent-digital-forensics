"""
services/confidence_engine.py
=============================
Deterministic Confidence Engine (DHCI) for Multi-Agent Digital Forensics System.

Evaluates:
1. Epistemic Evidence Confidence (C_ev) via Coverage, Reliability, Corroboration,
   Contradiction Penalty, and Provenance Gating.
2. Interpretation Fidelity Confidence (C_interp) via AERE citation grounding diagnostics.
3. Composite Confidence (C_overall).
4. Workflow Abstention Recommendations.

Architectural Guarantees:
- 100% Deterministic Python execution (Zero LLM invocations, zero prompt parsing, zero network I/O).
- Strict Read-Only execution over EvidenceLedger and AERE validation results.
- TCE Sovereignty: TCE is the sole authority for risk_score, trust_score, and verdict.
  TCE outputs are strictly excluded from Confidence Engine mathematics and appear only as
  contextual metadata in output contracts.
- Missing Telemetry Neutrality: Inactive telemetry (unavailable, skipped, error, restricted)
  remains an unobserved dimension and is never converted into positive/negative evidence.
- Zero Active Evidence Safety Guard: |E_active| == 0 strictly enforces C_ev = 0.0 and C_overall = 0.0.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.confidence_contract import (
    CONFIDENCE_CONTRACT_VERSION,
    CALIBRATION_STATUS,
    EVIDENCE_ID_REGEX,
    CLUSTER_DEFINITIONS,
    AGENT_CLUSTER_MAP,
    DEFAULT_TYPE_PRIORS,
    DEFAULT_LAMBDA_COR,
    DEFAULT_BETA_CONTRA,
    DEFAULT_AERE_FALLBACK_PRIOR,
    DEFAULT_ALPHA_COMP,
    DEFAULT_EVIDENCE_THRESHOLD,
    AbstentionRecommendation,
    InterpretationSemanticState,
    EvidenceConfidenceMetrics,
    InterpretationConfidenceMetrics,
    ConfidenceOutputPayload,
    validate_confidence_output
)
from services.evidence_schema import CANONICAL_AGENT_METADATA


class ConfidenceEngine:
    """
    Deterministic Epistemic Confidence & Reasoning Fidelity Evaluation Engine.
    """

    def __init__(
        self,
        type_priors: Optional[Dict[str, float]] = None,
        lambda_cor: float = DEFAULT_LAMBDA_COR,
        beta_contra: float = DEFAULT_BETA_CONTRA,
        fallback_prior: float = DEFAULT_AERE_FALLBACK_PRIOR,
        alpha_comp: float = DEFAULT_ALPHA_COMP,
        evidence_threshold: float = DEFAULT_EVIDENCE_THRESHOLD
    ):
        self.type_priors = type_priors or dict(DEFAULT_TYPE_PRIORS)
        self.lambda_cor = float(lambda_cor)
        self.beta_contra = float(beta_contra)
        self.fallback_prior = float(fallback_prior)
        self.alpha_comp = float(alpha_comp)
        self.evidence_threshold = float(evidence_threshold)

    def evaluate_confidence(
        self,
        ledger: Any,
        aere_result: Optional[Dict[str, Any]] = None,
        tce_result: Optional[Dict[str, Any]] = None,
        pipeline_session: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None
    ) -> ConfidenceOutputPayload:
        """
        Execute full confidence evaluation over an investigation ledger and optional AERE results.

        Args:
            ledger: EvidenceLedger instance or dictionary.
            aere_result: Optional output dictionary from AEREReasoningEngine.
            tce_result: Optional output dictionary from TrustCalculationEngine (contextual only).
            pipeline_session: Optional pipeline session dict containing raw agent execution states.
            investigation_id: Optional session identifier string.

        Returns:
            ConfidenceOutputPayload dataclass instance matching the Step 4B contract.
        """
        # 1. Normalize Ledger data
        ledger_dict, entries, relationships, target = self._extract_ledger(ledger)

        # 2. Evaluate Provenance Gate (G_prov)
        g_prov = self._evaluate_provenance(entries, relationships)

        # 3. Evaluate Telemetry Coverage (Phi_cov)
        phi_cov, app_count, obs_count, obs_dims, unobs_reasons = self._evaluate_coverage(
            entries=entries,
            pipeline_session=pipeline_session,
            target=target
        )

        # 4. Filter Active Evidence
        active_entries = self._get_active_evidence(entries)
        active_count = len(active_entries)

        # 5. Evaluate Source Reliability (Phi_rel)
        phi_rel = self._evaluate_reliability(active_entries)

        # 6. Evaluate Graph-Aware Corroboration (Phi_cor)
        phi_cor, concordant_count, concordant_clusters = self._evaluate_corroboration(
            relationships=relationships,
            entries_by_id=self._index_entries_by_id(entries)
        )

        # 7. Evaluate Contradiction Penalty (Phi_contra)
        phi_contra, gamma_contra = self._evaluate_contradiction(
            relationships=relationships,
            active_entries=active_entries
        )

        # 8. Synthesize Evidence Confidence (C_ev)
        # HARD INVARIANT: Zero active evidence strictly produces C_ev = 0.0
        if active_count == 0 or g_prov == 0:
            c_ev = 0.0
        else:
            weighted_core = (0.40 * phi_cov) + (0.30 * phi_rel) + (0.30 * phi_cor)
            c_ev = float(g_prov) * weighted_core * (phi_contra / 100.0)
            c_ev = max(0.0, min(100.0, c_ev))

        evidence_metrics = EvidenceConfidenceMetrics(
            telemetry_coverage_score=round(phi_cov, 4),
            source_reliability_score=round(phi_rel, 4),
            corroboration_score=round(phi_cor, 4),
            contradiction_score=round(phi_contra, 4),
            provenance_gate_passed=(g_prov == 1),
            evidence_confidence=round(c_ev, 4),
            concordant_cluster_count=concordant_count,
            concordant_clusters=concordant_clusters,
            contradiction_ratio=round(gamma_contra, 4),
            active_evidence_count=active_count
        )

        # 9. Evaluate Interpretation Fidelity (C_interp)
        interp_metrics = self._evaluate_interpretation(aere_result)
        c_interp = interp_metrics.interpretation_confidence

        # 10. Synthesize Composite Confidence (C_overall)
        # HARD INVARIANT: C_ev = 0 => C_overall = 0
        if c_ev == 0.0:
            c_overall = 0.0
        else:
            c_overall = c_ev * (self.alpha_comp + (1.0 - self.alpha_comp) * (c_interp / 100.0))
            c_overall = max(0.0, min(100.0, c_overall))

        # 11. Determine Abstention & Workflow Recommendation
        abstention_flag, abstention_reason = self._determine_abstention(
            g_prov=g_prov,
            phi_contra=phi_contra,
            c_ev=c_ev,
            c_interp=c_interp,
            c_overall=c_overall,
            aere_result=aere_result
        )

        # 12. Extract Collapsed Duplicate Count
        collapsed_dup_count = sum(1 for r in relationships if r.get("relationship_type") == "duplicate")

        # 13. Extract Contextual TCE Metadata (Non-authoritative, zero math impact)
        tce_verdict = None
        tce_risk = None
        tce_trust = None
        if tce_result and isinstance(tce_result, dict):
            tce_verdict = tce_result.get("verdict")
            tce_risk = tce_result.get("risk_score")
            tce_trust = tce_result.get("trust_score")
        elif pipeline_session and isinstance(pipeline_session, dict):
            tce_verdict = pipeline_session.get("verdict")
            tce_risk = pipeline_session.get("risk_score")
            tce_trust = pipeline_session.get("trust_score")

        # 14. Construct Final Step 4B Payload
        payload = ConfidenceOutputPayload(
            evidence_confidence=round(c_ev, 4),
            interpretation_confidence=round(c_interp, 4),
            composite_confidence=round(c_overall, 4),
            telemetry_coverage_score=round(phi_cov, 4),
            source_reliability_score=round(phi_rel, 4),
            corroboration_score=round(phi_cor, 4),
            contradiction_score=round(phi_contra, 4),
            provenance_gate_passed=(g_prov == 1),
            grounded_citation_ratio=round(interp_metrics.grounded_citation_ratio, 4),
            concordant_cluster_count=concordant_count,
            contradiction_ratio=round(gamma_contra, 4),
            abstention_flag=abstention_flag,
            abstention_reason=abstention_reason,
            calibration_status=CALIBRATION_STATUS,
            total_active_evidence_items=active_count,
            applicable_dimensions_count=app_count,
            observed_dimensions_count=obs_count,
            observed_dimensions=obs_dims,
            unobserved_reasons=unobs_reasons,
            collapsed_duplicate_count=collapsed_dup_count,
            aere_execution_state=interp_metrics.aere_execution_state,
            grounding_status=interp_metrics.grounding_status,
            unsubstantiated_claims_count=interp_metrics.unsubstantiated_claims_count,
            total_citations_emitted=interp_metrics.total_citations_emitted,
            valid_citations_count=interp_metrics.valid_citations_count,
            contextual_tce_verdict=str(tce_verdict) if tce_verdict is not None else None,
            contextual_tce_risk_score=float(tce_risk) if tce_risk is not None else None,
            contextual_tce_trust_score=float(tce_trust) if tce_trust is not None else None,
            engine_version=CONFIDENCE_CONTRACT_VERSION,
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            investigation_id=investigation_id or (pipeline_session.get("session_id") if pipeline_session else None),
            target=target,
            evidence_metrics=evidence_metrics.to_dict(),
            interpretation_metrics=interp_metrics.to_dict(),
            concordant_clusters=concordant_clusters
        )

        # Validate against Step 4B contract
        is_valid, validation_errors = validate_confidence_output(payload)
        if not is_valid:
            # Raise internal error if contract violated
            raise ValueError(f"Confidence Engine emitted invalid contract payload: {validation_errors}")

        return payload

    # =========================================================================
    # INTERNAL EVALUATION METHODS
    # =========================================================================

    def _extract_ledger(self, ledger: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Extract ledger dictionary, entries, relationships, and target."""
        if hasattr(ledger, "to_dict"):
            ledger_dict = ledger.to_dict()
            target = getattr(ledger, "target", None)
        elif isinstance(ledger, dict):
            ledger_dict = ledger
            target = ledger.get("target")
        else:
            ledger_dict = {"entries": [], "relationships": [], "summary": {}}
            target = None

        entries = ledger_dict.get("entries", [])
        relationships = ledger_dict.get("relationships", [])
        return ledger_dict, entries, relationships, target

    def _index_entries_by_id(self, entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Index all entries by their canonical evidence_id."""
        index: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            ev_id = entry.get("evidence_id")
            if ev_id:
                index[ev_id] = entry
        return index

    def _get_active_evidence(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter active, non-suppressed evidence items.
        Inactive telemetry statuses ('unavailable', 'skipped', 'error', 'restricted') are excluded.
        """
        active: List[Dict[str, Any]] = []
        for entry in entries:
            status = str(entry.get("status", "success")).lower()
            if status in ("unavailable", "skipped", "error", "restricted"):
                continue
            active.append(entry)
        return active

    def _evaluate_provenance(self, entries: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> int:
        """
        Evaluate structural and relational provenance gate (G_prov in {0, 1}).
        Checks canonical Evidence ID syntax, registered agent resolution, and relationship endpoints.
        """
        if not entries and not relationships:
            return 1  # Empty structure is technically consistent

        entries_by_id: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            ev_id = entry.get("evidence_id")
            if not ev_id or not isinstance(ev_id, str):
                return 0
            if not EVIDENCE_ID_REGEX.match(ev_id):
                return 0
            
            # Verify agent resolution
            agent_id = entry.get("agent_id")
            if agent_id is not None:
                try:
                    aid_int = int(agent_id)
                    if aid_int not in CANONICAL_AGENT_METADATA:
                        return 0
                except (ValueError, TypeError):
                    return 0

            entries_by_id[ev_id] = entry

        # Verify relationship pointers
        for rel in relationships:
            src_id = rel.get("source_evidence_id")
            tgt_id = rel.get("target_evidence_id")
            if not src_id or not tgt_id:
                return 0
            if src_id not in entries_by_id or tgt_id not in entries_by_id:
                return 0

        return 1

    def _evaluate_coverage(
        self,
        entries: List[Dict[str, Any]],
        pipeline_session: Optional[Dict[str, Any]],
        target: Optional[Dict[str, Any]]
    ) -> Tuple[float, int, int, List[str], Dict[str, str]]:
        """
        Evaluate telemetry coverage (Phi_cov).
        Derives applicability and observation state from pipeline execution semantics.
        """
        input_type = "url"
        session_status = "completed"
        agent_session_states: Dict[str, Any] = {}

        if pipeline_session and isinstance(pipeline_session, dict):
            input_type = pipeline_session.get("input_type", "url")
            session_status = pipeline_session.get("status", "completed")
            agent_session_states = pipeline_session.get("agents", {})

        # 1. Determine Applicability
        # Standard URL: 18 applicable dimensions (A1–A18)
        # QR with extracted URL: 18 applicable dimensions (A1–A18)
        # QR with plain text non-URL: 1 applicable dimension (A18 only)
        if input_type == "qr" and session_status == "completed_non_url":
            applicable_agent_ids = {18}
        else:
            applicable_agent_ids = set(range(1, 19))

        applicable_count = len(applicable_agent_ids)
        if applicable_count == 0:
            return 0.0, 0, 0, [], {}

        # 2. Determine Observed Dimensions
        # An applicable agent is observed if:
        # - It completed or succeeded in pipeline execution (even with zero findings, clean negative counts), OR
        # - It emitted entries into the ledger with status 'success', 'completed', or 'partial'
        observed_agent_ids: Set[int] = set()
        unobserved_reasons: Dict[str, str] = {}

        # Check session agent execution status
        for aid in applicable_agent_ids:
            agent_key = f"agent{aid}"
            agent_meta = CANONICAL_AGENT_METADATA.get(aid, {})
            agent_name = agent_meta.get("name", f"Agent {aid}")
            
            agent_res = agent_session_states.get(agent_key)
            if agent_res and isinstance(agent_res, dict):
                st = str(agent_res.get("status", "")).lower()
                if st in ("success", "completed"):
                    observed_agent_ids.add(aid)
                elif st == "partial":
                    # Partial counts as observed if it produced at least one evidence item
                    ev_items = agent_res.get("evidence", [])
                    if ev_items:
                        observed_agent_ids.add(aid)
                    else:
                        unobserved_reasons[agent_name] = "Partial execution produced zero valid evidence"
                elif st in ("error", "unavailable", "skipped", "restricted"):
                    unobserved_reasons[agent_name] = f"Agent returned status '{st}'"
            else:
                # If no session dictionary, fall back to checking ledger entries
                agent_entries = [e for e in entries if e.get("agent_id") == aid]
                active_agent_entries = [
                    e for e in agent_entries 
                    if str(e.get("status", "success")).lower() not in ("unavailable", "skipped", "error", "restricted")
                ]
                if active_agent_entries:
                    observed_agent_ids.add(aid)
                elif agent_entries:
                    unobserved_reasons[agent_name] = "All emitted entries were marked inactive/error"
                else:
                    unobserved_reasons[agent_name] = "No telemetry or observations recorded"

        # Also ensure any agent with valid active ledger entries is counted as observed
        for entry in entries:
            aid = entry.get("agent_id")
            if aid in applicable_agent_ids:
                st = str(entry.get("status", "success")).lower()
                if st not in ("unavailable", "skipped", "error", "restricted"):
                    observed_agent_ids.add(aid)
                    if aid in CANONICAL_AGENT_METADATA:
                        unobserved_reasons.pop(CANONICAL_AGENT_METADATA[aid]["name"], None)

        observed_count = len(observed_agent_ids)
        observed_dims = [
            CANONICAL_AGENT_METADATA[aid]["name"] for aid in sorted(observed_agent_ids) 
            if aid in CANONICAL_AGENT_METADATA
        ]

        phi_cov = (float(observed_count) / float(applicable_count)) * 100.0
        return max(0.0, min(100.0, phi_cov)), applicable_count, observed_count, observed_dims, unobserved_reasons

    def _evaluate_reliability(self, active_entries: List[Dict[str, Any]]) -> float:
        """
        Evaluate Intrinsic Source Reliability (Phi_rel) from active evidence.
        Weighted average of canonical evidence_type prior and item strength.
        """
        if not active_entries:
            return 0.0

        total_weighted_sum = 0.0
        total_strength_sum = 0.0

        for entry in active_entries:
            ev_type = str(entry.get("evidence_type", entry.get("type", "deterministic"))).lower()
            w_prior = self.type_priors.get(ev_type, 1.00)

            # Resolve item strength
            raw_strength = entry.get("evidence_strength")
            if raw_strength is not None:
                try:
                    strength = max(0.0, min(1.0, float(raw_strength)))
                except (ValueError, TypeError):
                    strength = 0.50 if ev_type == "inference" else 1.00
            else:
                strength = 0.50 if ev_type == "inference" else 1.00

            total_weighted_sum += (w_prior * strength)
            total_strength_sum += strength

        if total_strength_sum <= 0.0:
            return 0.0

        phi_rel = (total_weighted_sum / total_strength_sum) * 100.0
        return max(0.0, min(100.0, phi_rel))

    def _evaluate_corroboration(
        self,
        relationships: List[Dict[str, Any]],
        entries_by_id: Dict[str, Dict[str, Any]]
    ) -> Tuple[float, int, List[str]]:
        """
        Evaluate Graph-Aware Corroboration (Phi_cor).
        Identifies cross-cluster 'supporting' edges between distinct operational clusters.
        """
        if not relationships or not entries_by_id:
            return 0.0, 0, []

        concordant_clusters: Set[str] = set()

        for rel in relationships:
            rel_type = rel.get("relationship_type")
            if rel_type != "supporting":
                continue

            src_id = rel.get("source_evidence_id")
            tgt_id = rel.get("target_evidence_id")
            src_entry = entries_by_id.get(src_id)
            tgt_entry = entries_by_id.get(tgt_id)

            if not src_entry or not tgt_entry:
                continue

            # Ensure neither item is inactive telemetry
            src_st = str(src_entry.get("status", "success")).lower()
            tgt_st = str(tgt_entry.get("status", "success")).lower()
            if src_st in ("unavailable", "skipped", "error", "restricted"):
                continue
            if tgt_st in ("unavailable", "skipped", "error", "restricted"):
                continue

            src_agent = src_entry.get("agent_id")
            tgt_agent = tgt_entry.get("agent_id")
            if src_agent is None or tgt_agent is None:
                continue

            src_cluster = AGENT_CLUSTER_MAP.get(int(src_agent))
            tgt_cluster = AGENT_CLUSTER_MAP.get(int(tgt_agent))

            # Cross-cluster check: clusters must be distinct
            if src_cluster and tgt_cluster and src_cluster != tgt_cluster:
                concordant_clusters.add(src_cluster)
                concordant_clusters.add(tgt_cluster)

        n = len(concordant_clusters)
        if n < 2:
            phi_cor = 0.0
        else:
            phi_cor = 100.0 * (1.0 - math.exp(-self.lambda_cor * n))

        sorted_clusters = sorted(list(concordant_clusters))
        return max(0.0, min(100.0, phi_cor)), n, sorted_clusters

    def _evaluate_contradiction(
        self,
        relationships: List[Dict[str, Any]],
        active_entries: List[Dict[str, Any]]
    ) -> Tuple[float, float]:
        """
        Evaluate Contradiction Penalty (Phi_contra) from ledger 'contradiction' edges.
        """
        active_count = len(active_entries)
        if active_count == 0 or not relationships:
            return 100.0, 0.0

        active_ids = {e.get("evidence_id") for e in active_entries if e.get("evidence_id")}
        contradicted_ids: Set[str] = set()

        for rel in relationships:
            rel_type = rel.get("relationship_type")
            if rel_type != "contradiction":
                continue

            src_id = rel.get("source_evidence_id")
            tgt_id = rel.get("target_evidence_id")

            if src_id in active_ids:
                contradicted_ids.add(src_id)
            if tgt_id in active_ids:
                contradicted_ids.add(tgt_id)

        gamma_contra = float(len(contradicted_ids)) / float(active_count)
        gamma_contra = max(0.0, min(1.0, gamma_contra))

        phi_contra = 100.0 * max(0.0, 1.0 - self.beta_contra * gamma_contra)
        return max(0.0, min(100.0, phi_contra)), gamma_contra

    def _evaluate_interpretation(
        self,
        aere_result: Optional[Dict[str, Any]]
    ) -> InterpretationConfidenceMetrics:
        """
        Evaluate Interpretation Fidelity Confidence (C_interp) from AERE output diagnostics.
        """
        if not aere_result or not isinstance(aere_result, dict):
            return InterpretationConfidenceMetrics(
                grounded_citation_ratio=0.0,
                aere_execution_state="unavailable",
                grounding_status="UNVALIDATED",
                unsubstantiated_claims_count=0,
                total_citations_emitted=0,
                valid_citations_count=0,
                semantic_state=InterpretationSemanticState.INTERPRETATION_UNAVAILABLE,
                interpretation_confidence=0.0
            )

        state = str(aere_result.get("status", "error")).lower()
        grounding_report = aere_result.get("grounding_report") or {}
        
        grounding_status = grounding_report.get("grounding_status", "UNVALIDATED")
        unsubstantiated_count = int(grounding_report.get("unsubstantiated_claims_count", 0))
        total_citations = int(grounding_report.get("total_citations", 0))
        valid_citations = int(grounding_report.get("valid_citations_count", 0))

        # Handle SUCCESS execution
        if state == "success":
            if total_citations > 0:
                rho_ground = float(valid_citations) / float(total_citations)
            else:
                # Zero citations safety rule:
                # Perfect grounding (1.0) ONLY IF status is GROUNDED and 0 unsubstantiated claims
                if grounding_status == "GROUNDED" and unsubstantiated_count == 0:
                    rho_ground = 1.0
                else:
                    rho_ground = 0.0

            rho_ground = max(0.0, min(1.0, rho_ground))
            c_interp = 100.0 * rho_ground
            semantic_state = InterpretationSemanticState.INTERPRETATION_GROUNDED

        # Handle FALLBACK execution
        elif state == "fallback":
            rho_ground = 0.50
            c_interp = self.fallback_prior  # 50.0 (Uncalibrated policy prior)
            semantic_state = InterpretationSemanticState.INTERPRETATION_DEGRADED_FALLBACK

        # Handle REJECTED or ERROR execution
        else:
            rho_ground = 0.0
            c_interp = 0.0
            semantic_state = InterpretationSemanticState.INTERPRETATION_UNAVAILABLE

        return InterpretationConfidenceMetrics(
            grounded_citation_ratio=round(rho_ground, 4),
            aere_execution_state=state,
            grounding_status=str(grounding_status),
            unsubstantiated_claims_count=unsubstantiated_count,
            total_citations_emitted=total_citations,
            valid_citations_count=valid_citations,
            semantic_state=semantic_state,
            interpretation_confidence=round(c_interp, 4)
        )

    def _determine_abstention(
        self,
        g_prov: int,
        phi_contra: float,
        c_ev: float,
        c_interp: float,
        c_overall: float,
        aere_result: Optional[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Determine diagnostic abstention recommendation and workflow review flags.
        """
        # 1. Structural Provenance Failure
        if g_prov == 0:
            return True, AbstentionRecommendation.ABSTAIN_INTEGRITY_FAILURE

        # 2. Severe Relational Contradiction
        if phi_contra < 50.0:
            return True, AbstentionRecommendation.ABSTAIN_EVIDENTIARY_CONFLICT

        # 3. Insufficient Evidence Confidence (< 35.0)
        if c_ev < self.evidence_threshold:
            return True, AbstentionRecommendation.ABSTAIN_INSUFFICIENT_EVIDENCE

        # 4. Ungrounded Interpretation (if AERE was run successfully but failed grounding)
        if aere_result and str(aere_result.get("status", "")).lower() == "success" and c_interp < 50.0:
            return True, AbstentionRecommendation.REVIEW_REQUIRED_UNGROUNDED

        # 5. Low Overall Confidence (< 35.0)
        if c_overall < self.evidence_threshold:
            return True, AbstentionRecommendation.REVIEW_REQUIRED_LOW_CONFIDENCE

        # 6. Eligible for uncalibrated prototype workflow staging
        return False, AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY
