"""
services/aere_provider.py
=========================
LLM Provider Abstraction & Offline Mock Provider for AERE.

Defines:
1. Abstract base class `LLMProvider` for vendor-neutral model integration.
2. Comprehensive provider error hierarchy for failure handling.
3. Offline, deterministic `MockProvider` designed as a conservative structural
   test double that generates claims derived strictly from supplied input evidence.
"""

import copy
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


# =====================================================================
# 1. PROVIDER ERROR HIERARCHY
# =====================================================================
class ProviderError(Exception):
    """Base exception for all AERE LLM provider errors."""
    def __init__(self, message: str, provider_name: str = "generic", status_code: Optional[int] = None):
        super().__init__(message)
        self.provider_name = provider_name
        self.status_code = status_code


class ProviderTimeoutError(ProviderError):
    """Raised when an external model inference request times out."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when the LLM service endpoint is unreachable or in maintenance."""
    pass


class ProviderAuthenticationError(ProviderError):
    """Raised when API credentials are missing, invalid, or expired."""
    pass


class ProviderRateLimitError(ProviderError):
    """Raised when provider request limits or quota thresholds are exceeded."""
    pass


class ProviderMalformedResponseError(ProviderError):
    """Raised when the model output cannot be parsed as valid JSON."""
    pass


# =====================================================================
# 2. ABSTRACT PROVIDER INTERFACE
# =====================================================================
class LLMProvider(ABC):
    """
    Abstract Base Class for AERE LLM inference providers.
    
    Decouples reasoning logic from specific cloud AI SDKs (Gemini, OpenAI, Anthropic, etc.).
    """

    @abstractmethod
    def generate_reasoning(
        self,
        input_payload: Dict[str, Any],
        prompt_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute reasoning on an AERE input payload and return a structured response.
        
        Args:
            input_payload: Bounded structured payload from AEREInputBuilder.
            prompt_config: Optional configuration dictionary (prompt template, temperature, etc.).
            
        Returns:
            Structured dictionary matching the AERE output schema.
        """
        pass

    @abstractmethod
    def get_provider_metadata(self) -> Dict[str, Any]:
        """
        Return provider capabilities and identification metadata.
        """
        pass


# =====================================================================
# 3. OFFLINE DETERMINISTIC MOCK PROVIDER (Conservative Test Double)
# =====================================================================
class MockProvider(LLMProvider):
    """
    Offline, deterministic mock provider for testing and validation.
    
    Guarantees:
    1. Zero network calls or external API dependencies.
    2. Deterministic execution for identical inputs.
    3. Produces 100% schema-valid AERE output structures.
    4. Conservative Evidence Grounding: Emits only genuine Evidence IDs present
       in the input ledger, with claims derived strictly from input finding text.
    5. Zero Unsupported Claims: Never infers unstated brand names, unverified fraud,
       or stronger malicious conclusions than the supplied evidence explicitly states.
    6. Missing Data Integrity: Preserves unavailable/skipped/error states as gaps,
       never converting them into positive or negative forensic conclusions.
    7. Empty Ledger Safety: Empty input produces empty/neutral collections without
       fabricated forensic findings or fictional IDs.
    8. Leaves input payload completely immutable.
    9. Does not compute or alter TCE risk, trust, or verdicts.
    """

    def __init__(
        self,
        custom_response: Optional[Dict[str, Any]] = None,
        simulate_error: Optional[Exception] = None
    ):
        self.custom_response = custom_response
        self.simulate_error = simulate_error
        self.provider_name = "mock"
        self.model_id = "offline-mock-v1"

    def get_provider_metadata(self) -> Dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "model_id": self.model_id,
            "is_offline": True,
            "supports_structured_json": True
        }

    def generate_reasoning(
        self,
        input_payload: Dict[str, Any],
        prompt_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a deterministic, schema-valid AERE response derived strictly
        from the evidence present in the input payload.
        """
        # 1. Error simulation support for failure testing
        if self.simulate_error is not None:
            raise self.simulate_error

        # 2. Return custom fixture if configured
        if self.custom_response is not None:
            return copy.deepcopy(self.custom_response)

        # 3. Extract actual entries and TCE results from input payload without mutating it
        ledger_sum = input_payload.get("ledger_summary", {}) if isinstance(input_payload, dict) else {}
        entries: List[Dict[str, Any]] = ledger_sum.get("entries", [])
        relationships: List[Dict[str, Any]] = ledger_sum.get("relationships", [])
        tce_result: Dict[str, Any] = input_payload.get("tce_result", {}) if isinstance(input_payload, dict) else {}
        target: Dict[str, Any] = input_payload.get("target", {}) if isinstance(input_payload, dict) else {}

        verdict = str(tce_result.get("verdict", "unknown")).lower()
        risk_score = float(tce_result.get("risk_score", 0.0))

        # Target name resolution
        target_name = target.get("hostname") or target.get("domain") or target.get("normalized_url") or "investigated target"

        # Separate available entries from unavailable/skipped/error/restricted entries
        active_entries = [
            e for e in entries
            if isinstance(e, dict) and e.get("status") not in ("unavailable", "skipped", "error", "restricted")
        ]
        unavailable_entries = [
            e for e in entries
            if isinstance(e, dict) and e.get("status") in ("unavailable", "skipped", "error", "restricted")
        ]

        active_eids = [e["evidence_id"] for e in active_entries if e.get("evidence_id")]

        # If ledger is completely empty
        if not entries:
            return {
                "investigation_summary": f"Forensic investigation synthesis for {target_name}. The ledger contains no recorded evidence entries.",
                "primary_findings": [],
                "evidence_chains": [],
                "contradiction_analyses": [],
                "alternative_explanations": [],
                "investigative_gaps": [],
                "tce_interpretation": {
                    "mathematical_alignment": f"TCE risk score is {risk_score:.2f}.",
                    "verdict_support": f"Verdict '{verdict}' reflects baseline state with zero recorded telemetry."
                },
                "reasoning_metadata": {
                    "engine_version": "AERE-1.0-mock",
                    "prompt_version": "2026.09-mock-v1",
                    "provider_name": self.provider_name,
                    "model_id": self.model_id,
                    "generation_temperature": 0.0,
                    "grounding_validation_status": "UNVALIDATED",
                    "referenced_evidence_count": 0,
                    "invalid_evidence_ids_detected": []
                }
            }

        # 4. Build conservative, strictly evidence-derived primary findings
        primary_findings = []
        for idx, entry in enumerate(active_entries[:5]):
            eid = entry.get("evidence_id")
            if not eid:
                continue
            raw_finding = entry.get("finding") or entry.get("description") or f"Observation {eid}"
            sev = entry.get("severity", "info").lower()
            agent_name = entry.get("agent_name") or f"Agent {entry.get('agent_id', 'Unknown')}"

            # Map severity to allowed forensic significance level
            if sev in ("critical", "high", "medium", "low"):
                forensic_sig = sev
            else:
                forensic_sig = "informational"

            primary_findings.append({
                "finding_id": f"FINDING-MOCK-{idx+1:02d}",
                "topic": f"{agent_name} Observation",
                "summary": f"The ledger reports: '{raw_finding}'.",
                "grounded_evidence_ids": [eid],
                "forensic_significance": forensic_sig,
                "interpretation": f"Sensor '{agent_name}' recorded: '{raw_finding}' with severity '{sev}'."
            })

        # 5. Build evidence chains derived strictly from actual ledger relationships or adjacent entries
        evidence_chains = []
        supporting_rels = [
            r for r in relationships
            if isinstance(r, dict) and r.get("relationship_type") == "supporting"
            and r.get("source_evidence_id") in active_eids and r.get("target_evidence_id") in active_eids
        ]

        if supporting_rels:
            for idx, srel in enumerate(supporting_rels[:3]):
                src = srel["source_evidence_id"]
                tgt = srel["target_evidence_id"]
                rel_desc = srel.get("description", "Supporting relationship")
                evidence_chains.append({
                    "chain_id": f"CHAIN-MOCK-{idx+1:02d}",
                    "theme": f"Corroborating Observation Link ({src} -> {tgt})",
                    "evidence_ids": [src, tgt],
                    "narrative": f"The ledger identifies a supporting relationship between {src} and {tgt}: {rel_desc}."
                })
        elif len(active_eids) >= 2:
            evidence_chains.append({
                "chain_id": "CHAIN-MOCK-01",
                "theme": "Multi-Sensor Telemetry Sequence",
                "evidence_ids": active_eids[:2],
                "narrative": f"Telemetry includes observations {active_eids[0]} and {active_eids[1]}."
            })

        # 6. Build contradiction analyses derived strictly from explicit contradiction relationships
        contradiction_analyses = []
        contradiction_rels = [
            r for r in relationships
            if isinstance(r, dict) and r.get("relationship_type") == "contradiction"
            and r.get("source_evidence_id") in active_eids and r.get("target_evidence_id") in active_eids
        ]
        for idx, crel in enumerate(contradiction_rels[:3]):
            src = crel["source_evidence_id"]
            tgt = crel["target_evidence_id"]
            rel_desc = crel.get("description", "Discrepancy noted in ledger")
            contradiction_analyses.append({
                "conflict_id": f"CONFLICT-MOCK-{idx+1:02d}",
                "conflicting_evidence_ids": [src, tgt],
                "topic": f"Discrepancy between {src} and {tgt}",
                "analysis": f"The ledger records conflicting observations between {src} and {tgt}: {rel_desc}.",
                "material_impact": "Requires evaluation against corroborating telemetry."
            })

        # 7. Build alternative explanations derived strictly from actual entry text
        alternative_explanations = []
        if active_entries:
            primary_entry = active_entries[0]
            eid = primary_entry.get("evidence_id", active_eids[0])
            raw_finding = primary_entry.get("finding") or "Observation"
            counter_ids = [active_eids[1]] if len(active_eids) > 1 else []

            alternative_explanations.append({
                "evidence_ids": [eid],
                "primary_interpretation": f"The ledger reports '{raw_finding}'.",
                "alternative_interpretation": f"Plausible benign operational context for '{raw_finding}' pending corroboration.",
                "counter_evidence_ids": counter_ids,
                "plausibility_assessment": "Plausible subject to verification of surrounding infrastructure."
            })

        # 8. Build investigative gaps strictly from unavailable/skipped/error telemetry
        investigative_gaps = []
        for idx, ue in enumerate(unavailable_entries[:4]):
            ue_id = ue.get("evidence_id") or f"E{ue.get('agent_id', 'Unknown')}-XX"
            agent_label = ue.get("agent_name") or f"Agent {ue.get('agent_id', 'Unknown')}"
            status_label = ue.get("status", "unavailable")

            investigative_gaps.append({
                "gap_id": f"GAP-MOCK-{idx+1:02d}",
                "unobserved_dimension": f"{agent_label} ({ue_id})",
                "reason": f"Telemetry returned status '{status_label}'.",
                "recommended_action": f"Verify sensor connectivity and access for {agent_label}."
            })

        # 9. Assemble summary string
        inv_summary = (
            f"Forensic investigation synthesis for {target_name}. "
            f"The deterministic TCE evaluated {len(active_eids)} active evidence items, resulting in a verdict of '{verdict}' "
            f"with a risk score of {risk_score:.2f}."
        )

        all_referenced_eids = list({
            eid for f in primary_findings for eid in f.get("grounded_evidence_ids", [])
        } | {
            eid for c in evidence_chains for eid in c.get("evidence_ids", [])
        } | {
            eid for ct in contradiction_analyses for eid in ct.get("conflicting_evidence_ids", [])
        } | {
            eid for a in alternative_explanations for eid in a.get("evidence_ids", []) + a.get("counter_evidence_ids", [])
        })

        return {
            "investigation_summary": inv_summary,
            "primary_findings": primary_findings,
            "evidence_chains": evidence_chains,
            "contradiction_analyses": contradiction_analyses,
            "alternative_explanations": alternative_explanations,
            "investigative_gaps": investigative_gaps,
            "tce_interpretation": {
                "mathematical_alignment": f"TCE risk score of {risk_score:.2f} reflects aggregation of {len(active_eids)} active telemetry items.",
                "verdict_support": f"The '{verdict}' verdict is supported by cluster analysis of represented telemetry."
            },
            "reasoning_metadata": {
                "engine_version": "AERE-1.0-mock",
                "prompt_version": "2026.09-mock-v1",
                "provider_name": self.provider_name,
                "model_id": self.model_id,
                "generation_temperature": 0.0,
                "grounding_validation_status": "UNVALIDATED",
                "referenced_evidence_count": len(all_referenced_eids),
                "invalid_evidence_ids_detected": []
            }
        }
