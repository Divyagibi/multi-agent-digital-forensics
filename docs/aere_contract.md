# AERE Contract & Provider Abstraction Specification (Step 3D-2)

## 1. Overview

Step 3D-2 defines the formal machine-readable schemas and provider abstraction for the **AI Evidence Reasoning Engine (AERE)**:

```
AEREInputBuilder
       │
       ▼ (validate_aere_input)
  AERE Input Contract
       │
       ▼
  LLMProvider Interface (Abstract)
       │
       ├── MockProvider (Offline / Deterministic)
       ├── GeminiProvider (Future Cloud Integration)
       └── OpenAIProvider (Future Cloud Integration)
       │
       ▼ (validate_aere_output)
  AERE Output Contract (Schema-Constrained)
```

---

## 2. AERE Contract Specifications (`services/aere_contract.py`)

### A. Input Contract Requirements
The input contract accepts payloads produced by `AEREInputBuilder`:
- `investigation_metadata`: `investigation_id`, `schema_version`, `builder_version`, `ledger_sha256`, `created_at`
- `target`: Canonical entity target dictionary (`url`, `domain`, `hostname`, `ip`, `scheme`)
- `tce_result`: Authoritative runtime TCE dictionary (`risk_score`, `trust_score`, `verdict`, `aggregation_metrics`, `evidence_contributions`)
- `ledger_summary`: Bounded lists of normalized `entries` and `relationships`
- `agent_execution_summary`: Telemetry completeness metrics
- `builder_telemetry`: Operational counters (masked fields, bounds)

### B. Output Contract Requirements
The output contract enforces structured forensic reasoning:
- `investigation_summary`: Non-empty narrative summary
- `primary_findings`: Structured findings with `finding_id`, `topic`, `summary`, `grounded_evidence_ids`, `forensic_significance`, `interpretation`
- `evidence_chains`: Multi-agent synthesis with `chain_id`, `theme`, `evidence_ids`, `narrative`
- `contradiction_analyses`: Discrepancy evaluations with `conflict_id`, `conflicting_evidence_ids`, `topic`, `analysis`, `material_impact`
- `alternative_explanations`: Non-malicious hypotheses with `evidence_ids`, `primary_interpretation`, `alternative_interpretation`, `counter_evidence_ids`, `plausibility_assessment`
- `investigative_gaps`: Unobserved dimensions with `gap_id`, `unobserved_dimension`, `reason`, `recommended_action`
- `tce_interpretation`: Mathematical contextualization with `mathematical_alignment`, `verdict_support`
- `reasoning_metadata`: Provenance metadata with `engine_version`, `prompt_version`, `provider_name`, `model_id`, `generation_temperature`, `grounding_validation_status`, `referenced_evidence_count`, `invalid_evidence_ids_detected`

### C. Qualitative Boundary (Strict Absence of Scoring)
The contract forbids the following fields in AERE output to prevent score overwrites:
`risk_score`, `trust_score`, `confidence_score`, `numerical_confidence`, `confidence_interval`, `probability`, `alternative_verdict`, `recalculated_risk`.

---

## 3. Provider Abstraction (`services/aere_provider.py`)

### A. `LLMProvider` Abstract Base Class
- `generate_reasoning(input_payload, prompt_config=None) -> Dict[str, Any]`
- `get_provider_metadata() -> Dict[str, Any]`

### B. Error Handling Hierarchy
- `ProviderError` (Base)
  - `ProviderTimeoutError`
  - `ProviderUnavailableError`
  - `ProviderAuthenticationError`
  - `ProviderRateLimitError`
  - `ProviderMalformedResponseError`

### C. `MockProvider`
- 100% offline and deterministic.
- Produces schema-valid responses citing real Evidence IDs from the input ledger.
- Zero network activity.
