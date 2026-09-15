# AERE Pipeline Integration & End-to-End Orchestration (Step 3D-3C)

## 1. Purpose

This document specifies the end-to-end integration of the AI Evidence Reasoning Engine (AERE) into the central forensic analysis pipeline (`services/analysis_pipeline.py`).

> [!IMPORTANT]
> **Core Architectural Principles**:
> 1. **TCE Sovereignty**: The Trust Calculation Engine (TCE) remains the authoritative source for numerical risk, trust, and verdict.
> 2. **Additive Layer**: AERE is an additive qualitative reasoning layer.
> 3. **Pure Orchestration**: The integration layer orchestrates existing components and does not duplicate their internal validation or scoring algorithms.

---

## 2. Current Pipeline Architecture & AERE Insertion Point

The digital forensics pipeline processes inputs through a strictly layered flow:

```text
                        Target Input (URL or QR Code)
                                      │
                                      ▼
                        18 Forensic Agents Execution
                                      │
                                      ▼
                           Common Evidence Schema
                                      │
                                      ▼
                              Evidence Normalizer
                                      │
                                      ▼
                        Investigation Evidence Ledger
                                      │
                                      ▼
                       Trust Calculation Engine (TCE)
                        [Sole Numerical Authority]
                                      │
                                      ▼
    ═════════════════════════════════════════════════════════════════
    AERE QUALITATIVE REASONING LAYER (Non-Destructive & Additive)
    ═════════════════════════════════════════════════════════════════
                                      │
                                      ▼
                             AERE Input Builder
                      [Data Minimization & Redaction]
                                      │
                                      ▼
                          AERE Input Contract Gate
                                      │
                                      ▼
                            AERE Reasoning Engine
                     [Instruction / Data Prompt Boundary]
                                      │
                                      ▼
                           LLMProvider Abstraction
                            (MockProvider / Offline)
                                      │
                                      ▼
                         AERE Output Contract Gate
                                      │
                                      ▼
                          AERE Grounding Validator
                     [Evidence / Entity / Claim Check]
                                      │
                                      ▼
    ═════════════════════════════════════════════════════════════════
    FINAL SESSION ENVELOPE: TCE Baseline + Additive AERE Output
    ═════════════════════════════════════════════════════════════════
```

---

## 3. Strict Architectural Boundaries

| Component | Responsibility | Boundary & Invariant |
| :--- | :--- | :--- |
| **Trust Calculation Engine** | Computes deterministic `risk_score`, `trust_score`, `verdict`. | Sole authority for numerical risk/trust; never replaced by AERE. |
| **AERE Input Builder** | Sanitizes credentials, bounds text context, and hashes payload. | Sole mediation boundary between Ledger/TCE and AERE. |
| **AERE Contract** | Validates structural JSON schema for inputs and outputs. | Enforces absence of forbidden numerical fields (`risk_score`, etc.). |
| **LLM Provider** | Abstraction layer for model inference (`MockProvider`). | Vendor-neutral; offline deterministic execution in tests. |
| **AERE Grounding Validator** | Evaluates claim-level grounding against input evidence ledger. | Traps hallucinated IDs, unsupported entities, overclaims. |
| **AERE Reasoning Engine** | Orchestrates retry, prompt construction, and fallback logic. | Pure orchestrator; delegates validation algorithms. |
| **Analysis Pipeline** | Orchestrates full pipeline execution and session creation. | Invokes AERE Reasoning Engine; isolates failures completely. |

---

## 4. Failure Isolation & Fallback Policy

AERE is designed as an enhancement layer. If any failure occurs during AERE input building, contract validation, provider invocation, or grounding validation:

$$\text{Pipeline Status} = \text{Completed (TCE Verified)} \quad + \quad \text{AERE Status} = \text{Fallback / Error}$$

* **TCE Output Preserved**: Authoritative `risk_score`, `trust_score`, and `verdict` remain 100% available and intact in `session`.
* **Zero Fabrication**: AERE sets `aere_output: null` on fallback without fabricating synthetic findings or substitute verdicts.
* **Complete Diagnostics**: Preserves `failure.stage`, `failure.reason`, `invalid_evidence_ids`, and `affected_claims`.

---

## 5. Backward Compatibility

The addition of AERE is strictly **additive**:
* All legacy session keys (`session_id`, `input_type`, `original_input`, `target_url`, `created_at`, `status`, `agents`, `all_evidence`, `evidence_ledger`, `tce_summary`, `trust_score`, `risk_score`, `verdict`) are preserved verbatim.
* The new qualitative reasoning result is attached under `session["aere"]`.
* Frontend (`static/js/app.js`, `templates/index.html`) and API endpoints (`app.py`) continue operating seamlessly without breaking changes.

---

## 6. Security & Prompt-Injection Resistance

The pipeline integrates defense-in-depth against prompt-injection attacks:
1. **Instruction / Data Isolation**: Prompt configuration cleanly separates trusted system developer directives from untrusted evidence data.
2. **Passive Data Mandate**: LLM instructions explicitly command the model to treat all evidence text strictly as passive observational data and ignore embedded instructions.
3. **Strict Grounding Enforcement**: Grounding validator ensures any adversary-induced claim deviating from genuine ledger evidence is caught and rejected.
4. **TCE Verdict Sovereignty**: Adversarial text cannot alter the deterministic mathematical calculation of the TCE risk score or verdict.

---

## 7. Telemetry Neutrality & Inactive States

* Missing or unobserved sensor telemetry (`unavailable`, `skipped`, `error`, `restricted`) is preserved as an investigative gap.
* Unobserved telemetry contributes $0.0$ to TCE risk and trust scores and is never converted into clean or negative evidence.

---

## 8. Network Isolation & Test Verification

All integration tests (`tests/test_aere_pipeline_e2e.py`) execute completely offline:
* Zero live network sockets (`socket.socket` calls trapped and verified).
* Deterministic offline agent fixtures simulate multi-sensor telemetry.
* Verified across 12 comprehensive end-to-end integration test scenarios.

---

## 9. Position Regarding Future Stages

```text
Validated AERE Output
         ↓
Future Confidence Engine (Calibration / Uncertainty)
         ↓
Final Investigator Report Generation
```

The future Confidence Engine remains a separate downstream stage. AERE grounding status is strictly qualitative and is never treated as a numerical confidence score or probability.
