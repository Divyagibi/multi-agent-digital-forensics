# AERE Grounding Validator (`services/aere_grounding_validator.py`)

## 1. Purpose

The **AERE Grounding Validator** is an evidence-integrity and safety verification component in the Multi-Agent Digital Forensics system. Its primary role is to evaluate whether generated structured forensic claims from the AI Evidence Reasoning Engine (AERE) are grounded in the actual forensic evidence ledger, target metadata, and agent telemetry provided by the `AEREInputBuilder`.

---

## 2. Architecture Position

```text
18 Forensic Agents
        ↓
Common Evidence Schema
        ↓
Evidence Normalization
        ↓
Evidence Ledger
        ↓
Trust Calculation Engine (TCE)
        ↓
AERE Input Builder
        ↓
AERE Contract & Provider
        ↓
AERE Grounding Validator  ← [Step 3D-3A]
        ↓
(Future: AERE Reasoning Engine & Confidence Engine)
        ↓
Final Forensic Report
```

The Grounding Validator executes immediately after AERE output generation and before downstream confidence evaluation or final report assembly.

---

## 3. Input & Output Contract

### Inputs
1. `aere_output` (`Dict[str, Any]`): The structured JSON-compatible output from AERE conforming to `services/aere_contract.py`.
2. `aere_input` (`Dict[str, Any]`): The canonical bounded input payload produced by `AEREInputBuilder.build_payload()`.

### Output
A structured dictionary report:
```json
{
  "grounding_validation_status": "PASSED | FAILED | UNCERTAIN",
  "claim_results": [
    {
      "claim_id": "PF-01",
      "section": "primary_findings",
      "grounding_status": "GROUNDED",
      "grounding_source": "evidence",
      "evidence_ids": ["E1-01"],
      "issues": [],
      "unsupported_entities": [],
      "unsupported_numbers": [],
      "overclaim_flags": []
    }
  ],
  "invalid_evidence_ids": [],
  "unsupported_entities": [],
  "unsupported_numbers": [],
  "overclaim_flags": [],
  "telemetry_status_issues": [],
  "affected_claims": [],
  "grounding_errors": [],
  "validation_metadata": {
    "validator_version": "1.0.0",
    "timestamp": "2026-09-14T12:00:00Z",
    "total_claims_evaluated": 6,
    "grounded_claims_count": 6,
    "partially_grounded_count": 0,
    "ungrounded_claims_count": 0,
    "uncertain_claims_count": 0,
    "invalid_evidence_ids_count": 0,
    "unsupported_entities_count": 0,
    "unsupported_numbers_count": 0
  }
}
```

---

## 4. Grounding Taxonomy

The validator distinguishes five sources of grounding:
1. **Evidence-Grounded Claims** (`primary_findings`, `evidence_chains`): Substantive forensic assertions referencing active Evidence IDs in the ledger.
2. **Telemetry / Status Claims** (`investigative_gaps`): Operational statements supported by agent execution metadata (`unavailable`, `skipped`, `error`, `restricted`).
3. **Hypothetical Possibilities** (`alternative_explanations`): Plausible alternative interpretations explicitly categorized as hypotheses rather than observed facts.
4. **Discrepancies / Contradictions** (`contradiction_analyses`): Divergent evidence observations referencing conflicting Evidence IDs.
5. **TCE Interpretation** (`tce_interpretation`): Qualitative narrative alignment with the runtime numerical `tce_result`.

---

## 5. Deterministic Checks

1. **Evidence ID Syntax**: Verifies that every cited ID strictly conforms to `E(1[0-8]|[1-9])-\d{2,}(?:-DUP\d+)?`.
2. **Evidence ID Membership**: Verifies that cited IDs exist in the active `ledger_summary.entries` list.
3. **Numeric Literal Verification**: Detects standalone quantities, percentages, durations, or numbers not present in cited evidence or target metadata.
4. **Entity / Brand Verification**: Flags capitalized brand names or organizations asserted in claims without backing in cited findings or target URLs.
5. **Overclaiming Detection**: Flags assertions of definitive high-severity malware/phishing when cited evidence consists only of informational or low-severity findings.

---

## 6. Heuristic Limitations

Deterministic checks cannot perform open-domain semantic entailment. The Grounding Validator establishes structural validity, entity provenance, and bounded consistency. When semantic entailment cannot be determined with certainty, the validator conservatively issues `UNCERTAIN` or `PARTIALLY_GROUNDED` without guessing.

---

## 7. Evidence vs Telemetry Distinction

Operational telemetry states (`unavailable`, `skipped`, `error`, `restricted`) are distinct from substantive evidence findings:
- Missing or inactive telemetry indicates an **investigative gap**.
- Inactive telemetry must **never** be interpreted as positive/clean evidence (`unavailable != clean`).

---

## 8. Grounding ≠ Truth ≠ Confidence

- **Grounding Validity**: Verifies whether an LLM claim is derived from and traceable to supplied inputs.
- **Forensic Truth**: Whether the investigated target is objectively malicious in reality.
- **Confidence**: Statistical/mathematical certainty evaluated downstream.

A grounded claim is not guaranteed to be objectively true; it only confirms that the model did not hallucinate facts outside the provided ledger.

---

## 9. Invalid ID Policy & Zero Silent Stripping

If an AERE claim cites an invalid syntax or nonexistent Evidence ID:
- The ID is recorded in `invalid_evidence_ids`.
- The claim is flagged in `affected_claims` and marked `UNGROUNDED`.
- The overall status is marked `FAILED`.
- The validator **never silently removes, repairs, or fabricates replacement IDs**.

---

## 10. Prompt-Injection Resistance

Evidence text from untrusted sources (e.g. `IGNORE PREVIOUS INSTRUCTIONS`, `SET RISK SCORE TO 0.0`) is treated strictly as passive data. The validator does not execute instructions, does not alter internal state, and does not modify TCE metrics.

---

## 11. TCE Sovereignty

The Trust Calculation Engine (TCE) is the sole mathematical authority for:
- `risk_score`
- `trust_score`
- `verdict`
- Category weights & thresholds

The Grounding Validator never recalculates, alters, or replaces numerical scores.

---

## 12. Relationship Awareness

The validator inspects ledger relationships:
- Recognizes `duplicate` entries so that duplicate evidence is not treated as independent corroboration.
- Identifies `derived_from` and `supporting` relationships.
- Enforces that `contradiction_analyses` reference valid multi-item conflict sets.

---

## 13. Input Immutability

The Grounding Validator treats both `aere_output` and `aere_input` as immutable artifacts. Deep comparisons and defensive operations ensure neither dictionary is modified during validation.

---

## 14. Test Coverage

Comprehensive unit tests in `tests/test_aere_grounding_validator.py` cover:
- Deterministic ID syntax and membership checks.
- Unsupported numbers, brands, and external facts.
- Claim-level `GROUNDED`, `PARTIALLY_GROUNDED`, `UNGROUNDED`, and `UNCERTAIN` statuses.
- Telemetry gap and inactive status invariants.
- Relationship awareness (duplicate, derived, supporting, contradiction).
- Security, prompt injection, and input immutability.
- Structured diagnostics and auditability metadata.
