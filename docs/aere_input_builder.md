# AERE Input Builder Specification (Step 3D-1)

## Overview

The **AERE Input Builder** (`services/aere_input_builder.py`) serves as a deterministic, non-destructive mediation layer between the canonical **Investigation Evidence Ledger**, the **Trust Calculation Engine (TCE)**, and the downstream **AI Evidence Reasoning Engine (AERE)**.

```
Evidence Ledger (Canonical & Lossless)
                 │
                 ▼
     [ AERE Input Builder ]
   - Selects structured evidence entries
   - Preserves Evidence IDs and Provenance
   - Preserves explicit ledger relationships
   - Masks sensitive runtime values
   - Applies bounded-context length limits
   - Packages actual runtime TCE metrics
                 │
                 ▼
      Bounded AERE Input Payload
```

---

## Core Guarantees & Invariants

1. **Ledger Immutability:** The input builder treats the `EvidenceLedger` as an immutable forensic artifact. It never mutates, deletes, or re-indexes ledger entries.
2. **Actual Runtime Data:** Actual TCE results and Evidence IDs are copied verbatim into the payload. No hardcoded or illustrative values are generated.
3. **Evidence ID Grounding:** All Evidence IDs in the payload strictly match existing records in the ledger.
4. **Sensitive Data Masking:** Credential-like fields (passwords, tokens, API keys, session headers) are masked (`[REDACTED]`) in the AERE payload while remaining intact in the canonical ledger.
5. **Field-Aware Data Minimization:** Context length is controlled via configurable field-aware limits (`MAX_FINDING_LENGTH = 500`, `MAX_VALUE_STRING_LENGTH = 300`) rather than blind universal truncation.
6. **Missing Telemetry Neutrality:** Inactive or failed telemetry states (`unavailable`, `skipped`, `error`, `restricted`) are preserved without conversion into synthetic negative evidence.
7. **Deterministic Payload Digest:** Payload serialization produces a canonical SHA-256 hash (`ledger_sha256`) for audit reproducibility.

---

## Configuration Constants

| Parameter | Default Value | Purpose |
| :--- | :--- | :--- |
| `MAX_FINDING_LENGTH` | `500` chars | Bounded limit for finding/description text. |
| `MAX_VALUE_STRING_LENGTH` | `300` chars | Bounded limit for string representation of values. |
| `MAX_DATA_FIELD_STRING_LENGTH`| `300` chars | Bounded limit for nested string values. |
| `MAX_METADATA_ENTRIES` | `25` | Maximum number of metadata keys serialized per entry. |
| `MAX_COLLECTION_ITEMS` | `30` | Maximum number of items in a nested list before truncation. |
| `BUILDER_VERSION` | `"1.0.0"` | AERE Input Builder module version. |
| `AERE_INPUT_SCHEMA_VERSION` | `"2026.09-v1"` | Payload schema format version. |

---

## Verification & Testing

The builder is thoroughly tested by `tests/test_aere_input_builder.py` across 15 test scenarios:
- Exact TCE preservation
- Absence of hardcoded values
- Real Evidence ID extraction & zero fabrication
- Source ledger immutability
- Relational graph preservation across all 6 relationship types
- Telemetry neutrality
- Sensitive field masking
- Field-aware string bounding
- Deterministic canonical hashing
- Runtime target metadata propagation
- Zero scoring logic & TCE boundary maintenance
- Empty/minimal ledger handling
