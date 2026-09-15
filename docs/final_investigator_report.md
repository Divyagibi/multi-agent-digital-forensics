# Final Investigator Report (Step 5B)

## 1. Purpose

The **Final Investigator Report** is the definitive, post-hoc synthesis layer of the Multi-Agent Digital Forensics & Evidence Analysis System. It aggregates forensic telemetry across 18 specialized agents, the Investigation Evidence Ledger, the Trust Calculation Engine (TCE), the AI Evidence Reasoning Engine (AERE), and the Deterministic Heuristic Confidence Engine (DHCI) into a unified, human-readable forensic dossier.

### Core Architectural Axioms
1. **Risk ≠ Trust ≠ Confidence**: Risk represents the bounded probability/severity of threat indicators; Trust represents the verified resilience and legitimacy of the target; Confidence represents epistemic and grounding certainty over the forensic process.
2. **Grounding validity ≠ truth ≠ confidence**: Grounding verifies that qualitative claims are cited directly from ledger evidence and telemetry; it does not constitute metaphysical truth or frequentist confidence.
3. **The report layer does not introduce new mathematical scoring**: All numerical metrics are read directly from upstream authoritative engines (TCE and Confidence Engine) or represent structural counts.
4. **Human-in-the-Loop Sovereign Boundary**: The report is an advisory artifact designed exclusively for human forensic analysts and prohibits autonomous enforcement actions.

---

## 2. Architecture & Authority Boundaries

The report layer is strictly **additive, post-hoc, and read-only**. It executes only after all upstream analysis stages have completed.

```
+-------------------------------------------------------------------------+
|                  18-Agent Modular Extraction Pipeline                   |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                 Canonical Investigation Evidence Ledger                 |
|     (Structural Authority: Normalization, Deduplication, Lineage)       |
+-------------------------------------------------------------------------+
            |                                         |
            v                                         v
+-----------------------+                 +-----------------------+
|  Trust Calculation    |                 | AI Evidence Reasoning |
|      Engine (TCE)     |                 |     Engine (AERE)     |
| (Sole Authority for   |                 | (Qualitative Grounded |
| Risk, Trust, Verdict) |                 |       Reasoning)      |
+-----------------------+                 +-----------------------+
            \                                         /
             \                                       /
              v                                     v
+-------------------------------------------------------------------------+
|                 Deterministic Confidence Engine (DHCI)                  |
|       (Epistemic Evidence Confidence & Interpretation Fidelity)         |
+-------------------------------------------------------------------------+
                                     |
                                     v
+=========================================================================+
|                    FINAL INVESTIGATOR REPORT LAYER                      |
|           services/report_contract.py | services/report_generator.py     |
|                                                                         |
|  * Read-only session consumer    * Polarity grouping (TCE taxonomy)     |
|  * Presentation-only ordering    * Full lineage & audit trace           |
|  * Contradiction preservation    * Human review guidance                |
+=========================================================================+
```

### Authority Matrix
| Component / Engine | Sovereign Scope | Prohibited Scope |
| :--- | :--- | :--- |
| **Evidence Ledger** | Normalization, deduplication, relationships, lineage | Risk scoring, trust calculation, verdict assignment |
| **TCE** | `risk_score`, `trust_score`, `verdict`, `final_item_contribution` | LLM invocation, citation evaluation, epistemic confidence |
| **AERE** | Structured narrative, evidence chains, investigative gaps | Numerical scoring, score override, autonomous actions |
| **Confidence Engine** | $C_{\text{ev}}, C_{\text{interp}}, C_{\text{overall}}$, abstention recommendations | Modifying TCE scores, network I/O, LLM calls |
| **Report Generator** | Presentation assembly, formatting, deterministic ordering | Creating scores, overriding verdicts, autonomous enforcement |

---

## 3. Data Contract (`InvestigatorReportPayload`)

The report contract is implemented in `services/report_contract.py` using standard Python dataclasses:

| Top-Level Field | Type | Authority Tier | Description |
| :--- | :--- | :--- | :--- |
| `report_version` | `str` | Report Layer | Contract schema version (`1.0.0`). |
| `generated_at` | `str` | Presentation | ISO 8601 UTC timestamp of report generation. |
| `overview` | `ReportOverviewSection` | Session / Target | Investigation ID, canonical target, session timestamps, execution status. |
| `assessment` | `ReportAssessmentSection` | TCE & CE | TCE verdict, risk/trust scores, composite confidence, abstention recommendation. |
| `risk_increasing_findings` | `List[KeyFindingItem]` | Ledger + TCE Polarity | Evidence items with polarity `risk_increasing`, presentation-ordered. |
| `risk_reducing_findings` | `List[KeyFindingItem]` | Ledger + TCE Polarity | Evidence items with polarity `risk_reducing`, presentation-ordered. |
| `neutral_observations` | `List[KeyFindingItem]` | Ledger + TCE Polarity | Baseline/neutral observations, presentation-ordered. |
| `aere_reasoning_status` | `str` | AERE | Execution status (`success`, `fallback`, `rejected`, `error`, `unavailable`). |
| `investigation_summary` | `str` | AERE / Fallback | Narrative forensic summary. |
| `detailed_findings` | `List[Dict]` | AERE | Structured primary findings with topics and interpretations. |
| `grounded_claims` | `List[GroundedClaimItem]` | AERE Validator | Claim-by-claim citation verification with valid and invalid IDs. |
| `unsubstantiated_claims_count` | `int` | AERE Validator | Count of ungrounded factual assertions. |
| `grounded_citation_ratio` | `float` | Confidence Engine | Ratio of validly cited claims $\rho_{\text{ground}} \in [0.0, 1.0]$. |
| `total_active_evidence_items` | `int` | Ledger | Total non-suppressed evidence items. |
| `provenance_gate_passed` | `bool` | Confidence Engine | Integrity boolean indicating all entries have valid source agents. |
| `evidence_lineage` | `List[EvidenceLineageItem]` | Ledger + TCE | Complete audit trail of active evidence with source metadata and contributions. |
| `contradictions` | `List[ContradictionReportItem]` | Ledger | Cross-agent contradictory findings. |
| `contradiction_score` | `float` | Confidence Engine | Penalty metric $\Phi_{\text{contra}} \in [0.0, 100.0]$. |
| `observed_dimensions` | `List[str]` | Confidence Engine | List of agent IDs providing active or clean telemetry. |
| `inactive_telemetry_gaps` | `Dict[str, str]` | Confidence Engine | Unobserved agents mapped to operational reasons. |
| `telemetry_coverage_score` | `float` | Confidence Engine | Percentage of operational agents reporting $\Phi_{\text{cov}} \in [0.0, 100.0]$. |
| `source_reliability_score` | `float` | Confidence Engine | Prior reliability score $\Phi_{\text{rel}} \in [0.0, 100.0]$. |
| `corroboration_score` | `float` | Confidence Engine | Multi-cluster corroboration $\Phi_{\text{cor}} \in [0.0, 100.0]$. |
| `concordant_cluster_count` | `int` | Confidence Engine | Number of active concordant clusters $N_{\text{clusters}} \in [0, 7]$. |
| `concordant_clusters` | `List[str]` | Confidence Engine | Names of active concordant clusters. |
| `methodological_disclaimer` | `str` | Policy | Epistemic disclaimer regarding heuristic nature of confidence. |
| `human_review_guidance` | `str` | Policy | Operational boundary mandating human analyst verification. |
| `prohibited_autonomous_actions` | `List[str]` | Policy | Explicit listing of disallowed automated actions. |

---

## 4. Evidence Grouping & Presentation-Only Ordering

### Polarity Grouping
Evidence is categorized into three disjoint presentation partitions using the authoritative declarative taxonomy from `services/tce_config.py` (`resolve_evidence_polarity`):
1. **Risk-Increasing Findings (`+1.0`)**: Indicators of deception, malware, phishing feeds, young domains, or behavioral harvesting.
2. **Risk-Reducing Findings (`-1.0`)**: Indicators of established tenure, valid EV/OV certificates, verified enterprise identity, or positive reputation.
3. **Neutral Observations (`0.0`)**: Baseline telemetry (standard ports, language headers, normal content length) or inactive/error telemetry.

### Presentation-Only Deterministic Ordering
Within each partition, items are ordered deterministically for display:
$$\text{Sort Key} = \left( -\text{SEVERITY\_WEIGHTS}[\text{severity}], -\text{evidence\_strength}, \text{evidence\_id} \right)$$

> [!NOTE]
> This ordering is strictly for visual presentation and human readability. It does not alter evidence weights, recalculate risk scores, or impact TCE / Confidence Engine mathematics.

---

## 5. AERE Grounding & Contradiction Presentation

### Grounding Verification Preservation
- Valid citations and invalid citations are explicitly partitioned in `GroundedClaimItem`.
- Nonexistent or hallucinated Evidence IDs (e.g., `E99-99`) are **never silently stripped**; they are preserved in `invalid_evidence_ids` and diagnostic issues.
- If AERE fails or is unavailable, a deterministic fallback summary is generated without throwing errors.

### Contradiction Preservation
- The report extracts contradiction relationships directly from `ledger.relationships` where `relationship_type == "contradiction"`.
- Each record links the source and target Evidence IDs, source and target agent names, finding texts, and descriptive context.
- Contradictions are displayed prominently to alert the human investigator to conflicting telemetry.

---

## 6. Telemetry & Missing Data Neutrality

The report explicitly distinguishes three forensic states for all 18 agent dimensions:
1. **Active Observation**: Agent executed and detected anomalous or verifying evidence.
2. **Clean-Negative Observation**: Agent executed successfully and confirmed the absence of suspicious indicators.
3. **Unobserved / Telemetry Gap**: Agent was skipped, restricted, unavailable, or errored.

> [!IMPORTANT]
> Unobserved telemetry is reported under `inactive_telemetry_gaps` and is **never converted into positive or negative evidence**.

---

## 7. Security, Human Review & Prohibited Actions

### Security Assumptions
- All finding descriptions, raw values, and metadata strings are treated as **untrusted data**.
- The report generator does not evaluate (`eval`) or execute any code embedded within evidence strings.
- Presentation escaping (HTML entity encoding) belongs in the UI rendering layer.
- The report layer does not claim prompt-injection immunity; instead, it enforces structural data isolation.

### Prohibited Autonomous Actions
The report explicitly prohibits the following autonomous operations:
1. Automated domain or IP blocking
2. Automated account suspension or credential revocation
3. Automated infrastructure modification or network routing alterations
4. Automated legal takedown requests or external abuse dispatch

---

## 8. Calibration & Epistemic Disclaimer

All confidence indices ($C_{\text{ev}}$, $C_{\text{interp}}$, $C_{\text{overall}}$) emitted by the Confidence Engine and presented in this report represent **uncalibrated deterministic heuristics** (`UNCALIBRATED_DETERMINISTIC_HEURISTIC`). They are engineered diagnostic indicators designed to highlight data sparsity and reasoning conflicts, not calibrated Bayesian probabilities.

---

## 9. Hypothetical UI Example

> [!NOTE]
> **HYPOTHETICAL UI EXAMPLE — NOT HARDCODED PROJECT DATA**
> The following represents an illustrative execution trace for documentation purposes only.

```json
{
  "report_version": "1.0.0",
  "generated_at": "2026-09-15T10:30:00.000000+00:00",
  "overview": {
    "investigation_id": "hypothetical-uuid-001",
    "target": {
      "target_url": "https://hypothetical-phish-domain.fake",
      "input_type": "url",
      "original_input": "https://hypothetical-phish-domain.fake"
    },
    "investigation_timestamp": "2026-09-15T10:29:45.000000+00:00",
    "report_generated_at": "2026-09-15T10:30:00.000000+00:00",
    "execution_status": "completed"
  },
  "assessment": {
    "tce_verdict": "high_risk",
    "tce_risk_score": 72.5,
    "tce_trust_score": 27.5,
    "composite_confidence": 76.4,
    "evidence_confidence": 84.17,
    "interpretation_confidence": 58.33,
    "abstention_flag": false,
    "abstention_reason": "AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY",
    "confidence_calibration_status": "UNCALIBRATED_DETERMINISTIC_HEURISTIC"
  },
  "risk_increasing_findings": [
    {
      "evidence_id": "E6-01",
      "agent_id": 6,
      "agent_name": "Reputation & Threat Intelligence",
      "finding": "Domain listed on multiple active phishing intelligence feeds",
      "category": "phishing_feed_match",
      "severity": "critical",
      "evidence_type": "threat_intelligence",
      "evidence_strength": 0.95,
      "polarity": "risk_increasing",
      "tce_contribution": 0.855
    }
  ],
  "risk_reducing_findings": [],
  "neutral_observations": [
    {
      "evidence_id": "E2-01",
      "agent_id": 2,
      "agent_name": "DNS & Infrastructure",
      "finding": "Standard A record resolution",
      "category": "clean_dns_resolution",
      "severity": "info",
      "evidence_type": "deterministic",
      "evidence_strength": 1.0,
      "polarity": "neutral",
      "tce_contribution": 0.0
    }
  ]
}
```

---

## 10. Frontend Integration & Transport (Step 5C)

The Step 5C frontend implementation provides a complete web-based forensic interface without adding external dependencies or duplicating business logic:

### 1. API Transport Endpoint (`/api/report`)
- Exposes a dedicated `POST /api/report` Flask endpoint.
- Accepts `{ "url": target }` or `{ "session": session_data }`.
- Returns the authoritative `InvestigatorReportPayload` serialized directly via `to_dict()`.

### 2. Frontend Architecture
- **Single Source of Truth**: The frontend consumes `InvestigatorReportPayload` directly and never recalculates scores or re-sorts evidence.
- **XSS & Injection Protection**: Dynamic strings are strictly escaped using `escapeHtml` before DOM insertion; zero `eval()` calls.
- **Evidence Lineage Navigation**: Citations in AERE reasoning and Key Findings link directly to corresponding entries in the Evidence Lineage table.
- **Export & Print**:
  - **JSON Export**: Downloads the unmodified backend `InvestigatorReportPayload` via browser `Blob`.
  - **Print / PDF**: Media query `@media print` formats a clean, paginated dossier while hiding navigation buttons and UI chrome.
