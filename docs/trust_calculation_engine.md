# Trust Calculation Engine (TCE)
## Dissertation & Engineering Specification

---

## 1. Purpose

The **Trust Calculation Engine (TCE)** is the deterministic mathematical scoring engine of the Multi-Agent Digital Forensics System. Its core responsibility is to evaluate normalized, relational forensic evidence collected in the **Investigation Evidence Ledger** and produce:
* A calibrated **Risk Score** ($[0.0, 100.0]$)
* A complementary **Trust Score** ($[0.0, 100.0]$)
* A canonical, explainable **Verdict** (`benign`, `low_risk`, `suspicious`, `high_risk`, `malicious`, `unknown`)
* A fully traceable **Evidence Contribution Lineage** mapping each numerical contribution back to specific `evidence_id` instances.

The TCE is strictly deterministic, rule-based, and decoupled from LLM natural language generation.

---

## 2. Inputs

The TCE operates exclusively as a downstream consumer of the **Investigation Evidence Ledger**. It does not perform active network requests, scrape web pages, or invoke agents.

### Ledger Data Ingested:
1. **Entries:** Normalized evidence records containing `evidence_id`, `agent_id`, `evidence_type`, `severity`, `evidence_strength`, `data`, `category`, and `status`.
2. **Relationships:** Relational links between evidence records (`supporting`, `contradiction`, `duplicate`, `derived_from`, `related_dimension`, `same_target`).
3. **Canonical Target:** Target entity metadata (`registrable_domain`, `hostname`, `normalized_url`).
4. **Investigation Summary:** Sensor execution status and telemetry coverage.

---

## 3. Mathematical Formulation

The TCE executes a single-pass, 9-step mathematical pipeline:

```
Evidence Ledger Entries & Relational Graph
                 ↓
1. Base Item Contribution:
   C_{i, base} = W_{sev}(s_i) · S(e_i) · R_{type}(t_i)
                 ↓
2. Duplicate & Derived Suppression:
   M_{dup} = 0.0 (secondary), M_{derived} = 0.0 (semantic mirrors)
                 ↓
3. Collinearity Discounting:
   β = 0.70 applied to secondary related_dimension items
                 ↓
4. Cluster-Level Corroboration:
   C_{cluster} = C_{(1)} + α · Σ_{j=2}^M [ C_{(j)} / 2^{j-2} ]  (α = 0.25)
                 ↓
5. Inconsistency & Contradiction Indexing:
   Inconsistency Index = min(100.0, N_{contra} · 25.0)
   Δ_{contra} = min(10.0, N_{contra} · 5.0)
                 ↓
6. Net Aggregation:
   R^+ = Σ C_{cluster, risk_inc} + (Δ_{contra} / 100.0)
   R^- = Σ C_{cluster, risk_red}
   R_{net} = max(0.0, R^+ - γ · R^-)  (γ = 0.50)
                 ↓
7. Bounded Exponential Saturation:
   Risk Score = 100 · (1 - exp(-R_{net} / κ))  (κ = 1.20)
                 ↓
8. Complementary Trust Score:
   Trust Score = 100.0 - Risk Score
                 ↓
9. Verdict & Explainability Lineage Assembly
```

---

## 4. Severity Weights ($W_{\text{sev}}$)

Severity represents the potential forensic impact of an observation if true:

| Severity | Normalized Weight ($W_{\text{sev}}$) | Forensic Interpretation |
| :--- | :---: | :--- |
| `info` | $0.00$ | Baseline or neutral contextual observation. |
| `low` | $0.15$ | Minor anomaly or non-standard technical indicator. |
| `medium` | $0.45$ | Notable suspicious signal requiring scrutiny. |
| `high` | $0.75$ | Severe forensic indicator or strong deceptive pattern. |
| `critical` | $1.00$ | Confirmed compromise, active malware payload, or blacklist hit. |

*Status: Initial heuristic prototype parameters subject to benchmark calibration.*

---

## 5. Evidence Type Reliability ($R_{\text{type}}$)

Reflects the intrinsic measurement fidelity and error profile of the methodology:

| Evidence Type | Reliability Factor ($R_{\text{type}}$) | Default Strength if `None` ($S_{\text{default}}$) |
| :--- | :---: | :---: |
| `deterministic` | $1.00$ | $1.00$ |
| `threat_intelligence` | $0.90$ | $0.70$ |
| `external_source` | $0.85$ | $0.60$ |
| `historical` | $0.85$ | $0.60$ |
| `inference` | $0.70$ | $0.50$ |
| `subjective` | $0.50$ | $0.40$ |

*Status: Initial heuristic prototype parameters.*

---

## 6. Declarative Polarity Taxonomy

Severity and polarity are decoupled. Polarity is resolved through an explicit categorical taxonomy:
* `risk_increasing` ($P = +1.0$): Adds to positive risk evidence ($R^+$).
* `risk_reducing` ($P = -1.0$): Adds to mitigating credibility evidence ($R^-$).
* `neutral` ($P = 0.0$): Contextual telemetry that does not alter risk or trust.

**Safety Invariant:** Any unmapped or ambiguous evidence category safely defaults to `neutral` ($0.0$ contribution), preventing arbitrary scoring hallucinations.

---

## 7. Duplicate Suppression ($M_{\text{dup}}$)

* For items linked via `relationship_type = "duplicate"`:
  * Primary instance: $M_{\text{dup}} = 1.00$.
  * Secondary instances: $M_{\text{dup}} = 0.00$.
* Duplicate records are retained in the ledger and explainability output for provenance auditability, but suppressed from mathematical scoring.

---

## 8. Derived Evidence Handling ($M_{\text{derived}}$)

* **Semantic Mirrors ($M_{\text{derived}} = 0.00$):** When an agent simply exposes an artifact extracted upstream (e.g., QR decoded URL string). Suppressed.
* **New Downstream Analyses ($M_{\text{derived}} = 1.00$):** When a downstream agent performs a distinct analytical test on the derived artifact (e.g., lexical Punycode detection on the QR-extracted URL). Fully scored.

---

## 9. Related-Dimension Collinearity Discount ($\beta$)

* When two items share `related_dimension` (e.g., form fields in A4 and urgency language in A11):
* The secondary item receives collinearity factor $\beta = 0.70$ to prevent over-counting collinear symptoms of the same page feature.

---

## 10. Cluster-Level Corroboration ($\alpha$)

Independent multi-agent corroboration is evaluated at the cluster level with strict diminishing returns:

$$C_{\text{cluster}} = C_{(1)} + \alpha \sum_{j=2}^M \frac{C_{(j)}}{2^{j-2}} \quad (\alpha = 0.25)$$

* **Primary Item ($C_{(1)}$):** Full adjusted contribution.
* **Second Independent Item ($C_{(2)}$):** Adds $\alpha \cdot C_{(2)} = 0.25 \cdot C_{(2)}$.
* **Third Independent Item ($C_{(3)}$):** Adds $\frac{\alpha}{2} \cdot C_{(3)} = 0.125 \cdot C_{(3)}$.
* **Double-Counting Prevention:** Calculated once per connected supporting cluster, eliminating symmetric edge inflation.

---

## 11. Contradictions & Inconsistency

* Contradictions represent factual discrepancies (e.g., declared UK company with hosting server in India), which indicate uncertainty rather than definitive malice.
* **Outputs:**
  * **Inconsistency Index:** $\Omega_{\text{inconsistency}} = \min(100.0, N_{\text{contra}} \cdot 25.0)$.
  * **Bounded Contradiction Penalty:** $\Delta_{\text{contra}} = \min(10.0, N_{\text{contra}} \cdot 5.0) \text{ points}$.

---

## 12. Missing Telemetry & Coverage

* **Neutrality:** Missing, unavailable, restricted, skipped, or errored sensor telemetry contributes exactly $0.00$ to risk and trust.
* **Telemetry Coverage:** $T_{\text{cov}} = \frac{N_{\text{successful\_agents}}}{18.0} \in [0.0, 1.0]$.
* **Critical Threat Override:** If $T_{\text{cov}} < 0.20$ but a critical threat is confirmed (e.g., active Trojan C2), the verdict is `malicious` with `low_telemetry_coverage = true`.

---

## 13. Risk Aggregation ($R_{\text{net}}$)

$$R^+ = \sum_{k \in \text{RiskClusters}} C_{\text{cluster}, k} + \frac{\Delta_{\text{contra}}}{100.0}$$
$$R^- = \sum_{m \in \text{TrustClusters}} C_{\text{cluster}, m}$$
$$R_{\text{net}} = \max(0.0, R^+ - \gamma \cdot R^-) \quad (\gamma = 0.50)$$

---

## 14. Bounded Exponential Saturation ($\kappa$)

$$\text{Risk Score} = 100.0 \cdot \left(1.0 - \exp\left(-\frac{R_{\text{net}}}{\kappa}\right)\right) \quad (\kappa = 1.20)$$

* Clamped strictly to $[0.0, 100.0]$.
* Guarantees smooth non-linear saturation where moderate findings yield moderate risk ($R_{\text{net}} = 0.45 \rightarrow 31.3$), single critical threats yield substantial risk ($R_{\text{net}} = 1.0 \rightarrow 56.5$), and multi-vector threats reach the malicious ceiling ($R_{\text{net}} \ge 1.93 \rightarrow \ge 80.0$).

---

## 15. Complementary Trust Score

$$\text{Trust Score} = \max(0.0, \min(100.0, 100.0 - \text{Risk Score}))$$

* **Academic Classification:** The Trust Score is formally defined as the **complementary user-facing projection of the computed risk metric**, providing an intuitive inverse scale while ensuring 100% mathematical consistency.

---

## 16. Verdict Mapping

| Verdict | Risk Score Range | Trust Score Range | Operational Meaning |
| :--- | :---: | :---: | :--- |
| `malicious` | $\ge 80.0$ | $\le 20.0$ | Multi-vector confirmed active security threat. |
| `high_risk` | $60.0 - 79.9$ | $20.1 - 40.0$ | Strongly corroborated severe anomalies. |
| `suspicious` | $35.0 - 59.9$ | $40.1 - 65.0$ | Notable structural anomalies requiring analyst review. |
| `low_risk` | $15.0 - 34.9$ | $65.1 - 85.0$ | Minor non-standard indicators; predominantly standard benign signals. |
| `benign` | $< 15.0$ | $> 85.0$ | Verified legitimate infrastructure, active tenure, standard posture. |
| `unknown` | N/A | N/A | Telemetry coverage $T_{\text{cov}} < 0.20$ with no critical threats detected. |

---

## 17. Explainability & Lineage

The TCE generates a complete auditable envelope:
* `risk_score`, `trust_score`, `verdict`, `telemetry_coverage`, `inconsistency_index`
* `aggregation_metrics`: $R^+, R^-, R_{\text{net}}$
* `scoring_parameters`: exact constants ($\kappa, \gamma, \alpha, \beta, \Delta_{\text{contra}}$) used for that calculation
* `evidence_contributions`: per-item audit records containing `evidence_id`, `base_contribution`, `suppression_multiplier`, `collinearity_discount`, and `final_item_contribution`
* `contradiction_notes`: list of participating evidence IDs in factual discrepancies.

---

## 18. Research Parameter Classification

| Parameter | Symbol | Default Value | Classification |
| :--- | :---: | :---: | :---: |
| **Severity Weights** | $W_{\text{sev}}$ | `[0.0, 0.15, 0.45, 0.75, 1.0]` | **Initial Heuristic** |
| **Type Reliability** | $R_{\text{type}}$ | `[1.0, 0.9, 0.85, 0.85, 0.7, 0.5]` | **Initial Heuristic** |
| **Missing Strength Defaults** | $S_{\text{default}}$ | `[1.0, 0.7, 0.6, 0.6, 0.5, 0.4]` | **Initial Heuristic** |
| **Polarity Taxonomy** | $\text{Dict}$ | Declarative mapping table | **Structural** |
| **Duplicate Multiplier** | $M_{\text{dup}}$ | `0.00` (secondary) | **Structural** |
| **Derived Semantic Factor** | $M_{\text{derived}}$ | `0.00` / `1.00` | **Structural** |
| **Collinearity Factor** | $\beta$ | `0.70` | **Initial Heuristic** |
| **Corroboration Factor** | $\alpha$ | `0.25` | **Empirically Calibratable** |
| **Contradiction Penalty** | $\Delta_{\text{contra}}$ | `+5.0` (max 10.0) | **Initial Heuristic** |
| **Saturation Constant** | $\kappa$ | `1.20` | **Empirically Calibratable** |
| **Mitigation Factor** | $\gamma$ | `0.50` | **Empirically Calibratable** |
| **Verdict Cutoffs** | $\text{Cutoffs}$ | `[15.0, 35.0, 60.0, 80.0]` | **Initial Heuristic** |
| **Minimum Coverage** | $T_{\text{min}}$ | `0.20` | **Structural** |

---

## 19. Research Calibration & Evaluation Plan

The initial numerical parameters represent declared heuristic baseline choices. Future research calibration will:
1. Benchmark against labeled datasets of benign, suspicious, phishing, and malware domains.
2. Optimize $\kappa, \alpha, \gamma, \beta$ via grid search and cross-validation to maximize ROC-AUC / PR-AUC and minimize Expected Calibration Error (ECE).
3. Conduct ablation studies to isolate the marginal contribution of corroboration, duplicate suppression, and contradiction modeling.

---

## 20. Limitations & Scientific Caveats

1. **Not a Bayesian Probability:** The Risk Score and Trust Score are deterministic normalized weighted indices, not statistical Bayesian posterior probabilities.
2. **Prototype Parameters:** Initial weights are heuristic starting baselines requiring empirical validation.
3. **Absence of Proof $\neq$ Proof of Absence:** Missing telemetry is strictly neutral ($0.0$) and does not substitute for positive evidence of legitimacy.
