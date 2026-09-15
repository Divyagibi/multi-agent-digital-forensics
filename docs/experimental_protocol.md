# Step 6D-1 — Experimental Research Protocol & Evaluation Specification

**Milestone:** Step 6D-1  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Status:** Frozen Experimental Protocol (Pre-Evaluation Research Specification)  
**Implementation Boundary:** Protocol Definition & Integrity Locking Only — No Benchmark Data Collection, No System Execution, No Post-Hoc Threshold Tuning.

---

## 1. Executive Summary & Protocol Locking Mandate

This document defines the formal, pre-registered **Experimental Research Protocol** for the empirical evaluation (Step 6D) of the Multi-Agent Digital Forensics and Evidence Analysis System.

### Pre-Registration & Scientific Locking Principles
1. **Hypothesis Neutrality:** All hypotheses ($H_1$ through $H_6$) are formulated in direction-neutral terms. Positive, neutral, mixed, and negative outcomes are all recognized as scientifically valid findings.
2. **Prior Freezing:** The experimental design, candidate baseline models ($A_0$–$A_4$), ablation conditions ($M_0$–$M_6$), evaluation metrics, statistical tests, and partitioning boundaries are frozen prior to benchmark dataset collection and prior to inspecting any experimental model outputs.
3. **No Post-Hoc Tuning:** Heuristic parameters (TCE weights, corroboration $\alpha$, contradiction damping, Confidence Engine prior, and workflow review threshold $C_{ev} \ge 35$) are evaluated as frozen prototype heuristics. No parameters may be tuned against the final test or prospective holdout partitions.
4. **Ground-Truth Independence:** Benchmark ground truth is strictly derived from authoritative external references and independent multi-analyst adjudication. Under no circumstances may system verdicts, TCE risk scores, AERE reasoning chains, or Confidence Engine metrics contribute to ground-truth assignment.
5. **Passive & Safe Research Execution:** All evaluations are conducted in a passive, offline research boundary. Zero live network polling, zero dynamic malware detonation, and zero client-side exploit executions are performed during benchmark execution.

---

## 2. Research Questions (RQ1–RQ6)

The experimental investigation addresses six core research questions:

* **RQ1 (Comparative Performance):** How does the multi-agent digital forensics pipeline ($M_0$) compare against standard single-dimension, heuristic, and monolithic baselines ($A_0$–$A_4$) in identifying malicious web and QR artifacts across standard classification and ranking metrics?
* **RQ2 (Temporal Generalization & TI Decay):** To what extent does detection performance persist across temporal holdout partitions, and how does performance vary when evaluated on targets with prior documented Threat Intelligence (TI) exposure versus targets with no recorded positive TI observations?
* **RQ3 (Incremental Diagnostic Contribution — IDC):** What is the ablation-based incremental diagnostic contribution of individual agent families (DNS/Infrastructure, TLS, DOM/Content, TI/Reputation, Dynamic Scripting, Brand/Visual, QR Forensics) to the composite forensic assessment?
* **RQ4 (Cross-Modal Robustness & Quishing):** How robust is the multi-agent architecture when analyzing QR artifacts across modalities (Direct URL vs. QR Image vs. QR Payload), and does multi-modal cross-correlation mitigate quishing-specific evasion techniques?
* **RQ5 (Confidence Calibration & Abstention):** Does the post-hoc Confidence Engine ($C_{ev}$) provide effective selective classification, identifying low-confidence/uncertain assessments for human investigator review without degrading conditional accuracy on retained decisions?
* **RQ6 (Evidence Grounding & Reasoning Fidelity):** How accurately does the AERE Grounding Validator eliminate hallucinated claims, unsupported entity assertions, and logical contradictions in the Final Investigator Report?

---

## 3. Direction-Neutral Hypotheses (H1–H6)

All hypotheses are explicitly formulated to support bidirectional empirical outcomes without assuming positive system superiority:

* **$H_1$ (Baseline Comparison):**
  * *Null ($H_{1,0}$):* The multi-agent pipeline ($M_0$) exhibits no statistically significant difference in balanced accuracy, F1-score, or PR-AUC compared to heuristic, reputation-only, unweighted voting, additive, or monolithic LLM baselines ($A_0$–$A_4$).
  * *Alternative ($H_{1,A}$):* The multi-agent pipeline ($M_0$) exhibits a statistically significant difference (positive or negative) in balanced accuracy, F1-score, or PR-AUC compared to baselines ($A_0$–$A_4$).
* **$H_2$ (Temporal Holdout & TI Exposure Generalization):**
  * *Null ($H_{2,0}$):* Evaluation performance on the prospective temporal holdout partition and on targets with no recorded positive TI exposure does not differ significantly from performance on development partitions or targets with direct positive TI history.
  * *Alternative ($H_{2,A}$):* Evaluation performance varies significantly across temporal holdout splits and TI exposure strata, reflecting temporal decay or differential reliance on external reputation metadata.
* **$H_3$ (Incremental Diagnostic Contribution of Forensic Dimensions):**
  * *Null ($H_{3,0}$):* Ablating individual agent forensic dimensions ($M_1$–$M_4$) produces no statistically significant change in composite risk score distribution, balanced accuracy, or detection sensitivity.
  * *Alternative ($H_{3,A}$):* Individual forensic agent dimensions provide measurable, non-zero incremental diagnostic contributions ($\Delta M = \text{Score}_{\text{Full}} - \text{Score}_{\text{Ablated}}$) across distinct threat categories.
* **$H_4$ (Quishing & Modality Shift Robustness):**
  * *Null ($H_{4,0}$):* Forensic risk scoring and classification metrics do not differ significantly between direct URL artifacts and their corresponding QR-encoded image/payload counterparts.
  * *Alternative ($H_{4,A}$):* Modality shifts (QR image encoding, embedded redirection, visual distortion) introduce significant performance variations between direct URL and QR investigation targets.
* **$H_5$ (Selective Classification & Confidence Engine Abstention):**
  * *Null ($H_{5,0}$):* Filtering investigations using the qualitative confidence threshold ($C_{ev} \ge 35$) yields no significant difference in conditional classification accuracy compared to unconstrained decision-making.
  * *Alternative ($H_{5,A}$):* Applying the prototype workflow review threshold ($C_{ev} \ge 35$) yields a statistically significant difference in accuracy and false-positive rate on retained cases while appropriately routing ambiguous cases to human review.
* **$H_6$ (AERE Evidence Grounding Fidelity):**
  * *Null ($H_{6,0}$):* The AERE Grounding Validator ($M_0$) does not significantly alter the rate of unsupported forensic claims, ungrounded evidence IDs, or contradictory factual statements in the Final Investigator Report compared to unvalidated reasoning ($M_6$).
  * *Alternative ($H_{6,A}$):* The AERE Grounding Validator produces a statistically significant reduction in ungrounded evidence assertions, hallucinated identifiers, and internal contradictions.

---

## 4. Experimental Variables

### 4.1 Independent Variables
1. **System Architecture / Condition:**
   * Full Multi-Agent System ($M_0$)
   * Baseline Configurations ($A_0, A_1, A_2, A_3, A_4$)
   * Component Ablations ($M_1, M_2, M_3, M_4, M_5, M_6$)
2. **Input Modality:**
   * Direct Web URL (`DIRECT_URL`)
   * QR Barcode Image (`QR_IMAGE`)
   * Decoded QR Payload (`QR_PAYLOAD`)
3. **Temporal Partition:**
   * Development & Calibration (`DEVELOPMENT_CALIBRATION` — 30%)
   * Validation (`VALIDATION` — 20%)
   * Final Test (`FINAL_TEST` — 30%)
   * Prospective Temporal Holdout (`PROSPECTIVE_HOLDOUT` — 20%)
4. **Threat Intelligence Exposure Stratum:**
   * Direct Positive Observation (`DIRECT`)
   * Partial / Related Infrastructure Observation (`PARTIAL`)
   * No Recorded Positive Observation in Monitored Sources (`NONE`)
   * Source Unavailable / Unmonitored (`UNKNOWN_UNAVAILABLE`)
5. **Primary Ground-Truth Class & Secondary Threat Category:**
   * Primary: `BENIGN`, `MALICIOUS`, `AMBIGUOUS`
   * Secondary Taxonomy: `CREDENTIAL_PHISHING`, `BRAND_IMPERSONATION`, `SCAM_FRAUD`, `MALWARE_DISTRIBUTION`, `DRIVE_BY_EXPLOIT`, `TECH_SUPPORT_FRAUD`, `QUISHING`, `OTHER`

### 4.2 Dependent Variables
1. **Classification Metrics:** Balanced Accuracy, Precision, Recall / True Positive Rate (TPR), False Positive Rate (FPR), False Negative Rate (FNR), $F_1$-Score, $F_2$-Score (prioritizing threat recall).
2. **Ranking & Scoring Metrics:**
   * Area Under ROC Curve (ROC-AUC) on continuous risk score $R \in [0, 100]$.
   * Area Under Precision-Recall Curve (PR-AUC) under representative class prevalence.
3. **$5 \times 2$ Risk Band Contingency Analysis:** Distribution of binary ground truth across the five frozen TCE risk bands:
   $$\text{Benign } [0, 15), \quad \text{Low Risk } [15, 35), \quad \text{Suspicious } [35, 60), \quad \text{High Risk } [60, 80), \quad \text{Malicious } [80, 100]$$
4. **Incremental Diagnostic Contribution (IDC):** Score delta $\Delta \text{Metric} = \text{Metric}(M_0) - \text{Metric}(M_{\text{ablated}})$.
5. **Confidence & Abstention Metrics:** Abstention / Review Rate ($\% \text{ cases with } C_{ev} < 35$), Conditional Balanced Accuracy on retained cases ($C_{ev} \ge 35$), Risk-Coverage Curves.
6. **Reasoning & Grounding Metrics:** Unsupported Claim Rate ($\%$ claims without valid `evidence_ids`), Hallucination Rate ($\%$ non-existent IDs), Contradiction Resolution Rate.

---

## 5. Baselines ($A_0$–$A_4$) & Ablation Conditions ($M_0$–$M_6$)

### 5.1 Baseline Definitions ($A_0$–$A_4$)
To establish rigorous comparative benchmarks, the system is evaluated against five well-defined baseline models:

* **$A_0$ (Static Lexical / Single-Heuristic Baseline):**
  * Evaluates URL string structure, entropy, length, suspicious keywords, and basic static indicators alone.
  * Emits risk scores derived strictly from static lexical pattern heuristics without multi-agent domain, network, or dynamic execution.
* **$A_1$ (Standalone Threat Intelligence Feed Baseline):**
  * Aggregates detection counts strictly from the seven external threat intelligence feeds (VirusTotal, Google Safe Browsing, PhishTank, OpenPhish, URLhaus, AbuseIPDB, Spamhaus).
  * Computes risk strictly as normalized feed positive ratio: $R_{A1} = 100 \times (\text{positive\_feeds} / \text{available\_feeds})$.
* **$A_2$ (Unweighted Majority Voting Baseline):**
  * Collects binary flags from agents A1–A18 but assigns equal weight ($w_i = 1.0$) to every evidence item.
  * Bypasses TCE evidence reliability tiers, confidence weighting, and sublinear saturation.
* **$A_3$ (Linear Additive Risk Baseline):**
  * Computes a linear sum of risk evidence items: $R_{A3} = \min(100, \sum w_i s_i)$.
  * Bypasses non-linear saturation parameter $\kappa = 1.2$, related-dimension synergy $\beta = 0.70$, and contradiction damping.
* **$A_4$ (Standalone Monolithic LLM Baseline):**
  * Direct zero-shot prompt providing raw URL, HTTP headers, and visible text directly to a frontier LLM without agent decomposition, structured evidence schemas, or grounding validation.

### 5.2 Model & Ablation Conditions ($M_0$–$M_6$)
All ablation experiments are defined prior to benchmark execution:

* **$M_0$ (Full Proposed System):**
  * 18 Forensic Agents $\rightarrow$ Evidence Ledger $\rightarrow$ TCE ($w_i, \kappa=1.2, \alpha=0.25, \beta=0.70$) $\rightarrow$ AERE Reasoning & Grounding Validator $\rightarrow$ Confidence Engine ($C_{ev}$).
* **$M_1$ (A6 / Threat Intelligence Ablation):**
  * Agent A6 is disabled and emits zero evidence.
  * **Strict Invariant:** Removed TI evidence is recorded as *unavailable/ablated*. Under no circumstances is it replaced with synthetic "clean", "benign", or zero-risk evidence.
* **$M_2$ (A18 / QR Forensics Ablation):**
  * Agent A18 is disabled. QR artifacts are analyzed strictly by decoding payload text without visual anomaly checks, boundary inspection, or embedded code analysis.
* **$M_3$ (A8 / Dynamic Script Analysis Ablation):**
  * Agent A8 is disabled. System operates on static DOM and network headers without behavioral script execution telemetry.
* **$M_4$ (A9 + A10 / Brand & Visual Analysis Ablation):**
  * Agents A9 (Brand Verification) and A10 (Visual/UI Analysis) are disabled, evaluating performance in the absence of logo matching, screenshot comparison, and visual credential-harvesting indicators.
* **$M_5$ (TCE Mathematical Synergies Ablation):**
  * TCE operates with corroboration $\alpha = 0$, related-dimension synergy $\beta = 0$, and contradiction Inconsistency Index $= 0$.
* **$M_6$ (AERE Grounding Validator Ablation):**
  * AERE LLM reasoning operates without post-generation claim-evidence binding, grounding constraint verification, or hallucination filtering.

---

## 6. Incremental Diagnostic Contribution (IDC) Formulation

### Methodological Distinction: Diagnostic Contribution vs. Causal Attribution
* **Diagnostic Definition:** The Incremental Diagnostic Contribution ($\text{IDC}$) measures the empirical change in composite system risk assessment when a specific forensic evidence dimension is ablated:
  $$\text{IDC}_k = \text{Metric}(M_0) - \text{Metric}(M_{\text{ablated-}k})$$
* **Non-Causal Mandate:** $\text{IDC}$ represents observational forensic signal contribution within the pipeline. It is **NOT** a causal treatment effect estimate. Causal language (such as "Agent A6 caused the detection") is strictly prohibited in academic reporting.

---

## 7. Dataset Composition, Partitioning, & Leakage Isolation

### 7.1 Dataset Composition & Target Size
* **Planning Target:** Approximately $N \approx 1200$ retained, validated benchmark records.
* **Dynamic Retained Reporting:** $N \approx 1200$ is a design guideline. The exact retained count ($N_{\text{final}}$) will be reported empirically after liveness filtering, deduplication, and ground-truth adjudication.
* **Natural Prevalence Policy:** The ratio of benign to malicious records is treated as an **open empirical research decision** reflecting real-world candidate harvesting yields. Artificial class balancing via synthetic filler records is prohibited.

### 7.2 Partitioning Scheme & Isolation Invariants
The dataset is partitioned into four strictly segregated subsets:

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           BENCHMARK DATASET (N ≈ 1200)                          │
├───────────────────────────────┬─────────────────┬───────────────┬───────────────┤
│    DEVELOPMENT / CALIBRATION  │   VALIDATION    │  FINAL TEST   │  PROSPECTIVE  │
│             (30%)             │      (20%)      │     (30%)     │ HOLDOUT (20%) │
└───────────────────────────────┴─────────────────┴───────────────┴───────────────┘
```

1. **Development / Calibration Split (30%):**
   * Reserved for heuristic analysis, prompt refinement, and parameter exploration.
   * **Strict Isolation:** Parameters tuned on this split are permanently frozen before evaluating subsequent splits.
2. **Validation Split (20%):**
   * Intermediate model evaluation, threshold verification, and sanity checks.
3. **Final Test Split (30%):**
   * **Protected Evaluation Split:** Touched exactly once during final benchmarking. Parameter tuning, prompt modification, or threshold adjustments on this split are strictly prohibited.
4. **Prospective Temporal Holdout Split (20%):**
   * **Protected Forward-in-Time Split:** Sourced strictly from candidates observed chronologically later than the development and final test splits. Evaluates decay in detection performance over time.

### 7.3 Leakage Prevention & Auditor Enforcements
Step 6C-7 [`integrity_auditor.py`](file:///c:/Users/user/Desktop/digital/tools/benchmark/integrity_auditor.py) rules are enforced across all splits:
* **Target Identity (`TGT-`):** Must NEVER appear across different partitions (`CROSS_PARTITION_TARGET_LEAKAGE` $\rightarrow$ `CRITICAL`).
* **Grouping Identity (`GRP-`):** eTLD+1 domain and IP subnet clusters across partitions are audited as correlation risks (`CROSS_PARTITION_GROUP_OVERLAP` $\rightarrow$ `WARNING`).
* **QR / Direct Pairing:** QR records and direct URL records pointing to the same canonical target must be co-located in the same partition (`QR_DIRECT_CROSS_PARTITION_LEAKAGE` $\rightarrow$ `CRITICAL`).
* **Artifact Duplication:** Exact raw duplicates are flagged (`EXACT_ARTIFACT_DUPLICATE` $\rightarrow$ `WARNING`) without silent record deletion.

---

## 8. Ground-Truth Verification & Ambiguity Pool

### 8.1 Independent Ground-Truth Protocol
* **External Reference Rule:** Ground truth is established using external authoritative registries (e.g. official WHOIS/RDAP, cryptographic certificate transparency logs, corporate domain registrations, verified takedown feeds, independent malware repositories).
* **Zero System Contamination:** System outputs (TCE scores, AERE answers, CE confidence) **CANNOT** contribute to ground truth.
* **Qualitative Confidence (`HIGH`, `MEDIUM`, `LOW`):** Represents discrete expert adjudication certainty. Continuous probabilities (e.g. 0.95) are rejected by schema validators.

### 8.2 Ambiguity Pool Handling
* Records with conflicting evidence across independent sources are assigned `PrimaryOutcome.AMBIGUOUS` with status `VerificationStatus.DISPUTED` or `UNVERIFIABLE`.
* **No Silent Reclassification:** Ambiguous records remain in an explicit **Ambiguity Pool** and are evaluated separately. They are never arbitrarily coerced into `BENIGN` or `MALICIOUS`.

---

## 9. Threat Intelligence & Temporal Exposure Stratification

### 9.1 Monitored Feeds & Semantics
The 7 controlled feeds are:
1. `VirusTotal`
2. `GoogleSafeBrowsing`
3. `PhishTank`
4. `OpenPhish`
5. `URLhaus`
6. `AbuseIPDB`
7. `Spamhaus`

### 9.2 Provenance Semantics
* `NONE` (`negative_observation`): Indicates no positive threat detection was returned by the monitored feed at the observation timestamp.
* **Non-Equivalence Rule:**
  $$\text{NONE} \not\equiv \text{Benign}, \qquad \text{NONE} \not\equiv \text{Safe}, \qquad \text{NONE} \not\equiv \text{Clean}, \qquad \text{NONE} \not\equiv \text{Zero-Day}$$
* **No Universal Novelty Claim:** Lack of detection is documented factually as *no recorded positive observation in the monitored feeds prior to evaluation time*. Universal claims of "zero-day" or "globally undiscovered" threats are prohibited.

---

## 10. Passive Liveness & Eligibility Boundary

* **Passive Eligibility Criterion:** HTTP response body $\ge 100$ bytes on initial request.
* **Safety & Non-Contamination:** No headless browser rendering, no JavaScript payload execution, and no client-side DOM interaction are required for liveness eligibility.
* **Liveness Independence:** Targets failing passive liveness are retained with `LivenessMetadata.eligibility_status = "ineligible"` and audited rather than discarded without a trace. Liveness failure does not define ground truth.

---

## 11. Statistical Analysis, Uncertainty Estimation, & Effect Sizes

### 11.1 Point Estimates & Uncertainty Intervals
All reported experimental metrics must be accompanied by uncertainty quantification:
* **Bootstrap Confidence Intervals:** 95% non-parametric bootstrap confidence intervals computed using $B = 1000$ resamples with replacement.
* **Standard Error & Dispersion:** Standard deviation and interquartile ranges (IQR) reported for continuous score distributions.

### 11.2 Hypothesis Testing & Significance
* **Binary Classification Comparisons:** McNemar's test for paired binary classification outcomes ($M_0$ vs. baselines $A_0$–$A_4$).
* **Continuous Score Comparisons:** Wilcoxon signed-rank test for paired continuous risk score distributions ($M_0$ vs. ablated models $M_1$–$M_6$).
* **Multi-Condition Significance:** Friedman test with post-hoc Nemenyi or Bonferroni-Dunn correction for multi-baseline rankings across threat categories.
* **Significance Level:** $\alpha = 0.05$ (two-tailed).

### 11.3 Effect Sizes
* **Continuous Score Shifts:** Cohen's $d$ or Cliff's delta ($\delta$) for ordinal/non-normal risk score distributions.
* **Categorical Detection Shifts:** Odds Ratios ($\text{OR}$) and Risk Difference ($\text{RD}$) for threat detection proportions.

### 11.4 Scientific Integrity Rules
* **No p-Hacking:** All statistical tests and comparisons are defined in this protocol.
* **No Post-Hoc Hypothesis Rewriting:** Experimental results will be reported against hypotheses $H_1$–$H_6$ as written herein, regardless of whether hypotheses are confirmed or refuted.

---

## 12. Calibration & Workflow Review Threshold ($C_{ev} \ge 35$)

### 12.1 Calibration Separation
* Calibration analysis (reliability diagrams, expected calibration error on calibration partitions) is conducted exclusively on the `DEVELOPMENT_CALIBRATION` split.
* Final evaluation splits (`FINAL_TEST`, `PROSPECTIVE_HOLDOUT`) are evaluated strictly out-of-sample.

### 12.2 Prototype Workflow Review Threshold ($C_{ev} \ge 35$)
* **Operational Meaning:** $C_{ev} \ge 35$ is defined as an **uncalibrated prototype workflow/review threshold** for routing investigations between automated reporting and human investigator adjudication.
* **Non-Enforcement Boundary:** $C_{ev} \ge 35$ is not an autonomous binary gating threshold.
* **Qualitative Nature:** Qualitative adjudication confidence (`HIGH`, `MEDIUM`, `LOW`) must not be converted into probabilistic Brier scores or continuous probability distributions without rigorous empirical calibration.

---

## 13. Threat-Flagging & $5 \times 2$ Contingency Analysis

### 13.1 $5 \times 2$ Risk Band Contingency Table
The five frozen TCE risk bands are compared against binary ground truth in a formal $5 \times 2$ contingency matrix:

| TCE Risk Band | Risk Score Range ($R$) | Ground Truth Benign | Ground Truth Malicious | Total |
| :--- | :--- | :--- | :--- | :--- |
| **Benign** | $[0, 15)$ | $N_{B, Ben}$ | $N_{B, Mal}$ | $N_B$ |
| **Low Risk** | $[15, 35)$ | $N_{LR, Ben}$ | $N_{LR, Mal}$ | $N_{LR}$ |
| **Suspicious** | $[35, 60)$ | $N_{Susp, Ben}$ | $N_{Susp, Mal}$ | $N_{Susp}$ |
| **High Risk** | $[60, 80)$ | $N_{HR, Ben}$ | $N_{HR, Mal}$ | $N_{HR}$ |
| **Malicious** | $[80, 100]$ | $N_{Mal, Ben}$ | $N_{Mal, Mal}$ | $N_{Mal}$ |

### 13.2 Binary Threat-Flagging Mapping Rationale
* For binary operating characteristic curves and standard confusion matrices, the threat-flagging boundary maps:
  $$\text{Positive Class (Flagged Threat)} = \text{Suspicious } [35, 60) \cup \text{High Risk } [60, 80) \cup \text{Malicious } [80, 100] \quad (R \ge 35)$$
  $$\text{Negative Class (Non-Flagged / Low Concern)} = \text{Benign } [0, 15) \cup \text{Low Risk } [15, 35) \quad (R < 35)$$
* **Academic Rationale:** In digital forensic triage, an investigator must be alerted whenever an artifact demonstrates elevated suspicion ($R \ge 35$) requiring structured review, whereas $R < 35$ represents low-risk or benign telemetry.

---

## 14. Reproducibility & Cryptographic Snapshot Hashing

The experimental pipeline enforces full snapshot reproducibility using the Step 6C-6 hashing hierarchy:
1. **Record SHA-256 Digest:** Canonical line-delimited UTF-8 JSON representation.
2. **Records File Hash (`records_file_hash`):** Exact byte stream SHA-256 digest of `records.jsonl`.
3. **Dataset Cryptographic Hash (`dataset_hash`):** Deterministic SHA-256 computed over ordered record hashes.
4. **Manifest Non-Circular Hash (`manifest_hash`):** Cryptographic digest of `manifest.json` sans `manifest_hash`.
5. **Snapshot Identifier:** `SNAP-<dataset_hash[:16]>`.

---

## 15. Threats to Validity

1. **Construct Validity:**
   * Heuristic weights in TCE ($w_i, \kappa=1.2, \alpha=0.25, \beta=0.70$) and Confidence Engine ($C_{ev} \ge 35$) are prototype research heuristics requiring future empirical optimization.
   * Threat intelligence feed availability varies across time and network regions.
2. **Internal Validity:**
   * Potential correlation across targets hosted on the same infrastructure or bulletproof ASN (mitigated by Tier-3 `GRP-` group-level leakage auditing).
   * Feed reporting lag where phishing campaigns become known to feeds hours after initial harvesting.
3. **External Validity:**
   * Rapidly evolving evasion techniques (e.g. dynamic canvas QR rendering, multi-step OAuth redirects) may exhibit different detection profiles than static campaign samples.
4. **Reliability:**
   * Multi-analyst adjudication consistency measured using inter-rater agreement (Cohen's $\kappa$ / Fleiss' $\kappa$) during dispute resolution.

---

## 16. Research Safety & Ethics Boundaries

1. **Zero Malware Detonation:** All analysis is static, passive, and containment-safe. No binary executables or browser-based active exploits are executed locally.
2. **Safe QR Scanning:** QR decoding uses mathematical barcode reading from static images. No parsed intents (`intent:`, `smsto:`, `tel:`) are dispatched to operating system handlers.
3. **Ethical Responsible Disclosure:** If unrecorded zero-day infrastructure or high-impact credential harvesting campaigns are observed, they will be reported to appropriate CERTs/registrars following coordinated disclosure standards.

---

## 17. Protocol Locking Sign-Off

* **Experimental Protocol Status:** FROZEN & LOCKED (Pre-Evaluation).
* **Next Stage (Step 6D-2):** Synthetic / Sandbox Dry-Run & Pipeline Harness Verification.
* **Data Collection Status:** NOT STARTED (Pending Explicit User Authorization).
