# Step 6D-11 — Final Experimental Dataset Audit & Freeze Document

**Milestone:** Step 6D-11  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Dataset Version:** `1.0.0-locked`  
**Freeze Timestamp:** `2026-09-16T13:35:00Z`  
**Protocol Version:** Step 6D-1 Pre-Registered Research Protocol (`docs/experimental_protocol.md`)  
**Freeze Decision:** `READY_TO_FREEZE` (Snapshot Cryptographically Locked)

---

## 1. Executive Summary & Verification Scope

This document certifies the independent, comprehensive integrity audit and cryptographic freezing of the final experimental benchmark dataset for the empirical evaluation of the Multi-Agent Digital Forensics and Evidence Analysis System.

The frozen dataset resides immutably at:
- **Locked Experimental Snapshot Directory:** `benchmark_data/experimental_locked/`
- **Collection Master Snapshot:** `benchmark_data/full/`

### Explicit Negative Boundaries (Zero Evaluation Mandate)
1. **Zero System Execution:** Full Multi-Agent pipeline ($M_0$), Baselines ($A_0$–$A_4$), and Ablation models ($M_1$–$M_6$) were **NOT** executed during this audit.
2. **Zero Post-Hoc Parameter Tuning:** No heuristic weights, TCE parameters ($\kappa=1.2, \alpha=0.25, \beta=0.70$), Confidence Engine prior or threshold ($C_{ev} \ge 35$), AERE prompt templates, or LLM choices were altered based on the benchmark data.
3. **Zero Dynamic Exploitation:** Zero dynamic browser detonation, zero active exploit payload delivery, and zero client credential submissions occurred.

---

## 2. Cryptographic Dataset Integrity & Verification Hashes

All record, file, and dataset-level cryptographic hashes were verified independently and match the stored manifest with zero discrepancies.

| Integrity Metric | Recorded in Manifest | Independently Computed | Match Status |
| :--- | :--- | :--- | :--- |
| **Snapshot ID** | `SNAP-a51ba6748b8e3064` | `SNAP-a51ba6748b8e3064` | **MATCH** |
| **Dataset Hash (SHA-256)** | `a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb6` | `a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb6` | **VALID** |
| **Manifest Hash (SHA-256)** | `60e1c6dcea61386ee81911c9b56699c8a4402e04088b2ee9888f542e71e02cfe` | `60e1c6dcea61386ee81911c9b56699c8a4402e04088b2ee9888f542e71e02cfe` | **VALID** |
| **Records File SHA-256** | `6a800662a07d2a92b1abfa4e8722ec3fa410817bab2e4f4945ef1c871051a1ab` | `6a800662a07d2a92b1abfa4e8722ec3fa410817bab2e4f4945ef1c871051a1ab` | **VALID** |
| **Total Record Count** | 1,220 | 1,220 | **VALID** |
| **Per-Record Hash Index** | 1,220 entries | 1,220 entries | **100% MATCH (0 errors)** |

---

## 3. Dataset Composition & Modality Breakdown

The dataset contains $N = 1,220$ canonicalized records across three frozen modalities:

| Modality | Record Count | Percentage |
| :--- | :--- | :--- |
| `DIRECT_URL` | 1,100 | 90.16% |
| `QR_IMAGE` | 60 | 4.92% |
| `QR_PAYLOAD` | 60 | 4.92% |
| **Total** | **1,220** | **100.0%** |

### Identity Graph Counts
- **Unique Artifact IDs (`artifact_id`):** 1,220
- **Unique Target IDs (`target_id`):** 1,176
- **Unique Group IDs (`group_id`):** 315

---

## 4. Partition Allocation & Temporal Protocol Audit

The dataset was partitioned deterministically using the frozen Step 6D-6 assembly algorithm:

| Partition | Record Count | Proportion | Methodological Status |
| :--- | :--- | :--- | :--- |
| `development_calibration` | 466 | 38.20% | Historical Development Pool (37.5% nominal target) |
| `validation` | 317 | 25.98% | Historical Validation Pool (25.0% nominal target) |
| `final_test` | 437 | 35.82% | Protected Single-Evaluation Pool (37.5% nominal target) |
| `prospective_holdout` | 0 | 0.00% | Reserved for sequential forward-in-time collection |

### Partition Discrepancy Investigation
1. **Root Cause:** In Step 6D-10, data was harvested within a single synchronous collection window (`2026-09-16T13:07:39Z`). Under the frozen `DatasetAssembler` specification, when no prospective cutoff ($T_{\text{cutoff}}$) is specified, all contemporaneous clusters are assigned across the three historical evaluation splits (`development_calibration`, `validation`, and `final_test`).
2. **Methodological Validity:** Artificially synthesizing a prospective holdout partition from contemporaneous static data would violate temporal causality. `final_test` functions as the strictly protected out-of-sample generalization split for testing $H_1$, $H_3$, $H_4$, $H_5$, and $H_6$. Prospective temporal decay ($H_2$) remains evaluated via Threat Intelligence exposure strata (`DIRECT`, `PARTIAL`, `NONE`).
3. **Decision:** The partition allocation is compliant with Step 6D-6 assembly mechanics. No post-hoc repartitioning was performed.

---

## 5. Group Overlap & Leakage Isolation Audit

### Leakage Audit Findings
- **Cross-Partition Target Leakage (`target_id`):** **0** (Zero target endpoints appear in more than one partition).
- **QR / Direct Cross-Partition Leakage:** **0** (All 40 multi-modality target pairs are strictly co-located within the same temporal partition).
- **Exact Duplicate Artifacts:** **0**.
- **Duplicate Record IDs:** **0**.

### eTLD+1 Group Overlap Investigation (222 Warnings)
- **Observation:** 222 unique `group_id` hashes (representing shared eTLD+1 domains, such as institutional domains like `europa.eu`, `harvard.edu`, or phishing campaign root domains) appear across multiple partitions.
- **Classification:** Under Step 6C-7 and Step 6D-1, `CROSS_PARTITION_GROUP_OVERLAP` is categorized as `WARNING` (informational correlation risk), whereas `CROSS_PARTITION_TARGET_LEAKAGE` is `CRITICAL`.
- **Methodological Recommendation:** Modifying partition assignments post-hoc to force domain-level clustering would alter the deterministic hash allocation and risk skewing modality/class distributions. Group-level co-occurrence is retained as documented variance in the frozen dataset.

---

## 6. Ground-Truth Independence & Source Role Firewall

The ground-truth derivation was audited against the frozen independence firewall:

| Supporting Reference Sources | Primary Outcome | Record Count | Adjudication / Verification Method |
| :--- | :--- | :--- | :--- |
| `authoritative_registry_gt` + `trusted_curation_registry` | `BENIGN` | 620 | Multi-Source Consensus (`HIGH` Confidence) |
| `authoritative_registry_gt` + `incident_takedown_archive` | `MALICIOUS` | 210 | Multi-Source Consensus (`HIGH` Confidence) |
| Unverified / Single Uncorroborated Harvest Source | `AMBIGUOUS` | 340 | Unverifiable (`LOW` Confidence, Ambiguity Pool) |
| `incident_takedown_archive` (Single Source) | `AMBIGUOUS` | 50 | Single Source Uncorroborated (`MEDIUM` Confidence) |
| **Total** | | **1,220** | |

### Independence Firewall Verifications
- **Internal Systems Prohibited:** Zero ground-truth annotations reference TCE, AERE, Confidence Engine, Report Generator, or Agents A1–A18.
- **Candidate Harvesters Prohibited:** Candidate harvester claims (e.g. OpenPhish URL listings) were **not** converted directly into ground truth without independent registry/incident corroboration.
- **Threat Intelligence Feeds Prohibited:** Threat intelligence hits were **not** converted into ground truth.

---

## 7. Synthetic QR Testbed Handling & Stratification

- **Total Records:** 60 records (Modality: `QR_PAYLOAD`).
- **Source:** `synthetic_qr_testbed`.
- **Ground Truth:** 20 `BENIGN`, 10 `MALICIOUS`, 30 `AMBIGUOUS`.
- **Partition Distribution:** `development_calibration` (22), `validation` (12), `final_test` (26).
- **Evaluation Requirement:** Synthetic QR records are explicitly tagged in `provenance.source_name`. For hypothesis $H_4$ (QR modality robustness), results must be reported with a clearly identified `synthetic_qr_stratum` alongside in-the-wild datasets (`kaggle_qr_phishing`).

---

## 8. Threat Intelligence (TI) Exposure Stratification

| TI Exposure Stratum | Record Count | Semantic Definition |
| :--- | :--- | :--- |
| `DIRECT` | 185 | Exact target URL positively listed in monitored TI feeds prior to collection. |
| `NEGATIVE_ONLY` | 333 | Monitored feeds queried and returned confirmed negative responses. |
| `NONE` / `UNKNOWN_UNAVAILABLE` | 702 | Target was unlisted or feed was unqueried/unavailable. |

### Neutral Provenance Semantics Invariant
Absence of positive TI detection was strictly **NOT** interpreted as benign:
- 25 `MALICIOUS` records have `TI_NONE_OR_UNKNOWN` (zero TI positive detections).
- 390 `AMBIGUOUS` records have `TI_NONE_OR_UNKNOWN`.
- 620 `BENIGN` records have `TI_NONE_OR_UNKNOWN`.
- 185 `MALICIOUS` records have `TI_DIRECT_POSITIVE`.

---

## 9. Passive Liveness Verification

- **Eligible (Live / Responsive):** 675 records ($\ge 100$ bytes raw body, valid TLS, $\le 3$ redirects).
- **Ineligible (Unresponsive / Offline):** 525 records (500 OpenPhish, 25 Tranco; retained in benchmark for non-network analysis).
- **Not Applicable:** 20 records (Static non-network QR schemes like `wifi:`, `smsto:`).
- **Safety Invariant:** Zero dynamic JavaScript execution, browser DOM rendering, form posting, or malware payload execution was performed.

---

## 10. Production Isolation & Regression Test Results

- **Production Code Isolation:** Confirmed via repository audit that production files ([agents/](file:///c:/Users/user/Desktop/digital/agents), [services/](file:///c:/Users/user/Desktop/digital/services), [app.py](file:///c:/Users/user/Desktop/digital/app.py), [templates/](file:///c:/Users/user/Desktop/digital/templates), [static/](file:///c:/Users/user/Desktop/digital/static)) remain untouched.
- **Test Suite Result:** `python -m unittest discover -s tests`
  - **Result:** `Ran 802 tests in 89.242s — OK` (100% pass rate).

---

## 11. Final Freeze Decision

```text
================================================================================
FINAL BENCHMARK FREEZE DECISION: READY_TO_FREEZE
Snapshot Directory: benchmark_data/experimental_locked/
Dataset Hash (SHA-256): a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb6
Manifest Hash (SHA-256): 60e1c6dcea61386ee81911c9b56699c8a4402e04088b2ee9888f542e71e02cfe
Records File SHA-256: 6a800662a07d2a92b1abfa4e8722ec3fa410817bab2e4f4945ef1c871051a1ab
Total Verified Records: 1,220
Pre-Run Gate Status: READY_FOR_EXPERIMENT
================================================================================
```
