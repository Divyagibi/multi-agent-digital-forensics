# Digital Forensics Benchmark Archival Index

**Dataset Snapshot:** `SNAP-a51ba6748b8e3064`  
**Dataset Version:** `1.0.0-locked`  
**Dataset SHA-256 Hash:** `a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb6`  
**Archival Date:** 2026-09-16  

---

## 1. Locked Benchmark Dataset

| Resource | Path | SHA-256 Checksum | Description |
|---|---|---|---|
| **Locked Directory** | `benchmark_data/experimental_locked/` | — | Master immutable directory containing frozen evaluation data |
| **Records File** | `benchmark_data/experimental_locked/records.jsonl` | `6a800662a07d2a92b1abfa4e8722ec3fa410817bab2e4f4945ef1c871051a1ab` | 1,220 canonical forensic records across 3 modalities |
| **Dataset Manifest** | `benchmark_data/experimental_locked/manifest.json` | `60e1c6dcea61386ee81911c9b56699c8a4402e04088b2ee9888f542e71e02cfe` | Partition metadata, modality counts, and per-record hash index |
| **Collection Audit Log** | `benchmark_data/experimental_locked/collection_audit_log.json` | — | Provenance audit log of approved collection sources |
| **Raw QR Image Archive** | `benchmark_data/experimental_locked/raw_qr_images/` | — | 60 synthetic QR PNG images |

---

## 2. Experimental Results Artifacts

All experimental evaluation artifacts are preserved in `benchmark_data/experimental_results/`:

| Artifact Name | Relative Path | Purpose & Content |
|---|---|---|
| **Predictions Record** | `benchmark_data/experimental_results/predictions.jsonl` | 14,640 per-record predictions (12 conditions × 1,220 records) |
| **Primary Metrics** | `benchmark_data/experimental_results/metrics.json` | Comprehensive metrics (BalAcc, F1, F2, Precision, Recall, FPR, FNR, ROC-AUC, PR-AUC) |
| **Statistical Results** | `benchmark_data/experimental_results/statistical_results.json` | Bootstrap CIs ($B=1000$), McNemar tests, Wilcoxon signed-rank tests, Cohen's $d$, Odds ratios |
| **Risk Band Contingency** | `benchmark_data/experimental_results/risk_band_contingency.json` | 5×2 contingency tables mapping TCE risk bands to binary ground truth |
| **Confidence Engine Results**| `benchmark_data/experimental_results/confidence_results.json` | $C_{ev}$ distributions, abstention rates, and selective partition accuracy |
| **AERE Reasoning Results** | `benchmark_data/experimental_results/aere_results.json` | Grounding fidelity status distributions under $M_0$ and $M_6$ |
| **Ablation Results** | `benchmark_data/experimental_results/ablation_results.json` | Condition reports and IDC values for ablations $M_1$–$M_6$ |
| **Baseline Results** | `benchmark_data/experimental_results/baseline_results.json` | Condition reports for baselines $A_0$–$A_4$ |
| **Experiment Manifest** | `benchmark_data/experimental_results/experiment_manifest.json` | Reproducibility metadata, snapshot ID, random seed (42), timestamp |
| **Experiment Execution Log** | `benchmark_data/experimental_results/experiment_log.jsonl` | Chronological step execution logs |

---

## 3. Protocol & Audit Documentation

| Document Title | Path | Description |
|---|---|---|
| **Experimental Protocol** | `docs/experimental_protocol.md` | Pre-registered research protocol defining conditions, hypotheses, and metrics |
| **Dataset Freeze Audit** | `docs/experimental_dataset_freeze_audit.md` | Step 6D-11 integrity audit and snapshot freeze certification |
| **Results Report** | `docs/experimental_results_report.md` | Step 6D-12 controlled experimental evaluation execution report |
| **Independent Results Audit**| `docs/experimental_results_report.md` | Step 6D-13 independent metric recomputation and leakage audit |
| **Benchmark Synthesis** | `docs/final_benchmark_synthesis.md` | Step 6D-14 comprehensive synthesis of results, limitations, and findings |
| **Research Claims Matrix** | `docs/research_claims_matrix.md` | Structured matrix of supported vs unsupported empirical claims |

---

## 4. Verification & Regression Status

* **Dataset Hash Integrity:** VERIFIED (`a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb6` — IMMUTABLE)
* **Unit Test Regression:** 802/802 PASSING (`python -m unittest discover -s tests`)
* **Production Isolation:** VERIFIED (Zero modifications to `agents/`, `services/`, `app.py`, `templates/`, `static/`)
