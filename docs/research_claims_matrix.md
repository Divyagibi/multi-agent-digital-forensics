# Digital Forensics Research Claims Matrix

**Milestone:** Step 6D-14  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Snapshot:** `SNAP-a51ba6748b8e3064` (`1.0.0-locked`)  
**Audit Protocol:** Step 6D-13 Independent Results Audit & Scientific Validity Review  

---

## 1. Structured Claims Evaluation Matrix

| Claim | Empirical Evidence | Supported? | Strength | Limitation & Nuance |
|---|---|---|---|---|
| **Multi-Agent Evidence Integration** | $M_0$ successfully normalized and integrated evidence across 18 specialized forensic agents into a unified Evidence Ledger. | **YES** | **STRONG** | Relies on deterministic schema compatibility and category-based polarity rules. |
| **High $M_0$ Recall / Sensitivity** | $M_0$ achieved $\text{Recall} = 1.0000$ (210/210 true positives, 0 false negatives) across all binary ground-truth malicious samples. | **YES** | **STRONG** | Observed on a curated historical static benchmark; real-world evasion variants may yield false negatives. |
| **Predictive Superiority over Baselines** | $M_0$ outperformed $A_1$ (TI aggregate), $A_2$ (Majority voting), $A_3$ (Linear additive), and $A_4$ (Zero-shot LLM), but was outperformed by $A_0$ (Static lexical rule heuristic: 0.9984 vs 0.9677). | **PARTIAL** | **MODERATE** | **$M_0$ is NOT universally superior.** $A_0$ achieved higher accuracy on this static corpus due to explicit lexical signatures in historical phishing URLs. |
| **Multi-Modal Explainability & Provenance** | Every $M_0$ prediction links to immutable ledger evidence items with verifiable source telemetry and cryptographic hash provenance. | **YES** | **STRONG** | Explainability reflects internal agent consistency rather than external objective ground truth. |
| **AERE Evidence Grounding Validation** | AERE grounding validator deterministically identified 1,220 ungrounded assertions when synthesized narratives lacked ledger citations ($M_0$ vs $M_6$). | **YES** | **STRONG** | Validates structural citation enforcement; does **NOT** prove elimination of all dynamic LLM hallucinations. |
| **Confidence Assessment ($C_{ev}$)** | Confidence Engine computed evidence sufficiency ($C_{ev}$) across all records, identifying evidence depth and graph corroboration. | **YES** | **MODERATE** | All records in this dataset met the evidence sufficiency floor ($C_{ev} \ge 35.0$). |
| **Selective-Classification Abstention** | Evaluated coverage/performance trade-off using $C_{ev} \ge 35.0$ threshold. | **NO** | **UNSUPPORTED** | 100% of records met the threshold ($C_{ev} \ge 35.0$); abstention rate was 0.00%, so no selective-classification trade-off was demonstrated in this dataset. |
| **Zero-Day Threat Detection** | $M_0$ maintained 0.9677 Balanced Accuracy and 1.0000 Recall on records without observed positive TI exposure ($N=645$). | **PARTIAL** | **MODERATE** | TI absence at observation time does **NOT** establish true zero-day status. Prospective zero-day detection claims remain reserved for future temporal holdout. |
| **QR Code / Quishing Robustness** | $M_0$ achieved 0.9500 Balanced Accuracy on decoded `QR_PAYLOAD` records ($N=30$). `QR_IMAGE` records had 0 binary eligible ground-truth samples. | **PARTIAL** | **LIMITED** | Quishing robustness is supported **only** for decoded URL payloads. Broad in-the-wild visual QR image robustness is **NOT estimable**. |
| **Ablation Incremental Contribution (IDC)** | Continuous risk distributions shifted significantly when agents were ablated (Wilcoxon $p < 10^{-8}$ for $M_1, M_3, M_4, M_5$), while binary classification at $\text{Risk} \ge 35$ was invariant. | **YES** | **MODERATE** | IDC is strictly **descriptive and non-causal**. Coarse binary invariance reflects multi-agent redundancy rather than individual agent irrelevance. |
| **Deterministic Risk Band Calibration** | TCE mapped continuous risk scores into 5 discrete risk bands with 0 malicious samples in `benign`/`low_risk` and 210 in `malicious`. | **YES** | **STRONG** | 40 false positives in benign samples elevated risk into `high_risk` / `malicious` due to sensitive keywords without TI corroboration. |

---

## 2. Summary of Prohibited Scientific Claims

The following claims are **STRICTLY PROHIBITED** and refuted by empirical evidence:
1. **Universal Superiority:** Refuted by $A_0 > M_0$ ($0.9984 > 0.9677$).
2. **Universal Zero-Day Detection:** Unproven; TI absence is not equivalent to zero-day status.
3. **Total Hallucination Elimination:** Unproven; AERE validates citation schema adherence, not cognitive truth.
4. **Broad In-The-Wild QR Image Robustness:** Unproven; $N=0$ binary eligible samples for `QR_IMAGE`.
5. **Demonstrated Selective Classification:** Unproven; 0% abstention rate in this dataset.
6. **Causal Attribution of Ablations:** Unproven; IDC is descriptive and non-causal.
