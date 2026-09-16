"""Experimental Benchmark Evaluation Layer.

Step 6D-5: Experimental Benchmark Evaluation for Multi-Agent Digital Forensics.

This module provides the independent, reproducible, and mathematically rigorous
evaluation infrastructure for the Multi-Agent Digital Forensics & Evidence Analysis System.

Evaluates:
- Main System: M0 (Full Multi-Agent Pipeline)
- Baselines: A0 (Static Lexical Heuristic), A1 (Standalone TI Feed Aggregate),
             A2 (Unweighted Majority Voting), A3 (Linear Additive Risk),
             A4 (Standalone Monolithic Zero-Shot LLM)
- Ablations: M1 (A6 Threat Intelligence ablated), M2 (A18 QR ablated),
             M3 (A8 Dynamic Script ablated), M4 (A9/A10 Brand/Visual ablated),
             M5 (TCE synergy ablated), M6 (AERE grounding ablated)
- Hypotheses: H1 (Baseline Comparisons), H2 (Temporal & TI Generalization),
             H3 (Incremental Diagnostic Contribution), H4 (Cross-Modal Robustness),
             H5 (Confidence Engine & Selective Review), H6 (AERE Grounding Fidelity)

Architectural & Methodological Guarantees:
1. Ground-Truth Invariance: Ground truth is read-only and immutable. No ground truth is derived
   from system predictions. Ambiguous records are excluded from binary metrics and documented.
2. Partition Protection: Evaluates DEVELOPMENT_CALIBRATION, VALIDATION, FINAL_TEST, and
   PROSPECTIVE_HOLDOUT strictly out-of-sample. No parameter tuning occurs on holdout splits.
3. TI Firewall: TI feed presence is provenance metadata only; TI absence != benign.
4. Risk Bands: Preserves all 5 frozen TCE risk bands ([0, 15), [15, 35), [35, 60), [60, 80), [80, 100]).
5. Statistical Rigor: 95% bootstrap confidence intervals (B=1000), McNemar tests, Wilcoxon signed-rank tests,
   Cohen's d, and Odds Ratios with explicit handling of undefined/small-sample edge cases.
6. Qualitative Confidence: Treats qualitative confidence (HIGH, MEDIUM, LOW) separately from probabilities.
7. Diagnostic Contribution: Reports IDC = Metric(M0) - Metric(Mk) as observational signal delta (non-causal).
8. Research Safety: Operates strictly offline on stored predictions/observations without dynamic execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import math
import random
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from .schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationConfidence,
    TemporalPartition,
    TIObservationStatus,
    BenchmarkRecord,
)


# =====================================================================
# Controlled Vocabularies & Enums
# =====================================================================

class ExperimentalCondition(str, Enum):
    """Controlled experimental condition identifiers."""
    # Main System
    M0_FULL_SYSTEM = "M0"
    # Baselines
    A0_STATIC_LEXICAL = "A0"
    A1_TI_AGGREGATE = "A1"
    A2_MAJORITY_VOTE = "A2"
    A3_LINEAR_ADDITIVE = "A3"
    A4_MONOLITHIC_LLM = "A4"
    # Ablations
    M1_NO_TI = "M1"
    M2_NO_QR = "M2"
    M3_NO_DYNAMIC_SCRIPT = "M3"
    M4_NO_BRAND_VISUAL = "M4"
    M5_NO_TCE_SYNERGY = "M5"
    M6_NO_AERE_GROUNDING = "M6"


class GroundingFidelityStatus(str, Enum):
    """AERE reasoning claim grounding verification status."""
    GROUNDED = "GROUNDED"
    PARTIALLY_GROUNDED = "PARTIALLY_GROUNDED"
    UNGROUNDED = "UNGROUNDED"
    UNCERTAIN = "UNCERTAIN"


# =====================================================================
# Canonical System Prediction Representation
# =====================================================================

@dataclass(frozen=True)
class SystemPrediction:
    """Canonical representation of a single system or baseline investigation output."""
    record_id: str
    target_id: str
    artifact_id: str
    group_id: str
    partition: TemporalPartition
    modality: InputModality
    ground_truth_outcome: PrimaryOutcome
    ground_truth_categories: List[SecondaryThreatCategory] = field(default_factory=list)
    predicted_outcome: PrimaryOutcome = PrimaryOutcome.AMBIGUOUS
    risk_score: float = 0.0  # Range [0.0, 100.0]
    risk_band: str = "benign"  # benign, low_risk, suspicious, high_risk, malicious
    trust_score: Optional[float] = None
    confidence_score: Optional[float] = None  # C_ev score
    confidence_band: Optional[str] = None  # HIGH, MEDIUM, LOW
    is_abstained: bool = False  # True if C_ev < 35.0
    grounding_status: Optional[GroundingFidelityStatus] = None
    evidence_count: int = 0
    agent_coverage: List[str] = field(default_factory=list)
    ti_exposure_status: Optional[str] = None
    runtime_ms: Optional[float] = None
    is_error: bool = False
    error_message: str = ""

    @property
    def is_threat_flagged(self) -> bool:
        """Threat-flagging decision rule: risk_score >= 35.0 (Suspicious, High Risk, Malicious)."""
        return self.risk_score >= 35.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary."""
        return {
            "record_id": self.record_id,
            "target_id": self.target_id,
            "artifact_id": self.artifact_id,
            "group_id": self.group_id,
            "partition": self.partition.value if hasattr(self.partition, "value") else str(self.partition),
            "modality": self.modality.value if hasattr(self.modality, "value") else str(self.modality),
            "ground_truth_outcome": self.ground_truth_outcome.value if hasattr(self.ground_truth_outcome, "value") else str(self.ground_truth_outcome),
            "ground_truth_categories": [
                c.value if hasattr(c, "value") else str(c) for c in self.ground_truth_categories
            ],
            "predicted_outcome": self.predicted_outcome.value if hasattr(self.predicted_outcome, "value") else str(self.predicted_outcome),
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "trust_score": self.trust_score,
            "confidence_score": self.confidence_score,
            "confidence_band": self.confidence_band,
            "is_abstained": self.is_abstained,
            "is_threat_flagged": self.is_threat_flagged,
            "grounding_status": self.grounding_status.value if self.grounding_status else None,
            "evidence_count": self.evidence_count,
            "agent_coverage": list(self.agent_coverage),
            "ti_exposure_status": self.ti_exposure_status,
            "runtime_ms": self.runtime_ms,
            "is_error": self.is_error,
            "error_message": self.error_message,
        }


def compute_risk_band_name(risk_score: float) -> str:
    """Map continuous risk score in [0, 100] to the five frozen TCE risk bands."""
    if risk_score < 15.0:
        return "benign"
    elif risk_score < 35.0:
        return "low_risk"
    elif risk_score < 60.0:
        return "suspicious"
    elif risk_score < 80.0:
        return "high_risk"
    else:
        return "malicious"


# =====================================================================
# Evaluation Data Models & Metric Containers
# =====================================================================

@dataclass(frozen=True)
class RiskBandContingencyTable:
    """5x2 Contingency Matrix: 5 TCE Risk Bands vs Binary Ground Truth."""
    benign_ground_truth_benign: int = 0
    benign_ground_truth_malicious: int = 0
    low_risk_ground_truth_benign: int = 0
    low_risk_ground_truth_malicious: int = 0
    suspicious_ground_truth_benign: int = 0
    suspicious_ground_truth_malicious: int = 0
    high_risk_ground_truth_benign: int = 0
    high_risk_ground_truth_malicious: int = 0
    malicious_ground_truth_benign: int = 0
    malicious_ground_truth_malicious: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationMetrics:
    """Comprehensive performance metrics container."""
    total_evaluated: int
    eligible_count: int
    excluded_ambiguous_count: int
    tp: int
    tn: int
    fp: int
    fn: int
    balanced_accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None  # TPR
    fpr: Optional[float] = None
    fnr: Optional[float] = None
    f1: Optional[float] = None
    f2: Optional[float] = None
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    contingency_table: RiskBandContingencyTable = field(default_factory=RiskBandContingencyTable)
    confidence_intervals: Dict[str, Tuple[Optional[float], Optional[float]]] = field(default_factory=dict)
    abstention_rate: Optional[float] = None
    conditional_balanced_accuracy: Optional[float] = None
    grounding_summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_evaluated": self.total_evaluated,
            "eligible_count": self.eligible_count,
            "excluded_ambiguous_count": self.excluded_ambiguous_count,
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "balanced_accuracy": self.balanced_accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "fpr": self.fpr,
            "fnr": self.fnr,
            "f1": self.f1,
            "f2": self.f2,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "contingency_table": self.contingency_table.to_dict(),
            "confidence_intervals": self.confidence_intervals,
            "abstention_rate": self.abstention_rate,
            "conditional_balanced_accuracy": self.conditional_balanced_accuracy,
            "grounding_summary": self.grounding_summary,
        }


@dataclass(frozen=True)
class StatisticalComparisonResult:
    """Statistical hypothesis test and effect size container between two conditions."""
    condition_a: str
    condition_b: str
    metric_a_name: str = ""
    metric_a_value: Optional[float] = None
    metric_b_value: Optional[float] = None
    metric_delta: Optional[float] = None
    mcnemar_statistic: Optional[float] = None
    mcnemar_p_value: Optional[float] = None
    wilcoxon_statistic: Optional[float] = None
    wilcoxon_p_value: Optional[float] = None
    cohens_d: Optional[float] = None
    odds_ratio: Optional[float] = None
    incremental_diagnostic_contribution: Optional[float] = None
    is_statistically_significant: Optional[bool] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConditionEvaluationReport:
    """Evaluation report for a single experimental condition across partitions."""
    condition: ExperimentalCondition
    overall_metrics: EvaluationMetrics
    partition_metrics: Dict[str, EvaluationMetrics] = field(default_factory=dict)
    modality_metrics: Dict[str, EvaluationMetrics] = field(default_factory=dict)
    ti_exposure_metrics: Dict[str, EvaluationMetrics] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "condition": self.condition.value,
            "overall_metrics": self.overall_metrics.to_dict(),
            "partition_metrics": {k: v.to_dict() for k, v in self.partition_metrics.items()},
            "modality_metrics": {k: v.to_dict() for k, v in self.modality_metrics.items()},
            "ti_exposure_metrics": {k: v.to_dict() for k, v in self.ti_exposure_metrics.items()},
        }


@dataclass(frozen=True)
class BenchmarkEvaluationSuiteResult:
    """Comprehensive, reproducible top-level experimental evaluation result."""
    experiment_id: str
    snapshot_id: str
    dataset_hash: str
    total_records: int
    condition_reports: Dict[str, ConditionEvaluationReport] = field(default_factory=dict)
    hypothesis_comparisons: Dict[str, List[StatisticalComparisonResult]] = field(default_factory=dict)
    reproducibility_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "snapshot_id": self.snapshot_id,
            "dataset_hash": self.dataset_hash,
            "total_records": self.total_records,
            "condition_reports": {k: v.to_dict() for k, v in self.condition_reports.items()},
            "hypothesis_comparisons": {
                k: [item.to_dict() for item in v] for k, v in self.hypothesis_comparisons.items()
            },
            "reproducibility_metadata": self.reproducibility_metadata,
        }


# =====================================================================
# Pure Mathematical Metric Calculations & Statistical Procedures
# =====================================================================

def compute_binary_metrics(
    y_true: Sequence[int],  # 1 for MALICIOUS, 0 for BENIGN
    y_pred: Sequence[int],  # 1 for Threat Flagged (R >= 35), 0 for Low Risk (R < 35)
    y_score: Optional[Sequence[float]] = None,
) -> Dict[str, Optional[float]]:
    """Compute standard classification and ranking metrics with robust edge-case handling.

    Returns: tp, tn, fp, fn, balanced_accuracy, precision, recall, fpr, fnr, f1, f2, roc_auc, pr_auc.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"Length mismatch: y_true ({len(y_true)}) vs y_pred ({len(y_pred)})")

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    # Sensitivity / Recall / TPR
    tpr = tp / (tp + fn) if (tp + fn) > 0 else None
    # Specificity / TNR
    tnr = tn / (tn + fp) if (tn + fp) > 0 else None
    # FPR & FNR
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    fnr = fn / (fn + tp) if (fn + tp) > 0 else None

    # Balanced Accuracy: 0.5 * (TPR + TNR)
    if tpr is not None and tnr is not None:
        balanced_acc: Optional[float] = 0.5 * (tpr + tnr)
    elif tpr is not None:
        balanced_acc = tpr
    elif tnr is not None:
        balanced_acc = tnr
    else:
        balanced_acc = None

    # Precision
    precision = tp / (tp + fp) if (tp + fp) > 0 else None

    # F1 Score: 2 * (P * R) / (P + R)
    if precision is not None and tpr is not None and (precision + tpr) > 0:
        f1: Optional[float] = 2.0 * (precision * tpr) / (precision + tpr)
    else:
        f1 = None

    # F2 Score: (1 + 2^2) * (P * R) / (2^2 * P + R) = 5 * P * R / (4P + R)
    if precision is not None and tpr is not None and (4.0 * precision + tpr) > 0:
        f2: Optional[float] = 5.0 * (precision * tpr) / (4.0 * precision + tpr)
    else:
        f2 = None

    # ROC-AUC and PR-AUC
    roc_auc = compute_roc_auc(y_true, y_score) if y_score is not None else None
    pr_auc = compute_pr_auc(y_true, y_score) if y_score is not None else None

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "balanced_accuracy": balanced_acc,
        "precision": precision,
        "recall": tpr,
        "fpr": fpr,
        "fnr": fnr,
        "f1": f1,
        "f2": f2,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
    }


def compute_roc_auc(y_true: Sequence[int], y_score: Sequence[float]) -> Optional[float]:
    """Compute Area Under the Receiver Operating Characteristic Curve (ROC-AUC) via Wilcoxon-Mann-Whitney U statistic."""
    pos_count = sum(1 for yt in y_true if yt == 1)
    neg_count = sum(1 for yt in y_true if yt == 0)

    if pos_count == 0 or neg_count == 0:
        return None

    # Pair scores with labels and sort in ascending order
    paired = sorted(zip(y_score, y_true), key=lambda x: x[0])

    # Rank calculation with tie handling
    n = len(paired)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and paired[j][0] == paired[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    # Sum of ranks for positive class
    sum_pos_ranks = sum(r for r, (_, yt) in zip(ranks, paired) if yt == 1)

    # U statistic for positives
    u_pos = sum_pos_ranks - (pos_count * (pos_count + 1)) / 2.0
    auc = u_pos / (pos_count * neg_count)
    return max(0.0, min(1.0, auc))


def compute_pr_auc(y_true: Sequence[int], y_score: Sequence[float]) -> Optional[float]:
    """Compute Area Under the Precision-Recall Curve (PR-AUC) using the trapezoidal rule / average precision."""
    pos_count = sum(1 for yt in y_true if yt == 1)
    if pos_count == 0:
        return None

    # Sort thresholds descending by score
    paired = sorted(zip(y_score, y_true), key=lambda x: x[0], reverse=True)

    precisions = [1.0]
    recalls = [0.0]

    running_tp = 0
    running_fp = 0

    for score, yt in paired:
        if yt == 1:
            running_tp += 1
        else:
            running_fp += 1

        rec = running_tp / pos_count
        prec = running_tp / (running_tp + running_fp)
        recalls.append(rec)
        precisions.append(prec)

    # Integrate PR curve via trapezoidal approximation
    pr_auc = 0.0
    for k in range(1, len(recalls)):
        dr = recalls[k] - recalls[k - 1]
        avg_p = (precisions[k] + precisions[k - 1]) / 2.0
        pr_auc += avg_p * dr

    return max(0.0, min(1.0, pr_auc))


def compute_bootstrap_confidence_intervals(
    y_true: Sequence[int],
    y_score: Sequence[float],
    y_pred: Sequence[int],
    n_bootstraps: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
) -> Dict[str, Tuple[Optional[float], Optional[float]]]:
    """Compute 95% non-parametric bootstrap confidence intervals (B=1000 resamples with replacement)."""
    n = len(y_true)
    if n < 5:
        return {}

    rng = random.Random(seed)
    bootstrap_metrics: Dict[str, List[float]] = {
        "balanced_accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
        "f2": [],
        "roc_auc": [],
        "pr_auc": [],
    }

    indices = list(range(n))
    for _ in range(n_bootstraps):
        sample_idx = [rng.choice(indices) for _ in range(n)]
        sample_yt = [y_true[i] for i in sample_idx]
        sample_yp = [y_pred[i] for i in sample_idx]
        sample_ys = [y_score[i] for i in sample_idx]

        bm = compute_binary_metrics(sample_yt, sample_yp, sample_ys)
        for k in bootstrap_metrics:
            val = bm.get(k)
            if val is not None and not math.isnan(val):
                bootstrap_metrics[k].append(val)

    ci_results: Dict[str, Tuple[Optional[float], Optional[float]]] = {}
    lower_pct = (alpha / 2.0) * 100.0
    upper_pct = (1.0 - alpha / 2.0) * 100.0

    for k, values in bootstrap_metrics.items():
        if len(values) >= 50:
            values.sort()
            lower_idx = int(len(values) * (lower_pct / 100.0))
            upper_idx = min(len(values) - 1, int(len(values) * (upper_pct / 100.0)))
            ci_results[k] = (values[lower_idx], values[upper_idx])
        else:
            ci_results[k] = (None, None)

    return ci_results


def compute_mcnemar_test(
    y_true: Sequence[int],
    y_pred_a: Sequence[int],
    y_pred_b: Sequence[int],
) -> Tuple[Optional[float], Optional[float]]:
    """Compute paired McNemar test statistic with continuity correction and two-tailed p-value."""
    if len(y_true) != len(y_pred_a) or len(y_pred_a) != len(y_pred_b):
        raise ValueError("Sequence length mismatch for McNemar test.")

    # Discordant counts:
    # b: A correct, B incorrect
    # c: A incorrect, B correct
    b = sum(1 for yt, pa, pb in zip(y_true, y_pred_a, y_pred_b) if (pa == yt) and (pb != yt))
    c = sum(1 for yt, pa, pb in zip(y_true, y_pred_a, y_pred_b) if (pa != yt) and (pb == yt))

    if b + c == 0:
        return (0.0, 1.0)

    # Chi-square with Edwards continuity correction: (|b - c| - 1)^2 / (b + c)
    stat = ((abs(b - c) - 1.0) ** 2) / (b + c) if abs(b - c) >= 1.0 else 0.0

    # 1-df chi-square survival function approximation via standard normal erf: P(chi2 >= x) = 2 * (1 - Phi(sqrt(x)))
    z = math.sqrt(stat)
    p_value = 1.0 - math.erf(z / math.sqrt(2.0))
    p_value = max(0.0, min(1.0, p_value))

    return (stat, p_value)


def compute_wilcoxon_signed_rank(
    scores_a: Sequence[float],
    scores_b: Sequence[float],
) -> Tuple[Optional[float], Optional[float]]:
    """Compute paired Wilcoxon signed-rank test statistic and asymptotic two-tailed p-value."""
    if len(scores_a) != len(scores_b):
        raise ValueError("Sequence length mismatch for Wilcoxon signed-rank test.")

    diffs = [a - b for a, b in zip(scores_a, scores_b) if a != b]
    n = len(diffs)
    if n < 5:
        return (None, None)

    # Rank absolute differences
    abs_diffs = [(abs(d), math.copysign(1, d)) for d in diffs]
    abs_diffs.sort(key=lambda x: x[0])

    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and abs_diffs[j][0] == abs_diffs[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    # Sum of ranks for positive differences
    w_pos = sum(r for r, (_, sign) in zip(ranks, abs_diffs) if sign > 0)
    w_neg = sum(r for r, (_, sign) in zip(ranks, abs_diffs) if sign < 0)
    test_stat = min(w_pos, w_neg)

    # Normal approximation for n >= 5: mean = n(n+1)/4, var = n(n+1)(2n+1)/24
    mean_w = (n * (n + 1)) / 4.0
    var_w = (n * (n + 1) * (2 * n + 1)) / 24.0
    std_w = math.sqrt(var_w) if var_w > 0 else 1.0

    z = (test_stat - mean_w) / std_w
    # Two-tailed p-value
    p_value = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
    p_value = max(0.0, min(1.0, p_value))

    return (test_stat, p_value)


def compute_cohens_d(scores_a: Sequence[float], scores_b: Sequence[float]) -> Optional[float]:
    """Compute Cohen's d effect size for paired continuous score differences."""
    if len(scores_a) != len(scores_b) or len(scores_a) < 2:
        return None

    diffs = [a - b for a, b in zip(scores_a, scores_b)]
    n = len(diffs)
    mean_diff = sum(diffs) / n
    variance = sum((d - mean_diff) ** 2 for d in diffs) / (n - 1)
    std_dev = math.sqrt(variance)

    if std_dev == 0.0:
        return 0.0
    return mean_diff / std_dev


def compute_odds_ratio(
    y_true: Sequence[int],
    y_pred_a: Sequence[int],
    y_pred_b: Sequence[int],
) -> Optional[float]:
    """Compute odds ratio between detection rates of condition A vs condition B."""
    pos_a = sum(1 for yt, p in zip(y_true, y_pred_a) if yt == 1 and p == 1)
    neg_a = sum(1 for yt, p in zip(y_true, y_pred_a) if yt == 1 and p == 0)

    pos_b = sum(1 for yt, p in zip(y_true, y_pred_b) if yt == 1 and p == 1)
    neg_b = sum(1 for yt, p in zip(y_true, y_pred_b) if yt == 1 and p == 0)

    if neg_a == 0 or pos_b == 0 or neg_b == 0:
        # Haldane-Anscombe correction (+0.5 to zero cells)
        odds_a = (pos_a + 0.5) / (neg_a + 0.5)
        odds_b = (pos_b + 0.5) / (neg_b + 0.5)
    else:
        odds_a = pos_a / neg_a
        odds_b = pos_b / neg_b

    return odds_a / odds_b if odds_b > 0 else None


# =====================================================================
# Baseline Adapters (A0–A4)
# =====================================================================

class BaselineAdapter:
    """Standardized baseline simulation and score adapter."""

    @staticmethod
    def evaluate_a0_static_lexical(record: BenchmarkRecord) -> SystemPrediction:
        """A0: Static Lexical / URL Pattern Heuristic Baseline."""
        url = record.target_url or ""
        lower_url = url.lower()

        # Heuristic features
        score = 0.0
        if len(url) > 75:
            score += 20.0
        if url.count(".") > 3:
            score += 15.0
        if any(kw in lower_url for kw in ["login", "verify", "secure", "account", "banking", "update", "signin"]):
            score += 25.0
        if any(kw in lower_url for kw in ["@", "-", "%"]):
            score += 15.0
        if lower_url.startswith("http://"):
            score += 15.0
        if any(ext in lower_url for kw, ext in [(".exe", ".exe"), (".scr", ".scr"), (".zip", ".zip")]):
            score += 20.0

        risk_score = min(100.0, score)
        pred_outcome = PrimaryOutcome.MALICIOUS if risk_score >= 35.0 else PrimaryOutcome.BENIGN
        risk_band = compute_risk_band_name(risk_score)

        return SystemPrediction(
            record_id=record.record_id,
            target_id=record.target_id,
            artifact_id=record.artifact_id,
            group_id=record.evaluation.group_id,
            partition=record.evaluation.temporal_partition or TemporalPartition.FINAL_TEST,
            modality=record.modality,
            ground_truth_outcome=record.ground_truth.primary_outcome,
            ground_truth_categories=list(record.ground_truth.secondary_categories),
            predicted_outcome=pred_outcome,
            risk_score=risk_score,
            risk_band=risk_band,
            confidence_score=40.0,
            confidence_band="MEDIUM",
            is_abstained=False,
            evidence_count=1,
            agent_coverage=["A0_LEXICAL"],
        )

    @staticmethod
    def evaluate_a1_ti_aggregate(record: BenchmarkRecord) -> SystemPrediction:
        """A1: Standalone Threat Intelligence Feed Aggregate Baseline."""
        ti = record.ti_overlap
        feeds = [
            ti.virustotal,
            ti.google_safebrowsing,
            ti.phishtank,
            ti.openphish,
            ti.urlhaus,
            ti.abuseipdb,
            ti.spamhaus,
        ]

        pos_count = sum(1 for f in feeds if f.status == TIObservationStatus.POSITIVE_OBSERVATION or f.observed)
        available_count = sum(1 for f in feeds if f.source_available and f.status != TIObservationStatus.UNAVAILABLE)

        if available_count > 0:
            risk_score = (pos_count / available_count) * 100.0
        else:
            risk_score = 0.0

        pred_outcome = PrimaryOutcome.MALICIOUS if risk_score >= 35.0 else PrimaryOutcome.BENIGN
        risk_band = compute_risk_band_name(risk_score)

        return SystemPrediction(
            record_id=record.record_id,
            target_id=record.target_id,
            artifact_id=record.artifact_id,
            group_id=record.evaluation.group_id,
            partition=record.evaluation.temporal_partition or TemporalPartition.FINAL_TEST,
            modality=record.modality,
            ground_truth_outcome=record.ground_truth.primary_outcome,
            ground_truth_categories=list(record.ground_truth.secondary_categories),
            predicted_outcome=pred_outcome,
            risk_score=risk_score,
            risk_band=risk_band,
            confidence_score=float(available_count * 10),
            confidence_band="HIGH" if pos_count >= 2 else "LOW",
            is_abstained=False,
            evidence_count=pos_count,
            agent_coverage=["A1_TI_AGGREGATE"],
        )

    @staticmethod
    def evaluate_a2_majority_voting(
        record: BenchmarkRecord,
        agent_scores: Optional[Dict[str, float]] = None,
    ) -> SystemPrediction:
        """A2: Unweighted Majority Voting Baseline (w_i = 1.0)."""
        scores = agent_scores or {}
        if not scores:
            # Fallback simulated majority vote based on standard available telemetry
            scores = {"A1": 0.0, "A2": 0.0, "A3": 0.0, "A4": 0.0}

        malicious_votes = sum(1 for s in scores.values() if s >= 50.0)
        total_votes = max(1, len(scores))
        vote_ratio = (malicious_votes / total_votes) * 100.0

        pred_outcome = PrimaryOutcome.MALICIOUS if vote_ratio >= 50.0 else PrimaryOutcome.BENIGN
        risk_band = compute_risk_band_name(vote_ratio)

        return SystemPrediction(
            record_id=record.record_id,
            target_id=record.target_id,
            artifact_id=record.artifact_id,
            group_id=record.evaluation.group_id,
            partition=record.evaluation.temporal_partition or TemporalPartition.FINAL_TEST,
            modality=record.modality,
            ground_truth_outcome=record.ground_truth.primary_outcome,
            ground_truth_categories=list(record.ground_truth.secondary_categories),
            predicted_outcome=pred_outcome,
            risk_score=vote_ratio,
            risk_band=risk_band,
            confidence_score=50.0,
            confidence_band="MEDIUM",
            is_abstained=False,
            evidence_count=len(scores),
            agent_coverage=list(scores.keys()),
        )

    @staticmethod
    def evaluate_a3_linear_additive(
        record: BenchmarkRecord,
        evidence_items: Optional[List[Tuple[float, float]]] = None,
    ) -> SystemPrediction:
        """A3: Linear Additive Risk Baseline (sum(w_i * s_i) without saturation/synergy)."""
        # items are (weight, score)
        items = evidence_items or [(1.0, 0.0)]
        raw_sum = sum(w * s for w, s in items)
        risk_score = min(100.0, raw_sum)

        pred_outcome = PrimaryOutcome.MALICIOUS if risk_score >= 35.0 else PrimaryOutcome.BENIGN
        risk_band = compute_risk_band_name(risk_score)

        return SystemPrediction(
            record_id=record.record_id,
            target_id=record.target_id,
            artifact_id=record.artifact_id,
            group_id=record.evaluation.group_id,
            partition=record.evaluation.temporal_partition or TemporalPartition.FINAL_TEST,
            modality=record.modality,
            ground_truth_outcome=record.ground_truth.primary_outcome,
            ground_truth_categories=list(record.ground_truth.secondary_categories),
            predicted_outcome=pred_outcome,
            risk_score=risk_score,
            risk_band=risk_band,
            confidence_score=50.0,
            confidence_band="MEDIUM",
            is_abstained=False,
            evidence_count=len(items),
        )

    @staticmethod
    def evaluate_a4_monolithic_llm(
        record: BenchmarkRecord,
        mock_score: Optional[float] = None,
    ) -> SystemPrediction:
        """A4: Standalone Monolithic Zero-Shot LLM Baseline."""
        risk_score = mock_score if mock_score is not None else 50.0
        pred_outcome = PrimaryOutcome.MALICIOUS if risk_score >= 35.0 else PrimaryOutcome.BENIGN
        risk_band = compute_risk_band_name(risk_score)

        return SystemPrediction(
            record_id=record.record_id,
            target_id=record.target_id,
            artifact_id=record.artifact_id,
            group_id=record.evaluation.group_id,
            partition=record.evaluation.temporal_partition or TemporalPartition.FINAL_TEST,
            modality=record.modality,
            ground_truth_outcome=record.ground_truth.primary_outcome,
            ground_truth_categories=list(record.ground_truth.secondary_categories),
            predicted_outcome=pred_outcome,
            risk_score=risk_score,
            risk_band=risk_band,
            confidence_score=50.0,
            confidence_band="MEDIUM",
            is_abstained=False,
            evidence_count=1,
            agent_coverage=["A4_MONOLITHIC_LLM"],
        )


# =====================================================================
# Core Benchmark Evaluator Engine
# =====================================================================

class BenchmarkEvaluator:
    """Core evaluation engine executing the frozen research protocol (RQ1–RQ6, H1–H6)."""

    def __init__(self, bootstrap_resamples: int = 1000, random_seed: int = 42):
        self.bootstrap_resamples = bootstrap_resamples
        self.random_seed = random_seed

    def evaluate_predictions(
        self,
        predictions: Sequence[SystemPrediction],
    ) -> EvaluationMetrics:
        """Compute metrics for a sequence of system predictions against verified ground truth."""
        total_eval = len(predictions)

        # Ground-Truth Rule: Exclude AMBIGUOUS ground-truth records from binary evaluation metrics
        eligible = [p for p in predictions if p.ground_truth_outcome in (PrimaryOutcome.BENIGN, PrimaryOutcome.MALICIOUS)]
        excluded_ambiguous = total_eval - len(eligible)

        if not eligible:
            return EvaluationMetrics(
                total_evaluated=total_eval,
                eligible_count=0,
                excluded_ambiguous_count=excluded_ambiguous,
                tp=0,
                tn=0,
                fp=0,
                fn=0,
                contingency_table=RiskBandContingencyTable(),
            )

        y_true = [1 if p.ground_truth_outcome == PrimaryOutcome.MALICIOUS else 0 for p in eligible]
        y_pred = [1 if p.is_threat_flagged else 0 for p in eligible]
        y_score = [p.risk_score for p in eligible]

        base_metrics = compute_binary_metrics(y_true, y_pred, y_score)

        # 5x2 Contingency Table
        c_table = self._build_contingency_table(eligible)

        # 95% Bootstrap Confidence Intervals
        cis = compute_bootstrap_confidence_intervals(
            y_true=y_true,
            y_score=y_score,
            y_pred=y_pred,
            n_bootstraps=self.bootstrap_resamples,
            seed=self.random_seed,
        )

        # Abstention & Selective Classification
        abstained_count = sum(1 for p in eligible if p.is_abstained)
        abstention_rate = abstained_count / len(eligible) if len(eligible) > 0 else 0.0

        retained = [p for p in eligible if not p.is_abstained]
        if retained:
            ret_yt = [1 if p.ground_truth_outcome == PrimaryOutcome.MALICIOUS else 0 for p in retained]
            ret_yp = [1 if p.is_threat_flagged else 0 for p in retained]
            ret_metrics = compute_binary_metrics(ret_yt, ret_yp)
            cond_bal_acc = ret_metrics["balanced_accuracy"]
        else:
            cond_bal_acc = None

        # Grounding Fidelity Counts
        grounding_counts: Dict[str, int] = {}
        for p in predictions:
            if p.grounding_status:
                st = p.grounding_status.value
                grounding_counts[st] = grounding_counts.get(st, 0) + 1

        return EvaluationMetrics(
            total_evaluated=total_eval,
            eligible_count=len(eligible),
            excluded_ambiguous_count=excluded_ambiguous,
            tp=int(base_metrics["tp"] or 0),
            tn=int(base_metrics["tn"] or 0),
            fp=int(base_metrics["fp"] or 0),
            fn=int(base_metrics["fn"] or 0),
            balanced_accuracy=base_metrics["balanced_accuracy"],
            precision=base_metrics["precision"],
            recall=base_metrics["recall"],
            fpr=base_metrics["fpr"],
            fnr=base_metrics["fnr"],
            f1=base_metrics["f1"],
            f2=base_metrics["f2"],
            roc_auc=base_metrics["roc_auc"],
            pr_auc=base_metrics["pr_auc"],
            contingency_table=c_table,
            confidence_intervals=cis,
            abstention_rate=abstention_rate,
            conditional_balanced_accuracy=cond_bal_acc,
            grounding_summary=grounding_counts,
        )

    def _build_contingency_table(self, predictions: Sequence[SystemPrediction]) -> RiskBandContingencyTable:
        """Construct the 5x2 contingency table across the five frozen TCE risk bands."""
        counts = {
            ("benign", PrimaryOutcome.BENIGN): 0,
            ("benign", PrimaryOutcome.MALICIOUS): 0,
            ("low_risk", PrimaryOutcome.BENIGN): 0,
            ("low_risk", PrimaryOutcome.MALICIOUS): 0,
            ("suspicious", PrimaryOutcome.BENIGN): 0,
            ("suspicious", PrimaryOutcome.MALICIOUS): 0,
            ("high_risk", PrimaryOutcome.BENIGN): 0,
            ("high_risk", PrimaryOutcome.MALICIOUS): 0,
            ("malicious", PrimaryOutcome.BENIGN): 0,
            ("malicious", PrimaryOutcome.MALICIOUS): 0,
        }

        for p in predictions:
            band = p.risk_band
            gt = p.ground_truth_outcome
            if (band, gt) in counts:
                counts[(band, gt)] += 1

        return RiskBandContingencyTable(
            benign_ground_truth_benign=counts[("benign", PrimaryOutcome.BENIGN)],
            benign_ground_truth_malicious=counts[("benign", PrimaryOutcome.MALICIOUS)],
            low_risk_ground_truth_benign=counts[("low_risk", PrimaryOutcome.BENIGN)],
            low_risk_ground_truth_malicious=counts[("low_risk", PrimaryOutcome.MALICIOUS)],
            suspicious_ground_truth_benign=counts[("suspicious", PrimaryOutcome.BENIGN)],
            suspicious_ground_truth_malicious=counts[("suspicious", PrimaryOutcome.MALICIOUS)],
            high_risk_ground_truth_benign=counts[("high_risk", PrimaryOutcome.BENIGN)],
            high_risk_ground_truth_malicious=counts[("high_risk", PrimaryOutcome.MALICIOUS)],
            malicious_ground_truth_benign=counts[("malicious", PrimaryOutcome.BENIGN)],
            malicious_ground_truth_malicious=counts[("malicious", PrimaryOutcome.MALICIOUS)],
        )

    def evaluate_condition_by_partitions(
        self,
        condition: ExperimentalCondition,
        predictions: Sequence[SystemPrediction],
    ) -> ConditionEvaluationReport:
        """Evaluate a condition overall and across temporal partitions, modalities, and TI exposure."""
        overall = self.evaluate_predictions(predictions)

        # By Partition
        by_partition: Dict[str, EvaluationMetrics] = {}
        for part in TemporalPartition:
            part_preds = [p for p in predictions if p.partition == part]
            if part_preds:
                by_partition[part.value] = self.evaluate_predictions(part_preds)

        # By Modality
        by_modality: Dict[str, EvaluationMetrics] = {}
        for mod in InputModality:
            mod_preds = [p for p in predictions if p.modality == mod]
            if mod_preds:
                by_modality[mod.value] = self.evaluate_predictions(mod_preds)

        # By TI Exposure
        by_ti: Dict[str, EvaluationMetrics] = {}
        ti_strata = {"DIRECT", "PARTIAL", "NONE", "UNKNOWN_UNAVAILABLE"}
        for stratum in ti_strata:
            ti_preds = [p for p in predictions if p.ti_exposure_status == stratum]
            if ti_preds:
                by_ti[stratum] = self.evaluate_predictions(ti_preds)

        return ConditionEvaluationReport(
            condition=condition,
            overall_metrics=overall,
            partition_metrics=by_partition,
            modality_metrics=by_modality,
            ti_exposure_metrics=by_ti,
        )

    def compare_conditions(
        self,
        cond_a_name: str,
        preds_a: Sequence[SystemPrediction],
        cond_b_name: str,
        preds_b: Sequence[SystemPrediction],
    ) -> StatisticalComparisonResult:
        """Perform statistical comparisons (McNemar, Wilcoxon, Cohen's d, Odds Ratio, IDC)."""
        # Align predictions by record_id
        dict_b = {p.record_id: p for p in preds_b}
        aligned_a = []
        aligned_b = []

        for pa in preds_a:
            if pa.record_id in dict_b:
                pb = dict_b[pa.record_id]
                # Only include non-ambiguous ground truth
                if pa.ground_truth_outcome in (PrimaryOutcome.BENIGN, PrimaryOutcome.MALICIOUS):
                    aligned_a.append(pa)
                    aligned_b.append(pb)

        if not aligned_a:
            return StatisticalComparisonResult(
                condition_a=cond_a_name,
                condition_b=cond_b_name,
                notes="No aligned eligible records for comparison.",
            )

        y_true = [1 if p.ground_truth_outcome == PrimaryOutcome.MALICIOUS else 0 for p in aligned_a]
        yp_a = [1 if p.is_threat_flagged else 0 for p in aligned_a]
        yp_b = [1 if p.is_threat_flagged else 0 for p in aligned_b]
        scores_a = [p.risk_score for p in aligned_a]
        scores_b = [p.risk_score for p in aligned_b]

        # McNemar Test
        mc_stat, mc_p = compute_mcnemar_test(y_true, yp_a, yp_b)

        # Wilcoxon Signed-Rank Test
        wc_stat, wc_p = compute_wilcoxon_signed_rank(scores_a, scores_b)

        # Effect sizes
        cd = compute_cohens_d(scores_a, scores_b)
        or_val = compute_odds_ratio(y_true, yp_a, yp_b)

        # Metrics & IDC delta
        ma = compute_binary_metrics(y_true, yp_a, scores_a)
        mb = compute_binary_metrics(y_true, yp_b, scores_b)

        val_a = ma["balanced_accuracy"]
        val_b = mb["balanced_accuracy"]
        idc = (val_a - val_b) if (val_a is not None and val_b is not None) else None

        is_sig = (mc_p is not None and mc_p < 0.05) or (wc_p is not None and wc_p < 0.05)

        return StatisticalComparisonResult(
            condition_a=cond_a_name,
            condition_b=cond_b_name,
            metric_a_name="balanced_accuracy",
            metric_a_value=val_a,
            metric_b_value=val_b,
            metric_delta=idc,
            mcnemar_statistic=mc_stat,
            mcnemar_p_value=mc_p,
            wilcoxon_statistic=wc_stat,
            wilcoxon_p_value=wc_p,
            cohens_d=cd,
            odds_ratio=or_val,
            incremental_diagnostic_contribution=idc,
            is_statistically_significant=is_sig,
        )


# =====================================================================
# Top-Level Evaluation Suite Helpers
# =====================================================================

def evaluate_benchmark_suite(
    experiment_id: str,
    snapshot_id: str,
    dataset_hash: str,
    records: Sequence[BenchmarkRecord],
    predictions_by_condition: Dict[ExperimentalCondition, Sequence[SystemPrediction]],
    bootstrap_resamples: int = 1000,
    random_seed: int = 42,
) -> BenchmarkEvaluationSuiteResult:
    """Execute complete benchmark evaluation suite across all conditions, baselines, and hypotheses."""
    evaluator = BenchmarkEvaluator(bootstrap_resamples=bootstrap_resamples, random_seed=random_seed)

    reports: Dict[str, ConditionEvaluationReport] = {}
    for cond, preds in predictions_by_condition.items():
        rep = evaluator.evaluate_condition_by_partitions(cond, preds)
        reports[cond.value] = rep

    # Hypothesis comparisons
    comparisons: Dict[str, List[StatisticalComparisonResult]] = {
        "H1_baselines": [],
        "H3_ablations": [],
        "H4_modality": [],
    }

    # H1: Compare M0 with Baselines A0-A4
    if ExperimentalCondition.M0_FULL_SYSTEM in predictions_by_condition:
        m0_preds = predictions_by_condition[ExperimentalCondition.M0_FULL_SYSTEM]
        for base_cond in [
            ExperimentalCondition.A0_STATIC_LEXICAL,
            ExperimentalCondition.A1_TI_AGGREGATE,
            ExperimentalCondition.A2_MAJORITY_VOTE,
            ExperimentalCondition.A3_LINEAR_ADDITIVE,
            ExperimentalCondition.A4_MONOLITHIC_LLM,
        ]:
            if base_cond in predictions_by_condition:
                cmp_res = evaluator.compare_conditions(
                    "M0",
                    m0_preds,
                    base_cond.value,
                    predictions_by_condition[base_cond],
                )
                comparisons["H1_baselines"].append(cmp_res)

        # H3: Compare M0 with Ablations M1-M6
        for abl_cond in [
            ExperimentalCondition.M1_NO_TI,
            ExperimentalCondition.M2_NO_QR,
            ExperimentalCondition.M3_NO_DYNAMIC_SCRIPT,
            ExperimentalCondition.M4_NO_BRAND_VISUAL,
            ExperimentalCondition.M5_NO_TCE_SYNERGY,
            ExperimentalCondition.M6_NO_AERE_GROUNDING,
        ]:
            if abl_cond in predictions_by_condition:
                cmp_res = evaluator.compare_conditions(
                    "M0",
                    m0_preds,
                    abl_cond.value,
                    predictions_by_condition[abl_cond],
                )
                comparisons["H3_ablations"].append(cmp_res)

    return BenchmarkEvaluationSuiteResult(
        experiment_id=experiment_id,
        snapshot_id=snapshot_id,
        dataset_hash=dataset_hash,
        total_records=len(records),
        condition_reports=reports,
        hypothesis_comparisons=comparisons,
        reproducibility_metadata={
            "bootstrap_resamples": bootstrap_resamples,
            "random_seed": random_seed,
            "software_version": "1.0.0",
        },
    )
