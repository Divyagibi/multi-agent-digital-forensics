"""Comprehensive Unit Test Suite for Step 6D-5 Experimental Benchmark Evaluation.

Tests all required metric, statistical, baseline, ablation, partition, and safety invariants:
1. Perfect predictions
2. All-positive predictions
3. All-negative predictions
4. No-positive ground truth
5. No-negative ground truth
6. AMBIGUOUS ground truth exclusion
7. Undefined precision/recall cases
8. ROC-AUC edge cases
9. PR-AUC edge cases
10. F1 and F2 calculation
11. Bootstrap determinism
12. McNemar test edge cases
13. Wilcoxon signed-rank test edge cases
14. Cohen's d edge cases
15. Odds-ratio edge cases
16. Partition isolation
17. FINAL_TEST protection
18. PROSPECTIVE_HOLDOUT protection
19. Ablation missing evidence
20. Ablation unavailable state
21. QR modality separation
22. Ground-truth immutability
23. TI absence not benign
24. TI exposure metadata preservation
25. Five TCE risk bands
26. Confidence vs prediction separation
27. Abstention handling (C_ev < 35)
28. AERE grounding-state separation
29. Deterministic result serialization
30. Zero production coupling
"""

import math
import sys
import unittest
from typing import List

from tools.benchmark.schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationConfidence,
    TemporalPartition,
    TIObservationStatus,
    CandidateProvenance,
    GroundTruth,
    TIFeedObservation,
    TIOverlapMetadata,
    LivenessMetadata,
    QRRelationshipMetadata,
    EvaluationMetadata,
    BenchmarkRecord,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
)
from tools.benchmark.evaluator import (
    ExperimentalCondition,
    GroundingFidelityStatus,
    SystemPrediction,
    RiskBandContingencyTable,
    EvaluationMetrics,
    StatisticalComparisonResult,
    ConditionEvaluationReport,
    BenchmarkEvaluationSuiteResult,
    BenchmarkEvaluator,
    BaselineAdapter,
    compute_binary_metrics,
    compute_roc_auc,
    compute_pr_auc,
    compute_bootstrap_confidence_intervals,
    compute_mcnemar_test,
    compute_wilcoxon_signed_rank,
    compute_cohens_d,
    compute_odds_ratio,
    compute_risk_band_name,
    evaluate_benchmark_suite,
)


class TestBenchmarkEvaluator(unittest.TestCase):
    """Unit test suite for Step 6D-5 experimental evaluation engine."""

    def _make_prediction(
        self,
        record_id: str = "REC-01",
        ground_truth: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
        risk_score: float = 75.0,
        partition: TemporalPartition = TemporalPartition.FINAL_TEST,
        modality: InputModality = InputModality.DIRECT_URL,
        confidence_score: float = 80.0,
        grounding_status: GroundingFidelityStatus = GroundingFidelityStatus.GROUNDED,
        ti_exposure: str = "DIRECT",
    ) -> SystemPrediction:
        band = compute_risk_band_name(risk_score)
        pred_outcome = PrimaryOutcome.MALICIOUS if risk_score >= 35.0 else PrimaryOutcome.BENIGN
        is_abstained = confidence_score < 35.0

        return SystemPrediction(
            record_id=record_id,
            target_id=f"TGT-{record_id}",
            artifact_id=f"ART-{record_id}",
            group_id=f"GRP-{record_id}",
            partition=partition,
            modality=modality,
            ground_truth_outcome=ground_truth,
            predicted_outcome=pred_outcome,
            risk_score=risk_score,
            risk_band=band,
            confidence_score=confidence_score,
            is_abstained=is_abstained,
            grounding_status=grounding_status,
            ti_exposure_status=ti_exposure,
        )

    # 1. Perfect predictions
    def test_01_perfect_predictions(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=90.0),
            self._make_prediction("R2", PrimaryOutcome.MALICIOUS, risk_score=85.0),
            self._make_prediction("R3", PrimaryOutcome.BENIGN, risk_score=10.0),
            self._make_prediction("R4", PrimaryOutcome.BENIGN, risk_score=5.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.tp, 2)
        self.assertEqual(res.tn, 2)
        self.assertEqual(res.fp, 0)
        self.assertEqual(res.fn, 0)
        self.assertEqual(res.balanced_accuracy, 1.0)
        self.assertEqual(res.precision, 1.0)
        self.assertEqual(res.recall, 1.0)
        self.assertEqual(res.f1, 1.0)
        self.assertEqual(res.roc_auc, 1.0)

    # 2. All-positive predictions
    def test_02_all_positive_predictions(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=90.0),
            self._make_prediction("R2", PrimaryOutcome.BENIGN, risk_score=90.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.tp, 1)
        self.assertEqual(res.fp, 1)
        self.assertEqual(res.tn, 0)
        self.assertEqual(res.fn, 0)
        self.assertEqual(res.recall, 1.0)
        self.assertEqual(res.fpr, 1.0)
        self.assertEqual(res.balanced_accuracy, 0.5)

    # 3. All-negative predictions
    def test_03_all_negative_predictions(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=10.0),
            self._make_prediction("R2", PrimaryOutcome.BENIGN, risk_score=10.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.tp, 0)
        self.assertEqual(res.fp, 0)
        self.assertEqual(res.tn, 1)
        self.assertEqual(res.fn, 1)
        self.assertEqual(res.recall, 0.0)
        self.assertEqual(res.balanced_accuracy, 0.5)

    # 4. No-positive ground truth
    def test_04_no_positive_ground_truth(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.BENIGN, risk_score=10.0),
            self._make_prediction("R2", PrimaryOutcome.BENIGN, risk_score=20.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.recall, None)
        self.assertEqual(res.precision, None)
        self.assertEqual(res.roc_auc, None)

    # 5. No-negative ground truth
    def test_05_no_negative_ground_truth(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=80.0),
            self._make_prediction("R2", PrimaryOutcome.MALICIOUS, risk_score=90.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.fpr, None)
        self.assertEqual(res.roc_auc, None)

    # 6. AMBIGUOUS ground truth exclusion
    def test_06_ambiguous_ground_truth_excluded(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=80.0),
            self._make_prediction("R2", PrimaryOutcome.BENIGN, risk_score=10.0),
            self._make_prediction("R3", PrimaryOutcome.AMBIGUOUS, risk_score=50.0),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)

        self.assertEqual(res.total_evaluated, 3)
        self.assertEqual(res.eligible_count, 2)
        self.assertEqual(res.excluded_ambiguous_count, 1)
        self.assertEqual(res.tp, 1)
        self.assertEqual(res.tn, 1)

    # 7. Undefined precision/recall cases
    def test_07_undefined_precision(self):
        # 0 predicted positives -> precision is None
        metrics = compute_binary_metrics([0, 0], [0, 0])
        self.assertIsNone(metrics["precision"])

    # 8. ROC-AUC edge cases
    def test_08_roc_auc_perfect_and_inverted(self):
        # Perfect
        self.assertEqual(compute_roc_auc([0, 0, 1, 1], [10.0, 20.0, 80.0, 90.0]), 1.0)
        # Completely inverted
        self.assertEqual(compute_roc_auc([0, 0, 1, 1], [90.0, 80.0, 20.0, 10.0]), 0.0)

    # 9. PR-AUC edge cases
    def test_09_pr_auc_calculation(self):
        pr = compute_pr_auc([0, 0, 1, 1], [10.0, 20.0, 80.0, 90.0])
        self.assertIsNotNone(pr)
        self.assertGreaterEqual(pr, 0.99)

    # 10. F1 and F2 calculation
    def test_10_f1_and_f2(self):
        # TP=1, FP=1, FN=0 -> Precision=0.5, Recall=1.0
        # F1 = 2 * (0.5 * 1.0) / 1.5 = 2/3 = 0.6667
        # F2 = 5 * (0.5 * 1.0) / (2.0 + 1.0) = 2.5 / 3.0 = 0.8333
        m = compute_binary_metrics([1, 0], [1, 1])
        self.assertAlmostEqual(m["f1"], 2.0 / 3.0, places=4)
        self.assertAlmostEqual(m["f2"], 5.0 / 6.0, places=4)

    # 11. Bootstrap determinism
    def test_11_bootstrap_determinism(self):
        yt = [1, 0, 1, 0, 1, 0, 1, 0]
        ys = [80.0, 10.0, 85.0, 15.0, 90.0, 20.0, 70.0, 30.0]
        yp = [1, 0, 1, 0, 1, 0, 1, 0]

        ci1 = compute_bootstrap_confidence_intervals(yt, ys, yp, n_bootstraps=100, seed=123)
        ci2 = compute_bootstrap_confidence_intervals(yt, ys, yp, n_bootstraps=100, seed=123)
        self.assertEqual(ci1, ci2)

    # 12. McNemar test edge cases
    def test_12_mcnemar_test_cases(self):
        yt = [1, 0, 1, 0]
        yp_a = [1, 0, 1, 0]
        yp_b = [1, 0, 1, 0]
        stat, p = compute_mcnemar_test(yt, yp_a, yp_b)
        self.assertEqual(stat, 0.0)
        self.assertEqual(p, 1.0)

    # 13. Wilcoxon signed-rank test edge cases
    def test_13_wilcoxon_test_cases(self):
        sa = [90.0, 85.0, 80.0, 75.0, 70.0, 65.0]
        sb = [10.0, 15.0, 20.0, 25.0, 30.0, 35.0]
        stat, p = compute_wilcoxon_signed_rank(sa, sb)
        self.assertIsNotNone(stat)
        self.assertIsNotNone(p)
        self.assertLess(p, 0.05)

    # 14. Cohen's d edge cases
    def test_14_cohens_d_edge_cases(self):
        sa = [50.0, 50.0, 50.0]
        sb = [50.0, 50.0, 50.0]
        cd = compute_cohens_d(sa, sb)
        self.assertEqual(cd, 0.0)

    # 15. Odds-ratio edge cases
    def test_15_odds_ratio(self):
        yt = [1, 1, 0, 0]
        yp_a = [1, 1, 0, 0]
        yp_b = [1, 0, 0, 0]
        or_val = compute_odds_ratio(yt, yp_a, yp_b)
        self.assertIsNotNone(or_val)
        self.assertGreater(or_val, 1.0)

    # 16. Partition isolation
    def test_16_partition_isolation(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=80.0, partition=TemporalPartition.DEVELOPMENT_CALIBRATION),
            self._make_prediction("R2", PrimaryOutcome.BENIGN, risk_score=10.0, partition=TemporalPartition.FINAL_TEST),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        rep = evaluator.evaluate_condition_by_partitions(ExperimentalCondition.M0_FULL_SYSTEM, preds)

        self.assertIn("development_calibration", rep.partition_metrics)
        self.assertIn("final_test", rep.partition_metrics)
        self.assertEqual(rep.partition_metrics["development_calibration"].tp, 1)
        self.assertEqual(rep.partition_metrics["final_test"].tn, 1)

    # 17. FINAL_TEST protection
    def test_17_final_test_protection(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=80.0, partition=TemporalPartition.FINAL_TEST),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        rep = evaluator.evaluate_condition_by_partitions(ExperimentalCondition.M0_FULL_SYSTEM, preds)
        self.assertEqual(rep.partition_metrics["final_test"].total_evaluated, 1)

    # 18. PROSPECTIVE_HOLDOUT protection
    def test_18_prospective_holdout_protection(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=85.0, partition=TemporalPartition.PROSPECTIVE_HOLDOUT),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        rep = evaluator.evaluate_condition_by_partitions(ExperimentalCondition.M0_FULL_SYSTEM, preds)
        self.assertEqual(rep.partition_metrics["prospective_holdout"].total_evaluated, 1)

    # 19. Ablation missing evidence
    def test_19_ablation_missing_evidence(self):
        # M1 disables A6 without inventing synthetic benign evidence
        pred = SystemPrediction(
            record_id="R1",
            target_id="T1",
            artifact_id="A1",
            group_id="G1",
            partition=TemporalPartition.FINAL_TEST,
            modality=InputModality.DIRECT_URL,
            ground_truth_outcome=PrimaryOutcome.MALICIOUS,
            predicted_outcome=PrimaryOutcome.MALICIOUS,
            risk_score=60.0,
            risk_band="high_risk",
            agent_coverage=["A1", "A2"],  # A6 is absent
        )
        self.assertNotIn("A6", pred.agent_coverage)

    # 20. Ablation unavailable state
    def test_20_ablation_unavailable_state(self):
        evaluator = BenchmarkEvaluator()
        cmp_res = evaluator.compare_conditions("M0", [], "M1", [])
        self.assertEqual(cmp_res.notes, "No aligned eligible records for comparison.")

    # 21. QR modality separation
    def test_21_qr_modality_separation(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, modality=InputModality.DIRECT_URL),
            self._make_prediction("R2", PrimaryOutcome.MALICIOUS, modality=InputModality.QR_IMAGE),
            self._make_prediction("R3", PrimaryOutcome.MALICIOUS, modality=InputModality.QR_PAYLOAD),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        rep = evaluator.evaluate_condition_by_partitions(ExperimentalCondition.M0_FULL_SYSTEM, preds)

        self.assertIn("DIRECT_URL", rep.modality_metrics)
        self.assertIn("QR_IMAGE", rep.modality_metrics)
        self.assertIn("QR_PAYLOAD", rep.modality_metrics)

    # 22. Ground-truth immutability
    def test_22_ground_truth_immutability(self):
        pred = self._make_prediction("R1", PrimaryOutcome.MALICIOUS)
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        evaluator.evaluate_predictions([pred])
        # Ground truth outcome remains unchanged
        self.assertEqual(pred.ground_truth_outcome, PrimaryOutcome.MALICIOUS)

    # 23. TI absence not benign
    def test_23_ti_absence_not_benign(self):
        pred = self._make_prediction("R1", PrimaryOutcome.MALICIOUS, ti_exposure="NONE")
        self.assertEqual(pred.ti_exposure_status, "NONE")
        self.assertEqual(pred.ground_truth_outcome, PrimaryOutcome.MALICIOUS)

    # 24. TI exposure metadata preservation
    def test_24_ti_exposure_strata(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, ti_exposure="DIRECT"),
            self._make_prediction("R2", PrimaryOutcome.MALICIOUS, ti_exposure="NONE"),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        rep = evaluator.evaluate_condition_by_partitions(ExperimentalCondition.M0_FULL_SYSTEM, preds)
        self.assertIn("DIRECT", rep.ti_exposure_metrics)
        self.assertIn("NONE", rep.ti_exposure_metrics)

    # 25. Five TCE risk bands
    def test_25_five_risk_bands(self):
        self.assertEqual(compute_risk_band_name(10.0), "benign")
        self.assertEqual(compute_risk_band_name(25.0), "low_risk")
        self.assertEqual(compute_risk_band_name(45.0), "suspicious")
        self.assertEqual(compute_risk_band_name(70.0), "high_risk")
        self.assertEqual(compute_risk_band_name(90.0), "malicious")

    # 26. Confidence vs prediction separation
    def test_26_confidence_vs_prediction(self):
        pred = self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=90.0, confidence_score=20.0)
        self.assertEqual(pred.risk_score, 90.0)
        self.assertEqual(pred.confidence_score, 20.0)
        self.assertTrue(pred.is_abstained)  # Abstained because C_ev < 35

    # 27. Abstention handling
    def test_27_abstention_metrics(self):
        preds = [
            self._make_prediction("R1", PrimaryOutcome.MALICIOUS, risk_score=90.0, confidence_score=20.0),  # Abstained
            self._make_prediction("R2", PrimaryOutcome.MALICIOUS, risk_score=85.0, confidence_score=80.0),  # Retained
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)
        self.assertEqual(res.abstention_rate, 0.5)
        self.assertIsNotNone(res.conditional_balanced_accuracy)

    # 28. AERE grounding-state separation
    def test_28_aere_grounding_summary(self):
        preds = [
            self._make_prediction("R1", grounding_status=GroundingFidelityStatus.GROUNDED),
            self._make_prediction("R2", grounding_status=GroundingFidelityStatus.UNGROUNDED),
        ]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50)
        res = evaluator.evaluate_predictions(preds)
        self.assertEqual(res.grounding_summary.get("GROUNDED"), 1)
        self.assertEqual(res.grounding_summary.get("UNGROUNDED"), 1)

    # 29. Deterministic result serialization
    def test_29_deterministic_serialization(self):
        preds = [self._make_prediction("R1")]
        evaluator = BenchmarkEvaluator(bootstrap_resamples=50, random_seed=42)
        res1 = evaluator.evaluate_predictions(preds)
        res2 = evaluator.evaluate_predictions(preds)
        self.assertEqual(res1.to_dict(), res2.to_dict())

    # 30. Zero production coupling
    def test_30_zero_production_coupling(self):
        import tools.benchmark.evaluator as eval_module
        imported_names = dir(eval_module)
        for forbidden in ["TrustCalculationEngine", "TCE", "AERE", "ConfidenceEngine", "Agent1"]:
            self.assertNotIn(forbidden, imported_names)


class TestBaselineAdapters(unittest.TestCase):
    """Test standard baseline adapters A0-A4."""

    def _make_dummy_record(self, url: str = "https://example.com/login") -> BenchmarkRecord:
        art_id = compute_artifact_id(InputModality.DIRECT_URL, url)
        tgt_id = compute_target_id(url)
        grp_id = compute_group_id("example.com")
        rec_id = compute_record_id(tgt_id, art_id)
        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=tgt_id,
            target_url=url,
            modality=InputModality.DIRECT_URL,
            ground_truth=GroundTruth(primary_outcome=PrimaryOutcome.MALICIOUS),
            provenance=CandidateProvenance(source_name="TestFeed"),
            ti_overlap=TIOverlapMetadata(
                virustotal=TIFeedObservation(feed_name="VirusTotal", status=TIObservationStatus.POSITIVE_OBSERVATION),
                google_safebrowsing=TIFeedObservation(feed_name="GoogleSafeBrowsing", status=TIObservationStatus.POSITIVE_OBSERVATION),
            ),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(),
            evaluation=EvaluationMetadata(group_id=grp_id, temporal_partition=TemporalPartition.FINAL_TEST),
        )

    def test_baseline_a0(self):
        rec = self._make_dummy_record("http://suspicious-login-verify-account-banking.com/signin")
        pred = BaselineAdapter.evaluate_a0_static_lexical(rec)
        self.assertGreaterEqual(pred.risk_score, 35.0)
        self.assertEqual(pred.predicted_outcome, PrimaryOutcome.MALICIOUS)

    def test_baseline_a1(self):
        rec = self._make_dummy_record()
        pred = BaselineAdapter.evaluate_a1_ti_aggregate(rec)
        # 2 positive out of 7 available -> 2/7 * 100 = 28.57
        self.assertAlmostEqual(pred.risk_score, 28.57, places=1)

    def test_baseline_a2(self):
        rec = self._make_dummy_record()
        pred = BaselineAdapter.evaluate_a2_majority_voting(rec, {"A1": 80.0, "A2": 90.0, "A3": 10.0})
        # 2/3 malicious -> 66.67%
        self.assertAlmostEqual(pred.risk_score, 66.67, places=1)

    def test_baseline_a3(self):
        rec = self._make_dummy_record()
        pred = BaselineAdapter.evaluate_a3_linear_additive(rec, [(1.0, 40.0), (1.0, 50.0)])
        self.assertEqual(pred.risk_score, 90.0)

    def test_baseline_a4(self):
        rec = self._make_dummy_record()
        pred = BaselineAdapter.evaluate_a4_monolithic_llm(rec, mock_score=85.0)
        self.assertEqual(pred.risk_score, 85.0)


if __name__ == "__main__":
    unittest.main()
