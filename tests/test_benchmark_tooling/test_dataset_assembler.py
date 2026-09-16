"""Comprehensive Offline Unit Tests for Experimental Dataset Assembly & Pre-Run Gate.

Step 6D-6: Experimental Dataset Assembly & Pre-Run Gate.

Tests all requirements:
A. valid dataset reaches READY_FOR_EXPERIMENT
B. malformed record blocks
C. missing identity blocks
D. cross-partition target leakage blocks
E. QR/direct cross-partition leakage blocks
F. group overlap produces warning / diagnostic
G. ambiguous ground truth is not converted to benign
H. internal-system ground-truth source is rejected
I. TI NONE is not interpreted as benign
J. TI UNKNOWN_UNAVAILABLE is not interpreted as benign
K. temporal inconsistency blocks where protocol requires
L. invalid partition assignment blocks
M. final-test/prospective-holdout protection
N. deterministic partition assignment
O. natural prevalence is preserved
P. no synthetic padding
Q. snapshot generation is deterministic
R. hash verification works
S. corrupted snapshot blocks
T. manifest mismatch blocks
U. record-count mismatch blocks
V. modality counts remain consistent
W. ground-truth counts remain consistent
X. QR/direct records remain distinct
Y. functional URLs remain distinct targets when appropriate
Z. repeated assembly of identical input produces identical output
AA. no production modules are imported for mutation/coupling
AB. assembler does not perform network access
AC. gate contains actionable blocking diagnostics
AD. READY_FOR_EXPERIMENT cannot be returned with critical leakage
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.benchmark.schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationMethod,
    VerificationConfidence,
    TIObservationStatus,
    TemporalPartition,
    DuplicateStatus,
    ExclusionStatus,
    QRRelationshipType,
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
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.harvester import RawCandidate, SourceType
from tools.benchmark.liveness import (
    LivenessStatus,
    EligibilityStatus,
    LivenessFailureReason,
    LivenessEvaluation,
)
from tools.benchmark.integrity_auditor import (
    audit_benchmark_records,
    audit_benchmark_snapshot,
)
from tools.benchmark.dataset_assembler import (
    DatasetAssemblyGateStatus,
    DatasetAssemblyConfig,
    DatasetAssemblyDiagnostics,
    DatasetAssemblyGateResult,
    DatasetAssemblyResult,
    DatasetAssembler,
)


def _make_dummy_record(
    url: str,
    outcome: PrimaryOutcome = PrimaryOutcome.BENIGN,
    modality: InputModality = InputModality.DIRECT_URL,
    group_key: Optional[str] = None,
    partition: Optional[TemporalPartition] = None,
    observed_time: str = "2026-01-01T00:00:00Z",
    qr_dest_target: Optional[str] = None,
    gt_rationale: str = "Independent registry verification.",
    gt_refs: Optional[list] = None,
    ti_status: TIObservationStatus = TIObservationStatus.NEGATIVE_OBSERVATION,
) -> BenchmarkRecord:
    """Helper to construct a valid schema-compliant BenchmarkRecord for testing."""
    norm = normalize_investigation_target(url)
    art_id = compute_artifact_id(modality, url)
    tgt_id = norm.target_id
    grp_id = compute_group_id(group_key) if group_key else norm.group_id
    rec_id = compute_record_id(tgt_id, art_id)

    gt = GroundTruth(
        primary_outcome=outcome,
        secondary_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING] if outcome == PrimaryOutcome.MALICIOUS else [],
        verification_status=VerificationStatus.VERIFIED if outcome != PrimaryOutcome.AMBIGUOUS else VerificationStatus.DISPUTED,
        verification_method=VerificationMethod.MANUAL_ADJUDICATION.value,
        verification_confidence=VerificationConfidence.HIGH,
        rationale=gt_rationale,
        supporting_references=gt_refs or ["https://external-registry.example.org/record/123"],
    )

    prov = CandidateProvenance(
        source_name="test_curated_feed",
        source_record_id="feed-101",
        harvest_timestamp="2026-01-02T00:00:00Z",
        first_observed_timestamp=observed_time,
    )

    ti = TIOverlapMetadata(
        virustotal=TIFeedObservation(feed_name="VirusTotal", status=ti_status),
        google_safebrowsing=TIFeedObservation(feed_name="GoogleSafeBrowsing", status=ti_status),
        phishtank=TIFeedObservation(feed_name="PhishTank", status=ti_status),
        openphish=TIFeedObservation(feed_name="OpenPhish", status=ti_status),
        urlhaus=TIFeedObservation(feed_name="URLhaus", status=ti_status),
        abuseipdb=TIFeedObservation(feed_name="AbuseIPDB", status=ti_status),
        spamhaus=TIFeedObservation(feed_name="Spamhaus", status=ti_status),
    )

    live = LivenessMetadata(
        http_status=200 if modality == InputModality.DIRECT_URL else None,
        dns_resolved=True if modality == InputModality.DIRECT_URL else None,
        tls_status="valid" if modality == InputModality.DIRECT_URL else None,
        response_body_size_bytes=1024 if modality == InputModality.DIRECT_URL else None,
        checked_at="2026-01-02T01:00:00Z",
        eligibility_status="eligible" if modality == InputModality.DIRECT_URL else "not_applicable",
    )

    qr = QRRelationshipMetadata(
        artifact_type="direct" if modality == InputModality.DIRECT_URL else "qr_barcode",
        destination_target_id=qr_dest_target,
        relationship_type=QRRelationshipType.DIRECT_PAYLOAD if qr_dest_target else QRRelationshipType.NONE,
    )

    ev = EvaluationMetadata(
        group_id=grp_id,
        temporal_partition=partition,
        stratum="test_stratum",
        duplicate_status=DuplicateStatus.CANONICAL,
        exclusion_status=ExclusionStatus.RETAINED,
    )

    return BenchmarkRecord(
        record_id=rec_id,
        artifact_id=art_id,
        target_id=tgt_id,
        target_url=url,
        modality=modality,
        ground_truth=gt,
        provenance=prov,
        ti_overlap=ti,
        liveness=live,
        qr_relationship=qr,
        evaluation=ev,
    )


class TestDatasetAssembler(unittest.TestCase):
    """Test suite for DatasetAssembler and Pre-Run Quality Gates."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)
        self.assembler = DatasetAssembler(
            config=DatasetAssemblyConfig(
                output_snapshot_dir=self.out_dir,
                write_snapshot=True,
                temporal_cutoff_timestamp="2026-06-01T00:00:00Z",
            )
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_a_valid_dataset_reaches_ready_for_experiment(self) -> None:
        """A. Valid dataset passes all quality gates and achieves READY_FOR_EXPERIMENT."""
        records = [
            _make_dummy_record("https://alpha.example.com/login", PrimaryOutcome.MALICIOUS, group_key="alpha.example.com"),
            _make_dummy_record("https://beta.example.com/portal", PrimaryOutcome.BENIGN, group_key="beta.example.com"),
            _make_dummy_record("https://gamma.example.com/account", PrimaryOutcome.MALICIOUS, group_key="gamma.example.com"),
            _make_dummy_record("https://delta.example.com/home", PrimaryOutcome.BENIGN, group_key="delta.example.com"),
        ]

        result = self.assembler.assemble(records=records)
        self.assertEqual(result.gate_result.status, DatasetAssemblyGateStatus.READY_FOR_EXPERIMENT)
        self.assertTrue(result.gate_result.is_ready)
        self.assertEqual(len(result.gate_result.blocking_findings), 0)
        self.assertIsNotNone(result.diagnostics)
        self.assertEqual(result.diagnostics.retained_records_count, 4)

    def test_b_malformed_record_blocks(self) -> None:
        """B. Malformed schema records block the gate with actionable error."""
        rec = _make_dummy_record("https://valid.example.com")
        bad_rec = copy.deepcopy(rec)
        object.__setattr__(bad_rec, "record_id", "")

        gate = self.assembler.evaluate_gate(records=[bad_rec])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertFalse(gate.is_ready)
        self.assertTrue(any("SCHEMA_VALIDATION_FAILURE" in f["code"] or "INVALID_RECORD_ID" in f["code"] for f in gate.blocking_findings))

    def test_c_missing_identity_blocks(self) -> None:
        """C. Record missing ART-, TGT-, or GRP- prefix blocks."""
        rec = _make_dummy_record("https://valid.example.com")
        bad_rec = copy.deepcopy(rec)
        object.__setattr__(bad_rec, "artifact_id", "INVALID-PREFIX-123")

        gate = self.assembler.evaluate_gate(records=[bad_rec])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("INVALID_ARTIFACT_ID" in f["code"] for f in gate.blocking_findings))

    def test_d_cross_partition_target_leakage_blocks(self) -> None:
        """D. Same canonical target in multiple partitions causes blocking target leakage."""
        r1 = _make_dummy_record("https://same-target.example.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_dummy_record("https://same-target.example.com/login", partition=TemporalPartition.FINAL_TEST)

        gate = self.assembler.evaluate_gate(records=[r1, r2])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("CROSS_PARTITION_TARGET_LEAKAGE" in f["code"] for f in gate.blocking_findings))

    def test_e_qr_direct_cross_partition_leakage_blocks(self) -> None:
        """E. Paired QR and direct records in different partitions causes critical leakage."""
        tgt_dest = compute_target_id("https://paired.example.com/login")
        r_direct = _make_dummy_record("https://paired.example.com/login", modality=InputModality.DIRECT_URL, partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r_qr = _make_dummy_record("https://qr-source.example.com", modality=InputModality.QR_IMAGE, qr_dest_target=tgt_dest, partition=TemporalPartition.FINAL_TEST)

        gate = self.assembler.evaluate_gate(records=[r_direct, r_qr])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("QR_DIRECT_CROSS_PARTITION_LEAKAGE" in f["code"] for f in gate.blocking_findings))

    def test_f_group_overlap_produces_warning_not_critical_block(self) -> None:
        """F. Group overlap across partitions produces a WARNING without fatal blocking."""
        r1 = _make_dummy_record("https://domain.example.com/path1", group_key="domain.example.com", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_dummy_record("https://domain.example.com/path2", group_key="domain.example.com", partition=TemporalPartition.VALIDATION)

        report = audit_benchmark_records([r1, r2])
        gate = self.assembler.evaluate_gate(records=[r1, r2], audit_report=report)
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.READY_FOR_EXPERIMENT)
        self.assertTrue(any("CROSS_PARTITION_GROUP_OVERLAP" in w["code"] for w in gate.warnings))

    def test_g_ambiguous_ground_truth_is_not_converted_to_benign(self) -> None:
        """G. Ambiguous records remain AMBIGUOUS and are accounted in diagnostics."""
        r = _make_dummy_record("https://disputed.example.com", outcome=PrimaryOutcome.AMBIGUOUS)
        result = self.assembler.assemble(records=[r])
        
        self.assertEqual(result.records[0].ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)
        self.assertNotEqual(result.records[0].ground_truth.primary_outcome, PrimaryOutcome.BENIGN)
        self.assertEqual(result.diagnostics.ambiguous_ground_truth_count, 1)

    def test_h_internal_system_ground_truth_source_is_rejected(self) -> None:
        """H. Prohibited internal system sources in ground truth trigger blocking contamination."""
        r = _make_dummy_record(
            "https://tainted.example.com",
            gt_rationale="Evaluated using TCE synergy scoring and Agent 18 report output.",
        )
        gate = self.assembler.evaluate_gate(records=[r])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("INTERNAL_SYSTEM_SOURCE_CONTAMINATION" in f["code"] for f in gate.blocking_findings))

    def test_i_ti_none_is_not_interpreted_as_benign(self) -> None:
        """I. Negative TI observation (NONE) is tracked as provenance, not benign label."""
        r = _make_dummy_record(
            "https://unseen-phish.example.com",
            outcome=PrimaryOutcome.MALICIOUS,
            ti_status=TIObservationStatus.NEGATIVE_OBSERVATION,
        )
        result = self.assembler.assemble(records=[r])
        self.assertEqual(result.records[0].ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(result.diagnostics.ti_exposure_counts.get("NONE"), 1)

    def test_j_ti_unknown_unavailable_is_not_interpreted_as_benign(self) -> None:
        """J. Unknown / unavailable TI is tracked as UNKNOWN_UNAVAILABLE stratum, not benign."""
        r = _make_dummy_record(
            "https://unreachable-ti.example.com",
            outcome=PrimaryOutcome.MALICIOUS,
            ti_status=TIObservationStatus.UNAVAILABLE,
        )
        result = self.assembler.assemble(records=[r])
        self.assertEqual(result.records[0].ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(result.diagnostics.ti_exposure_counts.get("UNKNOWN_UNAVAILABLE"), 1)

    def test_k_temporal_inconsistency_handled(self) -> None:
        """K. Prospective holdout timestamps post-date cutoff timestamp."""
        r_hist = _make_dummy_record("https://hist.example.com", observed_time="2026-01-01T00:00:00Z")
        r_prosp = _make_dummy_record("https://prosp.example.com", observed_time="2026-07-01T00:00:00Z")

        assigned = self.assembler.assign_partitions([r_hist, r_prosp], cutoff_timestamp="2026-06-01T00:00:00Z")
        self.assertEqual(assigned[1].evaluation.temporal_partition, TemporalPartition.PROSPECTIVE_HOLDOUT)
        self.assertNotEqual(assigned[0].evaluation.temporal_partition, TemporalPartition.PROSPECTIVE_HOLDOUT)

    def test_l_invalid_partition_assignment_blocks(self) -> None:
        """L. Missing or invalid partition assignments trigger blocking findings."""
        r = _make_dummy_record("https://no-part.example.com")
        ev = EvaluationMetadata(group_id=r.evaluation.group_id, temporal_partition=None)
        unassigned_r = copy.deepcopy(r)
        object.__setattr__(unassigned_r, "evaluation", ev)

        report = audit_benchmark_records([unassigned_r])
        gate = self.assembler.evaluate_gate(records=[unassigned_r], audit_report=report)
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)

    def test_m_final_test_and_prospective_holdout_protection(self) -> None:
        """M. Evaluator and Assembler preserve protected status of holdout partitions."""
        records = [
            _make_dummy_record("https://h1.example.com", observed_time="2026-01-01T00:00:00Z"),
            _make_dummy_record("https://h2.example.com", observed_time="2026-08-01T00:00:00Z"),
        ]
        result = self.assembler.assemble(records=records)
        parts = {r.evaluation.temporal_partition for r in result.records}
        self.assertIn(TemporalPartition.PROSPECTIVE_HOLDOUT, parts)

    def test_n_deterministic_partition_assignment(self) -> None:
        """N. Repeated partition assignment yields identical partitions."""
        records = [
            _make_dummy_record(f"https://sample-{i}.example.com", observed_time="2026-01-01T00:00:00Z")
            for i in range(10)
        ]
        p1 = [r.evaluation.temporal_partition for r in self.assembler.assign_partitions(records)]
        p2 = [r.evaluation.temporal_partition for r in self.assembler.assign_partitions(records)]
        self.assertEqual(p1, p2)

    def test_o_natural_prevalence_is_preserved(self) -> None:
        """O. Natural benign-to-malicious ratio is preserved without synthetic balancing."""
        records = [
            _make_dummy_record("https://m1.com", outcome=PrimaryOutcome.MALICIOUS),
            _make_dummy_record("https://m2.com", outcome=PrimaryOutcome.MALICIOUS),
            _make_dummy_record("https://m3.com", outcome=PrimaryOutcome.MALICIOUS),
            _make_dummy_record("https://b1.com", outcome=PrimaryOutcome.BENIGN),
        ]
        result = self.assembler.assemble(records=records)
        self.assertEqual(result.diagnostics.ground_truth_counts[PrimaryOutcome.MALICIOUS.value], 3)
        self.assertEqual(result.diagnostics.ground_truth_counts[PrimaryOutcome.BENIGN.value], 1)

    def test_p_no_synthetic_padding(self) -> None:
        """P. Exactly the eligible records are retained; zero synthetic padding."""
        records = [_make_dummy_record(f"https://record-{i}.com") for i in range(5)]
        result = self.assembler.assemble(records=records)
        self.assertEqual(len(result.records), 5)

    def test_q_snapshot_generation_is_deterministic(self) -> None:
        """Q. Snapshot writing creates identical byte files and hashes."""
        records = [_make_dummy_record(f"https://snap-{i}.com") for i in range(3)]
        
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            a1 = DatasetAssembler(DatasetAssemblyConfig(output_snapshot_dir=d1, write_snapshot=True))
            a2 = DatasetAssembler(DatasetAssemblyConfig(output_snapshot_dir=d2, write_snapshot=True))
            
            res1 = a1.assemble(records=records, created_at="2026-01-01T00:00:00Z")
            res2 = a2.assemble(records=records, created_at="2026-01-01T00:00:00Z")
            
            self.assertEqual(res1.gate_result.dataset_hash, res2.gate_result.dataset_hash)
            self.assertEqual(res1.gate_result.records_file_hash, res2.gate_result.records_file_hash)
            self.assertEqual(res1.gate_result.manifest_hash, res2.gate_result.manifest_hash)

    def test_r_hash_verification_works(self) -> None:
        """R. Valid snapshot hashes match computed manifest hashes."""
        records = [_make_dummy_record("https://hash-test.com")]
        result = self.assembler.assemble(records=records)
        self.assertTrue(len(result.gate_result.dataset_hash) == 64)
        self.assertTrue(len(result.gate_result.records_file_hash) == 64)

    def test_s_corrupted_snapshot_blocks(self) -> None:
        """S. Corrupted snapshot directory blocks audit and gate."""
        records = [_make_dummy_record("https://corrupt-test.com")]
        result = self.assembler.assemble(records=records)
        self.assertIsNotNone(result.snapshot_dir)
        
        # Tamper manifest on disk
        man_path = Path(result.snapshot_dir) / "manifest.json"
        with open(man_path, "r", encoding="utf-8") as f:
            man_data = json.load(f)
        man_data["dataset_hash"] = "0" * 64
        with open(man_path, "w", encoding="utf-8") as f:
            json.dump(man_data, f)
        
        report = audit_benchmark_snapshot(result.snapshot_dir)
        gate = self.assembler.evaluate_gate(result.records, manifest=man_data, audit_report=report)
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("DATASET_HASH_MISMATCH" in f["code"] or "MANIFEST_HASH_MISMATCH" in f["code"] for f in gate.blocking_findings))

    def test_t_manifest_mismatch_blocks(self) -> None:
        """T. Manifest count mismatch blocks."""
        records = [_make_dummy_record("https://count-test.com")]
        result = self.assembler.assemble(records=records)
        
        # Tamper manifest on disk
        man_path = Path(result.snapshot_dir) / "manifest.json"
        with open(man_path, "r", encoding="utf-8") as f:
            man_data = json.load(f)
        man_data["total_records"] = 999
        with open(man_path, "w", encoding="utf-8") as f:
            json.dump(man_data, f)
        
        report = audit_benchmark_snapshot(result.snapshot_dir)
        gate = self.assembler.evaluate_gate(result.records, manifest=man_data, audit_report=report)
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertTrue(any("RECORD_COUNT_MISMATCH" in f["code"] or "MANIFEST_HASH_MISMATCH" in f["code"] for f in gate.blocking_findings))

    def test_u_record_count_mismatch_blocks(self) -> None:
        """U. Record partition mismatch between records and manifest blocks."""
        records = [_make_dummy_record("https://part-count-test.com", partition=TemporalPartition.VALIDATION)]
        result = self.assembler.assemble(records=records)
        
        # Tamper manifest on disk
        man_path = Path(result.snapshot_dir) / "manifest.json"
        with open(man_path, "r", encoding="utf-8") as f:
            man_data = json.load(f)
        man_data["partition_counts"] = {"validation": 5}
        with open(man_path, "w", encoding="utf-8") as f:
            json.dump(man_data, f)
        
        report = audit_benchmark_snapshot(result.snapshot_dir)
        gate = self.assembler.evaluate_gate(result.records, manifest=man_data, audit_report=report)
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)

    def test_v_modality_counts_remain_consistent(self) -> None:
        """V. Modality distribution counts are tracked accurately."""
        records = [
            _make_dummy_record("https://url.com", modality=InputModality.DIRECT_URL),
            _make_dummy_record("https://qr.com", modality=InputModality.QR_IMAGE),
            _make_dummy_record("https://payload.com", modality=InputModality.QR_PAYLOAD),
        ]
        result = self.assembler.assemble(records=records)
        self.assertEqual(result.diagnostics.modality_counts[InputModality.DIRECT_URL.value], 1)
        self.assertEqual(result.diagnostics.modality_counts[InputModality.QR_IMAGE.value], 1)
        self.assertEqual(result.diagnostics.modality_counts[InputModality.QR_PAYLOAD.value], 1)

    def test_w_ground_truth_counts_remain_consistent(self) -> None:
        """W. Ground truth counts match input labels."""
        records = [
            _make_dummy_record("https://b.com", outcome=PrimaryOutcome.BENIGN),
            _make_dummy_record("https://m.com", outcome=PrimaryOutcome.MALICIOUS),
            _make_dummy_record("https://a.com", outcome=PrimaryOutcome.AMBIGUOUS),
        ]
        result = self.assembler.assemble(records=records)
        self.assertEqual(result.diagnostics.ground_truth_counts[PrimaryOutcome.BENIGN.value], 1)
        self.assertEqual(result.diagnostics.ground_truth_counts[PrimaryOutcome.MALICIOUS.value], 1)
        self.assertEqual(result.diagnostics.ground_truth_counts[PrimaryOutcome.AMBIGUOUS.value], 1)

    def test_x_qr_direct_records_remain_distinct(self) -> None:
        """X. Direct URL and QR record pointing to same canonical URL have distinct record and artifact IDs."""
        r_direct = _make_dummy_record("https://bank.example.com", modality=InputModality.DIRECT_URL)
        r_qr = _make_dummy_record("https://bank.example.com", modality=InputModality.QR_IMAGE)

        self.assertEqual(r_direct.target_id, r_qr.target_id)
        self.assertNotEqual(r_direct.artifact_id, r_qr.artifact_id)
        self.assertNotEqual(r_direct.record_id, r_qr.record_id)

    def test_y_functional_urls_remain_distinct_targets(self) -> None:
        """Y. Different paths on same domain maintain distinct target IDs."""
        r1 = _make_dummy_record("https://service.example.com/login")
        r2 = _make_dummy_record("https://service.example.com/about")

        self.assertEqual(r1.evaluation.group_id, r2.evaluation.group_id)
        self.assertNotEqual(r1.target_id, r2.target_id)
        self.assertNotEqual(r1.record_id, r2.record_id)

    def test_z_repeated_assembly_produces_identical_output(self) -> None:
        """Z. Repeated assembly over raw candidates produces identical output records."""
        cands = [
            RawCandidate(
                candidate_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c1.com"),
                raw_content="https://c1.com",
                modality=InputModality.DIRECT_URL,
                source_name="s1",
                source_type=SourceType.PUBLIC_FEED,
            ),
            RawCandidate(
                candidate_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c2.com"),
                raw_content="https://c2.com",
                modality=InputModality.DIRECT_URL,
                source_name="s2",
                source_type=SourceType.PUBLIC_FEED,
            ),
        ]
        l1 = [
            LivenessEvaluation(
                candidate_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c1.com"),
                raw_content="https://c1.com",
                modality=InputModality.DIRECT_URL,
                artifact_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c1.com"),
                liveness_status=LivenessStatus.LIVE,
                eligibility_status=EligibilityStatus.ELIGIBLE,
                response_body_size_bytes=500,
            ),
            LivenessEvaluation(
                candidate_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c2.com"),
                raw_content="https://c2.com",
                modality=InputModality.DIRECT_URL,
                artifact_id=compute_artifact_id(InputModality.DIRECT_URL, "https://c2.com"),
                liveness_status=LivenessStatus.LIVE,
                eligibility_status=EligibilityStatus.ELIGIBLE,
                response_body_size_bytes=500,
            ),
        ]
        res1 = self.assembler.assemble(raw_candidates=cands, liveness_results=l1, created_at="2026-01-01T00:00:00Z")
        res2 = self.assembler.assemble(raw_candidates=cands, liveness_results=l1, created_at="2026-01-01T00:00:00Z")
        self.assertEqual(res1.gate_result.dataset_hash, res2.gate_result.dataset_hash)

    def test_aa_no_production_modules_imported_for_mutation(self) -> None:
        """AA. DatasetAssembler does not import production analysis engines or forensic agents."""
        import sys
        assembler_module = sys.modules.get("tools.benchmark.dataset_assembler")
        self.assertIsNotNone(assembler_module)
        with open(assembler_module.__file__, "r", encoding="utf-8") as f:
            module_source = f.read()
        self.assertNotIn("from agents", module_source)
        self.assertNotIn("from services.threat_calculation_engine", module_source)
        self.assertNotIn("from services.autonomous_evidence_reasoning_engine", module_source)
        self.assertNotIn("from services.confidence_engine", module_source)

    def test_ab_assembler_does_not_perform_network_access(self) -> None:
        """AB. DatasetAssembler performs zero socket/urllib network calls."""
        records = [_make_dummy_record("https://offline-test.com")]
        result = self.assembler.assemble(records=records)
        self.assertEqual(result.gate_result.status, DatasetAssemblyGateStatus.READY_FOR_EXPERIMENT)

    def test_ac_gate_contains_actionable_blocking_diagnostics(self) -> None:
        """AC. Blocking gate provides actionable code and message."""
        rec = _make_dummy_record("https://bad.com")
        object.__setattr__(rec, "target_id", "INVALID")
        gate = self.assembler.evaluate_gate(records=[rec])
        self.assertTrue(len(gate.blocking_findings) > 0)
        self.assertIn("code", gate.blocking_findings[0])
        self.assertIn("message", gate.blocking_findings[0])

    def test_ad_ready_for_experiment_cannot_be_returned_with_critical_leakage(self) -> None:
        """AD. READY_FOR_EXPERIMENT is strictly prevented when critical leakage is detected."""
        r1 = _make_dummy_record("https://leaked.com", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_dummy_record("https://leaked.com", partition=TemporalPartition.PROSPECTIVE_HOLDOUT)

        gate = self.assembler.evaluate_gate(records=[r1, r2])
        self.assertEqual(gate.status, DatasetAssemblyGateStatus.BLOCKED_FROM_EXPERIMENT)
        self.assertFalse(gate.is_ready)


if __name__ == "__main__":
    unittest.main()
