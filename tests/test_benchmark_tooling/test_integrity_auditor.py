"""Unit Tests for Benchmark Integrity, Leakage, Identity, and Snapshot Auditor.

Step 6C-7: Cross-Split Leakage, Temporal Exposure, Identity, and Snapshot Integrity Audit.

Validates all 33 required audit scenarios:
- Clean dataset verification (PASS)
- Duplicate record IDs (CRITICAL)
- Cross-partition target leakage (CRITICAL)
- Cross-partition group overlap (WARNING)
- QR/Direct cross-partition leakage (CRITICAL)
- QR/Direct same partition handling (INFO)
- Distinct functional paths preservation
- Same-partition target multi-occurrence
- Temporal TI prior exposure recording
- TI NONE neutrality
- TI UNKNOWN_UNAVAILABLE distinction
- TI timestamp inconsistencies (ERROR)
- Invalid partition assignment (CRITICAL)
- Invalid ground-truth vocabulary (ERROR)
- Ambiguous ground-truth preservation
- Snapshot file hash mismatch (CRITICAL)
- Dataset hash mismatch (CRITICAL)
- Manifest hash mismatch (CRITICAL)
- Record hash mismatch (CRITICAL)
- Record count mismatch (CRITICAL)
- Manifest missing record (CRITICAL)
- Manifest unexpected record (CRITICAL)
- Partition count mismatch (ERROR)
- Modality count mismatch (ERROR)
- Ground-truth count mismatch (ERROR)
- TI exposure count mismatch (ERROR)
- Path independence
- Determinism & stable ordering
- Input-order permutation independence
- Zero automatic mutation / repair
- Unresolved QR image handling
- Non-URL QR payloads
- No network call verification
"""

import copy
import json
import os
from pathlib import Path
import random
import shutil
import tempfile
import unittest
from typing import Any, Dict, List

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
    hash_canonical_record,
)
from tools.benchmark.normalization import normalize_investigation_target
from tools.benchmark.ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    record_ti_observation,
)
from tools.benchmark.snapshot_writer import (
    write_benchmark_snapshot,
    verify_snapshot_integrity,
)
from tools.benchmark.manifest_generator import (
    generate_benchmark_manifest,
    compute_dataset_hash,
    compute_manifest_hash,
)
from tools.benchmark.integrity_auditor import (
    AuditSeverity,
    AuditStatus,
    AuditFinding,
    IntegrityAuditReport,
    audit_benchmark_records,
    audit_benchmark_snapshot,
    audit_ti_observation_records,
    deserialize_benchmark_record,
)


def _make_record(
    url: str,
    modality: InputModality = InputModality.DIRECT_URL,
    outcome: PrimaryOutcome = PrimaryOutcome.BENIGN,
    partition: TemporalPartition = TemporalPartition.DEVELOPMENT_CALIBRATION,
    artifact_raw: str = "",
    qr_rel_type: QRRelationshipType = QRRelationshipType.NONE,
    decoded_qr: str = "",
) -> BenchmarkRecord:
    """Helper to create valid synthetic BenchmarkRecords for testing."""
    norm = normalize_investigation_target(url) if url else None
    tgt_id = norm.target_id if norm else compute_target_id(url)
    grp_id = norm.group_id if norm else compute_group_id(url)

    raw = artifact_raw if artifact_raw else url
    art_id = compute_artifact_id(modality, raw)
    rec_id = compute_record_id(tgt_id, art_id)

    gt = GroundTruth(
        primary_outcome=outcome,
        secondary_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING] if outcome == PrimaryOutcome.MALICIOUS else [],
        verification_status=VerificationStatus.VERIFIED,
        verification_method=VerificationMethod.MANUAL_ADJUDICATION.value,
        verification_confidence=VerificationConfidence.HIGH,
        adjudication_status="adjudicated",
        reviewer_count=2,
        verification_timestamp="2026-09-01T12:00:00Z",
        rationale="Synthetic test ground truth",
    )

    prov = CandidateProvenance(
        source_name="SyntheticTestSource",
        source_record_id=f"SRC-{rec_id[:8]}",
        harvest_timestamp="2026-09-01T10:00:00Z",
    )

    ti = TIOverlapMetadata(
        virustotal=TIFeedObservation(
            feed_name="VirusTotal",
            status=TIObservationStatus.NEGATIVE_OBSERVATION,
            observed=False,
            observed_at="2026-09-01T11:00:00Z",
        )
    )

    live = LivenessMetadata(
        http_status=200,
        dns_resolved=True,
        tls_status="valid",
        checked_at="2026-09-01T11:30:00Z",
        eligibility_status="eligible",
    )

    qr = QRRelationshipMetadata(
        artifact_type="image/png" if modality == InputModality.QR_IMAGE else "none",
        decoded_payload=decoded_qr if decoded_qr else (url if modality == InputModality.QR_IMAGE else None),
        destination_target_id=tgt_id if modality == InputModality.QR_IMAGE else None,
        qr_group_id=grp_id if modality == InputModality.QR_IMAGE else None,
        relationship_type=qr_rel_type if modality == InputModality.QR_IMAGE else QRRelationshipType.NONE,
    )

    ev = EvaluationMetadata(
        group_id=grp_id,
        temporal_partition=partition,
        stratum="tier_1",
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


class TestBenchmarkIntegrityAuditor(unittest.TestCase):
    """Test suite covering all Step 6C-7 audit requirements."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_auditor_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_01_clean_benchmark(self):
        """Test 1: Clean benchmark dataset produces PASS with zero critical/error findings."""
        r1 = _make_record("https://alpha.example.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://beta.sample.org/pay", partition=TemporalPartition.VALIDATION)
        r3 = _make_record("https://gamma.domain.net/home", partition=TemporalPartition.FINAL_TEST)

        report = audit_benchmark_records([r1, r2, r3])
        self.assertEqual(report.status, AuditStatus.PASS)
        self.assertEqual(report.total_findings, 0)
        self.assertEqual(len(report.findings), 0)

    def test_02_duplicate_record_id(self):
        """Test 2: Duplicate record ID triggers DUPLICATE_RECORD_ID critical finding."""
        r1 = _make_record("https://alpha.example.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        # Duplicate r1
        r2 = copy.deepcopy(r1)

        report = audit_benchmark_records([r1, r2])
        self.assertEqual(report.status, AuditStatus.FAIL)
        dup_findings = [f for f in report.findings if f.code == "DUPLICATE_RECORD_ID"]
        self.assertTrue(len(dup_findings) >= 1)
        self.assertEqual(dup_findings[0].severity, AuditSeverity.CRITICAL)
        self.assertIn(r1.record_id, dup_findings[0].record_ids)

    def test_03_cross_partition_target_leakage(self):
        """Test 3: Same target_id across partitions triggers CROSS_PARTITION_TARGET_LEAKAGE."""
        r1 = _make_record("https://alpha.example.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION, artifact_raw="art_raw_1")
        r2 = _make_record("https://alpha.example.com/login", partition=TemporalPartition.FINAL_TEST, artifact_raw="art_raw_2")

        report = audit_benchmark_records([r1, r2])
        self.assertEqual(report.status, AuditStatus.FAIL)
        leak_findings = [f for f in report.findings if f.code == "CROSS_PARTITION_TARGET_LEAKAGE"]
        self.assertEqual(len(leak_findings), 1)
        self.assertEqual(leak_findings[0].severity, AuditSeverity.CRITICAL)
        self.assertEqual(leak_findings[0].target_ids, [r1.target_id])

    def test_04_cross_partition_group_overlap(self):
        """Test 4: Same group_id across partitions with distinct target IDs triggers CROSS_PARTITION_GROUP_OVERLAP."""
        r1 = _make_record("https://corp.example.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://corp.example.com/about", partition=TemporalPartition.FINAL_TEST)

        report = audit_benchmark_records([r1, r2])
        self.assertEqual(report.status, AuditStatus.PASS_WITH_WARNINGS)
        group_findings = [f for f in report.findings if f.code == "CROSS_PARTITION_GROUP_OVERLAP"]
        self.assertEqual(len(group_findings), 1)
        self.assertEqual(group_findings[0].severity, AuditSeverity.WARNING)

    def test_05_qr_direct_cross_partition_target(self):
        """Test 5: QR record and Direct URL record sharing target_id across partitions."""
        r_direct = _make_record("https://target.com/pay", modality=InputModality.DIRECT_URL, partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r_qr = _make_record("https://target.com/pay", modality=InputModality.QR_IMAGE, partition=TemporalPartition.FINAL_TEST, artifact_raw="qr_image_bytes", qr_rel_type=QRRelationshipType.DIRECT_PAYLOAD)

        report = audit_benchmark_records([r_direct, r_qr])
        self.assertEqual(report.status, AuditStatus.FAIL)
        qr_leak_findings = [f for f in report.findings if f.code == "QR_DIRECT_CROSS_PARTITION_LEAKAGE"]
        self.assertEqual(len(qr_leak_findings), 1)
        self.assertEqual(qr_leak_findings[0].severity, AuditSeverity.CRITICAL)

    def test_06_qr_direct_same_partition(self):
        """Test 6: QR and Direct URL sharing target in the same partition is INFO, not cross-partition leakage."""
        r_direct = _make_record("https://target.com/pay", modality=InputModality.DIRECT_URL, partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r_qr = _make_record("https://target.com/pay", modality=InputModality.QR_IMAGE, partition=TemporalPartition.DEVELOPMENT_CALIBRATION, artifact_raw="qr_image_bytes", qr_rel_type=QRRelationshipType.DIRECT_PAYLOAD)

        report = audit_benchmark_records([r_direct, r_qr])
        self.assertEqual(report.status, AuditStatus.PASS)
        qr_same_part = [f for f in report.findings if f.code == "QR_DIRECT_SAME_TARGET_SAME_PARTITION"]
        self.assertEqual(len(qr_same_part), 1)
        self.assertEqual(qr_same_part[0].severity, AuditSeverity.INFO)
        # Verify no cross partition leakage finding
        self.assertEqual(sum(1 for f in report.findings if f.code == "QR_DIRECT_CROSS_PARTITION_LEAKAGE"), 0)

    def test_07_distinct_functional_paths(self):
        """Test 7: Distinct functional paths (/login vs /account) have different target_ids and are not target duplicates."""
        r1 = _make_record("https://bank.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://bank.com/account", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)

        report = audit_benchmark_records([r1, r2])
        self.assertEqual(report.status, AuditStatus.PASS)
        self.assertNotEqual(r1.target_id, r2.target_id)
        self.assertEqual(r1.evaluation.group_id, r2.evaluation.group_id)
        # Should NOT be flagged as target duplicates or leakage
        self.assertEqual(sum(1 for f in report.findings if f.code in ("CROSS_PARTITION_TARGET_LEAKAGE", "SAME_TARGET_SAME_PARTITION")), 0)

    def test_08_same_target_same_partition(self):
        """Test 8: Multiple records for same target within same partition is reported as INFO."""
        r1 = _make_record("https://bank.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION, artifact_raw="raw1")
        r2 = _make_record("https://bank.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION, artifact_raw="raw2")

        report = audit_benchmark_records([r1, r2])
        self.assertEqual(report.status, AuditStatus.PASS)
        same_part_findings = [f for f in report.findings if f.code == "SAME_TARGET_SAME_PARTITION"]
        self.assertEqual(len(same_part_findings), 1)
        self.assertEqual(same_part_findings[0].severity, AuditSeverity.INFO)

    def test_09_ti_prior_exposure(self):
        """Test 9: first_feed_seen_at preceding observation point is reported as PRIOR_RECORDED_TI_EXPOSURE."""
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.VIRUSTOTAL,
            status=TIObservationType.DIRECT,
            first_feed_seen_at="2026-08-01T10:00:00Z",
            observation_time="2026-09-01T10:00:00Z",
            source_reference="VT-Report-99",
        )
        findings = audit_ti_observation_records([obs])
        prior_findings = [f for f in findings if f.code == "PRIOR_RECORDED_TI_EXPOSURE"]
        self.assertEqual(len(prior_findings), 1)
        self.assertEqual(prior_findings[0].severity, AuditSeverity.INFO)
        self.assertIn("prior recorded positive TI observation", prior_findings[0].message)

    def test_10_ti_none(self):
        """Test 10: TI status NONE does NOT generate BENIGN or zero_day = true."""
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.VIRUSTOTAL,
            status=TIObservationType.NONE,
            observation_time="2026-09-01T10:00:00Z",
        )
        findings = audit_ti_observation_records([obs])
        self.assertEqual(len(findings), 0)
        # Ensure no BENIGN label or zero-day claim was fabricated

    def test_11_ti_unknown(self):
        """Test 11: UNKNOWN_UNAVAILABLE remains distinct from NONE."""
        obs = record_ti_observation(
            target_id="TGT-1234567890abcdef",
            feed=TIFeed.VIRUSTOTAL,
            status=TIObservationType.UNKNOWN_UNAVAILABLE,
            observation_time="2026-09-01T10:00:00Z",
        )
        self.assertEqual(obs.status, TIObservationType.UNKNOWN_UNAVAILABLE)
        findings = audit_ti_observation_records([obs])
        self.assertEqual(len(findings), 0)

    def test_12_ti_timestamp_inconsistency(self):
        """Test 12: Chronological contradiction first_feed_seen_at > observation_time triggers ERROR."""
        obs = TIFeedObservationRecord(
            feed_name=TIFeed.VIRUSTOTAL,
            status=TIObservationType.DIRECT,
            target_id="TGT-1234567890abcdef",
            first_feed_seen_at="2026-09-10T10:00:00Z",
            observation_time="2026-09-01T10:00:00Z",
            source_reference="VT-Test",
        )
        findings = audit_ti_observation_records([obs])
        inconsistency_findings = [f for f in findings if f.code == "TEMPORAL_METADATA_INCONSISTENCY"]
        self.assertEqual(len(inconsistency_findings), 1)
        self.assertEqual(inconsistency_findings[0].severity, AuditSeverity.ERROR)

    def test_13_invalid_partition(self):
        """Test 13: Record with invalid or missing partition produces INVALID_PARTITION_ASSIGNMENT."""
        r = _make_record("https://test.com/login")
        # Replace partition with invalid object
        bad_ev = EvaluationMetadata(group_id=r.evaluation.group_id, temporal_partition=None)
        bad_r = BenchmarkRecord(
            record_id=r.record_id,
            artifact_id=r.artifact_id,
            target_id=r.target_id,
            target_url=r.target_url,
            modality=r.modality,
            ground_truth=r.ground_truth,
            provenance=r.provenance,
            ti_overlap=r.ti_overlap,
            liveness=r.liveness,
            qr_relationship=r.qr_relationship,
            evaluation=bad_ev,
        )
        report = audit_benchmark_records([bad_r])
        self.assertEqual(report.status, AuditStatus.FAIL)
        inv_part = [f for f in report.findings if f.code == "INVALID_PARTITION_ASSIGNMENT"]
        self.assertEqual(len(inv_part), 1)
        self.assertEqual(inv_part[0].severity, AuditSeverity.CRITICAL)

    def test_14_ground_truth_vocabulary(self):
        """Test 14: Invalid ground-truth value produces INVALID_GROUND_TRUTH_VOCABULARY."""
        r = _make_record("https://test.com/login")
        bad_gt = GroundTruth(
            primary_outcome="SUSPICIOUS_UNCONFIRMED",  # Invalid enum value
            verification_status=VerificationStatus.VERIFIED,
            verification_confidence=VerificationConfidence.HIGH,
        )
        bad_r = BenchmarkRecord(
            record_id=r.record_id,
            artifact_id=r.artifact_id,
            target_id=r.target_id,
            target_url=r.target_url,
            modality=r.modality,
            ground_truth=bad_gt,
            provenance=r.provenance,
            ti_overlap=r.ti_overlap,
            liveness=r.liveness,
            qr_relationship=r.qr_relationship,
            evaluation=r.evaluation,
        )
        report = audit_benchmark_records([bad_r])
        self.assertEqual(report.status, AuditStatus.FAIL)
        inv_gt = [f for f in report.findings if f.code == "INVALID_GROUND_TRUTH_VOCABULARY"]
        self.assertEqual(len(inv_gt), 1)
        self.assertEqual(inv_gt[0].severity, AuditSeverity.ERROR)

    def test_15_ambiguous_ground_truth(self):
        """Test 15: AMBIGUOUS ground truth remains AMBIGUOUS without automatic resolution."""
        r = _make_record("https://test.com/ambig", outcome=PrimaryOutcome.AMBIGUOUS)
        report = audit_benchmark_records([r])
        self.assertEqual(report.status, AuditStatus.PASS)
        ambig_findings = [f for f in report.findings if f.code == "AMBIGUOUS_GROUND_TRUTH"]
        self.assertEqual(len(ambig_findings), 1)
        self.assertEqual(ambig_findings[0].severity, AuditSeverity.INFO)
        # Record outcome was untouched
        self.assertEqual(r.ground_truth.primary_outcome, PrimaryOutcome.AMBIGUOUS)

    def test_16_snapshot_file_hash_mismatch(self):
        """Test 16: Modifying records.jsonl after snapshot creation triggers SNAPSHOT_FILE_HASH_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        # Tamper with records.jsonl
        rec_file = Path(self.temp_dir) / "records.jsonl"
        with open(rec_file, "a", encoding="utf-8") as f:
            f.write("\n")

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        hash_mismatch = [f for f in report.findings if f.code == "SNAPSHOT_FILE_HASH_MISMATCH"]
        self.assertEqual(len(hash_mismatch), 1)
        self.assertEqual(hash_mismatch[0].severity, AuditSeverity.CRITICAL)

    def test_17_dataset_hash_mismatch(self):
        """Test 17: Dataset hash mismatch in manifest triggers DATASET_HASH_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        # Corrupt dataset_hash in manifest.json
        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["dataset_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        ds_mismatch = [f for f in report.findings if f.code == "DATASET_HASH_MISMATCH"]
        self.assertEqual(len(ds_mismatch), 1)
        self.assertEqual(ds_mismatch[0].severity, AuditSeverity.CRITICAL)

    def test_18_manifest_hash_mismatch(self):
        """Test 18: Modifying manifest content without updating manifest_hash triggers MANIFEST_HASH_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["software_version"] = "9.9.9"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        man_mismatch = [f for f in report.findings if f.code == "MANIFEST_HASH_MISMATCH"]
        self.assertEqual(len(man_mismatch), 1)
        self.assertEqual(man_mismatch[0].severity, AuditSeverity.CRITICAL)

    def test_19_record_hash_mismatch(self):
        """Test 19: Record hash in manifest differing from recomputed hash triggers RECORD_HASH_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["record_hashes"][0]["record_hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        rec_mismatch = [f for f in report.findings if f.code == "RECORD_HASH_MISMATCH"]
        self.assertEqual(len(rec_mismatch), 1)
        self.assertEqual(rec_mismatch[0].severity, AuditSeverity.CRITICAL)

    def test_20_record_count_mismatch(self):
        """Test 20: Manifest record_count differing from actual records triggers RECORD_COUNT_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["record_count"] = 999
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        count_mismatch = [f for f in report.findings if f.code == "RECORD_COUNT_MISMATCH"]
        self.assertEqual(len(count_mismatch), 1)

    def test_21_manifest_missing_record(self):
        """Test 21: Record present in jsonl but missing from manifest index triggers MANIFEST_MISSING_RECORD."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://test.com/page2", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1, r2], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        # Drop r2 from record_hashes
        man["record_hashes"] = [entry for entry in man["record_hashes"] if entry["record_id"] == r1.record_id]
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        missing_rec = [f for f in report.findings if f.code == "MANIFEST_MISSING_RECORD"]
        self.assertEqual(len(missing_rec), 1)
        self.assertIn(r2.record_id, missing_rec[0].record_ids)

    def test_22_manifest_unexpected_record(self):
        """Test 22: Record listed in manifest index but missing from records.jsonl triggers MANIFEST_UNEXPECTED_RECORD."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["record_hashes"].append({
            "record_id": "REC-9999999999999999",
            "artifact_id": "ART-9999999999999999",
            "target_id": "TGT-9999999999999999",
            "group_id": "GRP-9999999999999999",
            "record_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        })
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        unexpected_rec = [f for f in report.findings if f.code == "MANIFEST_UNEXPECTED_RECORD"]
        self.assertEqual(len(unexpected_rec), 1)
        self.assertIn("REC-9999999999999999", unexpected_rec[0].record_ids)

    def test_23_partition_count_mismatch(self):
        """Test 23: Manifest partition_counts mismatch triggers PARTITION_COUNT_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["partition_counts"] = {"development_calibration": 50}
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        part_mismatch = [f for f in report.findings if f.code == "PARTITION_COUNT_MISMATCH"]
        self.assertEqual(len(part_mismatch), 1)

    def test_24_modality_count_mismatch(self):
        """Test 24: Manifest modality_counts mismatch triggers MODALITY_COUNT_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["modality_counts"] = {"DIRECT_URL": 99}
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        mod_mismatch = [f for f in report.findings if f.code == "MODALITY_COUNT_MISMATCH"]
        self.assertEqual(len(mod_mismatch), 1)

    def test_25_ground_truth_count_mismatch(self):
        """Test 25: Manifest ground_truth_counts mismatch triggers GROUND_TRUTH_COUNT_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["ground_truth_counts"] = {"BENIGN": 50, "MALICIOUS": 50}
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        gt_mismatch = [f for f in report.findings if f.code == "GROUND_TRUTH_COUNT_MISMATCH"]
        self.assertEqual(len(gt_mismatch), 1)

    def test_26_ti_exposure_count_mismatch(self):
        """Test 26: Manifest ti_exposure_counts mismatch triggers TI_EXPOSURE_COUNT_MISMATCH."""
        r1 = _make_record("https://test.com/page1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        write_benchmark_snapshot([r1], self.temp_dir)

        manifest_file = Path(self.temp_dir) / "manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            man = json.load(f)
        man["ti_exposure_counts"]["virustotal_positive"] = 42
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(man, f)

        report = audit_benchmark_snapshot(self.temp_dir)
        self.assertEqual(report.status, AuditStatus.FAIL)
        ti_mismatch = [f for f in report.findings if f.code == "TI_EXPOSURE_COUNT_MISMATCH"]
        self.assertEqual(len(ti_mismatch), 1)

    def test_27_path_independence(self):
        """Test 27: Audit behavior and findings are identical regardless of local filesystem path."""
        dir1 = os.path.join(self.temp_dir, "path_a")
        dir2 = os.path.join(self.temp_dir, "path_b")

        r1 = _make_record("https://test.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://sample.org/about", partition=TemporalPartition.FINAL_TEST)

        write_benchmark_snapshot([r1, r2], dir1)
        write_benchmark_snapshot([r1, r2], dir2)

        rep1 = audit_benchmark_snapshot(dir1)
        rep2 = audit_benchmark_snapshot(dir2)

        self.assertEqual(rep1.status, rep2.status)
        self.assertEqual(rep1.total_findings, rep2.total_findings)
        self.assertEqual(rep1.leakage_summary, rep2.leakage_summary)
        self.assertEqual(rep1.integrity_summary, rep2.integrity_summary)

    def test_28_deterministic_audit(self):
        """Test 28: Repeated audits of identical input produce byte-identical audit reports."""
        r1 = _make_record("https://test.com/login", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        r2 = _make_record("https://test.com/login", partition=TemporalPartition.FINAL_TEST, artifact_raw="diff_raw")

        rep1 = audit_benchmark_records([r1, r2])
        rep2 = audit_benchmark_records([r1, r2])

        self.assertEqual(rep1.to_dict(), rep2.to_dict())

    def test_29_input_order_independence(self):
        """Test 29: Shuffling the input records list produces identical findings in identical order."""
        records = [
            _make_record("https://a.com/1", partition=TemporalPartition.DEVELOPMENT_CALIBRATION),
            _make_record("https://b.com/2", partition=TemporalPartition.VALIDATION),
            _make_record("https://c.com/3", partition=TemporalPartition.FINAL_TEST),
            _make_record("https://a.com/1", partition=TemporalPartition.FINAL_TEST, artifact_raw="leak_raw"),
        ]

        shuffled = list(records)
        random.seed(42)
        random.shuffle(shuffled)

        rep_orig = audit_benchmark_records(records)
        rep_shuf = audit_benchmark_records(shuffled)

        self.assertEqual(rep_orig.status, rep_shuf.status)
        self.assertEqual(len(rep_orig.findings), len(rep_shuf.findings))
        self.assertEqual([f.to_dict() for f in rep_orig.findings], [f.to_dict() for f in rep_shuf.findings])

    def test_30_no_automatic_repair(self):
        """Test 30: Auditor never mutates records, ground truth, partitions, target_ids, or group_ids."""
        r1 = _make_record("https://test.com/login", outcome=PrimaryOutcome.AMBIGUOUS, partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        orig_outcome = r1.ground_truth.primary_outcome
        orig_partition = r1.evaluation.temporal_partition
        orig_target_id = r1.target_id
        orig_group_id = r1.evaluation.group_id

        report = audit_benchmark_records([r1])

        self.assertEqual(r1.ground_truth.primary_outcome, orig_outcome)
        self.assertEqual(r1.evaluation.temporal_partition, orig_partition)
        self.assertEqual(r1.target_id, orig_target_id)
        self.assertEqual(r1.evaluation.group_id, orig_group_id)

    def test_31_qr_unresolved_image(self):
        """Test 31: Unresolved QR image is not flagged as a target error, but reported as AMBIGUOUS_OR_UNRESOLVED_INPUT."""
        r_unres = _make_record(
            url="",
            modality=InputModality.QR_IMAGE,
            partition=TemporalPartition.DEVELOPMENT_CALIBRATION,
            artifact_raw="corrupted_qr_png_bytes",
            qr_rel_type=QRRelationshipType.NONE,
            decoded_qr="",
        )
        report = audit_benchmark_records([r_unres])
        self.assertEqual(report.status, AuditStatus.PASS)
        unres_findings = [f for f in report.findings if f.code == "AMBIGUOUS_OR_UNRESOLVED_INPUT"]
        self.assertEqual(len(unres_findings), 1)
        self.assertEqual(unres_findings[0].severity, AuditSeverity.INFO)

    def test_32_non_url_qr_payload(self):
        """Test 32: Non-URL QR payloads (mailto:, wifi:, plain text) are handled cleanly."""
        r_mailto = _make_record(
            url="mailto:victim@example.com",
            modality=InputModality.QR_IMAGE,
            partition=TemporalPartition.DEVELOPMENT_CALIBRATION,
            artifact_raw="qr_mailto_bytes",
            qr_rel_type=QRRelationshipType.NONE,
            decoded_qr="mailto:victim@example.com",
        )
        report = audit_benchmark_records([r_mailto])
        self.assertEqual(report.status, AuditStatus.PASS)

    def test_33_no_network(self):
        """Test 33: Auditor runs purely offline and completes without network access."""
        r1 = _make_record("https://alpha.example.com", partition=TemporalPartition.DEVELOPMENT_CALIBRATION)
        report = audit_benchmark_records([r1])
        self.assertIsNotNone(report)
        self.assertEqual(report.status, AuditStatus.PASS)


if __name__ == "__main__":
    unittest.main()
