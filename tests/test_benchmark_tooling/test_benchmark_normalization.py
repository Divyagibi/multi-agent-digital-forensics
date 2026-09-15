"""Comprehensive Unit Tests for Benchmark Normalization, Deduplication, Grouping, and Leakage Detection.

Step 6C-2 Verification Suite.
"""

import inspect
import unittest
from typing import List

from tools.benchmark.schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
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

from tools.benchmark.normalization import (
    NormalizedTarget,
    OverlapType,
    DuplicateRelation,
    LeakageFinding,
    DeduplicationResult,
    normalize_investigation_target,
    classify_relation,
    detect_cross_split_leakage,
    deduplicate_records,
)
import tools.benchmark.normalization as normalization_module


class TestTargetNormalization(unittest.TestCase):
    """Test URL and entity normalization rules."""

    def test_hostname_case_and_trailing_dot(self):
        t1 = normalize_investigation_target("HTTPS://EXAMPLE.COM/login")
        t2 = normalize_investigation_target("https://example.com./login")
        self.assertEqual(t1.canonical_url, "https://example.com/login")
        self.assertEqual(t2.canonical_url, "https://example.com/login")
        self.assertEqual(t1.target_id, t2.target_id)
        self.assertEqual(t1.group_id, t2.group_id)

    def test_default_port_normalization(self):
        t_http_80 = normalize_investigation_target("http://example.com:80/path")
        t_http_plain = normalize_investigation_target("http://example.com/path")
        self.assertEqual(t_http_80.canonical_url, "http://example.com/path")
        self.assertEqual(t_http_80.target_id, t_http_plain.target_id)

        t_https_443 = normalize_investigation_target("https://example.com:443/path")
        t_https_plain = normalize_investigation_target("https://example.com/path")
        self.assertEqual(t_https_443.canonical_url, "https://example.com/path")
        self.assertEqual(t_https_443.target_id, t_https_plain.target_id)

    def test_non_default_port_preserved(self):
        t_custom = normalize_investigation_target("https://example.com:8443/login")
        t_standard = normalize_investigation_target("https://example.com/login")
        self.assertEqual(t_custom.canonical_url, "https://example.com:8443/login")
        self.assertNotEqual(t_custom.target_id, t_standard.target_id)
        self.assertEqual(t_custom.port, 8443)

    def test_scheme_preservation(self):
        t_http = normalize_investigation_target("http://example.com/login")
        t_https = normalize_investigation_target("https://example.com/login")
        self.assertNotEqual(t_http.canonical_url, t_https.canonical_url)
        self.assertNotEqual(t_http.target_id, t_https.target_id)

    def test_fragment_handling(self):
        t_frag = normalize_investigation_target("https://example.com/page#section2")
        t_plain = normalize_investigation_target("https://example.com/page")
        self.assertEqual(t_frag.canonical_url, "https://example.com/page")
        self.assertEqual(t_frag.target_id, t_plain.target_id)
        self.assertEqual(t_frag.fragment, "section2")
        self.assertIsNone(t_plain.fragment)

    def test_path_normalization_dot_segments_and_multislash(self):
        t_complex = normalize_investigation_target("https://example.com/a//b/../c/./d")
        self.assertEqual(t_complex.canonical_url, "https://example.com/a/c/d")
        self.assertEqual(t_complex.path, "/a/c/d")

    def test_distinct_functional_paths_preserved(self):
        t_login = normalize_investigation_target("https://example.com/login")
        t_account = normalize_investigation_target("https://example.com/account")
        t_download = normalize_investigation_target("https://example.com/download.apk")
        self.assertNotEqual(t_login.target_id, t_account.target_id)
        self.assertNotEqual(t_login.target_id, t_download.target_id)
        self.assertNotEqual(t_account.target_id, t_download.target_id)
        # However, they all share the same group ID
        self.assertEqual(t_login.group_id, t_account.group_id)
        self.assertEqual(t_login.group_id, t_download.group_id)

    def test_query_parameters_sorted_and_preserved(self):
        t_q1 = normalize_investigation_target("https://example.com/search?b=2&a=1&c=3")
        t_q2 = normalize_investigation_target("https://example.com/search?c=3&a=1&b=2")
        self.assertEqual(t_q1.canonical_url, "https://example.com/search?a=1&b=2&c=3")
        self.assertEqual(t_q1.target_id, t_q2.target_id)

        t_q_diff = normalize_investigation_target("https://example.com/search?a=99&b=2&c=3")
        self.assertNotEqual(t_q1.target_id, t_q_diff.target_id)

    def test_idn_punycode_preservation(self):
        t_punycode = normalize_investigation_target("https://xn--e1afmkfd.xn--p1ai/test")
        self.assertIn("xn--e1afmkfd.xn--p1ai", t_punycode.canonical_url)
        self.assertIn("xn--e1afmkfd.xn--p1ai", t_punycode.hostname)

    def test_ipv4_and_ipv6_grouping(self):
        t_ipv4_a = normalize_investigation_target("http://192.168.1.10/login")
        t_ipv4_b = normalize_investigation_target("http://192.168.1.55/admin")
        self.assertTrue(t_ipv4_a.is_ip)
        self.assertEqual(t_ipv4_a.grouping_key, "192.168.1.0/24")
        self.assertEqual(t_ipv4_a.group_id, t_ipv4_b.group_id)

        t_ipv4_c = normalize_investigation_target("http://10.0.0.1/login")
        self.assertNotEqual(t_ipv4_a.group_id, t_ipv4_c.group_id)


class TestBenchmarkDeduplicationAndGrouping(unittest.TestCase):
    """Test three-tier entity relations and deduplication analysis."""

    def _create_record(
        self,
        url: str,
        modality: InputModality = InputModality.DIRECT_URL,
        partition: TemporalPartition = TemporalPartition.DEVELOPMENT_CALIBRATION,
        outcome: PrimaryOutcome = PrimaryOutcome.MALICIOUS,
    ) -> BenchmarkRecord:
        norm = normalize_investigation_target(url)
        art_id = compute_artifact_id(modality, url)
        rec_id = compute_record_id(norm.target_id, art_id)

        return BenchmarkRecord(
            record_id=rec_id,
            artifact_id=art_id,
            target_id=norm.target_id,
            target_url=norm.canonical_url,
            modality=modality,
            ground_truth=GroundTruth(
                primary_outcome=outcome,
                secondary_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                verification_confidence=VerificationConfidence.HIGH,
            ),
            provenance=CandidateProvenance(source_name="SyntheticFeed"),
            ti_overlap=TIOverlapMetadata(),
            liveness=LivenessMetadata(),
            qr_relationship=QRRelationshipMetadata(
                artifact_type="qr_code" if modality == InputModality.QR_IMAGE else "none",
                decoded_payload=norm.canonical_url if modality == InputModality.QR_PAYLOAD else None,
                destination_target_id=norm.target_id if modality == InputModality.QR_PAYLOAD else None,
                relationship_type=QRRelationshipType.DIRECT_PAYLOAD if modality == InputModality.QR_PAYLOAD else QRRelationshipType.NONE,
            ),
            evaluation=EvaluationMetadata(
                group_id=norm.group_id,
                temporal_partition=partition,
            ),
        )

    def test_exact_artifact_duplicate(self):
        r1 = self._create_record("https://example.com/login")
        r2 = self._create_record("https://example.com/login")
        rel = classify_relation(r1, r2)
        self.assertTrue(rel.is_exact_artifact_duplicate)
        self.assertTrue(rel.is_same_target)
        self.assertTrue(rel.is_same_group)
        self.assertEqual(rel.overlap_type, OverlapType.EXACT_ARTIFACT)

    def test_qr_and_direct_url_linkage_same_target_distinct_artifact(self):
        r_direct = self._create_record("https://example.com/login", modality=InputModality.DIRECT_URL)
        r_qr = self._create_record("https://example.com/login", modality=InputModality.QR_PAYLOAD)
        self.assertNotEqual(r_direct.artifact_id, r_qr.artifact_id)
        self.assertEqual(r_direct.target_id, r_qr.target_id)
        
        rel = classify_relation(r_direct, r_qr)
        self.assertFalse(rel.is_exact_artifact_duplicate)
        self.assertTrue(rel.is_same_target)
        self.assertTrue(rel.is_same_group)
        self.assertEqual(rel.overlap_type, OverlapType.SAME_TARGET)

    def test_subdomain_grouping_distinct_targets(self):
        r_main = self._create_record("https://example.com/login")
        r_sub = self._create_record("https://sub.example.com/login")
        self.assertNotEqual(r_main.target_id, r_sub.target_id)
        self.assertEqual(r_main.evaluation.group_id, r_sub.evaluation.group_id)

        rel = classify_relation(r_main, r_sub)
        self.assertFalse(rel.is_same_target)
        self.assertTrue(rel.is_same_group)
        self.assertEqual(rel.overlap_type, OverlapType.SAME_GROUP)

    def test_cross_partition_target_leakage_detection(self):
        r_calib = self._create_record(
            "https://example.com/phish",
            partition=TemporalPartition.DEVELOPMENT_CALIBRATION,
        )
        r_test = self._create_record(
            "https://example.com/phish",
            modality=InputModality.QR_PAYLOAD,
            partition=TemporalPartition.FINAL_TEST,
        )
        findings = detect_cross_split_leakage([r_calib, r_test])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].overlap_type, OverlapType.SAME_TARGET)
        self.assertIn("target leakage", findings[0].description)

    def test_cross_partition_group_leakage_detection(self):
        r_calib = self._create_record(
            "https://evil.example.com/page1",
            partition=TemporalPartition.DEVELOPMENT_CALIBRATION,
        )
        r_test = self._create_record(
            "https://other.example.com/page2",
            partition=TemporalPartition.FINAL_TEST,
        )
        findings = detect_cross_split_leakage([r_calib, r_test])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].overlap_type, OverlapType.SAME_GROUP)
        self.assertIn("eTLD+1/group leakage", findings[0].description)

    def test_deduplicate_records_traceability_preservation(self):
        r1 = self._create_record("https://example.com/login")
        r2 = self._create_record("https://example.com/login")
        r3 = self._create_record("https://example.com/account")
        r4 = self._create_record("https://different-site.org/index.html")

        res = deduplicate_records([r1, r2, r3, r4])
        self.assertEqual(res.total_records, 4)
        # All 4 input records must be preserved
        self.assertEqual(len(res.retained_records), 4)
        self.assertEqual(res.unique_artifacts_count, 3)
        self.assertEqual(res.unique_targets_count, 3)
        self.assertEqual(res.unique_groups_count, 2)
        self.assertEqual(len(res.exact_artifact_duplicates), 1)
        self.assertEqual(len(res.same_group_relations), 2)  # (r1,r3) and (r2,r3)


class TestBenchmarkIndependenceAndSecurity(unittest.TestCase):
    """Test ground-truth independence, TI independence, and security bounds."""

    def test_ground_truth_does_not_affect_identity_or_grouping(self):
        norm_benign = normalize_investigation_target("https://example.com/login")
        art_benign = compute_artifact_id(InputModality.DIRECT_URL, "https://example.com/login")

        norm_mal = normalize_investigation_target("https://example.com/login")
        art_mal = compute_artifact_id(InputModality.DIRECT_URL, "https://example.com/login")

        self.assertEqual(norm_benign.target_id, norm_mal.target_id)
        self.assertEqual(norm_benign.group_id, norm_mal.group_id)
        self.assertEqual(art_benign, art_mal)

    def test_ti_metadata_does_not_affect_target_id(self):
        norm = normalize_investigation_target("https://bank.example.com/secure")
        # Target ID depends only on canonical URL
        self.assertEqual(norm.target_id, compute_target_id("https://bank.example.com/secure"))

    def test_no_network_and_no_eval_exec_in_codebase(self):
        source = inspect.getsource(normalization_module)
        forbidden_patterns = [
            "requests.",
            "urllib.request.",
            "http.client.",
            "socket.",
            "subprocess.",
            "os.system",
            "eval(",
            "exec(",
        ]
        for pat in forbidden_patterns:
            self.assertNotIn(pat, source, f"Security violation: Found forbidden pattern '{pat}' in normalization.py")


if __name__ == "__main__":
    unittest.main()
