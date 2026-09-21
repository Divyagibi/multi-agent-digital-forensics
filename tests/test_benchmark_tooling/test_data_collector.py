"""Offline Unit and Integration Tests for Real Benchmark Data Collection Layer.

Step 6D-8: Test suite for BenchmarkDataCollector, Source Role Firewall,
Provenance Preservation, Passive Liveness Integration, and Step 6D-6 Handoff.

Guarantees:
- Fully offline execution using MockHTTPTransport and in-memory mock feeds.
- Zero live external network connections or API queries.
- Zero execution of production forensic engines or models (M0, A0-A4, M1-M6).
"""

from __future__ import annotations

import hashlib
import json
import unittest
from typing import Dict, List, Optional

from tools.benchmark.schemas import (
    InputModality,
    PrimaryOutcome,
    SecondaryThreatCategory,
    VerificationStatus,
    VerificationConfidence,
    TIObservationStatus,
    TemporalPartition,
    compute_artifact_id,
    compute_target_id,
)
from tools.benchmark.harvester import (
    SourceType as HarvesterSourceType,
    RawCandidate,
    CandidateHarvester,
    TextListFeedAdapter,
    CSVFeedAdapter,
    JSONFeedAdapter,
    QRImageSourceAdapter,
    QRPayloadSourceAdapter,
)
from tools.benchmark.liveness import (
    LivenessStatus,
    EligibilityStatus,
    HTTPResponseObservation,
    MockHTTPTransport,
    PassiveLivenessEvaluator,
)
from tools.benchmark.ground_truth_verifier import (
    SourceType as GTSourceType,
    VerificationSourceRecord,
    AdjudicationRecord,
)
from tools.benchmark.ti_overlap_recorder import (
    TIFeed,
    TIObservationType,
    TIFeedObservationRecord,
    TIExposureSummary,
    TIOverlapRecord,
)
from tools.benchmark.dataset_assembler import (
    DatasetAssembler,
    DatasetAssemblyConfig,
    DatasetAssemblyGateStatus,
)
from tools.benchmark.data_collector import (
    SourceCategory,
    SourceRole,
    CollectionSessionStatus,
    CollectionStoppingReason,
    ApprovedSourceConfig,
    CollectionConfig,
    CollectionItemAudit,
    CollectionSourceAudit,
    CollectionManifest,
    CollectionResult,
    validate_source_role_firewall,
    sanitize_pii_parameters,
    BenchmarkDataCollector,
    create_standard_benchmark_collector,
)


class TestBenchmarkDataCollector(unittest.TestCase):
    """Test suite covering the complete BenchmarkDataCollector workflow and firewalls."""

    def setUp(self):
        # Build deterministic mock transport with >= 100 bytes HTTP bodies
        self.mock_transport = MockHTTPTransport()
        
        self.mock_transport.set_response(
            "https://phish.example.com/login",
            HTTPResponseObservation(
                status_code=200,
                body_bytes_len=250,
                content_type="text/html",
                tls_verified=True,
                final_url="https://phish.example.com/login",
            )
        )
        self.mock_transport.set_response(
            "https://malware.example.org/drop",
            HTTPResponseObservation(
                status_code=200,
                body_bytes_len=300,
                content_type="text/html",
                tls_verified=True,
                final_url="https://malware.example.org/drop",
            )
        )
        self.mock_transport.set_response(
            "https://legit-gov.gov/portal",
            HTTPResponseObservation(
                status_code=200,
                body_bytes_len=500,
                content_type="text/html",
                tls_verified=True,
                final_url="https://legit-gov.gov/portal",
            )
        )
        self.mock_transport.set_response(
            "https://qr-landing.example.net/verify",
            HTTPResponseObservation(
                status_code=200,
                body_bytes_len=450,
                content_type="text/html",
                tls_verified=True,
                final_url="https://qr-landing.example.net/verify",
            )
        )

        self.collector = create_standard_benchmark_collector(http_transport=self.mock_transport)

    def test_approved_source_config_serialization(self):
        """Test configuration dataclass fields and dictionary export."""
        cfg = ApprovedSourceConfig(
            source_name="test_feed",
            source_category=SourceCategory.PUBLIC_MALICIOUS_FEED,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
            source_reference="https://feed.test/list",
            licensing_or_access_notes="CC-BY-4.0",
        )
        d = cfg.to_dict()
        self.assertEqual(d["source_name"], "test_feed")
        self.assertEqual(d["source_category"], "PUBLIC_MALICIOUS_FEED")
        self.assertEqual(d["source_role"], "CANDIDATE_SOURCE")
        self.assertEqual(d["input_modality"], "DIRECT_URL")
        self.assertTrue(d["enabled"])

    def test_source_role_firewall_internal_system_rejection(self):
        """Enforce rejection of internal forensic system components as benchmark sources."""
        forbidden_names = [
            "TCE", "tce_v1", "AERE", "aere_grounding",
            "ConfidenceEngine", "confidence_engine_eval",
            "Agent1", "agent_10", "system_verdict_engine",
            "report_generator"
        ]
        for name in forbidden_names:
            cfg = ApprovedSourceConfig(
                source_name=name,
                source_category=SourceCategory.OTHER,
                source_role=SourceRole.CANDIDATE_SOURCE,
                input_modality=InputModality.DIRECT_URL,
            )
            valid, errors = validate_source_role_firewall(cfg)
            self.assertFalse(valid, f"Expected {name} to be rejected by firewall")
            self.assertTrue(len(errors) > 0)

    def test_source_role_firewall_public_feed_as_gt_rejection(self):
        """Enforce that raw public malicious feeds cannot be registered directly as GROUND_TRUTH_SOURCE."""
        cfg = ApprovedSourceConfig(
            source_name="unverified_public_feed",
            source_category=SourceCategory.PUBLIC_MALICIOUS_FEED,
            source_role=SourceRole.GROUND_TRUTH_SOURCE,
            input_modality=InputModality.DIRECT_URL,
        )
        valid, errors = validate_source_role_firewall(cfg)
        self.assertFalse(valid)
        self.assertIn("cannot be declared as a GROUND_TRUTH_SOURCE directly", errors[0])

    def test_source_role_firewall_ti_category_consistency(self):
        """Enforce that TI_OVERLAP_SOURCE must carry TI_EXPOSURE_FEED category."""
        cfg = ApprovedSourceConfig(
            source_name="misconfigured_ti",
            source_category=SourceCategory.CURATED_BENIGN_REGISTRY,
            source_role=SourceRole.TI_OVERLAP_SOURCE,
            input_modality=InputModality.DIRECT_URL,
        )
        valid, errors = validate_source_role_firewall(cfg)
        self.assertFalse(valid)
        self.assertIn("must have TI_EXPOSURE_FEED category", errors[0])

    def test_pii_parameter_sanitization(self):
        """Test sanitization of sensitive query tokens (password, token, api_key, email)."""
        url1 = "https://example.com/login?user=alice&password=SuperSecret123&session=active"
        sanitized1 = sanitize_pii_parameters(url1)
        self.assertNotIn("SuperSecret123", sanitized1)
        self.assertIn("password=[REDACTED]", sanitized1)
        self.assertIn("user=alice", sanitized1)

        url2 = "https://target.net/api/v1?token=abcdef987654&auth=bearerXYZ&email=test@example.com"
        sanitized2 = sanitize_pii_parameters(url2)
        self.assertNotIn("abcdef987654", sanitized2)
        self.assertNotIn("bearerXYZ", sanitized2)
        self.assertNotIn("test@example.com", sanitized2)
        self.assertIn("token=[REDACTED]", sanitized2)

    def test_collector_registration_and_querying(self):
        """Test registration, querying, and listing of approved sources."""
        collector = BenchmarkDataCollector()
        cfg = ApprovedSourceConfig(
            source_name="custom_research_archive",
            source_category=SourceCategory.RESEARCH_DATASET,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
        )
        collector.register_approved_source(cfg)
        retrieved = collector.get_approved_source("custom_research_archive")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.source_name, "custom_research_archive")

        # Duplicate or invalid registration throws error
        invalid_cfg = ApprovedSourceConfig(
            source_name="Agent5",
            source_category=SourceCategory.OTHER,
            source_role=SourceRole.CANDIDATE_SOURCE,
            input_modality=InputModality.DIRECT_URL,
        )
        with self.assertRaises(ValueError):
            collector.register_approved_source(invalid_cfg)

    def test_end_to_end_data_collection(self):
        """Execute end-to-end data collection across multiple approved sources and modalities."""
        source_inputs = {
            "openphish_community": "https://phish.example.com/login\nhttps://malware.example.org/drop",
            "tranco_top_curated": "rank,domain\n1,https://legit-gov.gov/portal",
            "synthetic_qr_testbed": [{"payload": "https://qr-landing.example.net/verify", "id": "qr_001"}],
        }

        # Independent Ground-Truth Evidence (2 sources agreeing for malicious targets)
        gt_evidence = [
            VerificationSourceRecord(
                source_name="authoritative_registry_gt",
                source_type=GTSourceType.AUTHORITATIVE_REGISTRY,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.MALICIOUS,
                asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                observation_time="2026-03-01T10:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="incident_takedown_archive",
                source_type=GTSourceType.INCIDENT_TAKEDOWN_RECORD,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.MALICIOUS,
                asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                observation_time="2026-03-01T11:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="authoritative_registry_gt",
                source_type=GTSourceType.AUTHORITATIVE_REGISTRY,
                source_reference="https://legit-gov.gov/portal",
                asserted_outcome=PrimaryOutcome.BENIGN,
                observation_time="2026-03-01T10:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="trusted_curation_registry",
                source_type=GTSourceType.TRUSTED_BENIGN_CURATION,
                source_reference="https://legit-gov.gov/portal",
                asserted_outcome=PrimaryOutcome.BENIGN,
                observation_time="2026-03-01T10:30:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
        ]

        # TI Overlap Records
        vt_obs = TIFeedObservationRecord(
            feed_name=TIFeed.VIRUSTOTAL,
            status=TIObservationType.DIRECT,
            target_id=compute_target_id("https://phish.example.com/login"),
            first_feed_seen_at="2026-03-01T09:00:00Z",
            observation_time="2026-03-01T12:00:00Z",
        )
        ti_records = [
            TIOverlapRecord(
                target_id=compute_target_id("https://phish.example.com/login"),
                observations={"VirusTotal": vt_obs},
                exposure=TIExposureSummary(
                    target_id=compute_target_id("https://phish.example.com/login"),
                    has_any_direct_positive=True,
                    has_any_partial_positive=False,
                    feed_count_positive=1,
                    feeds_observed_positive=["VirusTotal"],
                    feeds_observed_negative=[],
                    feeds_unavailable=[],
                    earliest_first_feed_seen_at="2026-03-01T09:00:00Z",
                ),
            )
        ]

        result = self.collector.collect_dataset(
            source_inputs=source_inputs,
            ground_truth_evidence=gt_evidence,
            ti_overlap_records=ti_records,
            harvest_timestamp_override="2026-03-02T12:00:00Z",
        )

        self.assertIsInstance(result, CollectionResult)
        self.assertTrue(result.is_ready_for_assembly)
        self.assertEqual(len(result.raw_candidates), 4)
        self.assertEqual(result.manifest.session_status, CollectionSessionStatus.COMPLETED)
        self.assertEqual(result.manifest.stopping_reason, CollectionStoppingReason.SOURCES_EXHAUSTED)
        self.assertEqual(len(result.manifest.manifest_sha256), 64)
        self.assertEqual(len(result.item_audits), 4)

        # Verify modality counts
        self.assertEqual(result.manifest.modality_counts.get("DIRECT_URL"), 3)
        self.assertEqual(result.manifest.modality_counts.get("QR_PAYLOAD"), 1)

    def test_temporal_cutoff_rule(self):
        """Test that candidates observed after temporal cutoff are rejected with audit trail."""
        cfg = CollectionConfig(
            temporal_cutoff_utc="2026-02-01T00:00:00Z",
        )
        collector = create_standard_benchmark_collector(config=cfg, http_transport=self.mock_transport)

        source_inputs = {
            "phishtank_verified": [
                {"url": "https://phish.example.com/login", "phish_id": "1", "submission_time": "2026-01-15T12:00:00Z"},
                {"url": "https://malware.example.org/drop", "phish_id": "2", "submission_time": "2026-02-15T12:00:00Z"}, # Past cutoff
            ]
        }

        result = collector.collect_dataset(source_inputs=source_inputs)
        self.assertEqual(len(result.raw_candidates), 1)
        self.assertEqual(result.manifest.total_candidates_rejected, 1)

        # Verify item audit rejection reason
        rejected_audit = [a for a in result.item_audits if a.liveness_status == "EXCLUDED_TEMPORAL_CUTOFF"][0]
        self.assertIn("cutoff", rejected_audit.rejection_reasons[0])

    def test_capacity_stopping_rule(self):
        """Test stopping collection when reaching max practical ceiling."""
        cfg = CollectionConfig(
            max_practical_ceiling=2,
        )
        collector = create_standard_benchmark_collector(config=cfg, http_transport=self.mock_transport)

        source_inputs = {
            "openphish_community": "https://phish.example.com/login\nhttps://malware.example.org/drop\nhttps://legit-gov.gov/portal",
        }

        result = collector.collect_dataset(source_inputs=source_inputs)
        self.assertEqual(len(result.raw_candidates), 2)
        self.assertEqual(result.manifest.stopping_reason, CollectionStoppingReason.CAPACITY_REACHED)

    def test_unregistered_and_disabled_sources_handling(self):
        """Test handling of unregistered and disabled sources without pipeline crashing."""
        collector = create_standard_benchmark_collector(http_transport=self.mock_transport)
        
        # Disable one source
        disabled_src = collector.get_approved_source("openphish_community")
        if disabled_src:
            collector.register_approved_source(
                ApprovedSourceConfig(
                    source_name=disabled_src.source_name,
                    source_category=disabled_src.source_category,
                    source_role=disabled_src.source_role,
                    input_modality=disabled_src.input_modality,
                    enabled=False,
                )
            )

        source_inputs = {
            "openphish_community": "https://phish.example.com/login",
            "unregistered_bogus_feed": "https://bogus.example.com/test",
            "tranco_top_curated": "rank,domain\n1,https://legit-gov.gov/portal",
        }

        result = collector.collect_dataset(source_inputs=source_inputs)
        self.assertEqual(len(result.raw_candidates), 1)
        self.assertEqual(result.manifest.source_audits["openphish_community"].status, "DISABLED")
        self.assertEqual(result.manifest.source_audits["unregistered_bogus_feed"].status, "UNREGISTERED")

    def test_handoff_to_dataset_assembler_integration(self):
        """Verify clean handoff from BenchmarkDataCollector to Step 6D-6 DatasetAssembler and Pre-Run Gate."""
        source_inputs = {
            "openphish_community": "https://phish.example.com/login",
            "tranco_top_curated": "rank,domain\n1,https://legit-gov.gov/portal",
        }

        gt_evidence = [
            VerificationSourceRecord(
                source_name="authoritative_registry_gt",
                source_type=GTSourceType.AUTHORITATIVE_REGISTRY,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.MALICIOUS,
                asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                observation_time="2026-03-01T10:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="incident_takedown_archive",
                source_type=GTSourceType.INCIDENT_TAKEDOWN_RECORD,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.MALICIOUS,
                asserted_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                observation_time="2026-03-01T11:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="authoritative_registry_gt",
                source_type=GTSourceType.AUTHORITATIVE_REGISTRY,
                source_reference="https://legit-gov.gov/portal",
                asserted_outcome=PrimaryOutcome.BENIGN,
                observation_time="2026-03-01T10:00:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="trusted_curation_registry",
                source_type=GTSourceType.TRUSTED_BENIGN_CURATION,
                source_reference="https://legit-gov.gov/portal",
                asserted_outcome=PrimaryOutcome.BENIGN,
                observation_time="2026-03-01T10:30:00Z",
                confidence=VerificationConfidence.HIGH,
            ),
        ]

        coll_result = self.collector.collect_dataset(
            source_inputs=source_inputs,
            ground_truth_evidence=gt_evidence,
        )
        self.assertTrue(coll_result.is_ready_for_assembly)

        # Handoff to Step 6D-6 Assembler
        assembly_result = self.collector.handoff_to_dataset_assembler(coll_result)
        self.assertEqual(len(assembly_result.records), 2)
        self.assertEqual(assembly_result.gate_result.status, DatasetAssemblyGateStatus.READY_FOR_EXPERIMENT)
        self.assertEqual(len(assembly_result.gate_result.blocking_findings), 0)

    def test_disputed_ground_truth_and_adjudication_resolution(self):
        """Test that conflicting GT evidence is resolved via explicit human analyst adjudication."""
        source_inputs = {
            "openphish_community": "https://phish.example.com/login",
        }

        # Contradictory evidence: one claims MALICIOUS, one claims BENIGN
        conflicting_gt = [
            VerificationSourceRecord(
                source_name="authoritative_registry_gt",
                source_type=GTSourceType.AUTHORITATIVE_REGISTRY,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.MALICIOUS,
                confidence=VerificationConfidence.HIGH,
            ),
            VerificationSourceRecord(
                source_name="trusted_curation_registry",
                source_type=GTSourceType.TRUSTED_BENIGN_CURATION,
                source_reference="https://phish.example.com/login",
                asserted_outcome=PrimaryOutcome.BENIGN,
                confidence=VerificationConfidence.HIGH,
            ),
        ]

        # Explicit human adjudication resolving dispute to MALICIOUS
        adjudications = [
            AdjudicationRecord(
                reviewer_id="analyst_01",
                adjudicated_outcome=PrimaryOutcome.MALICIOUS,
                adjudicated_categories=[SecondaryThreatCategory.CREDENTIAL_PHISHING],
                adjudication_timestamp="2026-03-01T15:00:00Z",
                confidence=VerificationConfidence.HIGH,
                rationale="Analyst inspected DOM and confirmed fake credential prompt.",
            )
        ]

        coll_result = self.collector.collect_dataset(
            source_inputs=source_inputs,
            ground_truth_evidence=conflicting_gt,
            human_adjudications=adjudications,
        )

        assembly_result = self.collector.handoff_to_dataset_assembler(coll_result)
        self.assertEqual(len(assembly_result.records), 1)
        rec = assembly_result.records[0]
        self.assertEqual(rec.ground_truth.primary_outcome, PrimaryOutcome.MALICIOUS)
        self.assertEqual(rec.ground_truth.verification_status, VerificationStatus.VERIFIED)
        self.assertEqual(rec.ground_truth.verification_confidence, VerificationConfidence.HIGH)

    def test_reproducibility_and_deterministic_manifest_hashing(self):
        """Verify that identical collection inputs and timestamps yield identical manifest hashes."""
        source_inputs = {
            "openphish_community": "https://phish.example.com/login\nhttps://malware.example.org/drop",
        }

        res1 = self.collector.collect_dataset(
            source_inputs=source_inputs,
            harvest_timestamp_override="2026-03-01T12:00:00Z",
        )
        res2 = self.collector.collect_dataset(
            source_inputs=source_inputs,
            harvest_timestamp_override="2026-03-01T12:00:00Z",
        )

        self.assertEqual(res1.manifest.raw_artifacts_sha256, res2.manifest.raw_artifacts_sha256)
        self.assertEqual(res1.manifest.manifest_sha256, res2.manifest.manifest_sha256)

    def test_manifest_and_item_audit_json_serialization(self):
        """Verify that all manifest, source audit, and item audit structures serialize to valid JSON."""
        source_inputs = {
            "openphish_community": "https://phish.example.com/login",
        }
        res = self.collector.collect_dataset(source_inputs=source_inputs)
        manifest_dict = res.manifest.to_dict()
        json_str = json.dumps(manifest_dict, sort_keys=True)
        self.assertTrue(len(json_str) > 0)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["session_status"], "COMPLETED")
        self.assertIn("source_audits", parsed)


if __name__ == "__main__":
    unittest.main()
