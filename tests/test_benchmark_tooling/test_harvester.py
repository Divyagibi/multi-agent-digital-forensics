"""Unit Tests for Candidate Harvesting and Raw Candidate Pool Layer.

Step 6D-2: Candidate Harvesting for Multi-Agent Digital Forensics Benchmark.

Validates all required harvesting scenarios:
1. Direct URL extraction (Text, JSON, CSV)
2. QR image candidate metadata
3. QR payload candidate metadata
4. Raw artifact preservation (casing, scheme, port, fragment)
5. Provenance preservation (source_name, source_record_id, source_reference)
6. Source timestamp preservation (first_observed_timestamp, harvest_timestamp)
7. Missing timestamp handling without fabrication
8. Source retrieval failure and unavailability handling
9. Duplicate candidate preservation across sources without deletion
10. Non-HTTP scheme preservation (mailto:, wifi:, smsto:, intent:, etc.)
11. Ground-Truth firewall verification (no BENIGN/MALICIOUS assignment)
12. Zero TCE/CE/AERE dependency
13. Deterministic candidate ID generation
14. Source availability and reporting metrics
15. Malformed candidate and empty line handling
16. Dynamic candidate counts (N≈1200 not a hard quota)
17. No synthetic candidate creation
"""

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.benchmark.schemas import InputModality
from tools.benchmark.harvester import (
    SourceType,
    RetrievalStatus,
    RawCandidate,
    SourceHarvestReport,
    HarvestingResult,
    compute_candidate_id,
    BaseSourceAdapter,
    TextListFeedAdapter,
    JSONFeedAdapter,
    CSVFeedAdapter,
    QRImageSourceAdapter,
    QRPayloadSourceAdapter,
    CustomSourceAdapter,
    CandidateHarvester,
)


class TestCandidateHarvester(unittest.TestCase):
    """Test suite for candidate harvesting and raw candidate pool layer."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_harvester_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_01_direct_url_extraction_text_feed(self):
        """Test 1: Direct URL extraction from plain text newline-separated feed."""
        feed_content = """
        # PhishTank Sample Feed
        https://login.example.com/auth
        http://secure-banking.update.org:8080/portal
        https://legit-domain.com/about
        """
        adapter = TextListFeedAdapter(
            source_name="PhishTank",
            source_type=SourceType.PUBLIC_FEED,
            modality=InputModality.DIRECT_URL,
        )
        candidates, report = adapter.harvest(feed_content, harvest_timestamp="2026-09-15T12:00:00Z")

        self.assertEqual(len(candidates), 3)
        self.assertEqual(report.candidates_harvested, 3)
        self.assertEqual(report.status, RetrievalStatus.SUCCESS)
        self.assertEqual(candidates[0].raw_content, "https://login.example.com/auth")
        self.assertEqual(candidates[0].source_name, "PhishTank")
        self.assertEqual(candidates[0].modality, InputModality.DIRECT_URL)

    def test_02_qr_image_candidate_metadata(self):
        """Test 2: QR image candidate harvesting from static image references."""
        img_items = [
            {"image_path": "/path/to/qr_sample_01.png", "id": "QR-001", "timestamp": "2026-09-01T10:00:00Z"},
            {"image_path": "/path/to/qr_sample_02.png", "id": "QR-002", "timestamp": "2026-09-01T10:05:00Z"},
        ]
        adapter = QRImageSourceAdapter(
            source_name="QuishingResearchDataset",
            source_type=SourceType.RESEARCH_DATASET,
        )
        candidates, report = adapter.harvest(img_items, harvest_timestamp="2026-09-15T12:00:00Z")

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].modality, InputModality.QR_IMAGE)
        self.assertEqual(candidates[0].raw_content, "/path/to/qr_sample_01.png")
        self.assertEqual(candidates[0].source_record_id, "QR-001")
        self.assertEqual(candidates[0].first_observed_timestamp, "2026-09-01T10:00:00Z")
        self.assertTrue(candidates[0].artifact_id.startswith("ART-"))

    def test_03_qr_payload_candidate_metadata(self):
        """Test 3: QR payload candidate harvesting from extracted text payloads."""
        payload_data = [
            {"payload": "https://m.bank.com/quick-login", "id": "PAY-1"},
            {"payload": "WIFI:S:MyNetwork;T:WPA;P:SecretPass;;", "id": "PAY-2"},
        ]
        adapter = QRPayloadSourceAdapter(
            source_name="QRFeed",
            source_type=SourceType.PUBLIC_FEED,
        )
        candidates, report = adapter.harvest(payload_data, harvest_timestamp="2026-09-15T12:00:00Z")

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].modality, InputModality.QR_PAYLOAD)
        self.assertEqual(candidates[0].raw_content, "https://m.bank.com/quick-login")
        self.assertEqual(candidates[1].raw_content, "WIFI:S:MyNetwork;T:WPA;P:SecretPass;;")

    def test_04_raw_artifact_preservation(self):
        """Test 4: Exact raw artifact (casing, port, fragment) is preserved without normalization."""
        raw_url = "HTTPS://Example-Bank.COM:443/Login/Auth?Session=XYZ#Step2"
        adapter = TextListFeedAdapter(source_name="RawSource")
        candidates, _ = adapter.harvest([raw_url])

        self.assertEqual(candidates[0].raw_content, raw_url)
        self.assertIn("Example-Bank.COM", candidates[0].raw_content)
        self.assertIn("#Step2", candidates[0].raw_content)

    def test_05_provenance_preservation(self):
        """Test 5: Full provenance attributes are preserved on candidates."""
        json_data = [
            {
                "url": "https://phish-site.org/login",
                "id": "REC-9876",
                "date_added": "2026-08-20T14:30:00Z",
                "reporter": "security_team",
                "tags": ["phishing", "brand_impersonation"],
            }
        ]
        adapter = JSONFeedAdapter(
            source_name="OpenPhishFeed",
            source_type=SourceType.PUBLIC_FEED,
            content_field="url",
            id_field="id",
            timestamp_field="date_added",
            license_or_access_notes="Public research feed access",
        )
        candidates, _ = adapter.harvest(json_data, harvest_timestamp="2026-09-15T10:00:00Z")

        c = candidates[0]
        self.assertEqual(c.source_name, "OpenPhishFeed")
        self.assertEqual(c.source_record_id, "REC-9876")
        self.assertEqual(c.first_observed_timestamp, "2026-08-20T14:30:00Z")
        self.assertEqual(c.harvest_timestamp, "2026-09-15T10:00:00Z")
        self.assertEqual(c.source_metadata["reporter"], "security_team")
        self.assertEqual(c.license_or_access_notes, "Public research feed access")

        prov = c.to_candidate_provenance()
        self.assertEqual(prov.source_name, "OpenPhishFeed")
        self.assertEqual(prov.source_record_id, "REC-9876")
        self.assertEqual(prov.harvest_timestamp, "2026-09-15T10:00:00Z")

    def test_06_source_timestamp_preservation(self):
        """Test 6: Source first_seen timestamp is preserved when supplied."""
        csv_content = "url,id,timestamp,threat\nhttps://malware-drop.com/file.apk,555,2026-07-01T08:00:00Z,malware\n"
        adapter = CSVFeedAdapter(
            source_name="URLhausCSV",
            content_column="url",
            id_column="id",
            timestamp_column="timestamp",
        )
        candidates, _ = adapter.harvest(csv_content)

        self.assertEqual(candidates[0].first_observed_timestamp, "2026-07-01T08:00:00Z")

    def test_07_missing_timestamp_handling(self):
        """Test 7: Missing timestamp is preserved as empty string without fabricating a date."""
        raw_list = ["https://example.org/home"]
        adapter = TextListFeedAdapter(source_name="NoTimestampFeed")
        candidates, _ = adapter.harvest(raw_list)

        self.assertEqual(candidates[0].first_observed_timestamp, "")

    def test_08_source_retrieval_failure_handling(self):
        """Test 8: Source retrieval failure is handled safely and recorded in SourceHarvestReport."""
        adapter = TextListFeedAdapter(source_name="MissingFileSource")
        non_existent_file = Path(self.temp_dir) / "does_not_exist.txt"
        candidates, report = adapter.harvest(non_existent_file)

        self.assertEqual(len(candidates), 0)
        self.assertEqual(report.status, RetrievalStatus.FAILED)
        self.assertTrue(len(report.errors) >= 1)

    def test_09_duplicate_candidate_preservation(self):
        """Test 9: Duplicate candidates across sources are retained with provenance, not silently dropped."""
        src1_data = ["https://shared-target.com/login", "https://unique-src1.com"]
        src2_data = ["https://shared-target.com/login", "https://unique-src2.com"]

        harvester = CandidateHarvester()
        harvester.register_adapter(TextListFeedAdapter("SourceA"))
        harvester.register_adapter(TextListFeedAdapter("SourceB"))

        result = harvester.harvest_all({
            "SourceA": src1_data,
            "SourceB": src2_data,
        })

        # All 4 records are retained
        self.assertEqual(result.total_candidates_harvested, 4)
        self.assertEqual(len(result.candidates), 4)
        # Duplicate is detected in diagnostics
        self.assertEqual(result.exact_duplicate_count, 1)
        self.assertEqual(result.diagnostics["unique_artifacts_count"], 3)

    def test_10_non_http_scheme_preservation(self):
        """Test 10: Non-HTTP schemes (mailto:, wifi:, smsto:, intent:) are stored safely without execution."""
        schemes = [
            "mailto:phish@victim.com?subject=Important",
            "smsto:123456:YourCodeIs999",
            "wifi:S:FakeGuest;P:None;;",
            "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end",
            "javascript:void(0)",
        ]
        adapter = TextListFeedAdapter(source_name="NonHttpSource", modality=InputModality.QR_PAYLOAD)
        candidates, _ = adapter.harvest(schemes)

        self.assertEqual(len(candidates), 5)
        self.assertEqual(candidates[0].raw_content, schemes[0])
        self.assertEqual(candidates[3].raw_content, schemes[3])

    def test_11_ground_truth_firewall(self):
        """Test 11: Harvester MUST NOT assign ground-truth labels (BENIGN / MALICIOUS)."""
        malicious_feed_json = [
            {"url": "https://confirmed-bad.com", "tag": "malware", "source_verdict": "malicious"}
        ]
        adapter = JSONFeedAdapter(source_name="MaliciousFeed")
        candidates, _ = adapter.harvest(malicious_feed_json)

        c = candidates[0]
        # Raw candidate has source metadata, but NO primary ground-truth field
        self.assertFalse(hasattr(c, "primary_outcome"))
        self.assertFalse(hasattr(c, "ground_truth"))
        self.assertEqual(c.source_metadata.get("source_verdict"), "malicious")

    def test_12_no_tce_ce_aere_dependency(self):
        """Test 12: Harvester operates with zero imports or couplings to forensic engines."""
        import tools.benchmark.harvester as h_mod
        # Inspect module imports
        imported_symbols = dir(h_mod)
        self.assertNotIn("TrustCalculationEngine", imported_symbols)
        self.assertNotIn("ConfidenceEngine", imported_symbols)
        self.assertNotIn("AEREReasoningEngine", imported_symbols)
        self.assertNotIn("analysis_pipeline", imported_symbols)

    def test_13_deterministic_candidate_ids(self):
        """Test 13: Candidate IDs are deterministic and reproducible."""
        cid1 = compute_candidate_id("OpenPhish", "https://example.com/test", "123")
        cid2 = compute_candidate_id("OpenPhish", "https://example.com/test", "123")
        cid3 = compute_candidate_id("URLhaus", "https://example.com/test", "123")

        self.assertEqual(cid1, cid2)
        self.assertNotEqual(cid1, cid3)
        self.assertTrue(cid1.startswith("CAN-"))

    def test_14_source_availability_reporting(self):
        """Test 14: Harvesting reports detailed source availability and counts."""
        harvester = CandidateHarvester()
        harvester.register_adapter(TextListFeedAdapter("ActiveSource"))

        result = harvester.harvest_all({
            "ActiveSource": ["https://active.com/1", "https://active.com/2"],
            "UnregisteredSource": ["https://foo.com"],
        })

        self.assertEqual(result.total_candidates_harvested, 2)
        self.assertEqual(result.source_reports["ActiveSource"].status, RetrievalStatus.SUCCESS)
        self.assertEqual(result.source_reports["UnregisteredSource"].status, RetrievalStatus.UNAVAILABLE)

    def test_15_malformed_candidate_handling(self):
        """Test 15: Malformed lines, empty strings, and comments are handled gracefully."""
        messy_feed = "\n\n# Header\n   \nhttps://valid.com\n// Another comment\n\n"
        adapter = TextListFeedAdapter("MessySource")
        candidates, report = adapter.harvest(messy_feed)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].raw_content, "https://valid.com")

    def test_16_dynamic_candidate_counts(self):
        """Test 16: Harvester operates dynamically without hard-coding N=1200."""
        # 5 items
        adapter = TextListFeedAdapter("SmallSource")
        cands5, _ = adapter.harvest([f"https://sample.com/{i}" for i in range(5)])
        self.assertEqual(len(cands5), 5)

        # 100 items
        cands100, _ = adapter.harvest([f"https://sample.com/{i}" for i in range(100)])
        self.assertEqual(len(cands100), 100)

    def test_17_no_synthetic_candidate_creation(self):
        """Test 17: No synthetic records are created to pad dataset counts."""
        adapter = TextListFeedAdapter("RealSource")
        input_urls = ["https://a.com", "https://b.com"]
        candidates, _ = adapter.harvest(input_urls)

        self.assertEqual(len(candidates), 2)
        self.assertEqual([c.raw_content for c in candidates], input_urls)


if __name__ == "__main__":
    unittest.main()
