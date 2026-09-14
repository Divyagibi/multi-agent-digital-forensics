"""
tests/test_evidence_ledger.py
=============================
Unit and Integration Tests for Evidence Normalization and Evidence Ledger.

Verifies:
1. Basic normalization of agent results
2. Evidence ID traceability and retention
3. Target and entity normalization consistency
4. Missing and unavailable data preservation (no fabricated zeros)
5. Provenance preservation and traceability
6. Cross-agent correlation across entities
7. Contradiction preservation without risk scoring
8. Duplicate handling with distinct provenance
9. Error / skipped / unavailable status preservation
10. Strict scoring separation (no trust/risk/confidence scores or verdicts)
11. Full pipeline integration generating complete Evidence Ledger
"""

import unittest
from unittest.mock import patch, MagicMock

from services.evidence_schema import create_evidence_item, build_agent_result
from services.evidence_normalizer import normalize_target, normalize_evidence_item
from services.evidence_ledger import EvidenceLedger, RELATIONSHIP_TYPES
from services.analysis_pipeline import run_full_pipeline, create_analysis_session


class TestEvidenceNormalizationAndLedger(unittest.TestCase):

    def setUp(self):
        self.sample_url = "https://example.com/login"
        self.sample_target = normalize_target(self.sample_url)

    # -----------------------------------------------------------------
    # Test 1: Basic Normalization
    # -----------------------------------------------------------------
    def test_01_basic_normalization(self):
        """Test that a valid agent result becomes a valid normalized evidence entry."""
        ev_item = create_evidence_item(
            agent_id=1,
            index=1,
            finding="Domain registered recently",
            value="15 days",
            severity="medium",
            source="WHOIS/RDAP",
            evidence_type="deterministic",
            evidence_strength=0.95,
            metadata={"domain_age_days": 15}
        )
        agent_result = build_agent_result(
            agent_identifier=1,
            target=self.sample_url,
            status="success",
            data={"domain_age_days": 15},
            evidence=[ev_item]
        )

        norm_entry = normalize_evidence_item(
            evidence_item=ev_item,
            agent_identifier=1,
            agent_result=agent_result,
            canonical_target=self.sample_target
        )

        self.assertEqual(norm_entry["evidence_id"], "E1-01")
        self.assertEqual(norm_entry["agent_id"], 1)
        self.assertEqual(norm_entry["agent_name"], "Domain Identity")
        self.assertEqual(norm_entry["evidence_type"], "deterministic")
        self.assertEqual(norm_entry["severity"], "medium")
        self.assertEqual(norm_entry["description"], "Domain registered recently")
        self.assertEqual(norm_entry["value"], "15 days")
        self.assertEqual(norm_entry["evidence_strength"], 0.95)
        self.assertEqual(norm_entry["status"], "success")
        self.assertIsInstance(norm_entry["target"], dict)
        self.assertIsInstance(norm_entry["provenance"], dict)

    # -----------------------------------------------------------------
    # Test 2: Evidence Identity Traceability
    # -----------------------------------------------------------------
    def test_02_evidence_identity_traceability(self):
        """Test that original evidence IDs remain uniquely traceable."""
        ev_item = create_evidence_item(
            agent_id=3,
            index=4,
            finding="Self-signed certificate detected",
            value=True,
            severity="high",
            source="TLS Handshake",
            evidence_type="deterministic"
        )
        norm_entry = normalize_evidence_item(
            evidence_item=ev_item,
            agent_identifier=3,
            canonical_target=self.sample_target
        )
        self.assertEqual(norm_entry["evidence_id"], "E3-04")
        self.assertEqual(norm_entry["provenance"]["source_agent"], "A3")

        ledger = EvidenceLedger(target=self.sample_url)
        ledger.add_entry(norm_entry)
        entries = ledger.get_entries(agent_id=3)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["evidence_id"], "E3-04")

    # -----------------------------------------------------------------
    # Test 3: Target Normalization
    # -----------------------------------------------------------------
    def test_03_target_normalization_consistency(self):
        """Test that different URL/domain representations normalize consistently."""
        t1 = normalize_target("https://www.example.com")
        t2 = normalize_target("http://example.com/")
        t3 = normalize_target("example.com")
        t4 = normalize_target("https://sub.example.co.uk:8443/auth/login?param=1")

        self.assertEqual(t1["registrable_domain"], "example.com")
        self.assertEqual(t2["registrable_domain"], "example.com")
        self.assertEqual(t3["registrable_domain"], "example.com")

        self.assertEqual(t4["registrable_domain"], "example.co.uk")
        self.assertEqual(t4["port"], 8443)
        self.assertEqual(t4["path"], "/auth/login")

        # Plain domain without path keeps path as None, not fabricated '/'
        self.assertIsNone(t3["path"])
        self.assertIsNone(t3["scheme"])

    # -----------------------------------------------------------------
    # Test 4: Missing Data Preservation
    # -----------------------------------------------------------------
    def test_04_missing_data_preservation(self):
        """Test that missing fields remain missing (None) and are not fabricated."""
        empty_target = normalize_target("")
        self.assertIsNone(empty_target["hostname"])
        self.assertIsNone(empty_target["registrable_domain"])
        self.assertIsNone(empty_target["port"])
        self.assertIsNone(empty_target["scheme"])

        ev_item = {
            "evidence_id": "E15-01",
            "finding": "Google Reviews unavailable",
            "value": None,
            "severity": "info",
            "source": "Google Places",
            "evidence_type": "external_source",
            "metadata": {}
        }
        norm_entry = normalize_evidence_item(
            evidence_item=ev_item,
            agent_identifier=15,
            agent_result={"status": "unavailable", "data": {}}
        )

        self.assertIsNone(norm_entry["value"])
        self.assertIsNone(norm_entry["evidence_strength"])
        self.assertEqual(norm_entry["status"], "unavailable")
        # Ensure it was not converted to value=0 or high severity
        self.assertNotEqual(norm_entry["value"], 0)
        self.assertEqual(norm_entry["severity"], "info")

    # -----------------------------------------------------------------
    # Test 5: Provenance Retention
    # -----------------------------------------------------------------
    def test_05_provenance_retention(self):
        """Test that agent and source provenance is completely retained."""
        ev_item = create_evidence_item(
            agent_id=9,
            index=2,
            finding="PayPal logo detected on non-official domain",
            value="PayPal",
            severity="high",
            source="Visual Matcher",
            evidence_type="inference",
            evidence_strength=0.92
        )
        norm_entry = normalize_evidence_item(
            evidence_item=ev_item,
            agent_identifier=9,
            agent_result={"status": "success", "agent": "Brand Verification"}
        )

        prov = norm_entry["provenance"]
        self.assertEqual(prov["source_agent"], "A9")
        self.assertEqual(prov["source_name"], "Brand Verification")
        self.assertEqual(prov["source_number"], 9)
        self.assertEqual(prov["source_detail"], "Visual Matcher")
        self.assertEqual(prov["agent_status"], "success")

    # -----------------------------------------------------------------
    # Test 6: Cross-Agent Target Correlation
    # -----------------------------------------------------------------
    def test_06_cross_agent_correlation(self):
        """Test that evidence from different agents on the same target is linked."""
        ledger = EvidenceLedger(target="https://example.com")

        e1 = normalize_evidence_item(
            evidence_item=create_evidence_item(1, 1, "WHOIS found registrar", "MarkMonitor", "info", "WHOIS"),
            agent_identifier=1,
            canonical_target=ledger.target
        )
        e2 = normalize_evidence_item(
            evidence_item=create_evidence_item(2, 1, "DNS A record resolved", "93.184.216.34", "info", "DNS"),
            agent_identifier=2,
            canonical_target=ledger.target
        )
        e3 = normalize_evidence_item(
            evidence_item=create_evidence_item(3, 1, "Valid DigiCert TLS certificate", "DigiCert", "info", "SSL"),
            agent_identifier=3,
            canonical_target=ledger.target
        )

        ledger.add_entry(e1)
        ledger.add_entry(e2)
        ledger.add_entry(e3)

        relationships = ledger.correlate_relationships()
        self.assertTrue(len(relationships) >= 3)
        rel_types = {r["relationship_type"] for r in relationships}
        self.assertTrue("same_target" in rel_types or "related_dimension" in rel_types)

    # -----------------------------------------------------------------
    # Test 7: Contradiction Preservation
    # -----------------------------------------------------------------
    def test_07_contradiction_preservation(self):
        """Test that contradictory observations are preserved as relationships without scoring."""
        ledger = EvidenceLedger(target="https://example.com")

        # Agent 12: Declared business in United Kingdom
        e_a12 = normalize_evidence_item(
            evidence_item=create_evidence_item(
                agent_id=12,
                index=1,
                finding="Contact address located in United Kingdom",
                value="UK",
                severity="info",
                source="Footer Parser",
                metadata={"country": "UK"}
            ),
            agent_identifier=12,
            canonical_target=ledger.target
        )

        # Agent 2: Server IP located in India
        e_a2 = normalize_evidence_item(
            evidence_item=create_evidence_item(
                agent_id=2,
                index=1,
                finding="Server infrastructure IP hosted in India",
                value="IN",
                severity="info",
                source="GeoIP",
                metadata={"country": "IN"}
            ),
            agent_identifier=2,
            canonical_target=ledger.target
        )

        ledger.add_entry(e_a12)
        ledger.add_entry(e_a2)
        ledger.correlate_relationships()

        contradictions = ledger.get_contradictions()
        self.assertEqual(len(contradictions), 1)
        self.assertEqual(contradictions[0]["relationship_type"], "contradiction")
        self.assertIn("location discrepancy", contradictions[0]["description"].lower())

        # Verify no risk score was added
        ledger_dict = ledger.to_dict()
        self.assertNotIn("risk_score", ledger_dict)
        self.assertNotIn("trust_score", ledger_dict)
        self.assertNotIn("verdict", ledger_dict)

    # -----------------------------------------------------------------
    # Test 8: Duplicate Handling
    # -----------------------------------------------------------------
    def test_08_duplicate_handling_preserves_provenance(self):
        """Test that duplicate evidence entries preserve distinct provenance."""
        ledger = EvidenceLedger(target="https://example.com")

        e1 = normalize_evidence_item(
            evidence_item=create_evidence_item(1, 1, "Domain created 2020", "2020-01-01", "info", "WHOIS Raw"),
            agent_identifier=1,
            canonical_target=ledger.target
        )
        e2 = normalize_evidence_item(
            evidence_item=create_evidence_item(1, 1, "Domain created 2020", "2020-01-01", "info", "RDAP Query"),
            agent_identifier=1,
            canonical_target=ledger.target
        )

        ledger.add_entry(e1)
        ledger.add_entry(e2)
        self.assertEqual(len(ledger.entries), 2)
        self.assertNotEqual(ledger.entries[0]["evidence_id"], ledger.entries[1]["evidence_id"])

        ledger.correlate_relationships()
        dups = ledger.get_relationships(relationship_type="duplicate")
        self.assertEqual(len(dups), 1)

    # -----------------------------------------------------------------
    # Test 9: Error/Skipped/Unavailable Status Distinguishable
    # -----------------------------------------------------------------
    def test_09_error_skipped_unavailable_handling(self):
        """Test that error, skipped, and unavailable states are distinguished from negative evidence."""
        ev_item = {
            "evidence_id": "E6-01",
            "finding": "VirusTotal API rate limit exceeded",
            "value": None,
            "severity": "info",
            "source": "VirusTotal",
            "evidence_type": "threat_intelligence"
        }
        norm_entry = normalize_evidence_item(
            evidence_item=ev_item,
            agent_identifier=6,
            agent_result={"status": "unavailable", "errors": ["HTTP 429"]}
        )

        self.assertEqual(norm_entry["status"], "unavailable")
        self.assertEqual(norm_entry["severity"], "info")
        self.assertIsNone(norm_entry["value"])

    # -----------------------------------------------------------------
    # Test 10: Strict Scoring Separation
    # -----------------------------------------------------------------
    def test_10_no_scoring_in_evidence_ledger(self):
        """Verify that EvidenceLedger does NOT compute trust/risk scores or verdicts."""
        ledger = EvidenceLedger(target="https://phishing-site.example.com")
        
        # Add high severity evidence
        for i in range(1, 6):
            e = normalize_evidence_item(
                evidence_item=create_evidence_item(i, 1, f"Malicious flag {i}", True, "critical", "Engine"),
                agent_identifier=i,
                canonical_target=ledger.target
            )
            ledger.add_entry(e)

        ledger.correlate_relationships()
        ledger_dict = ledger.to_dict()

        # Explicitly verify absence of scoring properties
        for key in ["risk_score", "trust_score", "confidence_score", "verdict", "risk_weight"]:
            self.assertNotIn(key, ledger_dict, f"Found forbidden scoring key: '{key}' in ledger root")
            self.assertNotIn(key, ledger_dict["summary"], f"Found forbidden scoring key: '{key}' in ledger summary")

    # -----------------------------------------------------------------
    # Test 11: Full Pipeline Integration
    # -----------------------------------------------------------------
    @patch("services.analysis_pipeline.analyze_qr")
    @patch("services.analysis_pipeline.run_single_agent")
    def test_11_full_pipeline_produces_evidence_ledger(self, mock_run_single, mock_analyze_qr):
        """Verify that running the full pipeline attaches a complete EvidenceLedger without breaking agent outputs."""
        def fake_run_single(agent_id, target_url, **kwargs):
            ev = create_evidence_item(
                agent_id=agent_id,
                index=1,
                finding=f"Agent {agent_id} observation on {target_url}",
                value=f"val_{agent_id}",
                severity="info" if agent_id % 2 == 0 else "medium",
                source=f"Module_{agent_id}"
            )
            return build_agent_result(
                agent_identifier=agent_id,
                target=target_url,
                status="success",
                data={f"metric_{agent_id}": 100},
                evidence=[ev]
            )

        mock_run_single.side_effect = fake_run_single
        mock_analyze_qr.return_value = build_agent_result(
            agent_identifier=18,
            target="https://example.com",
            status="success",
            data={"qr_detected": False},
            evidence=[create_evidence_item(18, 1, "No QR embedded", False, "info", "QR Inspector")]
        )

        session = run_full_pipeline("https://example.com")

        self.assertIn("evidence_ledger", session)
        ledger_data = session["evidence_ledger"]
        self.assertIsInstance(ledger_data, dict)
        self.assertIn("target", ledger_data)
        self.assertIn("entries", ledger_data)
        self.assertIn("relationships", ledger_data)
        self.assertIn("summary", ledger_data)

        # Verify all 18 agent output envelopes remain intact
        for i in range(1, 19):
            agent_key = f"agent{i}"
            self.assertIn(agent_key, session["agents"])
            self.assertIsInstance(session["agents"][agent_key], dict)

        # Verify backward compatibility
        self.assertIsInstance(session["all_evidence"], list)
        self.assertEqual(len(session["all_evidence"]), 18)
        self.assertIsNotNone(session["trust_score"])
        self.assertIsNotNone(session["risk_score"])
        self.assertIn(session["verdict"], ["benign", "low_risk", "suspicious", "high_risk", "malicious", "unknown"])
        self.assertIn("tce_summary", session)


if __name__ == "__main__":
    unittest.main()
