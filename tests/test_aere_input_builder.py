"""
tests/test_aere_input_builder.py
================================
Unit tests for the AERE Input Builder (Step 3D-1).

Verifies:
1. Actual TCE values are preserved verbatim.
2. No hardcoded TCE values exist in output.
3. Real Evidence IDs are extracted strictly from the ledger.
4. No fabricated or fictional Evidence IDs are introduced.
5. Source Evidence Ledger remains strictly immutable.
6. All 6 relationship types are preserved with IDs and metadata.
7. Missing and unavailable evidence states are preserved without mutation.
8. Provenance metadata survives payload construction intact.
9. Sensitive fields (passwords, tokens, keys) are masked while ledger remains untouched.
10. Field-aware bounded minimization operates cleanly without corrupting structure.
11. Deterministic sorting and canonical hashing across runs.
12. Actual runtime target and investigation metadata are propagated.
13. Builder performs zero risk/trust scoring calculations.
14. Empty and minimal ledgers are handled gracefully without hallucination.
15. TCE boundary is maintained with zero alternative scoring.
"""

import copy
import json
import unittest

from services.evidence_schema import create_evidence_item, build_agent_result
from services.evidence_normalizer import normalize_evidence_item, normalize_target
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.aere_input_builder import (
    AEREInputBuilder,
    build_aere_input_payload,
    MAX_FINDING_LENGTH,
    MAX_VALUE_STRING_LENGTH
)


class TestAEREInputBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = AEREInputBuilder()
        self.sample_url = "https://example-forensics.test/auth"
        self.target = normalize_target(self.sample_url)

    def _create_sample_ledger(self) -> EvidenceLedger:
        """Helper to create a populated EvidenceLedger for testing."""
        ledger = EvidenceLedger(target=self.sample_url)

        # Agent 1 Entry
        e1 = normalize_evidence_item(
            evidence_item={
                "evidence_id": "E1-01",
                "type": "deterministic",
                "finding": "Domain registered 3 days ago",
                "category": "domain_registered_recently",
                "severity": "medium",
                "source": "WHOIS",
                "evidence_strength": 0.95
            },
            agent_identifier=1,
            canonical_target=self.target
        )
        ledger.add_entry(e1)

        # Agent 3 Entry
        e3 = normalize_evidence_item(
            evidence_item={
                "evidence_id": "E3-02",
                "type": "deterministic",
                "finding": "Self-signed SSL certificate",
                "category": "self_signed_certificate",
                "severity": "high",
                "source": "TLS Handshake",
                "evidence_strength": 1.00
            },
            agent_identifier=3,
            canonical_target=self.target
        )
        ledger.add_entry(e3)

        # Agent 8 Entry
        e8 = normalize_evidence_item(
            evidence_item={
                "evidence_id": "E8-01",
                "type": "deterministic",
                "finding": "Fake login form with password harvester",
                "category": "fake_login_form",
                "severity": "critical",
                "source": "DOM Form Parser",
                "evidence_strength": 1.00,
                "metadata": {"password_field": "user_pass", "action": "/steal"}
            },
            agent_identifier=8,
            canonical_target=self.target
        )
        ledger.add_entry(e8)

        ledger.add_relationship(
            source_evidence_id="E1-01",
            target_evidence_id="E3-02",
            relationship_type="supporting",
            description="Young domain with untrusted certificate"
        )
        return ledger

    # -----------------------------------------------------------------
    # Test 01: Actual TCE Values Preserved
    # -----------------------------------------------------------------
    def test_01_actual_tce_values_preserved(self):
        """Verify the builder preserves the exact runtime TCE result without alteration."""
        ledger = self._create_sample_ledger()
        tce = TrustCalculationEngine()
        tce_result = tce.calculate_trust(ledger)

        payload = self.builder.build_payload(ledger=ledger, tce_result=tce_result)

        self.assertIn("tce_result", payload)
        self.assertEqual(payload["tce_result"]["risk_score"], tce_result["risk_score"])
        self.assertEqual(payload["tce_result"]["trust_score"], tce_result["trust_score"])
        self.assertEqual(payload["tce_result"]["verdict"], tce_result["verdict"])
        self.assertEqual(
            payload["tce_result"]["aggregation_metrics"]["r_plus"],
            tce_result["aggregation_metrics"]["r_plus"]
        )

    # -----------------------------------------------------------------
    # Test 02: No Hardcoded TCE Values
    # -----------------------------------------------------------------
    def test_02_no_hardcoded_tce_values(self):
        """Verify that deliberately custom/unusual TCE test values appear verbatim in payload."""
        ledger = self._create_sample_ledger()
        custom_tce = {
            "risk_score": 42.17,
            "trust_score": 57.83,
            "verdict": "suspicious",
            "low_telemetry_coverage": True,
            "telemetry_coverage": 0.1234,
            "inconsistency_index": 75.0,
            "contradiction_penalty_applied": 10.0,
            "aggregation_metrics": {"r_plus": 0.54321, "r_minus": 0.12345, "r_net": 0.48148},
            "evidence_contributions": []
        }

        payload = self.builder.build_payload(ledger=ledger, tce_result=custom_tce)

        self.assertEqual(payload["tce_result"]["risk_score"], 42.17)
        self.assertEqual(payload["tce_result"]["trust_score"], 57.83)
        self.assertEqual(payload["tce_result"]["verdict"], "suspicious")
        self.assertEqual(payload["tce_result"]["telemetry_coverage"], 0.1234)

    # -----------------------------------------------------------------
    # Test 03: Real Evidence IDs
    # -----------------------------------------------------------------
    def test_03_real_evidence_ids_extracted(self):
        """Verify all output Evidence IDs originate strictly from the supplied ledger."""
        ledger = self._create_sample_ledger()
        payload = self.builder.build_payload(ledger=ledger)

        output_ids = [e["evidence_id"] for e in payload["ledger_summary"]["entries"]]
        expected_ids = ["E1-01", "E3-02", "E8-01"]
        self.assertEqual(sorted(output_ids), sorted(expected_ids))

    # -----------------------------------------------------------------
    # Test 04: No Fabricated Evidence IDs
    # -----------------------------------------------------------------
    def test_04_no_fabricated_evidence_ids(self):
        """Verify the builder never introduces IDs not present in the ledger."""
        ledger = self._create_sample_ledger()
        payload = self.builder.build_payload(ledger=ledger)

        ledger_ids = {e["evidence_id"] for e in ledger.entries}
        for entry in payload["ledger_summary"]["entries"]:
            self.assertIn(entry["evidence_id"], ledger_ids)

        for rel in payload["ledger_summary"]["relationships"]:
            self.assertIn(rel["source_evidence_id"], ledger_ids)
            self.assertIn(rel["target_evidence_id"], ledger_ids)

    # -----------------------------------------------------------------
    # Test 05: Ledger Immutability
    # -----------------------------------------------------------------
    def test_05_ledger_immutability(self):
        """Verify that building a payload does NOT mutate or alter the source EvidenceLedger."""
        ledger = self._create_sample_ledger()
        ledger_copy_before = copy.deepcopy(ledger.to_dict())

        # Build payload with sensitive data and bounds
        payload = self.builder.build_payload(
            ledger=ledger,
            investigation_id="INV-999"
        )

        ledger_after = ledger.to_dict()
        self.assertEqual(ledger_copy_before, ledger_after)
        self.assertEqual(len(ledger.entries), len(ledger_copy_before["entries"]))
        self.assertEqual(len(ledger.relationships), len(ledger_copy_before["relationships"]))

    # -----------------------------------------------------------------
    # Test 06: Relationship Preservation
    # -----------------------------------------------------------------
    def test_06_relationship_preservation_all_types(self):
        """Verify supporting, contradiction, duplicate, derived_from, same_target, related_dimension are preserved."""
        ledger = EvidenceLedger(target=self.sample_url)

        # Add 6 entries
        for i in range(1, 7):
            ledger.add_entry(normalize_evidence_item({
                "evidence_id": f"E{i}-01",
                "finding": f"Observation {i}",
                "severity": "info"
            }, i, canonical_target=self.target))

        # Add one of each relationship type
        types = ["supporting", "contradiction", "duplicate", "derived_from", "same_target", "related_dimension"]
        for idx, rtype in enumerate(types):
            src = f"E{idx+1}-01"
            tgt = f"E{((idx+1)%6)+1}-01"
            ledger.add_relationship(src, tgt, rtype, description=f"Test {rtype} link")

        payload = self.builder.build_payload(ledger=ledger)
        rels = payload["ledger_summary"]["relationships"]
        self.assertEqual(len(rels), 6)

        rel_types_present = {r["relationship_type"] for r in rels}
        self.assertEqual(rel_types_present, set(types))

        for r in rels:
            self.assertTrue(r["relationship_id"].startswith("REL-"))
            self.assertIn("source_evidence_id", r)
            self.assertIn("target_evidence_id", r)

    # -----------------------------------------------------------------
    # Test 07: Missing Evidence Preservation
    # -----------------------------------------------------------------
    def test_07_missing_evidence_preservation(self):
        """Verify unavailable/skipped/error/restricted states remain unchanged without synthetic conversion."""
        ledger = EvidenceLedger(target=self.sample_url)

        agent_statuses = ["unavailable", "skipped", "error", "restricted", "success"]
        for idx, st in enumerate(agent_statuses):
            ev = normalize_evidence_item(
                evidence_item={
                    "evidence_id": f"E{idx+1}-01",
                    "finding": f"Finding with status {st}",
                    "severity": "info"
                },
                agent_identifier=idx+1,
                agent_result={"status": st},
                canonical_target=self.target
            )
            ledger.add_entry(ev)

        payload = self.builder.build_payload(ledger=ledger)
        entries = payload["ledger_summary"]["entries"]

        # In schema: unavailable and restricted map to unavailable entry status
        expected_entry_statuses = ["unavailable", "skipped", "error", "unavailable", "success"]
        for idx, exp_st in enumerate(expected_entry_statuses):
            self.assertEqual(entries[idx]["status"], exp_st)

        summary = payload["agent_execution_summary"]
        self.assertEqual(summary["missing_or_unavailable_entries_count"], 4)

    # -----------------------------------------------------------------
    # Test 08: Provenance Preservation
    # -----------------------------------------------------------------
    def test_08_provenance_preservation(self):
        """Verify provenance metadata survives payload construction intact."""
        ledger = self._create_sample_ledger()
        payload = self.builder.build_payload(ledger=ledger)

        for entry in payload["ledger_summary"]["entries"]:
            self.assertIn("provenance", entry)
            self.assertIsInstance(entry["provenance"], dict)
            self.assertIn("source_agent", entry["provenance"])
            self.assertIn("source_name", entry["provenance"])
            self.assertIn("source_function", entry["provenance"])

    # -----------------------------------------------------------------
    # Test 09: Sensitive-Data Masking
    # -----------------------------------------------------------------
    def test_09_sensitive_data_masking(self):
        """Verify passwords, tokens, and API keys are masked in payload while original ledger remains intact."""
        ledger = EvidenceLedger(target=self.sample_url)
        e = normalize_evidence_item({
            "evidence_id": "E8-09",
            "finding": "Form contains password field",
            "severity": "critical",
            "metadata": {
                "password": "SuperSecretPassword123!",
                "api_key": "sk-1234567890abcdef",
                "bearer_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "normal_field": "contact@example.com",
                "auth_token": "token_abc_xyz"
            }
        }, 8, canonical_target=self.target)
        ledger.add_entry(e)

        payload = self.builder.build_payload(ledger=ledger)
        clean_entry = payload["ledger_summary"]["entries"][0]

        # In payload: sensitive fields in data are masked
        self.assertEqual(clean_entry["data"]["password"], "[REDACTED]")
        self.assertEqual(clean_entry["data"]["api_key"], "[REDACTED]")
        self.assertEqual(clean_entry["data"]["bearer_token"], "[REDACTED]")
        self.assertEqual(clean_entry["data"]["normal_field"], "contact@example.com")
        self.assertEqual(clean_entry["data"]["auth_token"], "[REDACTED]")

        # In original ledger: values remain untouched
        orig_entry = ledger.entries[0]
        self.assertEqual(orig_entry["data"]["password"], "SuperSecretPassword123!")
        self.assertEqual(orig_entry["data"]["api_key"], "sk-1234567890abcdef")

        # Telemetry records masked count
        self.assertGreaterEqual(payload["builder_telemetry"]["masked_fields_count"], 1)

    # -----------------------------------------------------------------
    # Test 10: Large-Field Minimization
    # -----------------------------------------------------------------
    def test_10_large_field_minimization(self):
        """Verify oversized fields are bounded cleanly without corrupting structure."""
        ledger = EvidenceLedger(target=self.sample_url)
        huge_text = "A" * (MAX_FINDING_LENGTH + 200)
        huge_val = "B" * (MAX_VALUE_STRING_LENGTH + 200)

        e = normalize_evidence_item({
            "evidence_id": "E4-01",
            "finding": huge_text,
            "value": huge_val,
            "severity": "low"
        }, 4, canonical_target=self.target)
        ledger.add_entry(e)

        payload = self.builder.build_payload(ledger=ledger)
        entry = payload["ledger_summary"]["entries"][0]

        self.assertTrue(entry["finding"].endswith("[TRUNCATED]"))
        self.assertEqual(len(entry["finding"]), MAX_FINDING_LENGTH + len(" [TRUNCATED]"))
        self.assertTrue(entry["value"].endswith("[TRUNCATED]"))
        self.assertEqual(len(entry["value"]), MAX_VALUE_STRING_LENGTH + len(" [TRUNCATED]"))
        self.assertEqual(payload["builder_telemetry"]["truncated_fields_count"], 1)

    # -----------------------------------------------------------------
    # Test 11: Deterministic Ordering & SHA-256 Hash
    # -----------------------------------------------------------------
    def test_11_deterministic_ordering_and_hash(self):
        """Verify that building the payload twice from identical inputs yields matching structures and hashes."""
        ledger = self._create_sample_ledger()
        tce = TrustCalculationEngine()
        tce_res = tce.calculate_trust(ledger)

        payload1 = self.builder.build_payload(ledger=ledger, tce_result=tce_res, investigation_id="INV-01")
        payload2 = self.builder.build_payload(ledger=ledger, tce_result=tce_res, investigation_id="INV-01")

        # Hashes match
        hash1 = payload1["investigation_metadata"]["ledger_sha256"]
        hash2 = payload2["investigation_metadata"]["ledger_sha256"]
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

        # Structure matches exactly (excluding timestamp)
        p1_no_time = copy.deepcopy(payload1)
        p2_no_time = copy.deepcopy(payload2)
        p1_no_time["investigation_metadata"].pop("created_at")
        p2_no_time["investigation_metadata"].pop("created_at")
        self.assertEqual(p1_no_time, p2_no_time)

    # -----------------------------------------------------------------
    # Test 12: Actual Target Metadata
    # -----------------------------------------------------------------
    def test_12_actual_target_metadata_propagated(self):
        """Verify URL, hostname, domain, and IP are taken from actual runtime input."""
        runtime_url = "https://sub.portal.phish-bank.org:8443/login"
        ledger = EvidenceLedger(target=runtime_url)

        payload = self.builder.build_payload(
            ledger=ledger,
            target=runtime_url,
            investigation_id="SESSION-XYZ-99"
        )

        tgt = payload["target"]
        self.assertEqual(tgt["normalized_url"], "https://sub.portal.phish-bank.org:8443/login")
        self.assertEqual(tgt["hostname"], "sub.portal.phish-bank.org")
        self.assertEqual(tgt["registrable_domain"], "phish-bank.org")
        self.assertEqual(tgt["scheme"], "https")
        self.assertEqual(payload["investigation_metadata"]["investigation_id"], "SESSION-XYZ-99")

    # -----------------------------------------------------------------
    # Test 13: No Scoring Logic in Builder
    # -----------------------------------------------------------------
    def test_13_no_scoring_logic_in_builder(self):
        """Verify the builder does not calculate or alter risk/trust/verdict values."""
        ledger = self._create_sample_ledger()
        
        # When no TCE result provided, tce_result is empty dict, NOT recalculated
        payload = self.builder.build_payload(ledger=ledger, tce_result=None)
        self.assertEqual(payload["tce_result"], {})
        self.assertNotIn("calculated_risk", payload)
        self.assertNotIn("calculated_trust", payload)

    # -----------------------------------------------------------------
    # Test 14: Empty / Minimal Ledger Handling
    # -----------------------------------------------------------------
    def test_14_empty_minimal_ledger(self):
        """Verify the builder handles empty/minimal evidence without inventing entries."""
        empty_ledger = EvidenceLedger(target="https://empty.test")
        payload = self.builder.build_payload(ledger=empty_ledger)

        self.assertEqual(len(payload["ledger_summary"]["entries"]), 0)
        self.assertEqual(len(payload["ledger_summary"]["relationships"]), 0)
        self.assertEqual(payload["ledger_summary"]["summary"]["total_entries"], 0)
        self.assertEqual(payload["builder_telemetry"]["selected_entries_count"], 0)

    # -----------------------------------------------------------------
    # Test 15: TCE Boundary Maintained
    # -----------------------------------------------------------------
    def test_15_tce_boundary_maintained(self):
        """Verify supplied TCE output is preserved exactly and no alternative scores/confidence created."""
        ledger = self._create_sample_ledger()
        tce = TrustCalculationEngine()
        tce_res = tce.calculate_trust(ledger)

        payload = build_aere_input_payload(ledger=ledger, tce_result=tce_res)

        # Check TCE authority preservation
        self.assertIn("tce_result", payload)
        self.assertEqual(payload["tce_result"], tce_res)
        
        # Ensure no parallel confidence metrics exist
        self.assertNotIn("confidence_interval", payload)
        self.assertNotIn("statistical_confidence", payload)
        self.assertNotIn("alternative_risk_score", payload)


if __name__ == "__main__":
    unittest.main()
