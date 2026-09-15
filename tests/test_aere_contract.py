"""
tests/test_aere_contract.py
===========================
Unit tests for AERE schema contracts and validation functions (Step 3D-2).

Verifies:
1. Valid AERE input accepted.
2. Missing required input field rejected.
3. Invalid input type rejected.
4. Valid AERE output accepted.
5. Missing required output field rejected.
6. Invalid output nested structure rejected.
7. Invalid Evidence ID syntax rejected where syntax validation applies.
8. Valid Evidence ID syntax accepted.
9. Invalid reasoning metadata rejected.
10. Unknown/invalid enum values rejected where applicable.
11. Forbidden fields (risk_score, trust_score, confidence_score) are rejected in AERE output.
12. Actual TCE result structure can be represented without modification.
13. Empty evidence collections are structurally valid where appropriate.
14. Missing/unavailable evidence statuses remain representable.
15. Contract version and schema constants are present.
"""

import copy
import unittest

from services.evidence_normalizer import normalize_evidence_item, normalize_target
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.aere_input_builder import build_aere_input_payload
from services.aere_contract import (
    AERE_CONTRACT_VERSION,
    AERE_SCHEMA_IDENTIFIER,
    is_valid_evidence_id_syntax,
    validate_aere_input,
    validate_aere_output,
    FORBIDDEN_OUTPUT_FIELDS,
    FORENSIC_SIGNIFICANCE_LEVELS,
    GROUNDING_VALIDATION_STATUSES
)


class TestAEREContract(unittest.TestCase):

    def setUp(self):
        self.target = normalize_target("https://test-forensics.local/auth")
        self.ledger = EvidenceLedger(target=self.target)
        self.ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E1-01",
            "finding": "Domain created recently",
            "severity": "medium"
        }, 1, canonical_target=self.target))
        self.ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E3-02",
            "finding": "Untrusted certificate",
            "severity": "high"
        }, 3, canonical_target=self.target))
        self.ledger.add_relationship("E1-01", "E3-02", "supporting", description="Corroborating indicators")

        tce = TrustCalculationEngine()
        self.tce_result = tce.calculate_trust(self.ledger)
        self.valid_input = build_aere_input_payload(
            ledger=self.ledger,
            tce_result=self.tce_result,
            target=self.target,
            investigation_id="INV-TEST-001"
        )

        self.valid_output = {
            "investigation_summary": "Forensic synthesis indicates elevated risk associated with newly registered infrastructure.",
            "primary_findings": [
                {
                    "finding_id": "F-01",
                    "topic": "Domain & Certificate Risk",
                    "summary": "Recent registration accompanied by untrusted certificate.",
                    "grounded_evidence_ids": ["E1-01", "E3-02"],
                    "forensic_significance": "high",
                    "interpretation": "Strong correlation between age and TLS configuration."
                }
            ],
            "evidence_chains": [
                {
                    "chain_id": "C-01",
                    "theme": "Infrastructure Setup",
                    "evidence_ids": ["E1-01", "E3-02"],
                    "narrative": "Domain setup shows anomalous registration patterns."
                }
            ],
            "contradiction_analyses": [],
            "alternative_explanations": [
                {
                    "evidence_ids": ["E1-01"],
                    "primary_interpretation": "Suspicious newly created domain.",
                    "alternative_interpretation": "Legitimate newly launched business portal.",
                    "counter_evidence_ids": ["E3-02"],
                    "plausibility_assessment": "Plausible but weakened by certificate findings."
                }
            ],
            "investigative_gaps": [],
            "tce_interpretation": {
                "mathematical_alignment": "TCE risk calculation of 56.54 reflects high-severity TLS indicators.",
                "verdict_support": "The suspicious verdict is corroborated by the multi-agent findings."
            },
            "reasoning_metadata": {
                "engine_version": "AERE-1.0.0",
                "prompt_version": "2026.09-v1",
                "provider_name": "mock",
                "model_id": "offline-mock-v1",
                "generation_temperature": 0.0,
                "grounding_validation_status": "VALIDATED",
                "referenced_evidence_count": 2,
                "invalid_evidence_ids_detected": []
            }
        }

    # 1. Valid AERE Input Accepted
    def test_01_valid_input_accepted(self):
        is_valid, errors = validate_aere_input(self.valid_input)
        self.assertTrue(is_valid, f"Expected valid input, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    # 2. Missing Required Input Field Rejected
    def test_02_missing_input_field_rejected(self):
        bad_input = copy.deepcopy(self.valid_input)
        bad_input.pop("tce_result")
        is_valid, errors = validate_aere_input(bad_input)
        self.assertFalse(is_valid)
        self.assertTrue(any("tce_result" in e for e in errors))

    # 3. Invalid Input Type Rejected
    def test_03_invalid_input_type_rejected(self):
        is_valid, errors = validate_aere_input("not_a_dictionary")
        self.assertFalse(is_valid)
        self.assertIn("Input payload must be a dictionary.", errors)

    # 4. Valid AERE Output Accepted
    def test_04_valid_output_accepted(self):
        is_valid, errors = validate_aere_output(self.valid_output)
        self.assertTrue(is_valid, f"Expected valid output, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    # 5. Missing Required Output Field Rejected
    def test_05_missing_output_field_rejected(self):
        bad_output = copy.deepcopy(self.valid_output)
        bad_output.pop("tce_interpretation")
        is_valid, errors = validate_aere_output(bad_output)
        self.assertFalse(is_valid)
        self.assertTrue(any("tce_interpretation" in e for e in errors))

    # 6. Invalid Output Nested Structure Rejected
    def test_06_invalid_output_nested_structure_rejected(self):
        bad_output = copy.deepcopy(self.valid_output)
        bad_output["primary_findings"] = [{"finding_id": "F-01"}]  # Missing required fields
        is_valid, errors = validate_aere_output(bad_output)
        self.assertFalse(is_valid)
        self.assertTrue(any("missing required field" in e for e in errors))

    # 7. Invalid Evidence ID Syntax Rejected
    def test_07_invalid_evidence_id_syntax_rejected(self):
        bad_output = copy.deepcopy(self.valid_output)
        bad_output["primary_findings"][0]["grounded_evidence_ids"] = ["INVALID_ID_999", "E1-01"]
        is_valid, errors = validate_aere_output(bad_output)
        self.assertFalse(is_valid)
        self.assertTrue(any("invalid evidence_id syntax" in e for e in errors))

    # 8. Valid Evidence ID Syntax Accepted
    def test_08_valid_evidence_id_syntax_accepted(self):
        valid_ids = ["E1-01", "E12-05", "E18-12", "E3-01-DUP2"]
        for eid in valid_ids:
            self.assertTrue(is_valid_evidence_id_syntax(eid), f"Expected '{eid}' to be valid syntax")

        invalid_ids = ["E1", "1-01", "E999-01", "evidence_1", "E0-00", "", None, 123]
        for eid in invalid_ids:
            self.assertFalse(is_valid_evidence_id_syntax(eid), f"Expected '{eid}' to be invalid syntax")

    # 9. Invalid Reasoning Metadata Rejected
    def test_09_invalid_reasoning_metadata_rejected(self):
        bad_output = copy.deepcopy(self.valid_output)
        bad_output["reasoning_metadata"]["grounding_validation_status"] = "INVALID_STATUS_ENUM"
        is_valid, errors = validate_aere_output(bad_output)
        self.assertFalse(is_valid)
        self.assertTrue(any("grounding_validation_status" in e for e in errors))

    # 10. Unknown/Invalid Enum Values Rejected
    def test_10_invalid_enum_values_rejected(self):
        bad_output = copy.deepcopy(self.valid_output)
        bad_output["primary_findings"][0]["forensic_significance"] = "catastrophic_mega_danger"
        is_valid, errors = validate_aere_output(bad_output)
        self.assertFalse(is_valid)
        self.assertTrue(any("forensic_significance" in e for e in errors))

    # 11. Forbidden Scoring Fields Rejected
    def test_11_forbidden_scoring_fields_rejected(self):
        for forbidden_field in FORBIDDEN_OUTPUT_FIELDS:
            bad_output = copy.deepcopy(self.valid_output)
            bad_output[forbidden_field] = 95.0
            is_valid, errors = validate_aere_output(bad_output)
            self.assertFalse(is_valid, f"Expected forbidden field '{forbidden_field}' to be rejected")
            self.assertTrue(any(forbidden_field in e for e in errors))

    # 12. Actual TCE Result Represented Without Modification
    def test_12_tce_result_represented_without_modification(self):
        self.assertIn("tce_result", self.valid_input)
        self.assertEqual(self.valid_input["tce_result"], self.tce_result)

    # 13. Empty Evidence Collections Structurally Valid
    def test_13_empty_collections_structurally_valid(self):
        empty_ledger = EvidenceLedger(target="https://empty.test")
        empty_input = build_aere_input_payload(ledger=empty_ledger, tce_result={})
        is_valid, errors = validate_aere_input(empty_input)
        self.assertTrue(is_valid, f"Expected empty input to be valid, got: {errors}")

    # 14. Missing/Unavailable Statuses Remain Representable
    def test_14_missing_unavailable_statuses_representable(self):
        ledger = EvidenceLedger(target="https://test.local")
        for st in ["unavailable", "skipped", "error", "restricted"]:
            ledger.add_entry(normalize_evidence_item({
                "evidence_id": "E2-01",
                "finding": f"Status {st}",
                "status": st
            }, 2, canonical_target=self.target))
        payload = build_aere_input_payload(ledger=ledger, tce_result={})
        is_valid, errors = validate_aere_input(payload)
        self.assertTrue(is_valid)

    # 15. Contract Version & Constants Present
    def test_15_contract_version_present(self):
        self.assertEqual(AERE_CONTRACT_VERSION, "1.0.0")
        self.assertTrue(AERE_SCHEMA_IDENTIFIER.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
