"""
tests/test_confidence_contract.py
=================================
Unit tests for Confidence Engine Contract, Taxonomies, Clusters, and Validation.
"""

import unittest
from services.confidence_contract import (
    CONFIDENCE_CONTRACT_VERSION,
    CALIBRATION_STATUS,
    EVIDENCE_ID_REGEX,
    CLUSTER_DEFINITIONS,
    AGENT_CLUSTER_MAP,
    DEFAULT_TYPE_PRIORS,
    DEFAULT_LAMBDA_COR,
    DEFAULT_BETA_CONTRA,
    DEFAULT_AERE_FALLBACK_PRIOR,
    DEFAULT_ALPHA_COMP,
    DEFAULT_EVIDENCE_THRESHOLD,
    AbstentionRecommendation,
    InterpretationSemanticState,
    EvidenceConfidenceMetrics,
    InterpretationConfidenceMetrics,
    ConfidenceOutputPayload,
    validate_confidence_output
)


class TestConfidenceContract(unittest.TestCase):
    """Test suite for Confidence Contract definitions and validation functions."""

    def test_cluster_definitions_coverage(self):
        """Verify that exactly 18 agents are partitioned across exactly 7 disjoint clusters."""
        self.assertEqual(len(CLUSTER_DEFINITIONS), 7)
        
        all_agents = set()
        for cid, cdata in CLUSTER_DEFINITIONS.items():
            agents = cdata["agents"]
            self.assertTrue(len(agents) > 0)
            # Ensure no overlap
            self.assertTrue(all_agents.isdisjoint(agents), f"Overlap detected in cluster {cid}")
            all_agents.update(agents)

        self.assertEqual(all_agents, set(range(1, 19)))
        self.assertEqual(len(AGENT_CLUSTER_MAP), 18)
        for aid in range(1, 19):
            self.assertIn(aid, AGENT_CLUSTER_MAP)

    def test_evidence_id_regex(self):
        """Verify canonical Evidence ID regex."""
        valid_ids = ["E1-01", "E2-03", "E16-01", "E18-12", "E8-01-DUP2", "E10-99-DUP15"]
        invalid_ids = ["", "E0-01", "E19-01", "UUID-1234", "1-01", "E1-1", "E1_01"]

        for vid in valid_ids:
            self.assertTrue(bool(EVIDENCE_ID_REGEX.match(vid)), f"Should be valid: {vid}")

        for iid in invalid_ids:
            self.assertFalse(bool(EVIDENCE_ID_REGEX.match(iid)), f"Should be invalid: {iid}")

    def test_prototype_parameters(self):
        """Verify declared frozen prototype parameters."""
        self.assertEqual(DEFAULT_LAMBDA_COR, 0.45)
        self.assertEqual(DEFAULT_BETA_CONTRA, 2.0)
        self.assertEqual(DEFAULT_AERE_FALLBACK_PRIOR, 50.0)
        self.assertEqual(DEFAULT_ALPHA_COMP, 0.30)
        self.assertEqual(DEFAULT_EVIDENCE_THRESHOLD, 35.0)
        self.assertEqual(CALIBRATION_STATUS, "UNCALIBRATED_DETERMINISTIC_HEURISTIC")

    def test_valid_payload_validation(self):
        """Verify that a compliant payload passes validation."""
        payload = ConfidenceOutputPayload(
            evidence_confidence=84.17,
            interpretation_confidence=100.0,
            composite_confidence=84.17,
            telemetry_coverage_score=83.33,
            source_reliability_score=86.0,
            corroboration_score=83.47,
            contradiction_score=100.0,
            provenance_gate_passed=True,
            grounded_citation_ratio=1.0,
            concordant_cluster_count=4,
            contradiction_ratio=0.0,
            abstention_flag=False,
            abstention_reason=AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY
        )
        is_valid, errors = validate_confidence_output(payload)
        self.assertTrue(is_valid, f"Validation errors: {errors}")
        self.assertEqual(errors, [])

    def test_invalid_payload_validation(self):
        """Verify that malformed or out-of-bounds payloads fail validation."""
        # 1. Out of bounds score
        bad_data = {
            "evidence_confidence": 105.0,  # Invalid > 100
            "interpretation_confidence": 100.0,
            "composite_confidence": 84.17,
            "telemetry_coverage_score": 83.33,
            "source_reliability_score": 86.0,
            "corroboration_score": 83.47,
            "contradiction_score": 100.0,
            "provenance_gate_passed": True,
            "grounded_citation_ratio": 1.0,
            "concordant_cluster_count": 4,
            "contradiction_ratio": 0.0,
            "abstention_flag": False,
            "abstention_reason": AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY
        }
        is_valid, errors = validate_confidence_output(bad_data)
        self.assertFalse(is_valid)
        self.assertTrue(any("out of bounds" in e for e in errors))

        # 2. Forbidden field
        bad_data["evidence_confidence"] = 84.17
        bad_data["malicious_probability"] = 0.95
        is_valid, errors = validate_confidence_output(bad_data)
        self.assertFalse(is_valid)
        self.assertTrue(any("Forbidden key 'malicious_probability'" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
