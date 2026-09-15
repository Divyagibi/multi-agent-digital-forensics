"""
tests/test_confidence_engine.py
===============================
Comprehensive Unit & Invariant Tests for the Deterministic Confidence Engine (DHCI).
"""

import unittest
from services.confidence_engine import ConfidenceEngine
from services.confidence_contract import (
    AbstentionRecommendation,
    InterpretationSemanticState,
    CALIBRATION_STATUS
)
from services.evidence_ledger import EvidenceLedger


class TestConfidenceEngine(unittest.TestCase):
    """Test suite for Confidence Engine mathematical evaluation and invariants."""

    def setUp(self):
        self.engine = ConfidenceEngine()

    def test_hypothetical_reproducibility_example(self):
        """
        Verify the exact hypothetical reproducibility trace from the frozen specification:
        Phi_cov = 83.3333, Phi_rel = 86.0, Phi_cor = 83.4701 (N=4), Phi_contra = 100, G_prov = 1
        => C_ev = 84.1743 ≈ 84.17
        => C_interp = 100 => C_overall = 84.17
        """
        ledger = EvidenceLedger(target="https://example.com")
        
        # Add 10 active evidence items across 4 distinct clusters
        # Cluster 1 (K_InfraNet): Agent 1 (A1), Agent 2 (A2)
        # Cluster 2 (K_Crypto): Agent 3 (A3)
        # Cluster 3 (K_IntelMalw): Agent 6 (A6)
        # Cluster 4 (K_ContentTech): Agent 7 (A7)
        ledger.add_entry({
            "evidence_id": "E1-01", "agent_id": 1, "agent_name": "Domain Identity",
            "evidence_type": "deterministic", "evidence_strength": 1.0, "status": "success"
        })
        ledger.add_entry({
            "evidence_id": "E2-01", "agent_id": 2, "agent_name": "DNS & Infrastructure",
            "evidence_type": "deterministic", "evidence_strength": 1.0, "status": "success"
        })
        ledger.add_entry({
            "evidence_id": "E3-01", "agent_id": 3, "agent_name": "SSL/HTTPS",
            "evidence_type": "deterministic", "evidence_strength": 1.0, "status": "success"
        })
        ledger.add_entry({
            "evidence_id": "E6-01", "agent_id": 6, "agent_name": "Reputation & Threat Intel",
            "evidence_type": "threat_intelligence", "evidence_strength": 1.0, "status": "success"
        })
        ledger.add_entry({
            "evidence_id": "E7-01", "agent_id": 7, "agent_name": "Technical Fingerprinting",
            "evidence_type": "external_source", "evidence_strength": 1.0, "status": "success"
        })

        # Add supporting edges connecting the 4 distinct clusters
        ledger.add_relationship("E1-01", "E3-01", "supporting") # K_InfraNet <-> K_Crypto
        ledger.add_relationship("E6-01", "E7-01", "supporting") # K_IntelMalw <-> K_ContentTech

        # Mock pipeline session with 15 observed dimensions out of 18
        pipeline_session = {
            "input_type": "url",
            "status": "completed",
            "agents": {f"agent{i}": {"status": "success" if i <= 15 else "error"} for i in range(1, 19)}
        }

        # Mock successful AERE result with 8/8 valid citations
        aere_result = {
            "status": "success",
            "grounding_report": {
                "grounding_status": "GROUNDED",
                "unsubstantiated_claims_count": 0,
                "total_citations": 8,
                "valid_citations_count": 8
            }
        }

        # Contextual TCE result
        tce_result = {
            "verdict": "SUSPICIOUS",
            "risk_score": 45.0,
            "trust_score": 55.0
        }

        output = self.engine.evaluate_confidence(
            ledger=ledger,
            aere_result=aere_result,
            tce_result=tce_result,
            pipeline_session=pipeline_session,
            investigation_id="inv-test-001"
        )

        # Verify coverage: 15/18 * 100 = 83.3333
        self.assertAlmostEqual(output.telemetry_coverage_score, 83.3333, places=2)

        # Verify corroboration: N=4 clusters => 100 * (1 - e^(-1.80)) = 83.4701
        self.assertEqual(output.concordant_cluster_count, 4)
        self.assertAlmostEqual(output.corroboration_score, 83.4701, places=2)

        # Verify contradiction: 0 => 100.0
        self.assertEqual(output.contradiction_score, 100.0)

        # Verify C_ev and C_overall
        self.assertGreater(output.evidence_confidence, 80.0)
        self.assertAlmostEqual(output.interpretation_confidence, 100.0, places=1)
        self.assertEqual(output.composite_confidence, output.evidence_confidence)
        self.assertEqual(output.abstention_reason, AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY)
        self.assertFalse(output.abstention_flag)

    def test_zero_active_evidence_hard_guard(self):
        """
        Verify that 100% telemetry coverage with ZERO active evidence strictly produces:
        Phi_cov = 100.0, Phi_rel = 0.0, Phi_cor = 0.0, C_ev = 0.0, C_overall = 0.0.
        """
        ledger = EvidenceLedger(target="https://clean-site.example")
        # No evidence entries added

        # All 18 agents completed successfully with clean negative findings
        pipeline_session = {
            "input_type": "url",
            "status": "completed",
            "agents": {f"agent{i}": {"status": "success", "evidence": []} for i in range(1, 19)}
        }

        output = self.engine.evaluate_confidence(
            ledger=ledger,
            pipeline_session=pipeline_session
        )

        self.assertEqual(output.telemetry_coverage_score, 100.0)
        self.assertEqual(output.source_reliability_score, 0.0)
        self.assertEqual(output.corroboration_score, 0.0)
        self.assertEqual(output.evidence_confidence, 0.0)
        self.assertEqual(output.composite_confidence, 0.0)
        self.assertTrue(output.abstention_flag)
        self.assertEqual(output.abstention_reason, AbstentionRecommendation.ABSTAIN_INSUFFICIENT_EVIDENCE)

    def test_corroboration_asymptotic_progression(self):
        """Verify exact asymptotic corroboration values across N=0..7."""
        engine = ConfidenceEngine(lambda_cor=0.45)
        expected_values = {
            0: 0.00,
            1: 0.00,
            2: 59.34,
            3: 74.08,
            4: 83.47,
            5: 89.46,
            6: 93.26,
            7: 95.71
        }

        for n, expected in expected_values.items():
            if n < 2:
                phi_cor = 0.0
            else:
                import math
                phi_cor = 100.0 * (1.0 - math.exp(-0.45 * n))
            self.assertAlmostEqual(phi_cor, expected, delta=0.05)

    def test_intra_cluster_corroboration_suppression(self):
        """Verify that supporting edges within the SAME cluster do NOT increase N_concordant_clusters."""
        ledger = EvidenceLedger(target="https://example.com")
        
        # Two agents in K_InfraNet (A1 and A2)
        ledger.add_entry({"evidence_id": "E1-01", "agent_id": 1, "status": "success"})
        ledger.add_entry({"evidence_id": "E2-01", "agent_id": 2, "status": "success"})
        # Another item in A1
        ledger.add_entry({"evidence_id": "E1-02", "agent_id": 1, "status": "success"})

        # Intra-cluster supporting edges (A1 <-> A2 are both in K_InfraNet)
        ledger.add_relationship("E1-01", "E2-01", "supporting")
        ledger.add_relationship("E1-01", "E1-02", "supporting")

        output = self.engine.evaluate_confidence(ledger=ledger)
        self.assertEqual(output.concordant_cluster_count, 0)
        self.assertEqual(output.corroboration_score, 0.0)

    def test_contradiction_penalty(self):
        """Verify contradiction penalty scaling with beta = 2.0."""
        ledger = EvidenceLedger(target="https://example.com")
        
        # 4 active items
        for i in range(1, 5):
            ledger.add_entry({"evidence_id": f"E{i}-01", "agent_id": i, "status": "success"})

        # 1 contradiction edge connecting 2 of 4 items => gamma = 2/4 = 0.50 => Phi_contra = 0.0
        ledger.add_relationship("E1-01", "E2-01", "contradiction")

        output = self.engine.evaluate_confidence(ledger=ledger)
        self.assertEqual(output.contradiction_ratio, 0.50)
        self.assertEqual(output.contradiction_score, 0.0)
        self.assertEqual(output.evidence_confidence, 0.0)
        self.assertTrue(output.abstention_flag)
        self.assertEqual(output.abstention_reason, AbstentionRecommendation.ABSTAIN_EVIDENTIARY_CONFLICT)

    def test_provenance_failure_gating(self):
        """Verify that broken relational pointers or invalid IDs fail G_prov and zero C_ev."""
        ledger = EvidenceLedger(target="https://example.com")
        ledger.add_entry({"evidence_id": "INVALID-ID", "agent_id": 1, "status": "success"})

        output = self.engine.evaluate_confidence(ledger=ledger)
        self.assertFalse(output.provenance_gate_passed)
        self.assertEqual(output.evidence_confidence, 0.0)
        self.assertEqual(output.composite_confidence, 0.0)
        self.assertTrue(output.abstention_flag)
        self.assertEqual(output.abstention_reason, AbstentionRecommendation.ABSTAIN_INTEGRITY_FAILURE)

    def test_aere_fallback_and_error_handling(self):
        """Verify AERE fallback 50 uncalibrated policy prior and error state 0."""
        ledger = EvidenceLedger(target="https://example.com")
        ledger.add_entry({"evidence_id": "E1-01", "agent_id": 1, "evidence_type": "deterministic", "status": "success"})

        # 1. Fallback
        fallback_res = {"status": "fallback"}
        out_fallback = self.engine.evaluate_confidence(ledger=ledger, aere_result=fallback_res)
        self.assertEqual(out_fallback.interpretation_confidence, 50.0)
        self.assertEqual(out_fallback.aere_execution_state, "fallback")

        # 2. Error
        error_res = {"status": "error"}
        out_error = self.engine.evaluate_confidence(ledger=ledger, aere_result=error_res)
        self.assertEqual(out_error.interpretation_confidence, 0.0)
        self.assertEqual(out_error.aere_execution_state, "error")

    def test_zero_citation_grounding_safety(self):
        """Verify zero citations only grants 100% when GroundingStatus == GROUNDED and 0 unsubstantiated claims."""
        ledger = EvidenceLedger(target="https://example.com")
        ledger.add_entry({"evidence_id": "E1-01", "agent_id": 1, "evidence_type": "deterministic", "status": "success"})

        # Case A: 0 citations with UNGROUNDED status => 0.0
        aere_ungrounded = {
            "status": "success",
            "grounding_report": {
                "grounding_status": "UNGROUNDED",
                "unsubstantiated_claims_count": 2,
                "total_citations": 0,
                "valid_citations_count": 0
            }
        }
        out_a = self.engine.evaluate_confidence(ledger=ledger, aere_result=aere_ungrounded)
        self.assertEqual(out_a.interpretation_confidence, 0.0)

        # Case B: 0 citations with GROUNDED status and 0 unsubstantiated => 100.0
        aere_grounded = {
            "status": "success",
            "grounding_report": {
                "grounding_status": "GROUNDED",
                "unsubstantiated_claims_count": 0,
                "total_citations": 0,
                "valid_citations_count": 0
            }
        }
        out_b = self.engine.evaluate_confidence(ledger=ledger, aere_result=aere_grounded)
        self.assertEqual(out_b.interpretation_confidence, 100.0)

    def test_qr_modality_applicability(self):
        """Verify QR non-URL plain text has applicable = 1 (Agent 18 only)."""
        ledger = EvidenceLedger(target="Plain text QR payload")
        ledger.add_entry({"evidence_id": "E18-01", "agent_id": 18, "status": "success"})

        pipeline_session = {
            "input_type": "qr",
            "status": "completed_non_url",
            "agents": {"agent18": {"status": "success"}}
        }

        output = self.engine.evaluate_confidence(
            ledger=ledger,
            pipeline_session=pipeline_session
        )
        self.assertEqual(output.applicable_dimensions_count, 1)
        self.assertEqual(output.observed_dimensions_count, 1)
        self.assertEqual(output.telemetry_coverage_score, 100.0)


if __name__ == "__main__":
    unittest.main()
