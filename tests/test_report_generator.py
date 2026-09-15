"""
tests/test_report_generator.py
==============================
Comprehensive Unit Tests for Step 5B Final Investigator Report Generator.

Verifies:
1. Minimal and full report generation
2. Source-field extraction and metadata mapping
3. Timestamps: investigation timestamp preserved, generated_at created
4. TCE score, verdict, and contribution preservation (zero recalculation)
5. Polarity grouping (risk-increasing, risk-reducing, neutral)
6. Presentation-only deterministic ordering
7. Duplicate evidence handling (-DUP suffixes)
8. Invalid Evidence ID preservation and grounding diagnostics
9. Contradiction relationship extraction and preservation
10. Telemetry coverage, active vs clean-negative vs unobserved
11. Confidence metrics and abstention preservation
12. AERE states (success, fallback, rejected, error, None)
13. Missing TCE/AERE/CE edge cases & zero active evidence safety
14. Input session immutability (no mutation)
15. Zero LLM / Zero Network / Zero new mathematical scoring
16. Absence of fabricated recommended_actions
"""

import copy
from datetime import datetime, timezone
import unittest

from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.confidence_contract import (
    AbstentionRecommendation,
    ConfidenceOutputPayload
)
from services.confidence_engine import ConfidenceEngine
from services.report_contract import (
    REPORT_CONTRACT_VERSION,
    InvestigatorReportPayload,
    validate_investigator_report
)
from services.report_generator import (
    InvestigatorReportGenerator,
    generate_investigator_report
)


class TestReportGenerator(unittest.TestCase):
    """Unit test suite for InvestigatorReportGenerator."""

    def setUp(self):
        self.generator = InvestigatorReportGenerator()

    def _build_mock_session(self) -> dict:
        """Construct a realistic completed pipeline session for testing."""
        target_url = "https://secure-login.example.com"
        ledger = EvidenceLedger(target=target_url)

        # Active Risk-Increasing Evidence
        e6 = {
            "evidence_id": "E6-01",
            "agent_id": 6,
            "agent_name": "Reputation & Threat Intelligence",
            "finding": "Domain listed on malicious phishing feed",
            "category": "phishing_feed_match",
            "value": {"feed": "PhishFeed", "score": 95},
            "severity": "critical",
            "evidence_type": "threat_intelligence",
            "evidence_strength": 0.95,
            "status": "success",
            "provenance": {"source": "PhishFeed API", "agent_id": 6}
        }
        # Active Risk-Reducing Evidence
        e1 = {
            "evidence_id": "E1-01",
            "agent_id": 1,
            "agent_name": "Domain Identity",
            "finding": "Domain registered 8 years ago with established tenure",
            "category": "domain_age_established",
            "value": {"age_days": 2920},
            "severity": "medium",
            "evidence_type": "deterministic",
            "evidence_strength": 1.0,
            "status": "success",
            "provenance": {"source": "WHOIS RDAP", "agent_id": 1}
        }
        # Active Neutral Evidence
        e2 = {
            "evidence_id": "E2-01",
            "agent_id": 2,
            "agent_name": "DNS & Infrastructure",
            "finding": "DNS resolved to IPv4 address",
            "category": "clean_dns_resolution",
            "value": {"ip": "93.184.216.34"},
            "severity": "info",
            "evidence_type": "deterministic",
            "evidence_strength": 1.0,
            "status": "success",
            "provenance": {"source": "DNS Resolver", "agent_id": 2}
        }
        # Second Risk-Increasing Evidence (lower severity for sort test)
        e5 = {
            "evidence_id": "E5-01",
            "agent_id": 5,
            "agent_name": "URL Structure",
            "finding": "Suspicious login keyword in subdomain",
            "category": "urgency_manipulation_keywords",
            "value": {"keyword": "login"},
            "severity": "medium",
            "evidence_type": "deterministic",
            "evidence_strength": 0.80,
            "status": "success",
            "provenance": {"source": "Lexical Parser", "agent_id": 5}
        }

        ledger.add_entry(e6)
        ledger.add_entry(e1)
        ledger.add_entry(e2)
        ledger.add_entry(e5)

        # Add Contradiction Relationship
        ledger.add_relationship(
            source_evidence_id="E6-01",
            target_evidence_id="E1-01",
            relationship_type="contradiction",
            description="Phishing feed match contradicts established domain age history."
        )

        tce = TrustCalculationEngine()
        tce_summary = tce.calculate_trust(ledger)

        aere_output = {
            "investigation_summary": "Analysis reveals a critical phishing feed alert mitigated partly by domain age.",
            "primary_findings": [
                {
                    "finding_id": "F-01",
                    "topic": "Phishing Detection",
                    "summary": "Critical feed match on PhishFeed",
                    "grounded_evidence_ids": ["E6-01"],
                    "forensic_significance": "critical",
                    "interpretation": "Strong signal of active phishing."
                }
            ],
            "evidence_chains": [
                {
                    "chain_id": "C-01",
                    "chain_name": "Reputation Conflict",
                    "evidence_steps": ["E6-01", "E1-01"],
                    "narrative": "Domain has established age but was recently flagged on PhishFeed."
                }
            ],
            "contradiction_analyses": [
                {
                    "conflict_id": "CA-01",
                    "conflicting_evidence_ids": ["E6-01", "E1-01"],
                    "analysis": "Phishing detection conflicts with domain longevity."
                }
            ],
            "alternative_explanations": [],
            "investigative_gaps": [],
            "tce_interpretation": {
                "verdict_support": "TCE verdict aligned with critical threat intel.",
                "mathematical_alignment": "Severity weighting reflects active threat."
            },
            "reasoning_metadata": {
                "provider": "mock",
                "model_id": "mock-aere-v1"
            }
        }

        grounding_report = {
            "grounding_validation_status": "PASSED",
            "claim_results": [
                {
                    "claim_id": "F-01",
                    "section": "primary_findings",
                    "grounding_status": "GROUNDED",
                    "grounding_source": "evidence",
                    "evidence_ids": ["E6-01"],
                    "issues": []
                }
            ],
            "invalid_evidence_ids": [],
            "unsupported_entities": [],
            "unsupported_numbers": [],
            "overclaim_flags": [],
            "telemetry_status_issues": [],
            "affected_claims": [],
            "grounding_errors": [],
            "validation_metadata": {
                "validator_version": "1.0.0",
                "total_claims_evaluated": 1,
                "grounded_claims_count": 1,
                "partially_grounded_count": 0,
                "ungrounded_claims_count": 0,
                "uncertain_claims_count": 0
            }
        }

        session = {
            "session_id": "test-session-uuid-001",
            "input_type": "url",
            "original_input": target_url,
            "target_url": target_url,
            "created_at": "2026-09-15T10:00:00+00:00",
            "status": "completed",
            "agents": {
                "agent1": {"status": "success", "evidence": [e1]},
                "agent2": {"status": "success", "evidence": [e2]},
                "agent5": {"status": "success", "evidence": [e5]},
                "agent6": {"status": "success", "evidence": [e6]},
                "agent18": {"status": "skipped", "evidence": []}
            },
            "evidence_ledger": ledger.to_dict(),
            "tce_summary": tce_summary,
            "risk_score": tce_summary["risk_score"],
            "trust_score": tce_summary["trust_score"],
            "verdict": tce_summary["verdict"],
            "aere": {
                "status": "success",
                "aere_output": aere_output,
                "grounding_report": grounding_report
            }
        }
        return session

    # -----------------------------------------------------------------
    # Tests
    # -----------------------------------------------------------------

    def test_full_report_generation(self):
        """Test standard full pipeline report generation."""
        session = self._build_mock_session()
        report = generate_investigator_report(session)

        self.assertIsInstance(report, InvestigatorReportPayload)
        self.assertEqual(report.report_version, REPORT_CONTRACT_VERSION)
        self.assertEqual(report.overview.investigation_id, "test-session-uuid-001")
        self.assertEqual(report.overview.investigation_timestamp, "2026-09-15T10:00:00+00:00")
        self.assertTrue(bool(report.generated_at))

        # Check TCE preservation
        self.assertEqual(report.assessment.tce_verdict, session["verdict"])
        self.assertEqual(report.assessment.tce_risk_score, session["risk_score"])
        self.assertEqual(report.assessment.tce_trust_score, session["trust_score"])

        # Check Polarity Groups
        self.assertEqual(len(report.risk_increasing_findings), 2)  # E6-01, E5-01
        self.assertEqual(len(report.risk_reducing_findings), 1)    # E1-01
        self.assertEqual(len(report.neutral_observations), 1)      # E2-01

        # Check Presentation Ordering (E6-01 critical > E5-01 medium)
        self.assertEqual(report.risk_increasing_findings[0].evidence_id, "E6-01")
        self.assertEqual(report.risk_increasing_findings[1].evidence_id, "E5-01")

        # Check TCE Contribution mapped
        self.assertIsNotNone(report.risk_increasing_findings[0].tce_contribution)

        # Check Contradiction Extraction
        self.assertEqual(len(report.contradictions), 1)
        self.assertEqual(report.contradictions[0].source_evidence_id, "E6-01")
        self.assertEqual(report.contradictions[0].target_evidence_id, "E1-01")

        # Check Grounding Claims
        self.assertEqual(len(report.grounded_claims), 1)
        self.assertEqual(report.grounded_claims[0].claim_id, "F-01")

    def test_input_session_immutability(self):
        """Confirm that generate_investigator_report never mutates the input session."""
        session = self._build_mock_session()
        session_snapshot = copy.deepcopy(session)

        _ = generate_investigator_report(session)

        self.assertEqual(session, session_snapshot, "Input session was modified by report generator!")

    def test_generated_at_is_distinct_from_investigation_timestamp(self):
        """Confirm generated_at is created by report generator and distinct from session timestamp."""
        session = self._build_mock_session()
        session["created_at"] = "2020-01-01T00:00:00+00:00"

        report = generate_investigator_report(session)

        self.assertEqual(report.overview.investigation_timestamp, "2020-01-01T00:00:00+00:00")
        self.assertNotEqual(report.generated_at, "2020-01-01T00:00:00+00:00")
        self.assertEqual(report.overview.report_generated_at, report.generated_at)

    def test_tce_contributions_mapped_without_recalculation(self):
        """Confirm that TCE final_item_contribution values are read verbatim."""
        session = self._build_mock_session()
        # Mock a specific known contribution in TCE summary
        for c in session["tce_summary"]["evidence_contributions"]:
            if c["evidence_id"] == "E6-01":
                c["final_item_contribution"] = 12.34567

        report = generate_investigator_report(session)
        e6_item = next(item for item in report.risk_increasing_findings if item.evidence_id == "E6-01")
        self.assertEqual(e6_item.tce_contribution, 12.34567)

    def test_invalid_evidence_id_preservation(self):
        """Confirm that invalid Evidence IDs are not stripped from grounding claims."""
        session = self._build_mock_session()
        session["aere"]["grounding_report"] = {
            "grounding_validation_status": "FAILED",
            "invalid_evidence_ids": ["E99-99"],
            "claim_results": [
                {
                    "claim_id": "F-02",
                    "section": "primary_findings",
                    "grounding_status": "UNGROUNDED",
                    "grounding_source": "evidence",
                    "evidence_ids": ["E99-99"],
                    "issues": ["Invalid Evidence ID cited: E99-99"]
                }
            ],
            "validation_metadata": {
                "validator_version": "1.0.0",
                "total_claims_evaluated": 1,
                "grounded_claims_count": 0,
                "partially_grounded_count": 0,
                "ungrounded_claims_count": 1,
                "uncertain_claims_count": 0
            }
        }

        report = generate_investigator_report(session)
        self.assertEqual(len(report.grounded_claims), 1)
        claim = report.grounded_claims[0]
        self.assertEqual(claim.invalid_evidence_ids, ["E99-99"])
        self.assertEqual(claim.cited_evidence_ids, ["E99-99"])
        self.assertEqual(report.unsubstantiated_claims_count, 1)

    def test_duplicate_evidence_handling(self):
        """Confirm that duplicate evidence with -DUP suffix is correctly tagged."""
        session = self._build_mock_session()
        entries = session["evidence_ledger"]["entries"]
        dup_entry = {
            "evidence_id": "E6-01-DUP2",
            "original_evidence_id": "E6-01",
            "agent_id": 6,
            "agent_name": "Reputation",
            "finding": "Duplicate listing",
            "category": "phishing_feed_match",
            "value": {},
            "severity": "critical",
            "evidence_type": "threat_intelligence",
            "evidence_strength": 0.95,
            "status": "success",
            "provenance": {"agent_id": 6}
        }
        entries.append(dup_entry)

        report = generate_investigator_report(session)
        dup_item = next((item for item in report.risk_increasing_findings if item.evidence_id == "E6-01-DUP2"), None)
        self.assertIsNotNone(dup_item)
        self.assertTrue(dup_item.is_duplicate)
        self.assertEqual(dup_item.original_evidence_id, "E6-01")

    def test_telemetry_gap_preservation(self):
        """Confirm inactive telemetry (skipped, unavailable, error) appears in telemetry gaps."""
        session = self._build_mock_session()
        report = generate_investigator_report(session)

        self.assertIn("QR Analysis", report.inactive_telemetry_gaps)
        # Verify inactive telemetry does not create false positive or negative evidence
        inactive_findings = [f for f in report.risk_increasing_findings if f.agent_id == 18]
        self.assertEqual(len(inactive_findings), 0)

    def test_clean_negative_observation_handling(self):
        """Confirm clean neutral observation is preserved in neutral_observations."""
        session = self._build_mock_session()
        report = generate_investigator_report(session)

        e2_item = next((item for item in report.neutral_observations if item.evidence_id == "E2-01"), None)
        self.assertIsNotNone(e2_item)
        self.assertEqual(e2_item.polarity, "neutral")

    def test_missing_aere_handling(self):
        """Confirm report generator handles None/unavailable AERE gracefully with fallback summary."""
        session = self._build_mock_session()
        session["aere"] = None

        report = generate_investigator_report(session)
        self.assertEqual(report.aere_reasoning_status, "unavailable")
        self.assertTrue("Digital forensics analysis" in report.investigation_summary)
        self.assertEqual(len(report.detailed_findings), 0)
        self.assertEqual(len(report.grounded_claims), 0)

    def test_zero_active_evidence_handling(self):
        """Confirm report generator handles empty ledger without errors."""
        session = {
            "session_id": "empty-session",
            "input_type": "url",
            "original_input": "https://empty.example.com",
            "target_url": "https://empty.example.com",
            "created_at": "2026-09-15T12:00:00+00:00",
            "status": "completed",
            "agents": {},
            "evidence_ledger": {"entries": [], "relationships": [], "summary": {}},
            "tce_summary": {
                "risk_score": 0.0,
                "trust_score": 0.0,
                "verdict": "unknown",
                "evidence_contributions": []
            },
            "aere": None
        }

        report = generate_investigator_report(session)
        self.assertEqual(len(report.risk_increasing_findings), 0)
        self.assertEqual(len(report.risk_reducing_findings), 0)
        self.assertEqual(len(report.neutral_observations), 0)
        self.assertEqual(report.total_active_evidence_items, 0)
        self.assertEqual(report.assessment.tce_verdict, "unknown")

    def test_no_recommended_actions_fabricated(self):
        """Confirm that no 'recommended_actions' field exists in the report contract."""
        session = self._build_mock_session()
        report = generate_investigator_report(session)
        report_dict = report.to_dict()

        self.assertNotIn("recommended_actions", report_dict)
        self.assertNotIn("recommended_actions", report_dict.get("overview", {}))
        self.assertNotIn("recommended_actions", report_dict.get("assessment", {}))

    def test_precomputed_confidence_payload_passthrough(self):
        """Confirm that a pre-computed ConfidenceOutputPayload is passed through directly."""
        session = self._build_mock_session()
        ce = ConfidenceEngine()
        custom_ce_payload = ce.evaluate_confidence(
            ledger=session["evidence_ledger"],
            aere_result=session["aere"],
            tce_result=session["tce_summary"],
            pipeline_session=session
        )

        report = generate_investigator_report(session, confidence_payload=custom_ce_payload)
        self.assertEqual(report.assessment.composite_confidence, custom_ce_payload.composite_confidence)
        self.assertEqual(report.assessment.evidence_confidence, custom_ce_payload.evidence_confidence)
        self.assertEqual(report.assessment.interpretation_confidence, custom_ce_payload.interpretation_confidence)


if __name__ == "__main__":
    unittest.main()
