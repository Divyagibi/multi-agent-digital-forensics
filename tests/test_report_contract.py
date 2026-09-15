"""
tests/test_report_contract.py
=============================
Unit tests for Step 5B Final Investigator Report Contract & Validation.

Tests:
- Minimal valid report payload validation
- Schema structural invariants (report_version, timestamps, enums)
- Strict validation failure cases:
  - Missing required sections (overview, assessment)
  - Invalid TCE verdicts
  - Out of bounds numerical scores [0.0, 100.0]
  - Out of bounds ratios [0.0, 1.0]
  - Invalid Evidence ID formats
  - Invalid severities, types, polarities, grounding statuses
  - Forbidden recalculation keys (recalculated_risk_score, etc.)
  - Prohibited autonomous actions boundary validation
"""

import copy
from datetime import datetime, timezone
import unittest

from services.report_contract import (
    REPORT_CONTRACT_VERSION,
    VALID_TCE_VERDICTS,
    VALID_GROUNDING_STATUSES,
    VALID_POLARITIES,
    DEFAULT_METHODOLOGICAL_DISCLAIMER,
    DEFAULT_HUMAN_REVIEW_GUIDANCE,
    DEFAULT_PROHIBITED_AUTONOMOUS_ACTIONS,
    ReportOverviewSection,
    ReportAssessmentSection,
    KeyFindingItem,
    GroundedClaimItem,
    ContradictionReportItem,
    EvidenceLineageItem,
    InvestigatorReportPayload,
    validate_investigator_report
)
from services.confidence_contract import (
    CALIBRATION_STATUS,
    AbstentionRecommendation
)


class TestReportContract(unittest.TestCase):
    """Test suite for Report Contract dataclasses and schema validation."""

    def _create_minimal_valid_payload(self) -> InvestigatorReportPayload:
        """Helper to create a fully conforming minimal InvestigatorReportPayload."""
        now_iso = datetime.now(timezone.utc).isoformat()
        return InvestigatorReportPayload(
            report_version=REPORT_CONTRACT_VERSION,
            generated_at=now_iso,
            overview=ReportOverviewSection(
                investigation_id="inv-12345",
                target={"target_url": "https://example.com", "input_type": "url", "original_input": "https://example.com"},
                investigation_timestamp=now_iso,
                report_generated_at=now_iso,
                execution_status="completed"
            ),
            assessment=ReportAssessmentSection(
                tce_verdict="suspicious",
                tce_risk_score=45.50,
                tce_trust_score=54.50,
                composite_confidence=78.20,
                evidence_confidence=82.10,
                interpretation_confidence=70.00,
                abstention_flag=False,
                abstention_reason=AbstentionRecommendation.AUTOMATION_ELIGIBLE_BY_UNCALIBRATED_PROTOTYPE_POLICY,
                confidence_calibration_status=CALIBRATION_STATUS
            ),
            risk_increasing_findings=[
                KeyFindingItem(
                    evidence_id="E6-01",
                    agent_id=6,
                    agent_name="Reputation & Threat Intelligence",
                    finding="Listed on suspicious feed",
                    category="threat_intel_blocklist",
                    severity="high",
                    evidence_type="threat_intelligence",
                    evidence_strength=0.90,
                    polarity="risk_increasing",
                    tce_contribution=0.6075
                )
            ],
            risk_reducing_findings=[
                KeyFindingItem(
                    evidence_id="E1-01",
                    agent_id=1,
                    agent_name="Domain Identity",
                    finding="Domain registered 10 years ago",
                    category="domain_age_mature",
                    severity="low",
                    evidence_type="deterministic",
                    evidence_strength=1.00,
                    polarity="risk_reducing",
                    tce_contribution=0.1500
                )
            ],
            neutral_observations=[
                KeyFindingItem(
                    evidence_id="E2-01",
                    agent_id=2,
                    agent_name="DNS & Infrastructure",
                    finding="Standard DNS resolution clean",
                    category="clean_dns_resolution",
                    severity="info",
                    evidence_type="deterministic",
                    evidence_strength=1.00,
                    polarity="neutral",
                    tce_contribution=0.0
                )
            ],
            aere_reasoning_status="success",
            investigation_summary="Target exhibits mixed forensic indicators with domain tenure mitigating threat intel listing.",
            detailed_findings=[
                {
                    "finding_id": "F-01",
                    "topic": "Threat Intel Listing",
                    "summary": "Listed on 1 blocklist",
                    "grounded_evidence_ids": ["E6-01"],
                    "forensic_significance": "high",
                    "interpretation": "Reputation flag indicates prior suspicious activity."
                }
            ],
            grounded_claims=[
                GroundedClaimItem(
                    claim_id="C-01",
                    section="primary_findings",
                    grounding_status="GROUNDED",
                    grounding_source="evidence",
                    cited_evidence_ids=["E6-01"],
                    valid_evidence_ids=["E6-01"],
                    invalid_evidence_ids=[],
                    issues=[]
                )
            ],
            unsubstantiated_claims_count=0,
            grounded_citation_ratio=1.0,
            total_active_evidence_items=3,
            provenance_gate_passed=True,
            evidence_lineage=[
                EvidenceLineageItem(
                    evidence_id="E6-01",
                    agent_id=6,
                    agent_name="Reputation & Threat Intelligence",
                    finding="Listed on suspicious feed",
                    raw_value={"feed": "PhishFeed", "status": "flagged"},
                    evidence_type="threat_intelligence",
                    severity="high",
                    evidence_strength=0.90,
                    polarity="risk_increasing",
                    provenance={"agent_id": 6, "agent_name": "Reputation"},
                    status="success",
                    tce_final_contribution=0.6075
                )
            ],
            contradictions=[],
            contradiction_score=0.0,
            observed_dimensions=["A1", "A2", "A6"],
            inactive_telemetry_gaps={"A18": "QR analysis skipped for standard URL input"},
            telemetry_coverage_score=66.67,
            source_reliability_score=95.00,
            corroboration_score=50.00,
            concordant_cluster_count=2,
            concordant_clusters=["K_IntelMalw", "K_InfraNet"]
        )

    def test_minimal_valid_report_passes(self):
        """Confirm that a fully conforming minimal report passes validation."""
        payload = self._create_minimal_valid_payload()
        is_valid, errors = validate_investigator_report(payload)
        self.assertTrue(is_valid, f"Validation failed with errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_dict_payload_validation(self):
        """Confirm that a valid dict representation passes validation."""
        payload = self._create_minimal_valid_payload()
        payload_dict = payload.to_dict()
        is_valid, errors = validate_investigator_report(payload_dict)
        self.assertTrue(is_valid, f"Validation failed: {errors}")

    def test_invalid_tce_verdict_fails(self):
        """Confirm that non-canonical TCE verdicts fail contract validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["assessment"]["tce_verdict"] = "SUPER_MALICIOUS"
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid 'tce_verdict'" in e for e in errors))

    def test_score_out_of_bounds_fails(self):
        """Confirm that numerical scores outside [0.0, 100.0] fail validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["assessment"]["tce_risk_score"] = 150.0
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("out of bounds [0.0, 100.0]" in e for e in errors))

        payload["assessment"]["tce_risk_score"] = -5.0
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)

    def test_ratio_out_of_bounds_fails(self):
        """Confirm that ratios outside [0.0, 1.0] fail validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["grounded_citation_ratio"] = 1.25
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("out of bounds [0.0, 1.0]" in e for e in errors))

    def test_invalid_evidence_id_syntax_fails(self):
        """Confirm that malformed Evidence IDs in findings fail validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["risk_increasing_findings"][0]["evidence_id"] = "INVALID_ID_999"
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("invalid Evidence ID syntax" in e for e in errors))

    def test_invalid_severity_fails(self):
        """Confirm that non-canonical severities fail validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["risk_increasing_findings"][0]["severity"] = "ultra-critical"
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("invalid severity" in e for e in errors))

    def test_invalid_polarity_fails(self):
        """Confirm that non-canonical polarity fails validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["risk_increasing_findings"][0]["polarity"] = "danger_zone"
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("invalid polarity" in e for e in errors))

    def test_forbidden_keys_fail_validation(self):
        """Confirm that rogue recalculated score keys fail validation."""
        for fk in ["recalculated_risk_score", "override_verdict", "malicious_probability", "autonomous_action_authorized"]:
            payload = self._create_minimal_valid_payload().to_dict()
            payload[fk] = 99.9
            is_valid, errors = validate_investigator_report(payload)
            self.assertFalse(is_valid, f"Expected failure for forbidden key: {fk}")
            self.assertTrue(any("Forbidden key" in e for e in errors))

    def test_empty_prohibited_actions_fails(self):
        """Confirm that missing prohibited actions list fails validation."""
        payload = self._create_minimal_valid_payload().to_dict()
        payload["prohibited_autonomous_actions"] = []
        is_valid, errors = validate_investigator_report(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any("prohibited_autonomous_actions" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
