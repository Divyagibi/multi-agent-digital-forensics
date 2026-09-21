"""
tests/test_session_orchestration.py
===================================
Regression test suite for Application Session & Report Orchestration.

Verifies:
1. Manual investigation flow creates a completed authoritative session.
2. Trust Score, Risk Score, and Verdict are populated after agent collection.
3. /api/report does NOT execute Agents 1–18 or run_full_pipeline when supplied an existing session.
4. Report output accurately preserves the completed session's TCE scores, verdict, and evidence.
5. New investigation cleanly replaces old session state without stale cross-talk.
6. Missing or incomplete session payloads are rejected with controlled HTTP error responses.
7. AERE failure is isolated, preserving TCE results and report generation.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from app import app
from services.analysis_pipeline import (
    create_analysis_session,
    finalize_session_from_agent_results,
    run_full_pipeline
)
from services.evidence_schema import create_evidence_item, build_agent_result
from services.aere_provider import (
    LLMProvider,
    MockProvider,
    ProviderUnavailableError
)


def _create_mock_agent_result(agent_id: int, target_url: str, severity: str = "info", category: str = "neutral") -> dict:
    """Helper to generate a schema-compliant mock agent finding."""
    item = create_evidence_item(
        agent_id=agent_id,
        index=1,
        finding=f"Mock evidence observation from Agent {agent_id}",
        value={"url": target_url},
        severity=severity,
        source=f"Agent{agent_id}Sensor",
        evidence_type="deterministic",
        category=category
    )
    return build_agent_result(
        agent_identifier=agent_id,
        target=target_url,
        status="completed",
        data={"url": target_url},
        evidence=[item]
    )


class FailingMockProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "FailingMock"

    @property
    def model_id(self) -> str:
        return "mock-failing-model"

    def get_provider_metadata(self) -> dict:
        return {
            "provider_name": self.provider_name,
            "model_id": self.model_id,
            "is_offline": False,
            "supports_structured_json": True
        }

    def generate_reasoning(self, payload: dict, prompt_config: dict = None) -> dict:
        raise ProviderUnavailableError("Simulated LLM network timeout")


class TestSessionOrchestration(unittest.TestCase):
    """Test suite for single-execution session finalization and report orchestration."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_manual_investigation_creates_completed_session(self):
        """Test 1: Finalization endpoint converts agent results into a completed authoritative session."""
        target_url = "https://legitimate-service.org"
        mock_agents = {
            f"agent{i}": _create_mock_agent_result(i, target_url, severity="low", category="valid_ca_signed_certificate" if i == 3 else "neutral")
            for i in range(1, 19)
        }

        response = self.client.post(
            "/api/pipeline/finalize",
            json={
                "url": target_url,
                "input_type": "url",
                "agents": mock_agents
            }
        )

        self.assertEqual(response.status_code, 200)
        session = response.get_json()

        self.assertIsNotNone(session)
        self.assertEqual(session["status"], "completed")
        self.assertEqual(session["target_url"], target_url)
        self.assertIn("session_id", session)
        self.assertIn("evidence_ledger", session)
        self.assertIn("tce_summary", session)
        self.assertEqual(len(session["all_evidence"]), 18)

    def test_02_trust_score_populated_after_finalization(self):
        """Test 2: Trust Score, Risk Score, and Verdict are populated after agent collection without waiting for report."""
        target_url = "https://safe-domain.example"
        mock_agents = {
            f"agent{i}": _create_mock_agent_result(i, target_url, severity="info", category="neutral")
            for i in range(1, 19)
        }

        session = finalize_session_from_agent_results(
            target_url=target_url,
            agent_results=mock_agents
        )

        self.assertIsNotNone(session["trust_score"])
        self.assertIsNotNone(session["risk_score"])
        self.assertNotEqual(session["verdict"], "not_calculated")
        self.assertIn(session["verdict"], ["benign", "low_risk", "suspicious", "high_risk", "malicious"])
        self.assertIsInstance(session["tce_summary"], dict)

    def test_03_report_does_not_rerun_agents_or_full_pipeline(self):
        """Test 3: Calling /api/report with a valid completed session does NOT re-execute Agents or run_full_pipeline."""
        target_url = "https://test-once.org"
        mock_agents = {
            f"agent{i}": _create_mock_agent_result(i, target_url, severity="info", category="neutral")
            for i in range(1, 19)
        }

        # Step 1: Create completed session once
        completed_session = finalize_session_from_agent_results(
            target_url=target_url,
            agent_results=mock_agents
        )

        # Step 2: Call /api/report with spy/mock on run_full_pipeline and run_single_agent
        with patch("app.run_full_pipeline") as mock_run_full, \
             patch("services.analysis_pipeline.run_single_agent") as mock_run_single:

            response = self.client.post(
                "/api/report",
                json={
                    "session": completed_session
                }
            )

            self.assertEqual(response.status_code, 200)
            report_data = response.get_json()

            # Verify that full pipeline and individual agents were NEVER called
            mock_run_full.assert_not_called()
            mock_run_single.assert_not_called()

            # Verify report output was returned successfully
            self.assertIn("overview", report_data)
            self.assertIn("assessment", report_data)
            self.assertEqual(report_data["overview"]["target"]["target_url"], target_url)

    def test_04_report_uses_exact_session_data(self):
        """Test 4: Report preserves exact TCE Trust Score, Risk Score, Verdict, and Evidence from session."""
        target_url = "https://phishing-threat.biz"
        # Create agents with high-risk findings
        mock_agents = {
            f"agent{i}": _create_mock_agent_result(
                i, target_url,
                severity="critical" if i in [6, 9, 17] else "info",
                category="threat_intel_blocklist" if i == 6 else ("brand_name_impersonation" if i == 9 else "neutral")
            )
            for i in range(1, 19)
        }

        session = finalize_session_from_agent_results(
            target_url=target_url,
            agent_results=mock_agents
        )

        expected_risk = round(float(session["risk_score"]), 2)
        expected_trust = round(float(session["trust_score"]), 2)
        expected_verdict = session["verdict"]

        response = self.client.post(
            "/api/report",
            json={"session": session}
        )

        self.assertEqual(response.status_code, 200)
        report = response.get_json()

        assessment = report["assessment"]
        self.assertEqual(assessment["tce_risk_score"], expected_risk)
        self.assertEqual(assessment["tce_trust_score"], expected_trust)
        self.assertEqual(assessment["tce_verdict"], expected_verdict)
        self.assertEqual(len(report["evidence_lineage"]), 18)

    def test_05_new_investigation_replaces_old_session(self):
        """Test 5: Running investigation B creates a distinct session and report B never leaks session A."""
        url_a = "https://investigation-alpha.com"
        url_b = "https://investigation-beta.com"

        agents_a = {f"agent{i}": _create_mock_agent_result(i, url_a, severity="info") for i in range(1, 19)}
        agents_b = {f"agent{i}": _create_mock_agent_result(i, url_b, severity="high", category="threat_intel_blocklist" if i == 6 else "neutral") for i in range(1, 19)}

        session_a = finalize_session_from_agent_results(target_url=url_a, agent_results=agents_a)
        session_b = finalize_session_from_agent_results(target_url=url_b, agent_results=agents_b)

        self.assertNotEqual(session_a["session_id"], session_b["session_id"])
        self.assertNotEqual(session_a["target_url"], session_b["target_url"])

        # Fetch report for session B
        resp_b = self.client.post("/api/report", json={"session": session_b})
        self.assertEqual(resp_b.status_code, 200)
        report_b = resp_b.get_json()

        self.assertEqual(report_b["overview"]["target"]["target_url"], url_b)
        self.assertEqual(report_b["overview"]["investigation_id"], session_b["session_id"])
        self.assertNotEqual(report_b["overview"]["target"]["target_url"], url_a)

    def test_06_missing_or_incomplete_session_handled_safely(self):
        """Test 6: Missing, null, or incomplete session payloads return controlled 400 errors without silent second run."""
        # 1. Null session without fallback flag
        resp1 = self.client.post("/api/report", json={"session": None})
        self.assertEqual(resp1.status_code, 400)
        self.assertIn("error", resp1.get_json())

        # 2. Incomplete session (missing ledger and TCE)
        resp2 = self.client.post("/api/report", json={"session": {"target_url": "https://bad.com"}})
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("error", resp2.get_json())

        # 3. Finalize endpoint with empty URL
        resp3 = self.client.post("/api/pipeline/finalize", json={"url": "", "agents": {}})
        self.assertEqual(resp3.status_code, 400)

    def test_07_aere_failure_allows_tce_and_report_fallback(self):
        """Test 7: AERE failure/timeout allows TCE scores and final report to generate cleanly in fallback mode."""
        target_url = "https://resilient-test.org"
        mock_agents = {f"agent{i}": _create_mock_agent_result(i, target_url, severity="info") for i in range(1, 19)}

        failing_provider = FailingMockProvider()

        session = finalize_session_from_agent_results(
            target_url=target_url,
            agent_results=mock_agents,
            aere_provider=failing_provider
        )

        # TCE must remain intact
        self.assertIsNotNone(session["trust_score"])
        self.assertIsNotNone(session["risk_score"])
        self.assertEqual(session["aere"]["status"], "fallback")

        # Report must still generate successfully using fallback reasoning
        resp = self.client.post("/api/report", json={"session": session})
        self.assertEqual(resp.status_code, 200)
        report = resp.get_json()
        self.assertIn("overview", report)
        self.assertIn("assessment", report)


if __name__ == "__main__":
    unittest.main()
