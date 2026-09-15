"""
tests/test_aere_provider.py
===========================
Unit & Regression tests for AERE Provider Abstraction & Conservative MockProvider (Step 3D-2).

Verifies:
Test A: Real evidence IDs only (every emitted ID exists in supplied input ledger).
Test B: Evidence-derived claims (claims are strictly derived from input evidence text).
Test C: No unsupported brand claims (never invents unstated brand names).
Test D: No unsupported malicious confirmation (never invents unverified attack confirmations).
Test E: Empty ledger handling (empty evidence produces zero fabricated findings or IDs).
Test F: Missing/unavailable evidence (preserved as investigative gaps, not positive/negative claims).
Test G: Determinism (identical input produces identical output).
Test H: Input immutability (input payload remains strictly unchanged).
Test I: No scoring (never calculates or alters risk_score, trust_score, confidence_score, or probability).
Test J: Offline execution (zero network calls).
"""

import copy
import socket
import unittest
from unittest.mock import patch

from services.evidence_normalizer import normalize_evidence_item, normalize_target
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.aere_input_builder import build_aere_input_payload
from services.aere_contract import validate_aere_output
from services.aere_provider import (
    LLMProvider,
    MockProvider,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ProviderAuthenticationError,
    ProviderRateLimitError,
    ProviderMalformedResponseError
)


class TestAEREProvider(unittest.TestCase):

    def setUp(self):
        self.target = normalize_target("https://secure-portal.phish-test.org/login")
        self.ledger = EvidenceLedger(target=self.target)

        # Add sample entries
        self.ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E1-01",
            "finding": "Domain registered recently",
            "category": "domain_registered_recently",
            "severity": "high"
        }, 1, canonical_target=self.target))

        self.ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E8-01",
            "finding": "Fake authentication form detected",
            "category": "fake_login_form",
            "severity": "critical"
        }, 8, canonical_target=self.target))

        self.ledger.add_relationship(
            source_evidence_id="E1-01",
            target_evidence_id="E8-01",
            relationship_type="supporting",
            description="Young domain with credential harvesting form"
        )

        tce = TrustCalculationEngine()
        self.tce_res = tce.calculate_trust(self.ledger)
        self.input_payload = build_aere_input_payload(
            ledger=self.ledger,
            tce_result=self.tce_res,
            target=self.target,
            investigation_id="INV-PROV-001"
        )

    # 1. LLMProvider Interface Exists
    def test_01_llm_provider_abstract_interface(self):
        """Verify LLMProvider is an abstract base class."""
        with self.assertRaises(TypeError):
            LLMProvider()

    # 2. MockProvider Works Offline (Test J)
    def test_02_mock_provider_works_offline(self):
        """Test J: Verify MockProvider runs locally without network or API keys."""
        provider = MockProvider()
        meta = provider.get_provider_metadata()
        self.assertEqual(meta["provider_name"], "mock")
        self.assertTrue(meta["is_offline"])

    # 3. MockProvider Produces Schema-Valid Output
    def test_03_mock_provider_produces_schema_valid_output(self):
        """Verify MockProvider response conforms 100% to AERE output schema."""
        provider = MockProvider()
        output = provider.generate_reasoning(self.input_payload)

        is_valid, errors = validate_aere_output(output)
        self.assertTrue(is_valid, f"MockProvider output failed schema validation: {errors}")
        self.assertIn("investigation_summary", output)
        self.assertIn("primary_findings", output)
        self.assertIn("evidence_chains", output)
        self.assertIn("tce_interpretation", output)
        self.assertIn("reasoning_metadata", output)

    # 4. MockProvider Is Deterministic (Test G)
    def test_04_mock_provider_deterministic(self):
        """Test G: Verify identical inputs produce identical reasoning outputs."""
        provider = MockProvider()
        output1 = provider.generate_reasoning(self.input_payload)
        output2 = provider.generate_reasoning(self.input_payload)

        self.assertEqual(output1, output2)

    # 5. Provider Does Not Make Network Calls (Test J)
    def test_05_provider_zero_network_calls(self):
        """Test J: Verify MockProvider does not invoke socket connections."""
        with patch.object(socket.socket, "connect", side_effect=RuntimeError("Network forbidden")):
            provider = MockProvider()
            output = provider.generate_reasoning(self.input_payload)
            self.assertIsInstance(output, dict)

    # 6. Provider Failure Hierarchy
    def test_06_provider_failure_hierarchy(self):
        """Verify provider exception hierarchy can be instantiated and raised."""
        timeout_err = ProviderTimeoutError("Inference request timed out after 5.0s", provider_name="mock")
        self.assertIsInstance(timeout_err, ProviderError)
        self.assertEqual(timeout_err.provider_name, "mock")

        unavail_err = ProviderUnavailableError("Service 503 unavailable")
        self.assertIsInstance(unavail_err, ProviderError)

        rate_err = ProviderRateLimitError("429 Too Many Requests", status_code=429)
        self.assertEqual(rate_err.status_code, 429)

        provider_with_err = MockProvider(simulate_error=timeout_err)
        with self.assertRaises(ProviderTimeoutError):
            provider_with_err.generate_reasoning(self.input_payload)

    # 7. Provider Vendor Neutrality
    def test_07_provider_vendor_neutrality(self):
        """Verify provider interface does not require specific vendor SDK objects."""
        class CustomTestProvider(LLMProvider):
            def generate_reasoning(self, input_payload, prompt_config=None):
                return {"custom": "test"}
            def get_provider_metadata(self):
                return {"provider_name": "custom_neutral"}

        cp = CustomTestProvider()
        self.assertEqual(cp.get_provider_metadata()["provider_name"], "custom_neutral")
        self.assertEqual(cp.generate_reasoning({}), {"custom": "test"})

    # 8. Provider Does Not Compute or Modify TCE (Test I)
    def test_08_provider_does_not_modify_tce(self):
        """Test I: Verify provider preserves TCE authority and creates zero new score fields."""
        provider = MockProvider()
        output = provider.generate_reasoning(self.input_payload)

        self.assertNotIn("risk_score", output)
        self.assertNotIn("trust_score", output)
        self.assertNotIn("confidence_score", output)
        self.assertNotIn("numerical_confidence", output)
        self.assertNotIn("probability", output)

    # 9. Provider Leaves Input Payload Immutable (Test H)
    def test_09_provider_leaves_input_immutable(self):
        """Test H: Verify calling generate_reasoning does not mutate the input payload."""
        input_copy = copy.deepcopy(self.input_payload)
        provider = MockProvider()
        provider.generate_reasoning(self.input_payload)

        self.assertEqual(self.input_payload, input_copy)

    # 10. Test A: Real Evidence IDs Only
    def test_10_real_evidence_ids_only(self):
        """Test A: Every Evidence ID emitted by MockProvider must exist in the supplied input ledger."""
        provider = MockProvider()
        output = provider.generate_reasoning(self.input_payload)

        input_eids = {e["evidence_id"] for e in self.input_payload["ledger_summary"]["entries"]}

        # Check primary findings
        for f in output.get("primary_findings", []):
            for eid in f.get("grounded_evidence_ids", []):
                self.assertIn(eid, input_eids, f"Emitted Evidence ID '{eid}' does not exist in input ledger")

        # Check evidence chains
        for c in output.get("evidence_chains", []):
            for eid in c.get("evidence_ids", []):
                self.assertIn(eid, input_eids, f"Emitted Evidence ID '{eid}' does not exist in input ledger")

        # Check contradiction analyses
        for ct in output.get("contradiction_analyses", []):
            for eid in ct.get("conflicting_evidence_ids", []):
                self.assertIn(eid, input_eids, f"Emitted Evidence ID '{eid}' does not exist in input ledger")

        # Check alternative explanations
        for alt in output.get("alternative_explanations", []):
            for eid in alt.get("evidence_ids", []) + alt.get("counter_evidence_ids", []):
                self.assertIn(eid, input_eids, f"Emitted Evidence ID '{eid}' does not exist in input ledger")

    # 11. Test B: Evidence-Derived Claims
    def test_11_evidence_derived_claims(self):
        """Test B: Generated findings are directly traceable to actual supplied evidence findings."""
        custom_ledger = EvidenceLedger(target=self.target)
        custom_ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E5-01",
            "finding": "Lexical entropy elevated in subpath",
            "severity": "medium"
        }, 5, canonical_target=self.target))

        custom_input = build_aere_input_payload(ledger=custom_ledger, tce_result={})
        provider = MockProvider()
        output = provider.generate_reasoning(custom_input)

        findings = output.get("primary_findings", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("Lexical entropy elevated in subpath", findings[0]["summary"])
        self.assertEqual(findings[0]["grounded_evidence_ids"], ["E5-01"])

    # 12. Test C: No Unsupported Brand Claims
    def test_C_no_unsupported_brand_claims(self):
        """Test C: If input says 'Domain resembles a known brand', mock does NOT invent brand names."""
        brand_ledger = EvidenceLedger(target=self.target)
        brand_ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E9-01",
            "finding": "Domain name resembles a known brand",
            "severity": "medium"
        }, 9, canonical_target=self.target))

        brand_input = build_aere_input_payload(ledger=brand_ledger, tce_result={})
        provider = MockProvider()
        output = provider.generate_reasoning(brand_input)

        serialized_output = str(output).lower()
        # Verify no hallucinated brand names are introduced
        self.assertNotIn("google", serialized_output)
        self.assertNotIn("microsoft", serialized_output)
        self.assertNotIn("paypal", serialized_output)
        self.assertNotIn("apple", serialized_output)

    # 13. Test D: No Unsupported Malicious Confirmation
    def test_D_no_unsupported_malicious_confirmation(self):
        """Test D: If input says 'URL contains a shortened redirect', mock does NOT claim 'Confirmed phishing attack'."""
        short_ledger = EvidenceLedger(target=self.target)
        short_ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E5-02",
            "finding": "URL contains a shortened redirect",
            "severity": "low"
        }, 5, canonical_target=self.target))

        short_input = build_aere_input_payload(ledger=short_ledger, tce_result={})
        provider = MockProvider()
        output = provider.generate_reasoning(short_input)

        serialized_output = str(output).lower()
        self.assertNotIn("confirmed phishing attack", serialized_output)
        self.assertNotIn("malicious financial fraud", serialized_output)

    # 14. Test E: Empty Ledger Handling
    def test_E_empty_ledger_handling(self):
        """Test E: Empty evidence does NOT produce fabricated forensic findings or fabricated IDs."""
        empty_ledger = EvidenceLedger(target="https://empty.test")
        empty_input = build_aere_input_payload(ledger=empty_ledger, tce_result={})
        provider = MockProvider()
        output = provider.generate_reasoning(empty_input)

        is_valid, errors = validate_aere_output(output)
        self.assertTrue(is_valid, f"Empty output failed schema validation: {errors}")
        self.assertEqual(len(output["primary_findings"]), 0)
        self.assertEqual(len(output["evidence_chains"]), 0)
        self.assertEqual(len(output["contradiction_analyses"]), 0)
        self.assertEqual(len(output["alternative_explanations"]), 0)
        self.assertEqual(len(output["investigative_gaps"]), 0)
        self.assertEqual(output["reasoning_metadata"]["referenced_evidence_count"], 0)

    # 15. Test F: Missing / Unavailable Evidence
    def test_F_missing_unavailable_evidence_handling(self):
        """Test F: Unavailable/skipped/error evidence is represented as investigative gaps, not positive/negative claims."""
        unavail_ledger = EvidenceLedger(target=self.target)
        unavail_ledger.add_entry(normalize_evidence_item({
            "evidence_id": "E6-01",
            "finding": "Threat intelligence feed timeout",
            "status": "unavailable"
        }, 6, agent_result={"status": "unavailable"}, canonical_target=self.target))

        unavail_input = build_aere_input_payload(ledger=unavail_ledger, tce_result={})
        provider = MockProvider()
        output = provider.generate_reasoning(unavail_input)

        # Should NOT appear as primary positive/negative finding
        self.assertEqual(len(output["primary_findings"]), 0)

        # SHOULD appear as an investigative gap
        gaps = output.get("investigative_gaps", [])
        self.assertGreaterEqual(len(gaps), 1)
        self.assertIn("unavailable", gaps[0]["reason"])
        self.assertIn("E6-01", gaps[0]["unobserved_dimension"])


if __name__ == "__main__":
    unittest.main()
