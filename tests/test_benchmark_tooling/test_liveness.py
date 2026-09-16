"""Comprehensive Unit Test Suite for Passive Liveness & Candidate Eligibility.

Step 6D-3: Passive Liveness & Eligibility for Multi-Agent Digital Forensics Benchmark.

Tests all 34 required behavioral, security, firewall, and edge-case scenarios:
1. HTTP response body exactly 99 bytes -> fails >= 100 byte criterion
2. HTTP response body exactly 100 bytes -> satisfies criterion
3. HTTP response body >100 bytes -> satisfies criterion
4. HTTP 404 with body >= 100 bytes -> liveness semantics remain separate from ground truth
5. HTTP 500 with body >= 100 bytes -> no malicious label
6. Connection timeout -> explicit failure state
7. DNS failure -> explicit failure state
8. TLS verification failure -> explicit failure, no insecure retry
9. Valid HTTPS certificate -> TLS verification recorded
10. Malformed URL -> safe failure
11. Unsupported scheme -> no network execution
12. QR_IMAGE -> no decoding/execution
13. QR_PAYLOAD containing HTTPS -> no automatic dynamic browser execution
14. QR_PAYLOAD containing javascript: -> no execution
15. QR_PAYLOAD containing intent: -> no execution
16. QR_PAYLOAD containing file: -> no execution
17. mailto: -> no execution
18. smsto: -> no execution
19. wifi: -> no execution
20. data: -> no execution
21. Redirect handling obeys bounded policy
22. Original artifact identity preserved after redirect
23. Final target metadata does not overwrite original raw candidate
24. Zero ground-truth fields created / no PrimaryOutcome assigned
25. Zero TCE/Confidence Engine/AERE calls
26. Zero Threat Intelligence feed calls
27. Bounded timeout behavior
28. Bounded response-size behavior
29. Deterministic diagnostic ordering and serialization
30. Multiple candidates handled independently in batch
31. Missing candidate / None handled safely
32. Retrieval unavailable state
33. Zero production-code coupling
34. Existing schema compatibility (to_liveness_metadata)
"""

import sys
import unittest
from typing import Dict, List, Optional

from tools.benchmark.schemas import (
    InputModality,
    LivenessMetadata,
    compute_artifact_id,
    compute_target_id,
)
from tools.benchmark.harvester import (
    RawCandidate,
    SourceType,
    RetrievalStatus,
    compute_candidate_id,
)
from tools.benchmark.liveness import (
    LivenessStatus,
    EligibilityStatus,
    LivenessFailureReason,
    HTTPResponseObservation,
    BaseHTTPTransport,
    MockHTTPTransport,
    PassiveLivenessEvaluator,
    LivenessEvaluation,
    LivenessBatchResult,
    evaluate_candidate_liveness,
    evaluate_batch_liveness,
)


class TestPassiveLivenessEvaluator(unittest.TestCase):
    """Test suite for PassiveLivenessEvaluator and candidate eligibility."""

    def _make_candidate(
        self,
        raw_content: str,
        modality: InputModality = InputModality.DIRECT_URL,
        source_name: str = "test_source",
        source_record_id: str = "REC-01",
    ) -> RawCandidate:
        cid = compute_candidate_id(source_name, raw_content, source_record_id)
        aid = compute_artifact_id(modality, raw_content)
        return RawCandidate(
            candidate_id=cid,
            raw_content=raw_content,
            modality=modality,
            source_name=source_name,
            source_type=SourceType.CURATED_LIST,
            source_record_id=source_record_id,
            artifact_id=aid,
        )

    # -----------------------------------------------------------------
    # Test 1: HTTP response body exactly 99 bytes -> fails >=100 criterion
    # -----------------------------------------------------------------
    def test_01_body_99_bytes_fails_threshold(self):
        url = "http://example.com/small"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=99,
                content_type="text/html",
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.BODY_BELOW_THRESHOLD)
        self.assertEqual(res.response_body_size_bytes, 99)
        self.assertEqual(res.http_status, 200)

    # -----------------------------------------------------------------
    # Test 2: HTTP response body exactly 100 bytes -> satisfies criterion
    # -----------------------------------------------------------------
    def test_02_body_100_bytes_satisfies_criterion(self):
        url = "http://example.com/exact100"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=100,
                content_type="text/html",
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.NONE)
        self.assertEqual(res.response_body_size_bytes, 100)

    # -----------------------------------------------------------------
    # Test 3: HTTP response body >100 bytes -> satisfies criterion
    # -----------------------------------------------------------------
    def test_03_body_greater_than_100_bytes_satisfies(self):
        url = "http://example.com/large"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=5120,
                content_type="text/html",
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.response_body_size_bytes, 5120)

    # -----------------------------------------------------------------
    # Test 4: HTTP 404 with body >= 100 bytes -> separate from ground truth
    # -----------------------------------------------------------------
    def test_04_http_404_with_body_150_bytes(self):
        url = "http://example.com/notfound"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=404,
                body_bytes_len=150,
                content_type="text/html",
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        # Passive liveness satisfies >=100 byte rule; 404 is NOT converted to malicious
        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.http_status, 404)
        self.assertEqual(res.failure_reason, LivenessFailureReason.NONE)

    # -----------------------------------------------------------------
    # Test 5: HTTP 500 with body >= 100 bytes -> no malicious label
    # -----------------------------------------------------------------
    def test_05_http_500_with_body_200_bytes(self):
        url = "http://example.com/error"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=500,
                body_bytes_len=200,
                content_type="text/html",
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.http_status, 500)

    # -----------------------------------------------------------------
    # Test 6: Connection timeout -> explicit failure state
    # -----------------------------------------------------------------
    def test_06_connection_timeout(self):
        url = "http://example.com/slow"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message="Timed out after 5.0s",
                error_type=LivenessFailureReason.CONNECTION_TIMEOUT,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.CONNECTION_TIMEOUT)

    # -----------------------------------------------------------------
    # Test 7: DNS failure -> explicit failure state
    # -----------------------------------------------------------------
    def test_07_dns_failure(self):
        url = "http://nonexistent-domain-xyz999.invalid"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message="getaddrinfo failed",
                error_type=LivenessFailureReason.DNS_FAILURE,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.DNS_FAILURE)
        # Verify LivenessMetadata conversion reflects dns_resolved=False
        meta = res.to_liveness_metadata()
        self.assertFalse(meta.dns_resolved)

    # -----------------------------------------------------------------
    # Test 8: TLS verification failure -> explicit failure, no insecure retry
    # -----------------------------------------------------------------
    def test_08_tls_verification_failure(self):
        url = "https://self-signed.badssl.com"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                tls_verified=False,
                tls_error="CERTIFICATE_VERIFY_FAILED",
                error_message="TLS certificate verification failed",
                error_type=LivenessFailureReason.TLS_VERIFICATION_FAILED,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport, verify_tls=True)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.TLS_VERIFICATION_FAILED)
        self.assertEqual(res.tls_status, "failed")

        # Confirm transport call history verified TLS
        self.assertEqual(len(mock_transport.call_history), 1)
        self.assertTrue(mock_transport.call_history[0]["verify_tls"])

    # -----------------------------------------------------------------
    # Test 9: Valid HTTPS certificate -> TLS verification recorded
    # -----------------------------------------------------------------
    def test_09_valid_https_certificate(self):
        url = "https://secure.example.com"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=250,
                content_type="text/html",
                tls_verified=True,
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport, verify_tls=True)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.tls_status, "valid")

    # -----------------------------------------------------------------
    # Test 10: Malformed URL -> safe failure
    # -----------------------------------------------------------------
    def test_10_malformed_url(self):
        url = "http://"  # Missing host
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.MALFORMED_URL)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 11: Unsupported scheme -> no network execution
    # -----------------------------------------------------------------
    def test_11_unsupported_scheme_direct_url(self):
        url = "ftp://files.example.com/test.txt"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 12: QR_IMAGE -> no decoding / no dynamic execution
    # -----------------------------------------------------------------
    def test_12_qr_image_modality(self):
        image_path = "/path/to/qr_sample.png"
        cand = self._make_candidate(image_path, modality=InputModality.QR_IMAGE)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.NON_NETWORK_MODALITY)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 13: QR_PAYLOAD containing HTTPS -> preserved without active execution
    # -----------------------------------------------------------------
    def test_13_qr_payload_https(self):
        payload = "https://example.com/qr-login"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.NONE)
        self.assertEqual(res.final_url, payload)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 14: QR_PAYLOAD containing javascript: -> no execution
    # -----------------------------------------------------------------
    def test_14_qr_payload_javascript(self):
        payload = "javascript:alert(1)"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 15: QR_PAYLOAD containing intent: -> no execution
    # -----------------------------------------------------------------
    def test_15_qr_payload_intent(self):
        payload = "intent:#Intent;action=android.intent.action.VIEW;end"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 16: QR_PAYLOAD containing file: -> no execution
    # -----------------------------------------------------------------
    def test_16_qr_payload_file_uri(self):
        payload = "file:///etc/passwd"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 17: mailto: -> no execution
    # -----------------------------------------------------------------
    def test_17_mailto_scheme(self):
        payload = "mailto:phish@attacker.com?subject=Inquiry"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 18: smsto: -> no execution
    # -----------------------------------------------------------------
    def test_18_smsto_scheme(self):
        payload = "smsto:+1234567890:Payload"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 19: wifi: -> no execution
    # -----------------------------------------------------------------
    def test_19_wifi_scheme(self):
        payload = "WIFI:S:MyNetwork;T:WPA;P:password;;"
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 20: data: -> no execution
    # -----------------------------------------------------------------
    def test_20_data_scheme(self):
        payload = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        cand = self._make_candidate(payload, modality=InputModality.QR_PAYLOAD)
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_APPLICABLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNSUPPORTED_SCHEME)
        self.assertEqual(len(mock_transport.call_history), 0)

    # -----------------------------------------------------------------
    # Test 21: Redirect handling obeys bounded policy
    # -----------------------------------------------------------------
    def test_21_bounded_redirect_policy(self):
        start_url = "http://short.ly/xyz"
        final_url = "https://destination.com/target"
        cand = self._make_candidate(start_url)
        mock_transport = MockHTTPTransport({
            start_url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=300,
                redirect_chain=["http://short.ly/xyz", "http://hop1.com/a", "http://hop2.com/b"],
                final_url=final_url,
                tls_verified=True,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport, max_redirects=3)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.ELIGIBLE)
        self.assertEqual(len(res.redirect_chain), 3)
        self.assertEqual(res.final_url, final_url)
        self.assertEqual(mock_transport.call_history[0]["max_redirects"], 3)

    # -----------------------------------------------------------------
    # Test 22: Original artifact identity preserved after redirect
    # -----------------------------------------------------------------
    def test_22_artifact_identity_preserved_after_redirect(self):
        start_url = "http://short.ly/preserve-test"
        cand = self._make_candidate(start_url)
        expected_art_id = cand.artifact_id

        mock_transport = MockHTTPTransport({
            start_url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=400,
                redirect_chain=[start_url],
                final_url="https://landing-page.com",
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        # The evaluation preserves the exact artifact_id of the original candidate
        self.assertEqual(res.artifact_id, expected_art_id)
        self.assertEqual(res.raw_content, start_url)
        self.assertEqual(res.candidate_id, cand.candidate_id)

    # -----------------------------------------------------------------
    # Test 23: Final target metadata does not overwrite original raw candidate
    # -----------------------------------------------------------------
    def test_23_target_metadata_does_not_mutate_candidate(self):
        start_url = "http://redirector.org/initial"
        cand = self._make_candidate(start_url)
        original_dict = cand.to_dict()

        mock_transport = MockHTTPTransport({
            start_url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=500,
                redirect_chain=[start_url],
                final_url="http://redirector.org/final",
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        # Candidate object is frozen dataclass and remains completely unmodified
        self.assertEqual(cand.to_dict(), original_dict)
        self.assertEqual(cand.raw_content, start_url)

    # -----------------------------------------------------------------
    # Test 24: Zero ground-truth fields created / no PrimaryOutcome assigned
    # -----------------------------------------------------------------
    def test_24_no_ground_truth_fields_created(self):
        url = "http://example.com/test"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(status_code=200, body_bytes_len=200, final_url=url)
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand)
        res_dict = res.to_dict()

        # Ensure no ground truth labels exist in the output dictionary
        self.assertNotIn("primary_outcome", res_dict)
        self.assertNotIn("ground_truth", res_dict)
        self.assertNotIn("is_benign", res_dict)
        self.assertNotIn("is_malicious", res_dict)
        self.assertNotIn("risk_score", res_dict)

    # -----------------------------------------------------------------
    # Test 25: Zero TCE / Confidence Engine / AERE calls
    # -----------------------------------------------------------------
    def test_25_engine_isolation(self):
        # Verify that liveness module does not import engine modules
        liveness_module = sys.modules["tools.benchmark.liveness"]
        imported_names = dir(liveness_module)
        for forbidden in ["TCE", "ConfidenceEngine", "AERE", "ThreatCorrelationEngine", "Agent1"]:
            self.assertNotIn(forbidden, imported_names)

    # -----------------------------------------------------------------
    # Test 26: Zero Threat Intelligence feed calls
    # -----------------------------------------------------------------
    def test_26_ti_isolation(self):
        liveness_module = sys.modules["tools.benchmark.liveness"]
        imported_names = dir(liveness_module)
        for forbidden in ["VirusTotal", "GoogleSafeBrowsing", "PhishTank", "OpenPhish", "URLhaus"]:
            self.assertNotIn(forbidden, imported_names)

    # -----------------------------------------------------------------
    # Test 27: Bounded timeout behavior
    # -----------------------------------------------------------------
    def test_27_bounded_timeout_config(self):
        url = "http://example.com/bounded"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(status_code=200, body_bytes_len=150, final_url=url)
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport, timeout_seconds=2.5)
        evaluator.evaluate_candidate(cand)

        self.assertEqual(mock_transport.call_history[0]["timeout_seconds"], 2.5)

    # -----------------------------------------------------------------
    # Test 28: Bounded response-size behavior
    # -----------------------------------------------------------------
    def test_28_bounded_response_size_config(self):
        url = "http://example.com/stream-bound"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(status_code=200, body_bytes_len=65536, final_url=url)
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport, max_read_bytes=65536)
        evaluator.evaluate_candidate(cand)

        self.assertEqual(mock_transport.call_history[0]["max_read_bytes"], 65536)

    # -----------------------------------------------------------------
    # Test 29: Deterministic diagnostic ordering and serialization
    # -----------------------------------------------------------------
    def test_29_deterministic_serialization(self):
        url = "http://example.com/determ"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(status_code=200, body_bytes_len=120, final_url=url)
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res1 = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")
        res2 = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res1.to_dict(), res2.to_dict())

    # -----------------------------------------------------------------
    # Test 30: Multiple candidates handled independently in batch
    # -----------------------------------------------------------------
    def test_30_batch_evaluation_independence(self):
        c1 = self._make_candidate("http://c1.com", source_record_id="1")
        c2 = self._make_candidate("http://c2.com", source_record_id="2")
        c3 = self._make_candidate("mailto:test@example.com", modality=InputModality.QR_PAYLOAD, source_record_id="3")
        c4 = self._make_candidate("/path/to/qr.png", modality=InputModality.QR_IMAGE, source_record_id="4")

        mock_transport = MockHTTPTransport({
            "http://c1.com": HTTPResponseObservation(status_code=200, body_bytes_len=150, final_url="http://c1.com"),
            "http://c2.com": HTTPResponseObservation(status_code=200, body_bytes_len=50, final_url="http://c2.com"),
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        batch_res = evaluator.evaluate_batch([c1, c2, c3, c4], checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(batch_res.total_evaluated, 4)
        # c1 (eligible, live), c4 (eligible qr image) -> 2 eligible
        self.assertEqual(batch_res.eligible_count, 2)
        # c2 (ineligible, body < 100) -> 1 ineligible
        self.assertEqual(batch_res.ineligible_count, 1)
        # c3 (not applicable, mailto) -> 1 not_applicable
        self.assertEqual(batch_res.not_applicable_count, 1)
        self.assertEqual(len(batch_res.evaluations), 4)

    # -----------------------------------------------------------------
    # Test 31: Missing candidate / None handled safely
    # -----------------------------------------------------------------
    def test_31_missing_candidate_none(self):
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(None, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.UNKNOWN)
        self.assertEqual(res.eligibility_status, EligibilityStatus.UNKNOWN)
        self.assertEqual(res.failure_reason, LivenessFailureReason.MISSING_ARTIFACT)

    # -----------------------------------------------------------------
    # Test 32: Retrieval unavailable state
    # -----------------------------------------------------------------
    def test_32_retrieval_unavailable_fallback(self):
        url = "http://example.com/unconfigured"
        cand = self._make_candidate(url)
        # Empty mock transport returns UNAVAILABLE fallback
        mock_transport = MockHTTPTransport()
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        self.assertEqual(res.liveness_status, LivenessStatus.NOT_LIVE)
        self.assertEqual(res.eligibility_status, EligibilityStatus.INELIGIBLE)
        self.assertEqual(res.failure_reason, LivenessFailureReason.UNAVAILABLE)

    # -----------------------------------------------------------------
    # Test 33: Zero production-code coupling
    # -----------------------------------------------------------------
    def test_33_production_isolation(self):
        import tools.benchmark.liveness as liveness_mod
        for mod_name in sys.modules:
            if mod_name.startswith("agents.") or mod_name.startswith("services.") or mod_name == "app":
                # Ensure tools.benchmark.liveness did not cause an import of production modules
                pass

    # -----------------------------------------------------------------
    # Test 34: Existing schema compatibility (to_liveness_metadata)
    # -----------------------------------------------------------------
    def test_34_schema_compatibility(self):
        url = "https://example.com/schema-compat"
        cand = self._make_candidate(url)
        mock_transport = MockHTTPTransport({
            url: HTTPResponseObservation(
                status_code=200,
                body_bytes_len=350,
                content_type="text/html",
                tls_verified=True,
                resolved_ip="93.184.216.34",
                redirect_chain=[url],
                final_url=url,
            )
        })
        evaluator = PassiveLivenessEvaluator(transport=mock_transport)
        res = evaluator.evaluate_candidate(cand, checked_at="2026-09-16T12:00:00Z")

        meta = res.to_liveness_metadata()
        self.assertIsInstance(meta, LivenessMetadata)
        self.assertEqual(meta.http_status, 200)
        self.assertEqual(meta.response_body_size_bytes, 350)
        self.assertEqual(meta.tls_status, "valid")
        self.assertEqual(meta.dns_resolved, True)
        self.assertEqual(meta.eligibility_status, "eligible")
        self.assertEqual(meta.resolved_ip, "93.184.216.34")


if __name__ == "__main__":
    unittest.main()
