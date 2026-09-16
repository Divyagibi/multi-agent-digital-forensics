"""Passive Liveness and Candidate Eligibility Layer.

Step 6D-3: Passive Liveness & Eligibility for Multi-Agent Digital Forensics Benchmark.

This module provides deterministic, research-safe, and ground-truth-isolated
liveness evaluation and eligibility determination for harvested candidates.

Architectural & Methodological Guarantees:
1. Ground-Truth Firewall:
   Liveness is NOT ground truth. HTTP 200 != benign; HTTP 404/500 != malicious;
   DNS timeout != benign; Empty body != malicious.
   This module NEVER assigns PrimaryOutcome (BENIGN/MALICIOUS/AMBIGUOUS) and contains
   ZERO imports or couplings to TCE, Confidence Engine, AERE, or forensic agents A1-A18.
2. Threat Intelligence Firewall:
   Zero queries to external threat intelligence feeds (VirusTotal, Google Safe Browsing,
   PhishTank, OpenPhish, URLhaus, AbuseIPDB, Spamhaus).
3. Passive HTTP Criterion:
   Liveness for DIRECT_URL is determined strictly by observing raw HTTP response body >= 100 bytes.
   Zero browser automation, zero JavaScript execution, zero DOM rendering, zero form submission,
   zero credential interaction, zero vulnerability scanning, zero port scanning, zero crawling.
4. Transport & TLS Verification:
   TLS verification is enabled by default. Certificate verification failures are explicitly
   recorded; no silent insecure retries or automatic fallback to unverified TLS.
5. Modality Safety:
   - QR_IMAGE: Preserved as passive artifact; zero image decoding or dynamic execution.
   - QR_PAYLOAD: Preserved as static payload; non-HTTP schemes (mailto:, smsto:, wifi:, intent:,
     javascript:, file:, data:) remain passive data without OS handler invocation or network execution.
6. Identity & Integrity:
   Preserves raw candidate identities, artifact identities, target identities, and grouping identities.
   Does NOT mutate candidates or manufacture synthetic records.
7. Offline Testability:
   Provides pluggable transport abstractions allowing 100% offline verification via mocks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import urllib.parse

from .schemas import (
    InputModality,
    LivenessMetadata,
    compute_artifact_id,
    compute_target_id,
)
from .harvester import (
    RawCandidate,
    RetrievalStatus,
)


# =====================================================================
# Controlled Vocabularies / Enums
# =====================================================================

class LivenessStatus(str, Enum):
    """Controlled status for network liveness observation."""
    LIVE = "LIVE"
    NOT_LIVE = "NOT_LIVE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EligibilityStatus(str, Enum):
    """Controlled eligibility status for downstream benchmark processing."""
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class LivenessFailureReason(str, Enum):
    """Explicit categorical failure and ineligibility reasons."""
    NONE = "NONE"
    BODY_BELOW_THRESHOLD = "BODY_BELOW_THRESHOLD"
    EMPTY_BODY = "EMPTY_BODY"
    HTTP_ERROR = "HTTP_ERROR"
    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TLS_VERIFICATION_FAILED = "TLS_VERIFICATION_FAILED"
    MALFORMED_URL = "MALFORMED_URL"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    NON_NETWORK_MODALITY = "NON_NETWORK_MODALITY"
    RETRIEVAL_ERROR = "RETRIEVAL_ERROR"
    UNAVAILABLE = "UNAVAILABLE"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"


# =====================================================================
# Transport Abstractions & Observations
# =====================================================================

@dataclass(frozen=True)
class HTTPResponseObservation:
    """Raw observation from passive HTTP/HTTPS retrieval."""
    status_code: int = 0
    body_bytes_len: int = 0
    content_type: str = ""
    tls_verified: bool = True
    tls_error: str = ""
    resolved_ip: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    final_url: str = ""
    error_message: str = ""
    error_type: Optional[LivenessFailureReason] = None


class BaseHTTPTransport(ABC):
    """Abstract base class for pluggable HTTP transport implementations."""

    @abstractmethod
    def fetch_head_or_get(
        self,
        url: str,
        timeout_seconds: float,
        verify_tls: bool,
        max_redirects: int,
        max_read_bytes: int,
    ) -> HTTPResponseObservation:
        """Perform passive GET/HEAD observation within bounded constraints."""
        pass


class MockHTTPTransport(BaseHTTPTransport):
    """Deterministic offline mock transport for hermetic testing."""

    def __init__(self, responses: Optional[Dict[str, Union[HTTPResponseObservation, Exception]]] = None):
        self._responses: Dict[str, Union[HTTPResponseObservation, Exception]] = responses or {}
        self._call_history: List[Dict[str, Any]] = []

    def set_response(self, url: str, response: Union[HTTPResponseObservation, Exception]) -> None:
        self._responses[url] = response

    @property
    def call_history(self) -> List[Dict[str, Any]]:
        return list(self._call_history)

    def fetch_head_or_get(
        self,
        url: str,
        timeout_seconds: float,
        verify_tls: bool,
        max_redirects: int,
        max_read_bytes: int,
    ) -> HTTPResponseObservation:
        self._call_history.append({
            "url": url,
            "timeout_seconds": timeout_seconds,
            "verify_tls": verify_tls,
            "max_redirects": max_redirects,
            "max_read_bytes": max_read_bytes,
        })

        if url in self._responses:
            resp = self._responses[url]
            if isinstance(resp, Exception):
                raise resp
            return resp

        # Default fallback for unconfigured URLs in mock
        return HTTPResponseObservation(
            status_code=0,
            body_bytes_len=0,
            error_message=f"Mock response not configured for URL: {url}",
            error_type=LivenessFailureReason.UNAVAILABLE,
        )


class RequestsHTTPTransport(BaseHTTPTransport):
    """Production passive HTTP transport using requests with bounded safety controls."""

    def fetch_head_or_get(
        self,
        url: str,
        timeout_seconds: float,
        verify_tls: bool,
        max_redirects: int,
        max_read_bytes: int,
    ) -> HTTPResponseObservation:
        import requests
        from requests.exceptions import SSLError, Timeout, ConnectionError as ReqConnectionError, RequestException

        session = requests.Session()
        session.max_redirects = max_redirects

        redirect_chain: List[str] = []
        try:
            # Passive streaming GET to enforce bounded byte reading
            resp = session.get(
                url,
                timeout=timeout_seconds,
                verify=verify_tls,
                allow_redirects=True,
                stream=True,
                headers={"User-Agent": "DigitalForensicsBenchmark/1.0 (Passive Liveness Auditor; Research Safety)"},
            )

            if resp.history:
                redirect_chain = [r.url for r in resp.history]

            final_url = resp.url
            status_code = resp.status_code
            content_type = resp.headers.get("Content-Type", "")

            # Read up to max_read_bytes
            raw_bytes = resp.raw.read(max_read_bytes)
            body_len = len(raw_bytes)
            resp.close()

            return HTTPResponseObservation(
                status_code=status_code,
                body_bytes_len=body_len,
                content_type=content_type,
                tls_verified=verify_tls if url.startswith("https://") else True,
                redirect_chain=redirect_chain,
                final_url=final_url,
            )

        except SSLError as exc:
            return HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                tls_verified=False,
                tls_error=str(exc),
                error_message=f"TLS verification failed: {exc}",
                error_type=LivenessFailureReason.TLS_VERIFICATION_FAILED,
                redirect_chain=redirect_chain,
            )
        except Timeout as exc:
            return HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message=f"Connection timed out after {timeout_seconds}s: {exc}",
                error_type=LivenessFailureReason.CONNECTION_TIMEOUT,
                redirect_chain=redirect_chain,
            )
        except ReqConnectionError as exc:
            err_str = str(exc).lower()
            if "name or service not known" in err_str or "getaddrinfo failed" in err_str or "nodename nor servname provided" in err_str:
                err_type = LivenessFailureReason.DNS_FAILURE
            else:
                err_type = LivenessFailureReason.CONNECTION_REFUSED
            return HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message=f"Network connection failed: {exc}",
                error_type=err_type,
                redirect_chain=redirect_chain,
            )
        except RequestException as exc:
            return HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message=f"HTTP retrieval failed: {exc}",
                error_type=LivenessFailureReason.RETRIEVAL_ERROR,
                redirect_chain=redirect_chain,
            )
        except Exception as exc:
            return HTTPResponseObservation(
                status_code=0,
                body_bytes_len=0,
                error_message=f"Unexpected error during retrieval: {exc}",
                error_type=LivenessFailureReason.RETRIEVAL_ERROR,
                redirect_chain=redirect_chain,
            )
        finally:
            session.close()


# =====================================================================
# Structured Evaluation Results
# =====================================================================

@dataclass(frozen=True)
class LivenessEvaluation:
    """Deterministic structured result of candidate liveness and eligibility evaluation."""
    candidate_id: str
    raw_content: str
    modality: InputModality
    artifact_id: str
    liveness_status: LivenessStatus
    eligibility_status: EligibilityStatus
    failure_reason: LivenessFailureReason = LivenessFailureReason.NONE
    http_status: Optional[int] = None
    response_body_size_bytes: Optional[int] = None
    content_type: Optional[str] = None
    tls_status: Optional[str] = None  # "valid", "failed", "unverified", "not_applicable"
    resolved_ip: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    checked_at: str = ""
    diagnostic_notes: str = ""

    def to_liveness_metadata(self) -> LivenessMetadata:
        """Convert evaluation to canonical LivenessMetadata schema."""
        dns_resolved: Optional[bool] = None
        if self.failure_reason == LivenessFailureReason.DNS_FAILURE:
            dns_resolved = False
        elif self.liveness_status == LivenessStatus.LIVE:
            dns_resolved = True

        return LivenessMetadata(
            http_status=self.http_status,
            dns_resolved=dns_resolved,
            tls_status=self.tls_status,
            response_body_size_bytes=self.response_body_size_bytes,
            resolved_ip=self.resolved_ip,
            redirect_chain=list(self.redirect_chain),
            checked_at=self.checked_at,
            eligibility_status=self.eligibility_status.value.lower(),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation to serializable dictionary."""
        return {
            "candidate_id": self.candidate_id,
            "raw_content": self.raw_content,
            "modality": self.modality.value if hasattr(self.modality, "value") else str(self.modality),
            "artifact_id": self.artifact_id,
            "liveness_status": self.liveness_status.value,
            "eligibility_status": self.eligibility_status.value,
            "failure_reason": self.failure_reason.value,
            "http_status": self.http_status,
            "response_body_size_bytes": self.response_body_size_bytes,
            "content_type": self.content_type,
            "tls_status": self.tls_status,
            "resolved_ip": self.resolved_ip,
            "redirect_chain": list(self.redirect_chain),
            "final_url": self.final_url,
            "checked_at": self.checked_at,
            "diagnostic_notes": self.diagnostic_notes,
        }


@dataclass(frozen=True)
class LivenessBatchResult:
    """Aggregated batch result for multiple candidate liveness evaluations."""
    total_evaluated: int
    eligible_count: int
    ineligible_count: int
    not_applicable_count: int
    evaluations: List[LivenessEvaluation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch result to serializable dictionary."""
        return {
            "total_evaluated": self.total_evaluated,
            "eligible_count": self.eligible_count,
            "ineligible_count": self.ineligible_count,
            "not_applicable_count": self.not_applicable_count,
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


# =====================================================================
# Passive Liveness Evaluator Engine
# =====================================================================

class PassiveLivenessEvaluator:
    """Core passive liveness and eligibility evaluation engine for benchmark candidates."""

    MIN_LIVENESS_BYTES: int = 100
    DEFAULT_TIMEOUT: float = 5.0
    DEFAULT_MAX_REDIRECTS: int = 3
    DEFAULT_MAX_READ_BYTES: int = 1_048_576  # 1 MB bounded read

    def __init__(
        self,
        min_body_bytes: int = MIN_LIVENESS_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        verify_tls: bool = True,
        max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
        transport: Optional[BaseHTTPTransport] = None,
    ):
        if min_body_bytes < 1:
            raise ValueError(f"min_body_bytes must be >= 1, got {min_body_bytes}")
        if timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be > 0, got {timeout_seconds}")
        if max_redirects < 0:
            raise ValueError(f"max_redirects must be >= 0, got {max_redirects}")
        if max_read_bytes < min_body_bytes:
            raise ValueError(f"max_read_bytes ({max_read_bytes}) cannot be less than min_body_bytes ({min_body_bytes})")

        self.min_body_bytes = min_body_bytes
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.verify_tls = verify_tls
        self.max_read_bytes = max_read_bytes
        self.transport = transport or RequestsHTTPTransport()

    def evaluate_candidate(
        self,
        candidate: Optional[RawCandidate],
        checked_at: Optional[str] = None,
    ) -> LivenessEvaluation:
        """Evaluate a single raw candidate's passive liveness and eligibility."""
        timestamp = checked_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if candidate is None:
            return LivenessEvaluation(
                candidate_id="CAN-UNKNOWN",
                raw_content="",
                modality=InputModality.DIRECT_URL,
                artifact_id="ART-UNKNOWN",
                liveness_status=LivenessStatus.UNKNOWN,
                eligibility_status=EligibilityStatus.UNKNOWN,
                failure_reason=LivenessFailureReason.MISSING_ARTIFACT,
                checked_at=timestamp,
                diagnostic_notes="Candidate is None; cannot evaluate liveness.",
            )

        raw_str = (
            candidate.raw_content
            if isinstance(candidate.raw_content, str)
            else f"<bytes len={len(candidate.raw_content)}>"
        )
        artifact_id = (
            candidate.artifact_id
            if candidate.artifact_id
            else compute_artifact_id(candidate.modality, candidate.raw_content)
        )

        # -------------------------------------------------------------
        # Modality: QR_IMAGE
        # -------------------------------------------------------------
        if candidate.modality == InputModality.QR_IMAGE:
            # Static image artifact. No network liveness check; no dynamic decoding/execution.
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.QR_IMAGE,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_APPLICABLE,
                eligibility_status=EligibilityStatus.ELIGIBLE,
                failure_reason=LivenessFailureReason.NON_NETWORK_MODALITY,
                tls_status="not_applicable",
                checked_at=timestamp,
                diagnostic_notes="Static QR image artifact; passive network liveness not applicable; no decoding or dynamic execution performed.",
            )

        # -------------------------------------------------------------
        # Modality: QR_PAYLOAD
        # -------------------------------------------------------------
        if candidate.modality == InputModality.QR_PAYLOAD:
            return self._evaluate_qr_payload(candidate, raw_str, artifact_id, timestamp)

        # -------------------------------------------------------------
        # Modality: DIRECT_URL
        # -------------------------------------------------------------
        if candidate.modality == InputModality.DIRECT_URL:
            return self._evaluate_direct_url(candidate, raw_str, artifact_id, timestamp)

        # Fallback for unexpected modality
        return LivenessEvaluation(
            candidate_id=candidate.candidate_id,
            raw_content=raw_str,
            modality=candidate.modality,
            artifact_id=artifact_id,
            liveness_status=LivenessStatus.UNKNOWN,
            eligibility_status=EligibilityStatus.UNKNOWN,
            failure_reason=LivenessFailureReason.UNSUPPORTED_SCHEME,
            checked_at=timestamp,
            diagnostic_notes=f"Unsupported modality: {candidate.modality}",
        )

    def _evaluate_qr_payload(
        self,
        candidate: RawCandidate,
        raw_str: str,
        artifact_id: str,
        timestamp: str,
    ) -> LivenessEvaluation:
        """Evaluate a QR payload string safely without dynamic handler invocation."""
        content = raw_str.strip()

        # Check for non-HTTP schemes
        non_http_schemes = ("mailto:", "smsto:", "tel:", "wifi:", "data:", "javascript:", "file:", "intent:")
        lower_content = content.lower()
        if any(lower_content.startswith(scheme) for scheme in non_http_schemes):
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.QR_PAYLOAD,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_APPLICABLE,
                eligibility_status=EligibilityStatus.NOT_APPLICABLE,
                failure_reason=LivenessFailureReason.UNSUPPORTED_SCHEME,
                tls_status="not_applicable",
                checked_at=timestamp,
                diagnostic_notes=f"Non-HTTP QR payload scheme detected; passive network retrieval not applicable; zero execution performed.",
            )

        # If it is not a URL (e.g. plain text, alphanumeric, contact card), it remains a static payload
        parsed = urllib.parse.urlparse(content)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.QR_PAYLOAD,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_APPLICABLE,
                eligibility_status=EligibilityStatus.NOT_APPLICABLE,
                failure_reason=LivenessFailureReason.NON_NETWORK_MODALITY,
                tls_status="not_applicable",
                checked_at=timestamp,
                diagnostic_notes="Non-URL QR payload; passive network retrieval not applicable; preserved as static payload string.",
            )

        # For HTTP/HTTPS QR payloads, record as an observed payload with target identity metadata
        # without automatic dynamic browser execution.
        return LivenessEvaluation(
            candidate_id=candidate.candidate_id,
            raw_content=raw_str,
            modality=InputModality.QR_PAYLOAD,
            artifact_id=artifact_id,
            liveness_status=LivenessStatus.NOT_APPLICABLE,
            eligibility_status=EligibilityStatus.ELIGIBLE,
            failure_reason=LivenessFailureReason.NONE,
            tls_status="not_applicable",
            final_url=content,
            checked_at=timestamp,
            diagnostic_notes="HTTP/HTTPS QR payload candidate; payload preserved for downstream target evaluation without active browser invocation.",
        )

    def _evaluate_direct_url(
        self,
        candidate: RawCandidate,
        raw_str: str,
        artifact_id: str,
        timestamp: str,
    ) -> LivenessEvaluation:
        """Passively evaluate HTTP/HTTPS liveness and >=100-byte response criterion."""
        url = raw_str.strip()

        # Parse and validate URL structure
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as exc:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.MALFORMED_URL,
                checked_at=timestamp,
                diagnostic_notes=f"Malformed URL structure: {exc}",
            )

        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_APPLICABLE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.UNSUPPORTED_SCHEME,
                checked_at=timestamp,
                diagnostic_notes=f"Unsupported URL scheme '{parsed.scheme}'; only http/https supported for direct URL liveness.",
            )

        if not parsed.netloc or not parsed.netloc.strip():
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.MALFORMED_URL,
                checked_at=timestamp,
                diagnostic_notes="URL missing host / network location.",
            )

        # Perform passive observation via transport
        try:
            obs = self.transport.fetch_head_or_get(
                url=url,
                timeout_seconds=self.timeout_seconds,
                verify_tls=self.verify_tls,
                max_redirects=self.max_redirects,
                max_read_bytes=self.max_read_bytes,
            )
        except Exception as exc:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.RETRIEVAL_ERROR,
                checked_at=timestamp,
                diagnostic_notes=f"Transport error during retrieval: {exc}",
            )

        tls_status = None
        if parsed.scheme.lower() == "https":
            tls_status = "valid" if obs.tls_verified else "failed"

        # Check for retrieval errors
        if obs.error_type is not None and obs.error_type != LivenessFailureReason.NONE:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=obs.error_type,
                http_status=obs.status_code if obs.status_code > 0 else None,
                response_body_size_bytes=obs.body_bytes_len,
                content_type=obs.content_type if obs.content_type else None,
                tls_status=tls_status,
                resolved_ip=obs.resolved_ip,
                redirect_chain=list(obs.redirect_chain),
                final_url=obs.final_url if obs.final_url else None,
                checked_at=timestamp,
                diagnostic_notes=obs.error_message or f"Retrieval failed with error: {obs.error_type.value}",
            )

        # Check TLS verification status
        if parsed.scheme.lower() == "https" and not obs.tls_verified:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.TLS_VERIFICATION_FAILED,
                http_status=obs.status_code if obs.status_code > 0 else None,
                response_body_size_bytes=obs.body_bytes_len,
                content_type=obs.content_type if obs.content_type else None,
                tls_status="failed",
                resolved_ip=obs.resolved_ip,
                redirect_chain=list(obs.redirect_chain),
                final_url=obs.final_url if obs.final_url else None,
                checked_at=timestamp,
                diagnostic_notes=obs.tls_error or "TLS certificate verification failed.",
            )

        # Evaluate body length criterion: >= min_body_bytes (default 100 bytes)
        body_len = obs.body_bytes_len
        if body_len >= self.min_body_bytes:
            # Satisfies >= 100 bytes criterion
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.LIVE,
                eligibility_status=EligibilityStatus.ELIGIBLE,
                failure_reason=LivenessFailureReason.NONE,
                http_status=obs.status_code,
                response_body_size_bytes=body_len,
                content_type=obs.content_type if obs.content_type else None,
                tls_status=tls_status,
                resolved_ip=obs.resolved_ip,
                redirect_chain=list(obs.redirect_chain),
                final_url=obs.final_url if obs.final_url else url,
                checked_at=timestamp,
                diagnostic_notes=f"HTTP response observed ({obs.status_code}); body size {body_len} bytes satisfies >= {self.min_body_bytes} bytes criterion.",
            )
        elif body_len == 0:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.EMPTY_BODY,
                http_status=obs.status_code,
                response_body_size_bytes=0,
                content_type=obs.content_type if obs.content_type else None,
                tls_status=tls_status,
                resolved_ip=obs.resolved_ip,
                redirect_chain=list(obs.redirect_chain),
                final_url=obs.final_url if obs.final_url else url,
                checked_at=timestamp,
                diagnostic_notes=f"HTTP response observed ({obs.status_code}); empty body (0 bytes) fails >= {self.min_body_bytes} bytes criterion.",
            )
        else:
            return LivenessEvaluation(
                candidate_id=candidate.candidate_id,
                raw_content=raw_str,
                modality=InputModality.DIRECT_URL,
                artifact_id=artifact_id,
                liveness_status=LivenessStatus.NOT_LIVE,
                eligibility_status=EligibilityStatus.INELIGIBLE,
                failure_reason=LivenessFailureReason.BODY_BELOW_THRESHOLD,
                http_status=obs.status_code,
                response_body_size_bytes=body_len,
                content_type=obs.content_type if obs.content_type else None,
                tls_status=tls_status,
                resolved_ip=obs.resolved_ip,
                redirect_chain=list(obs.redirect_chain),
                final_url=obs.final_url if obs.final_url else url,
                checked_at=timestamp,
                diagnostic_notes=f"HTTP response observed ({obs.status_code}); body size {body_len} bytes is below required {self.min_body_bytes} bytes threshold.",
            )

    def evaluate_batch(
        self,
        candidates: Sequence[Optional[RawCandidate]],
        checked_at: Optional[str] = None,
    ) -> LivenessBatchResult:
        """Evaluate a sequence of candidates and return an aggregated batch result."""
        evaluations: List[LivenessEvaluation] = []
        eligible_count = 0
        ineligible_count = 0
        not_applicable_count = 0

        for cand in candidates:
            res = self.evaluate_candidate(cand, checked_at=checked_at)
            evaluations.append(res)
            if res.eligibility_status == EligibilityStatus.ELIGIBLE:
                eligible_count += 1
            elif res.eligibility_status == EligibilityStatus.INELIGIBLE:
                ineligible_count += 1
            elif res.eligibility_status == EligibilityStatus.NOT_APPLICABLE:
                not_applicable_count += 1

        return LivenessBatchResult(
            total_evaluated=len(evaluations),
            eligible_count=eligible_count,
            ineligible_count=ineligible_count,
            not_applicable_count=not_applicable_count,
            evaluations=evaluations,
        )


# =====================================================================
# Top-Level Convenience Helpers
# =====================================================================

def evaluate_candidate_liveness(
    candidate: Optional[RawCandidate],
    evaluator: Optional[PassiveLivenessEvaluator] = None,
    checked_at: Optional[str] = None,
) -> LivenessEvaluation:
    """Convenience helper to evaluate a single candidate's passive liveness and eligibility."""
    ev = evaluator or PassiveLivenessEvaluator()
    return ev.evaluate_candidate(candidate, checked_at=checked_at)


def evaluate_batch_liveness(
    candidates: Sequence[Optional[RawCandidate]],
    evaluator: Optional[PassiveLivenessEvaluator] = None,
    checked_at: Optional[str] = None,
) -> LivenessBatchResult:
    """Convenience helper to evaluate multiple candidates in batch."""
    ev = evaluator or PassiveLivenessEvaluator()
    return ev.evaluate_batch(candidates, checked_at=checked_at)
