# -*- coding: utf-8 -*-
"""
tests/test_evidence_schema.py
=============================
Comprehensive unit tests for the Common Evidence Schema and Validation Framework.

Tests cover:
    1. Canonical Agent Registry (A1–A18 metadata completeness & accuracy)
    2. create_evidence_item ID generation (E1-01, E18-05, etc.)
    3. create_evidence_item type, severity, and strength validation
    4. validate_evidence_item with valid and malformed evidence records
    5. build_agent_result envelope formatting and legacy score decoupling
    6. validate_agent_result with valid and malformed agent results
    7. Multi-agent evidence ID uniqueness and format conformance
"""

import sys
import os
import unittest

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.evidence_schema import (
    CANONICAL_AGENT_METADATA,
    AGENT_ID_MAP,
    VALID_EVIDENCE_TYPES,
    VALID_SEVERITIES,
    VALID_STATUSES,
    EVIDENCE_ID_PATTERN,
    create_evidence_item,
    validate_evidence_item,
    build_agent_result,
    validate_agent_result,
)


class TestEvidenceSchema(unittest.TestCase):
    """Test suite for Common Evidence Schema definitions and validators."""

    def test_01_canonical_registry_completeness(self):
        """Verify all 18 agents are registered with complete canonical metadata."""
        self.assertEqual(len(CANONICAL_AGENT_METADATA), 18)
        for i in range(1, 19):
            self.assertIn(i, CANONICAL_AGENT_METADATA)
            meta = CANONICAL_AGENT_METADATA[i]
            self.assertEqual(meta["id"], f"A{i}")
            self.assertEqual(meta["number"], i)
            self.assertIsInstance(meta["name"], str)
            self.assertGreater(len(meta["name"]), 0)
            self.assertIsInstance(meta["desc"], str)
            self.assertGreater(len(meta["desc"]), 0)

    def test_02_agent_id_map(self):
        """Verify string and numeric agent ID resolutions."""
        for i in range(1, 19):
            self.assertEqual(AGENT_ID_MAP[f"A{i}"], i)
            self.assertEqual(AGENT_ID_MAP[str(i)], i)

    def test_03_create_evidence_item_id_formatting(self):
        """Verify evidence ID deterministic formatting (E<agent>-<index:02d>)."""
        # Numeric agent ID
        item1 = create_evidence_item(
            agent_id=1,
            index=1,
            finding="Domain age verified",
            value=365,
            severity="info",
            source="RDAP"
        )
        self.assertEqual(item1["evidence_id"], "E1-01")

        # String agent ID 'A18'
        item18 = create_evidence_item(
            agent_id="A18",
            index=7,
            finding="QR Reed-Solomon level",
            value="Level M",
            severity="info",
            source="QR Parser"
        )
        self.assertEqual(item18["evidence_id"], "E18-07")

        # String agent ID '6'
        item6 = create_evidence_item(
            agent_id="6",
            index=12,
            finding="VirusTotal detection",
            value=0,
            severity="info",
            source="VirusTotal"
        )
        self.assertEqual(item6["evidence_id"], "E6-12")

    def test_04_create_evidence_item_controlled_vocabularies(self):
        """Verify fallback behavior for invalid evidence type and severity."""
        item = create_evidence_item(
            agent_id=3,
            index=1,
            finding="TLS 1.3 in use",
            value="TLSv1.3",
            severity="invalid_severity",
            source="TLS Socket",
            evidence_type="unknown_type"
        )
        self.assertEqual(item["severity"], "info")
        self.assertEqual(item["type"], "deterministic")

    def test_05_create_evidence_item_strength_bounds(self):
        """Verify evidence strength is normalized between 0.0 and 1.0 or None."""
        # Valid float
        i1 = create_evidence_item(1, 1, "test", "v", evidence_strength=0.85432)
        self.assertEqual(i1["evidence_strength"], 0.8543)

        # Out of bounds (> 1.0)
        i2 = create_evidence_item(1, 1, "test", "v", evidence_strength=1.5)
        self.assertIsNone(i2["evidence_strength"])

        # Negative (< 0.0)
        i3 = create_evidence_item(1, 1, "test", "v", evidence_strength=-0.1)
        self.assertIsNone(i3["evidence_strength"])

        # Non-numeric
        i4 = create_evidence_item(1, 1, "test", "v", evidence_strength="invalid")
        self.assertIsNone(i4["evidence_strength"])

    def test_06_validate_evidence_item_success(self):
        """Verify validation passes for correctly structured items."""
        item = create_evidence_item(
            agent_id="A7",
            index=3,
            finding="Cloudflare CDN detected",
            value="Cloudflare",
            severity="info",
            source="HTTP Headers",
            evidence_type="deterministic",
            evidence_strength=0.9,
            metadata={"header": "cf-ray"}
        )
        is_valid, errors = validate_evidence_item(item)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_07_validate_evidence_item_failures(self):
        """Verify validation rejects invalid evidence records."""
        # Not a dict
        v, errs = validate_evidence_item(["not", "a", "dict"])
        self.assertFalse(v)
        self.assertGreaterEqual(len(errs), 1)

        # Bad evidence_id
        bad_id = {
            "evidence_id": "INVALID-ID",
            "type": "deterministic",
            "finding": "Test",
            "value": 1,
            "severity": "info",
            "source": "Unit Test"
        }
        v, errs = validate_evidence_item(bad_id)
        self.assertFalse(v)
        self.assertTrue(any("evidence_id" in e for e in errs))

        # Bad severity
        bad_sev = {
            "evidence_id": "E1-01",
            "type": "deterministic",
            "finding": "Test",
            "value": 1,
            "severity": "extreme_danger",
            "source": "Unit Test"
        }
        v, errs = validate_evidence_item(bad_sev)
        self.assertFalse(v)
        self.assertTrue(any("severity" in e for e in errs))

        # Bad type
        bad_type = {
            "evidence_id": "E1-01",
            "type": "magic_guess",
            "finding": "Test",
            "value": 1,
            "severity": "info",
            "source": "Unit Test"
        }
        v, errs = validate_evidence_item(bad_type)
        self.assertFalse(v)
        self.assertTrue(any("type" in e for e in errs))

        # Out of bounds strength
        bad_strength = {
            "evidence_id": "E1-01",
            "type": "inference",
            "finding": "Test",
            "value": 1,
            "severity": "info",
            "source": "Unit Test",
            "evidence_strength": 2.5
        }
        v, errs = validate_evidence_item(bad_strength)
        self.assertFalse(v)
        self.assertTrue(any("evidence_strength" in e for e in errs))

    def test_08_build_agent_result_structure(self):
        """Verify build_agent_result wraps output envelopes consistently with legacy score decoupling."""
        ev = [create_evidence_item(1, 1, "Domain age", 500, "info", "RDAP")]
        res = build_agent_result(
            agent_identifier=1,
            target="example.com",
            status="completed",
            data={"domain": "example.com", "age": 500},
            evidence=ev,
            errors=[],
            extra_fields={"custom_metric": 42}
        )

        self.assertEqual(res["agent"], "Domain Identity")
        self.assertEqual(res["agent_id"], "A1")
        self.assertEqual(res["agent_number"], 1)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["target"], "example.com")
        self.assertEqual(len(res["evidence"]), 1)
        self.assertEqual(res["data"]["domain"], "example.com")
        self.assertEqual(res["custom_metric"], 42)

        # Strict score decoupling
        self.assertIn("legacy", res)
        self.assertIsNone(res["legacy"]["trust_score"])
        self.assertIsNone(res["legacy"]["risk_score"])
        self.assertEqual(res["legacy"]["verdict"], "not_calculated")

    def test_09_validate_agent_result_envelope(self):
        """Verify validate_agent_result validates full agent envelopes and nested evidence items."""
        ev = [
            create_evidence_item("A2", 1, "DNS A record", ["93.184.216.34"], "info", "DNS Resolver"),
            create_evidence_item("A2", 2, "DNSSEC status", False, "medium", "DNS Resolver", "deterministic", 0.5)
        ]
        res = build_agent_result(
            agent_identifier="A2",
            target="example.com",
            status="success",
            data={"dns": "records"},
            evidence=ev
        )

        is_valid, errors = validate_agent_result(res)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_10_validate_agent_result_catches_invalid_nested_evidence(self):
        """Verify validate_agent_result fails if any nested evidence item is invalid."""
        res = build_agent_result(
            agent_identifier="A5",
            target="example.com",
            status="success",
            data={},
            evidence=[
                {"evidence_id": "BAD-ID", "finding": "broken"}
            ]
        )
        is_valid, errors = validate_agent_result(res)
        self.assertFalse(is_valid)
        self.assertTrue(any("evidence" in e.lower() for e in errors))


if __name__ == "__main__":
    unittest.main()
