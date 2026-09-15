"""Unit Tests for Step 6D-1 Experimental Research Protocol Specification.

Step 6D-1: Research Protocol Definition & Freeze.

Validates that the experimental protocol document exists, contains all required
methodological sections, directional-neutral hypotheses (H1-H6), research questions (RQ1-RQ6),
baselines (A0-A4), ablation conditions (M0-M6), statistical testing rules, and research safety boundaries.
"""

import os
from pathlib import Path
import unittest


class TestExperimentalProtocol(unittest.TestCase):
    """Test suite ensuring integrity and completeness of the frozen experimental research protocol."""

    def setUp(self):
        self.doc_path = Path(__file__).resolve().parent.parent.parent / "docs" / "experimental_protocol.md"

    def test_01_protocol_document_exists(self):
        """Verify that docs/experimental_protocol.md exists and is non-empty."""
        self.assertTrue(self.doc_path.exists(), f"Missing experimental protocol document at {self.doc_path}")
        self.assertGreater(self.doc_path.stat().st_size, 5000, "Protocol document is unexpectedly small")

    def test_02_research_questions_present(self):
        """Verify that all six research questions RQ1-RQ6 are defined."""
        content = self.doc_path.read_text(encoding="utf-8")
        for rq in ["RQ1", "RQ2", "RQ3", "RQ4", "RQ5", "RQ6"]:
            self.assertIn(rq, content, f"Missing research question {rq} in protocol")

    def test_03_direction_neutral_hypotheses_present(self):
        """Verify that direction-neutral hypotheses H1 through H6 with null/alternative are defined."""
        content = self.doc_path.read_text(encoding="utf-8")
        for h in ["H_1", "H_2", "H_3", "H_4", "H_5", "H_6"]:
            self.assertIn(h, content, f"Missing hypothesis {h} in protocol")
        self.assertIn("H_{1,0}", content)
        self.assertIn("H_{1,A}", content)

    def test_04_baselines_a0_to_a4_defined(self):
        """Verify that baseline models A0 through A4 are explicitly defined."""
        content = self.doc_path.read_text(encoding="utf-8")
        for b in ["A_0", "A_1", "A_2", "A_3", "A_4"]:
            self.assertIn(b, content, f"Missing baseline {b} in protocol")

    def test_05_ablation_conditions_m0_to_m6_defined(self):
        """Verify that model and ablation conditions M0 through M6 are explicitly defined."""
        content = self.doc_path.read_text(encoding="utf-8")
        for m in ["M_0", "M_1", "M_2", "M_3", "M_4", "M_5", "M_6"]:
            self.assertIn(m, content, f"Missing model condition {m} in protocol")

    def test_06_ti_ablation_invariant(self):
        """Verify that A6/TI ablation requires recording unavailable/ablated state with no synthetic clean data."""
        content = self.doc_path.read_text(encoding="utf-8")
        self.assertIn("Agent A6 is disabled", content)
        self.assertIn("unavailable/ablated", content)

    def test_07_idc_non_causal_language(self):
        """Verify that Incremental Diagnostic Contribution (IDC) is explicitly defined as non-causal."""
        content = self.doc_path.read_text(encoding="utf-8")
        self.assertIn("Incremental Diagnostic Contribution", content)
        self.assertTrue("causal" in content.lower())
        self.assertIn("Non-Causal Mandate", content)

    def test_08_five_by_two_contingency_table(self):
        """Verify that TCE risk bands are analyzed via a 5x2 contingency table against binary ground truth."""
        content = self.doc_path.read_text(encoding="utf-8")
        self.assertIn("5 \\times 2", content)
        self.assertIn("Benign", content)
        self.assertIn("Low Risk", content)
        self.assertIn("Suspicious", content)
        self.assertIn("High Risk", content)
        self.assertIn("Malicious", content)

    def test_09_confidence_engine_threshold_semantics(self):
        """Verify that C_ev >= 35 is defined as an uncalibrated workflow review threshold."""
        content = self.doc_path.read_text(encoding="utf-8")
        self.assertIn("35", content)
        self.assertIn("uncalibrated prototype workflow/review threshold", content)

    def test_10_statistical_rigor_and_safety_boundaries(self):
        """Verify that bootstrap confidence intervals, hypothesis tests, and safety boundaries are documented."""
        content = self.doc_path.read_text(encoding="utf-8")
        self.assertIn("bootstrap", content.lower())
        self.assertIn("McNemar", content)
        self.assertIn("Wilcoxon", content)
        self.assertIn("Zero Malware Detonation", content)
        self.assertIn("Passive Eligibility Criterion", content)


if __name__ == "__main__":
    unittest.main()
