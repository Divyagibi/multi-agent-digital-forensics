"""
tests/test_trust_calculation_engine.py
======================================
Comprehensive Unit & Mathematical Validation Tests for Trust Calculation Engine (TCE).

Verifies:
1. Basic severity scaling (low, medium, high, critical)
2. Evidence strength handling (1.0, 0.5, 0.0, None -> default by type)
3. All evidence types reliability scaling
4. Declarative polarity resolution (risk_increasing, risk_reducing, neutral, unmapped)
5. Duplicate suppression (M_dup = 0.0)
6. Derived evidence handling (semantic mirrors = 0.0, new analysis = 1.0)
7. Related-dimension collinearity discount (beta = 0.70)
8. Critical mathematical test: C1=1.0, C2=0.75, C3=0.75, alpha=0.25 -> C_cluster=1.28125, Risk=65.62
9. Saturated aggregation curve (R_net=0 -> 0, R_net=1.0 -> 56.54, R_net=1.28125 -> 65.62, R_net=1.931 -> 80.0)
10. Mitigating trust evidence interaction (R_net = max(0, R+ - gamma*R-))
11. Bounded contradiction penalty and Inconsistency Index
12. Missing & unavailable telemetry neutrality (0.0 contribution)
13. Low coverage handling (unknown vs critical threat override with low_telemetry_coverage flag)
14. Full explainability lineage tracing back to evidence IDs
"""

import math
import unittest

from services.evidence_schema import create_evidence_item, build_agent_result
from services.evidence_normalizer import normalize_evidence_item, normalize_target
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.tce_config import (
    SEVERITY_WEIGHTS,
    TYPE_RELIABILITY,
    DEFAULT_STRENGTH_BY_TYPE,
    CORROBORATION_ALPHA,
    RELATED_DIMENSION_BETA,
    SATURATION_KAPPA,
    MITIGATION_GAMMA,
    MAX_CONTRADICTION_PENALTY,
    resolve_evidence_polarity,
)


class TestTrustCalculationEngine(unittest.TestCase):

    def setUp(self):
        self.tce = TrustCalculationEngine()
        self.target = normalize_target("https://example.com")

    # -----------------------------------------------------------------
    # Test 1: Basic Severity Scaling
    # -----------------------------------------------------------------
    def test_01_basic_severity_scaling(self):
        """Test individual severity levels produce expected base contributions and risk scores."""
        severities = ["low", "medium", "high", "critical"]
        expected_weights = [0.15, 0.45, 0.75, 1.00]

        for sev, exp_w in zip(severities, expected_weights):
            ledger = EvidenceLedger(target=self.target)
            ev = normalize_evidence_item(
                evidence_item={
                    "evidence_id": "E1-01",
                    "type": "deterministic",
                    "finding": "domain_registered_recently",
                    "category": "domain_registered_recently",
                    "severity": sev,
                    "source": "WHOIS",
                    "evidence_strength": 1.0,
                    "metadata": {"category": "domain_registered_recently"}
                },
                agent_identifier=1,
                canonical_target=self.target
            )
            ledger.add_entry(ev)
            res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)

            item_contrib = res["evidence_contributions"][0]["base_contribution"]
            self.assertAlmostEqual(item_contrib, exp_w, places=3)
            expected_risk = round(100.0 * (1.0 - math.exp(-exp_w / SATURATION_KAPPA)), 2)
            self.assertEqual(res["risk_score"], expected_risk)
            self.assertEqual(res["trust_score"], round(100.0 - expected_risk, 2))

    # -----------------------------------------------------------------
    # Test 2: Evidence Strength Handling
    # -----------------------------------------------------------------
    def test_02_evidence_strength_handling(self):
        """Test evidence strength scaling and fallback to type default when None."""
        # Strength = 1.0
        ev1 = {"evidence_id": "E1-01", "type": "deterministic", "severity": "high", "category": "domain_registered_recently", "evidence_strength": 1.0}
        # Strength = 0.5
        ev2 = {"evidence_id": "E1-02", "type": "deterministic", "severity": "high", "category": "domain_registered_recently", "evidence_strength": 0.5}
        # Strength = 0.0
        ev3 = {"evidence_id": "E1-03", "type": "deterministic", "severity": "high", "category": "domain_registered_recently", "evidence_strength": 0.0}
        # Strength = None (type deterministic -> default 1.0)
        ev4 = {"evidence_id": "E1-04", "type": "deterministic", "severity": "high", "category": "domain_registered_recently", "evidence_strength": None}
        # Strength = None (type inference -> default 0.50)
        ev5 = {"evidence_id": "E1-05", "type": "inference", "severity": "high", "category": "domain_registered_recently", "evidence_strength": None}

        ledger = EvidenceLedger(target=self.target)
        for ev in [ev1, ev2, ev3, ev4, ev5]:
            ledger.add_entry(normalize_evidence_item(ev, 1, canonical_target=self.target))

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        contribs = {item["evidence_id"]: item for item in res["evidence_contributions"]}

        self.assertAlmostEqual(contribs["E1-01"]["base_contribution"], 0.75 * 1.0 * 1.0, places=3)
        self.assertAlmostEqual(contribs["E1-02"]["base_contribution"], 0.75 * 0.5 * 1.0, places=3)
        self.assertAlmostEqual(contribs["E1-03"]["base_contribution"], 0.0, places=3)
        self.assertAlmostEqual(contribs["E1-04"]["base_contribution"], 0.75 * 1.0 * 1.0, places=3)
        # inference default strength = 0.50, type reliability = 0.70 -> 0.75 * 0.50 * 0.70 = 0.2625
        self.assertAlmostEqual(contribs["E1-05"]["base_contribution"], 0.75 * 0.50 * 0.70, places=3)

    # -----------------------------------------------------------------
    # Test 3: Evidence Types Reliability
    # -----------------------------------------------------------------
    def test_03_evidence_types_reliability(self):
        """Test all 6 evidence types scale by their configured reliability."""
        types = ["deterministic", "threat_intelligence", "external_source", "historical", "inference", "subjective"]
        expected_rel = [1.00, 0.90, 0.85, 0.85, 0.70, 0.50]

        for ev_t, exp_r in zip(types, expected_rel):
            ledger = EvidenceLedger(target=self.target)
            ev = {
                "evidence_id": "E1-01",
                "type": ev_t,
                "severity": "critical",
                "category": "malware_signature_match",
                "evidence_strength": 1.0
            }
            ledger.add_entry(normalize_evidence_item(ev, 1, canonical_target=self.target))
            res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
            self.assertAlmostEqual(res["evidence_contributions"][0]["type_reliability"], exp_r, places=3)
            self.assertAlmostEqual(res["evidence_contributions"][0]["base_contribution"], 1.0 * 1.0 * exp_r, places=3)

    # -----------------------------------------------------------------
    # Test 4: Declarative Polarity Taxonomy
    # -----------------------------------------------------------------
    def test_04_declarative_polarity_resolution(self):
        """Test risk_increasing, risk_reducing, neutral, and unmapped category defaults."""
        self.assertEqual(resolve_evidence_polarity("malware_signature_match"), "risk_increasing")
        self.assertEqual(resolve_evidence_polarity("domain_age_established"), "risk_reducing")
        self.assertEqual(resolve_evidence_polarity("standard_port_open"), "neutral")
        self.assertEqual(resolve_evidence_polarity("completely_unknown_custom_metric"), "neutral")

        # Verify unmapped item contributes zero to risk
        ledger = EvidenceLedger(target=self.target)
        ev_unmapped = {
            "evidence_id": "E1-01",
            "type": "deterministic",
            "severity": "critical",
            "category": "completely_unknown_custom_metric",
            "evidence_strength": 1.0
        }
        ledger.add_entry(normalize_evidence_item(ev_unmapped, 1, canonical_target=self.target))
        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        self.assertEqual(res["evidence_contributions"][0]["polarity"], "neutral")
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(res["trust_score"], 100.0)

    # -----------------------------------------------------------------
    # Test 5: Duplicate Suppression
    # -----------------------------------------------------------------
    def test_05_duplicate_suppression(self):
        """Verify secondary duplicate evidence receives multiplier 0.0."""
        ledger = EvidenceLedger(target=self.target)
        ev1 = {
            "evidence_id": "E6-01",
            "type": "threat_intelligence",
            "severity": "high",
            "category": "blacklist_entry",
            "finding": "Domain listed on security blacklist",
            "value": "Spamhaus",
            "evidence_strength": 1.0
        }
        ev2 = {
            "evidence_id": "E6-01",
            "type": "threat_intelligence",
            "severity": "high",
            "category": "blacklist_entry",
            "finding": "Domain listed on security blacklist",
            "value": "Spamhaus",
            "evidence_strength": 1.0
        }

        ledger.add_entry(normalize_evidence_item(ev1, 6, canonical_target=self.target))
        ledger.add_entry(normalize_evidence_item(ev2, 6, canonical_target=self.target))
        ledger.correlate_relationships()

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        contribs = {item["evidence_id"]: item for item in res["evidence_contributions"]}

        # Primary contributes full
        self.assertAlmostEqual(contribs["E6-01"]["final_item_contribution"], 0.75 * 1.0 * 0.90, places=3)
        # Duplicate contributes 0
        dup_key = [k for k in contribs if "-DUP" in k][0]
        self.assertEqual(contribs[dup_key]["suppression_multiplier"], 0.0)
        self.assertEqual(contribs[dup_key]["final_item_contribution"], 0.0)

    # -----------------------------------------------------------------
    # Test 6: Derived Evidence Handling
    # -----------------------------------------------------------------
    def test_06_derived_evidence_handling(self):
        """Verify semantic mirrors contribute 0.0 while new downstream analyses contribute normally."""
        ledger = EvidenceLedger(target=self.target)
        # Parent: QR analysis
        e_qr = normalize_evidence_item({"evidence_id": "E18-01", "type": "deterministic", "severity": "info", "category": "qr_format_parsed", "finding": "QR parsed"}, 18, canonical_target=self.target)
        # Child 1: URL mirror
        e_url_mirror = normalize_evidence_item({"evidence_id": "E5-01", "type": "deterministic", "severity": "info", "category": "qr_format_parsed", "finding": "QR URL mirror"}, 5, canonical_target=self.target)
        # Child 2: Punycode detected (new analysis)
        e_puny = normalize_evidence_item({"evidence_id": "E5-02", "type": "deterministic", "severity": "high", "category": "homograph_punycode", "finding": "Punycode homograph detected", "evidence_strength": 1.0}, 5, canonical_target=self.target)

        ledger.add_entry(e_qr)
        ledger.add_entry(e_url_mirror)
        ledger.add_entry(e_puny)

        # Record derived relationships
        ledger.add_relationship("E5-01", "E18-01", "derived_from", "URL mirror", details={"is_new_analysis": False})
        ledger.add_relationship("E5-02", "E18-01", "derived_from", "Punycode analysis", details={"is_new_analysis": True})

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        contribs = {item["evidence_id"]: item for item in res["evidence_contributions"]}

        self.assertEqual(contribs["E5-01"]["suppression_multiplier"], 0.0)
        self.assertEqual(contribs["E5-02"]["suppression_multiplier"], 1.0)
        self.assertAlmostEqual(contribs["E5-02"]["final_item_contribution"], 0.75, places=3)

    # -----------------------------------------------------------------
    # Test 7: Related Dimension Collinearity Discount
    # -----------------------------------------------------------------
    def test_07_related_dimension_collinearity_discount(self):
        """Verify beta = 0.70 is applied to secondary related_dimension evidence items."""
        ledger = EvidenceLedger(target=self.target)
        e_a4 = normalize_evidence_item({"evidence_id": "E4-01", "type": "deterministic", "severity": "medium", "category": "fake_login_form", "finding": "Login form detected", "evidence_strength": 1.0}, 4, canonical_target=self.target)
        e_a11 = normalize_evidence_item({"evidence_id": "E11-01", "type": "deterministic", "severity": "medium", "category": "urgency_manipulation_keywords", "finding": "Urgency keywords detected", "evidence_strength": 1.0}, 11, canonical_target=self.target)

        ledger.add_entry(e_a4)
        ledger.add_entry(e_a11)
        ledger.add_relationship("E4-01", "E11-01", "related_dimension", "Complementary form deception")

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        contribs = {item["evidence_id"]: item for item in res["evidence_contributions"]}

        # Primary has collinearity discount 1.0
        self.assertEqual(contribs["E4-01"]["collinearity_discount"], 1.0)
        # Secondary has collinearity discount 0.70
        self.assertEqual(contribs["E11-01"]["collinearity_discount"], RELATED_DIMENSION_BETA)
        self.assertAlmostEqual(contribs["E11-01"]["final_item_contribution"], 0.45 * 0.70, places=3)

    # -----------------------------------------------------------------
    # Test 8: CRITICAL MATHEMATICAL TEST (Corroboration & Case E)
    # -----------------------------------------------------------------
    def test_08_critical_mathematical_corroboration_test(self):
        """
        Critical mathematical consistency test:
        C1 = 1.00, C2 = 0.75, C3 = 0.75, alpha = 0.25
        Expected C_cluster = 1.00 + 0.25*(0.75) + 0.125*(0.75) = 1.28125 (NOT 2.78)
        Expected Risk = 100 * (1 - exp(-1.28125 / 1.20)) ≈ 65.62
        """
        ledger = EvidenceLedger(target=self.target)
        e1 = normalize_evidence_item({"evidence_id": "E17-01", "type": "deterministic", "severity": "critical", "category": "malware_signature_match", "finding": "Malware signature found", "evidence_strength": 1.0}, 17, canonical_target=self.target)
        e2 = normalize_evidence_item({"evidence_id": "E6-01", "type": "deterministic", "severity": "high", "category": "blacklist_entry", "finding": "Blacklist entry found", "evidence_strength": 1.0}, 6, canonical_target=self.target)
        e3 = normalize_evidence_item({"evidence_id": "E8-01", "type": "deterministic", "severity": "high", "category": "fake_login_form", "finding": "Fake login form found", "evidence_strength": 1.0}, 8, canonical_target=self.target)

        ledger.add_entry(e1)
        ledger.add_entry(e2)
        ledger.add_entry(e3)

        ledger.add_relationship("E17-01", "E6-01", "supporting", "Independent threat corroboration")
        ledger.add_relationship("E17-01", "E8-01", "supporting", "Independent behavioral threat corroboration")

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)

        # Expected calculations
        c1 = 1.00
        c2 = 0.75
        c3 = 0.75
        alpha = CORROBORATION_ALPHA  # 0.25
        expected_cluster_contrib = c1 + alpha * c2 + (alpha / 2.0) * c3  # 1.0 + 0.1875 + 0.09375 = 1.28125
        self.assertAlmostEqual(res["aggregation_metrics"]["r_plus"], expected_cluster_contrib, places=4)

        expected_risk = round(100.0 * (1.0 - math.exp(-expected_cluster_contrib / SATURATION_KAPPA)), 2)
        self.assertEqual(expected_risk, 65.62)
        self.assertEqual(res["risk_score"], 65.62)
        self.assertEqual(res["trust_score"], 34.38)
        self.assertEqual(res["verdict"], "high_risk")

    # -----------------------------------------------------------------
    # Test 9: Saturation Curve Verification
    # -----------------------------------------------------------------
    def test_09_saturation_curve_mathematical_points(self):
        """Verify mathematical saturation points: R_net=0->0, R_net=1.0->56.54, R_net=1.28125->65.62, R_net=1.931325->80.0."""
        # 1. R_net = 0.0 -> Risk = 0.0
        risk_0 = 100.0 * (1.0 - math.exp(-0.0 / 1.20))
        self.assertEqual(round(risk_0, 2), 0.0)

        # 2. R_net = 1.0 -> Risk = 56.54
        risk_1 = 100.0 * (1.0 - math.exp(-1.0 / 1.20))
        self.assertEqual(round(risk_1, 2), 56.54)

        # 3. R_net = 1.28125 -> Risk = 65.62
        risk_cluster = 100.0 * (1.0 - math.exp(-1.28125 / 1.20))
        self.assertEqual(round(risk_cluster, 2), 65.62)

        # 4. R_net = -ln(1 - 0.80) * 1.20 = 1.931326 -> Risk = 80.00 (Malicious cutoff)
        r_malicious = -math.log(1.0 - 0.80) * 1.20
        risk_malicious = 100.0 * (1.0 - math.exp(-r_malicious / 1.20))
        self.assertEqual(round(risk_malicious, 2), 80.00)

    # -----------------------------------------------------------------
    # Test 10: Mitigating Evidence Interaction
    # -----------------------------------------------------------------
    def test_10_mitigating_evidence_interaction(self):
        """Verify risk-reducing evidence reduces net risk by gamma*R- without allowing negative risk."""
        ledger = EvidenceLedger(target=self.target)
        # Risk-increasing item: High severity (0.75)
        e_risk = normalize_evidence_item({"evidence_id": "E1-01", "type": "deterministic", "severity": "high", "category": "domain_registered_recently", "finding": "Recently registered", "evidence_strength": 1.0}, 1, canonical_target=self.target)
        # Risk-reducing item: Long tenure (0.75)
        e_mitigate = normalize_evidence_item({"evidence_id": "E14-01", "type": "deterministic", "severity": "high", "category": "long_term_archive_tenure", "finding": "10+ years archive tenure", "evidence_strength": 1.0}, 14, canonical_target=self.target)

        ledger.add_entry(e_risk)
        ledger.add_entry(e_mitigate)

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)

        r_plus = 0.75
        r_minus = 0.75
        expected_r_net = max(0.0, r_plus - (MITIGATION_GAMMA * r_minus))  # 0.75 - 0.50*0.75 = 0.375
        self.assertAlmostEqual(res["aggregation_metrics"]["r_net"], expected_r_net, places=3)
        expected_risk = round(100.0 * (1.0 - math.exp(-expected_r_net / SATURATION_KAPPA)), 2)
        self.assertEqual(res["risk_score"], expected_risk)

        # Verify pure mitigating evidence cannot drop risk below 0.0
        ledger_pure_mitigate = EvidenceLedger(target=self.target)
        ledger_pure_mitigate.add_entry(e_mitigate)
        res_pure = self.tce.calculate_trust(ledger_pure_mitigate, telemetry_coverage=1.0)
        self.assertEqual(res_pure["risk_score"], 0.0)
        self.assertEqual(res_pure["trust_score"], 100.0)

    # -----------------------------------------------------------------
    # Test 11: Contradiction Handling
    # -----------------------------------------------------------------
    def test_11_contradiction_handling_bounded(self):
        """Verify contradiction penalty is bounded at 10.0 and inconsistency index is calculated."""
        ledger = EvidenceLedger(target=self.target)
        e_a12 = normalize_evidence_item({"evidence_id": "E12-01", "type": "deterministic", "severity": "info", "category": "company_registration_verified", "finding": "Company UK verified"}, 12, canonical_target=self.target)
        e_a2 = normalize_evidence_item({"evidence_id": "E2-01", "type": "deterministic", "severity": "info", "category": "clean_dns_resolution", "finding": "Server IP India"}, 2, canonical_target=self.target)
        e_a1 = normalize_evidence_item({"evidence_id": "E1-01", "type": "deterministic", "severity": "info", "category": "domain_registered_recently", "finding": "Domain age 10 days"}, 1, canonical_target=self.target)
        e_a14 = normalize_evidence_item({"evidence_id": "E14-01", "type": "deterministic", "severity": "info", "category": "long_term_archive_tenure", "finding": "Wayback archive 10 years"}, 14, canonical_target=self.target)

        ledger.add_entry(e_a12)
        ledger.add_entry(e_a2)
        ledger.add_entry(e_a1)
        ledger.add_entry(e_a14)

        # Add 2 distinct contradictions: 2 * 5.0 = 10.0 (reaches MAX_CONTRADICTION_PENALTY)
        ledger.add_relationship("E12-01", "E2-01", "contradiction", "Country discrepancy")
        ledger.add_relationship("E1-01", "E14-01", "contradiction", "Domain timeline discrepancy")

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)

        self.assertEqual(res["contradiction_penalty_applied"], MAX_CONTRADICTION_PENALTY)
        self.assertEqual(res["inconsistency_index"], min(100.0, 2 * 25.0))
        self.assertEqual(len(res["contradiction_notes"]), 2)

    # -----------------------------------------------------------------
    # Test 12: Missing & Unavailable Telemetry Neutrality
    # -----------------------------------------------------------------
    def test_12_missing_and_unavailable_telemetry_neutrality(self):
        """Verify missing/unavailable/skipped/error items contribute 0.0 to risk and trust."""
        ledger = EvidenceLedger(target=self.target)
        ev_unavail = {
            "evidence_id": "E6-01",
            "type": "threat_intelligence",
            "severity": "critical",
            "category": "threat_intel_blocklist",
            "finding": "Threat feed unavailable",
            "status": "unavailable"
        }
        ev_error = {
            "evidence_id": "E17-01",
            "type": "deterministic",
            "severity": "critical",
            "category": "malware_signature_match",
            "finding": "Malware scanner failed",
            "status": "error"
        }
        ledger.add_entry(normalize_evidence_item(ev_unavail, 6, agent_result={"status": "unavailable"}, canonical_target=self.target))
        ledger.add_entry(normalize_evidence_item(ev_error, 17, agent_result={"status": "error"}, canonical_target=self.target))

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(res["trust_score"], 100.0)
        self.assertEqual(res["verdict"], "benign")

    # -----------------------------------------------------------------
    # Test 13: Low Telemetry Coverage Handling
    # -----------------------------------------------------------------
    def test_13_low_telemetry_coverage_and_critical_threat_override(self):
        """Test coverage < 0.20 produces 'unknown', but confirmed critical threat overrides to 'malicious'."""
        # Case A: Low coverage (< 0.20) with only low/info findings -> unknown
        ledger_low = EvidenceLedger(target=self.target)
        ledger_low.add_entry(normalize_evidence_item({"evidence_id": "E1-01", "type": "deterministic", "severity": "low", "category": "domain_registered_recently"}, 1, canonical_target=self.target))

        res_low = self.tce.calculate_trust(ledger_low, telemetry_coverage=0.10)
        self.assertTrue(res_low["low_telemetry_coverage"])
        self.assertEqual(res_low["verdict"], "unknown")

        # Case B: Low coverage (< 0.20) with confirmed critical threat -> malicious override
        ledger_crit = EvidenceLedger(target=self.target)
        ledger_crit.add_entry(normalize_evidence_item({"evidence_id": "E17-01", "type": "threat_intelligence", "severity": "critical", "category": "malware_signature_match", "evidence_strength": 1.0}, 17, canonical_target=self.target))

        res_crit = self.tce.calculate_trust(ledger_crit, telemetry_coverage=0.10)
        self.assertTrue(res_crit["low_telemetry_coverage"])
        self.assertEqual(res_crit["verdict"], "malicious")

    # -----------------------------------------------------------------
    # Test 14: Explainability Lineage
    # -----------------------------------------------------------------
    def test_14_explainability_lineage(self):
        """Verify complete trace from final score to individual evidence IDs and scoring parameters."""
        ledger = EvidenceLedger(target=self.target)
        ev = normalize_evidence_item({
            "evidence_id": "E6-01",
            "type": "threat_intelligence",
            "severity": "high",
            "category": "threat_intel_blocklist",
            "finding": "Domain listed on 2 threat feeds",
            "evidence_strength": 0.95
        }, 6, canonical_target=self.target)
        ledger.add_entry(ev)

        res = self.tce.calculate_trust(ledger, telemetry_coverage=1.0)

        self.assertIn("scoring_parameters", res)
        self.assertEqual(res["scoring_parameters"]["kappa"], SATURATION_KAPPA)
        self.assertEqual(res["scoring_parameters"]["gamma"], MITIGATION_GAMMA)

        contrib = res["evidence_contributions"][0]
        self.assertEqual(contrib["evidence_id"], "E6-01")
        self.assertEqual(contrib["agent_id"], 6)
        self.assertEqual(contrib["agent_name"], "Reputation & Threat Intelligence")
        self.assertEqual(contrib["severity"], "high")
        self.assertEqual(contrib["evidence_type"], "threat_intelligence")
        self.assertEqual(contrib["polarity"], "risk_increasing")
        self.assertGreater(contrib["base_contribution"], 0.0)
        self.assertEqual(contrib["final_item_contribution"], contrib["base_contribution"])


if __name__ == "__main__":
    unittest.main()
