"""
services/trust_calculation_engine.py
====================================
Trust Calculation Engine (TCE) for Multi-Agent Digital Forensics System.

Evaluates normalized evidence from the Investigation Evidence Ledger using a
deterministic, non-linear mathematical aggregation model.

Core Invariants:
1. Deterministic & Reproducible: Pure mathematical execution; identical inputs produce identical scores.
2. Independent of LLMs: Does NOT invoke LLMs, natural-language sentiment, or external APIs.
3. Scoring & Polarity Decoupled: Severity and polarity are evaluated independently.
4. Bounded Exponential Saturation: Guaranteed risk score in [0.0, 100.0] via calibrated saturation curve.
5. Single-Pass Corroboration: Cluster-level corroboration with diminishing returns prevents double-counting.
6. Missing Telemetry Neutrality: Unobserved or unavailable data contributes exactly 0.0 to risk and trust.
7. Explainable Lineage: Complete audit trail mapping final scores back to individual evidence IDs.
"""

import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from services.tce_config import (
    SEVERITY_WEIGHTS,
    TYPE_RELIABILITY,
    DEFAULT_STRENGTH_BY_TYPE,
    CORROBORATION_ALPHA,
    RELATED_DIMENSION_BETA,
    DUPLICATE_MULTIPLIER,
    DERIVED_MIRROR_MULTIPLIER,
    DERIVED_NEW_ANALYSIS_MULTIPLIER,
    CONTRADICTION_PENALTY,
    MAX_CONTRADICTION_PENALTY,
    SATURATION_KAPPA,
    MITIGATION_GAMMA,
    MIN_TELEMETRY_COVERAGE,
    VERDICT_THRESHOLDS,
    resolve_evidence_polarity,
)


class TrustCalculationEngine:
    """
    Deterministic Trust & Risk Calculation Engine.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.severity_weights = self.config.get("SEVERITY_WEIGHTS", SEVERITY_WEIGHTS)
        self.type_reliability = self.config.get("TYPE_RELIABILITY", TYPE_RELIABILITY)
        self.default_strength = self.config.get("DEFAULT_STRENGTH_BY_TYPE", DEFAULT_STRENGTH_BY_TYPE)
        self.corroboration_alpha = self.config.get("CORROBORATION_ALPHA", CORROBORATION_ALPHA)
        self.related_beta = self.config.get("RELATED_DIMENSION_BETA", RELATED_DIMENSION_BETA)
        self.duplicate_multiplier = self.config.get("DUPLICATE_MULTIPLIER", DUPLICATE_MULTIPLIER)
        self.derived_mirror_multiplier = self.config.get("DERIVED_MIRROR_MULTIPLIER", DERIVED_MIRROR_MULTIPLIER)
        self.derived_new_analysis_multiplier = self.config.get("DERIVED_NEW_ANALYSIS_MULTIPLIER", DERIVED_NEW_ANALYSIS_MULTIPLIER)
        self.contradiction_penalty = self.config.get("CONTRADICTION_PENALTY", CONTRADICTION_PENALTY)
        self.max_contradiction_penalty = self.config.get("MAX_CONTRADICTION_PENALTY", MAX_CONTRADICTION_PENALTY)
        self.kappa = self.config.get("SATURATION_KAPPA", SATURATION_KAPPA)
        self.gamma = self.config.get("MITIGATION_GAMMA", MITIGATION_GAMMA)
        self.min_coverage = self.config.get("MIN_TELEMETRY_COVERAGE", MIN_TELEMETRY_COVERAGE)
        self.verdict_thresholds = self.config.get("VERDICT_THRESHOLDS", VERDICT_THRESHOLDS)

    def calculate_trust(
        self,
        ledger: Union[Dict[str, Any], Any],
        telemetry_coverage: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Compute deterministic Trust Score, Risk Score, Verdict, and Explainable Evidence Contributions
        from an Investigation Evidence Ledger.
        """
        # 1. Extract Ledger components
        if hasattr(ledger, "to_dict"):
            ledger_dict = ledger.to_dict()
        elif isinstance(ledger, dict):
            ledger_dict = ledger
        else:
            ledger_dict = {"entries": [], "relationships": [], "summary": {}}

        entries: List[Dict[str, Any]] = ledger_dict.get("entries", [])
        relationships: List[Dict[str, Any]] = ledger_dict.get("relationships", [])
        summary: Dict[str, Any] = ledger_dict.get("summary", {})

        # 2. Compute Telemetry Coverage
        if telemetry_coverage is not None:
            coverage = float(telemetry_coverage)
        else:
            agents_represented = summary.get("agents_represented", [])
            if agents_represented:
                coverage = len(agents_represented) / 18.0
            else:
                agent_ids = {e.get("agent_id") for e in entries if e.get("agent_id") is not None}
                coverage = len(agent_ids) / 18.0 if agent_ids else 0.0

        coverage = max(0.0, min(1.0, coverage))

        # 3. Step 1: Base Item Evaluation
        scored_items: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            ev_id = entry.get("evidence_id")
            if not ev_id:
                continue

            status = entry.get("status", "success")
            ev_type = str(entry.get("evidence_type", "deterministic")).lower()
            sev = str(entry.get("severity", "info")).lower()

            # Strength resolution
            raw_strength = entry.get("evidence_strength")
            if raw_strength is not None:
                try:
                    strength = max(0.0, min(1.0, float(raw_strength)))
                except (ValueError, TypeError):
                    strength = self.default_strength.get(ev_type, 1.00)
            else:
                strength = self.default_strength.get(ev_type, 1.00)

            # Severity weight & type reliability
            w_sev = self.severity_weights.get(sev, 0.00)
            r_type = self.type_reliability.get(ev_type, 1.00)

            # Polarity resolution
            cat = entry.get("category") or (entry.get("data") or {}).get("category") or ""
            finding = entry.get("finding") or entry.get("description") or ""
            polarity = resolve_evidence_polarity(cat, finding)

            # Missing or error telemetry contributes zero
            if status in ("unavailable", "restricted", "skipped", "error"):
                c_base = 0.00
                polarity = "neutral"
            else:
                c_base = round(w_sev * strength * r_type, 5)

            scored_items[ev_id] = {
                "evidence_id": ev_id,
                "agent_id": entry.get("agent_id"),
                "agent_name": entry.get("agent_name"),
                "severity": sev,
                "evidence_type": ev_type,
                "evidence_strength": strength,
                "status": status,
                "polarity": polarity,
                "severity_weight": w_sev,
                "type_reliability": r_type,
                "base_contribution": c_base,
                "suppression_multiplier": 1.00,
                "collinearity_discount": 1.00,
                "adjusted_contribution": c_base,
                "supporting_evidence_ids": [],
                "finding": finding,
                "provenance": entry.get("provenance", {})
            }

        # 4. Step 2: Duplicate & Derived Suppression
        # Build relational maps
        for rel in relationships:
            rel_type = rel.get("relationship_type")
            src_id = rel.get("source_evidence_id")
            tgt_id = rel.get("target_evidence_id")

            if rel_type == "duplicate" and tgt_id in scored_items:
                # Secondary duplicate suppressed
                scored_items[tgt_id]["suppression_multiplier"] = self.duplicate_multiplier
                scored_items[tgt_id]["adjusted_contribution"] *= self.duplicate_multiplier

            elif rel_type == "derived_from" and src_id in scored_items:
                # If pure mirror
                is_new_analysis = rel.get("details", {}).get("is_new_analysis", False)
                mult = self.derived_new_analysis_multiplier if is_new_analysis else self.derived_mirror_multiplier
                scored_items[src_id]["suppression_multiplier"] = mult
                scored_items[src_id]["adjusted_contribution"] *= mult

            elif rel_type == "related_dimension" and tgt_id in scored_items:
                # Collinearity discount on secondary
                scored_items[tgt_id]["collinearity_discount"] = self.related_beta
                scored_items[tgt_id]["adjusted_contribution"] *= self.related_beta

        # 5. Step 3: Cluster-Level Corroboration
        # Find supporting groups
        supporting_graph: Dict[str, Set[str]] = {ev_id: set() for ev_id in scored_items}
        for rel in relationships:
            if rel.get("relationship_type") == "supporting":
                src = rel.get("source_evidence_id")
                tgt = rel.get("target_evidence_id")
                if src in scored_items and tgt in scored_items:
                    supporting_graph[src].add(tgt)
                    supporting_graph[tgt].add(src)

        # Identify connected supporting clusters
        visited: Set[str] = set()
        clusters: List[List[str]] = []
        for ev_id in scored_items:
            if ev_id not in visited:
                cluster = []
                queue = [ev_id]
                visited.add(ev_id)
                while queue:
                    curr = queue.pop(0)
                    cluster.append(curr)
                    for neighbor in supporting_graph.get(curr, []):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                clusters.append(cluster)

        # Evaluate each cluster
        risk_increasing_clusters: List[Dict[str, Any]] = []
        risk_reducing_clusters: List[Dict[str, Any]] = []

        for cluster in clusters:
            # Partition cluster by polarity
            inc_items = [scored_items[eid] for eid in cluster if scored_items[eid]["polarity"] == "risk_increasing"]
            red_items = [scored_items[eid] for eid in cluster if scored_items[eid]["polarity"] == "risk_reducing"]

            # Evaluate risk-increasing cluster
            if inc_items:
                # Sort descending by adjusted contribution
                inc_items.sort(key=lambda x: x["adjusted_contribution"], reverse=True)
                c_cluster = inc_items[0]["adjusted_contribution"]
                for j in range(1, len(inc_items)):
                    # C_cluster = C1 + alpha * sum_{j=2}^M Cj / 2^(j-2)
                    c_cluster += self.corroboration_alpha * (inc_items[j]["adjusted_contribution"] / (2 ** (j - 1)))
                
                risk_increasing_clusters.append({
                    "items": [item["evidence_id"] for item in inc_items],
                    "primary_id": inc_items[0]["evidence_id"],
                    "cluster_contribution": round(c_cluster, 5)
                })

            # Evaluate risk-reducing cluster
            if red_items:
                red_items.sort(key=lambda x: x["adjusted_contribution"], reverse=True)
                c_cluster = red_items[0]["adjusted_contribution"]
                for j in range(1, len(red_items)):
                    c_cluster += self.corroboration_alpha * (red_items[j]["adjusted_contribution"] / (2 ** (j - 1)))

                risk_reducing_clusters.append({
                    "items": [item["evidence_id"] for item in red_items],
                    "primary_id": red_items[0]["evidence_id"],
                    "cluster_contribution": round(c_cluster, 5)
                })

        # 6. Step 4: Contradiction & Inconsistency Evaluation
        contradiction_rels = [r for r in relationships if r.get("relationship_type") == "contradiction"]
        n_contra = len(contradiction_rels)
        inconsistency_index = min(100.0, n_contra * 25.0)
        contradiction_penalty_val = min(self.max_contradiction_penalty, n_contra * self.contradiction_penalty)

        # 7. Step 5: Net Risk Aggregation
        r_plus = sum(c["cluster_contribution"] for c in risk_increasing_clusters) + (contradiction_penalty_val / 100.0)
        r_minus = sum(c["cluster_contribution"] for c in risk_reducing_clusters)
        r_net = max(0.0, r_plus - (self.gamma * r_minus))

        # 8. Step 6: Bounded Exponential Saturation
        if r_net <= 0.0:
            raw_risk = 0.0
        else:
            raw_risk = 100.0 * (1.0 - math.exp(-r_net / self.kappa))

        risk_score = round(max(0.0, min(100.0, raw_risk)), 2)

        # 9. Step 7: Complementary Trust Score
        trust_score = round(max(0.0, min(100.0, 100.0 - risk_score)), 2)

        # 10. Step 8: Verdict Resolution
        # Check for confirmed high/critical threats
        has_critical_threat = any(
            item["severity"] == "critical" and item["polarity"] == "risk_increasing" and item["adjusted_contribution"] > 0.0
            for item in scored_items.values()
        )
        has_high_threat = any(
            item["severity"] == "high" and item["polarity"] == "risk_increasing" and item["adjusted_contribution"] > 0.0
            for item in scored_items.values()
        )

        low_telemetry = coverage < self.min_coverage

        if low_telemetry and not (has_critical_threat or has_high_threat):
            verdict = "unknown"
        elif low_telemetry and has_critical_threat:
            verdict = "malicious"
        elif low_telemetry and has_high_threat:
            verdict = "high_risk"
        elif risk_score >= self.verdict_thresholds["malicious"]:
            verdict = "malicious"
        elif risk_score >= self.verdict_thresholds["high_risk"]:
            verdict = "high_risk"
        elif risk_score >= self.verdict_thresholds["suspicious"]:
            verdict = "suspicious"
        elif risk_score >= self.verdict_thresholds["benign"]:
            verdict = "low_risk"
        else:
            verdict = "benign"

        # 11. Step 9: Assemble Explainability Breakdown
        evidence_contributions_list = []
        for item in scored_items.values():
            evidence_contributions_list.append({
                "evidence_id": item["evidence_id"],
                "agent_id": item["agent_id"],
                "agent_name": item["agent_name"],
                "severity": item["severity"],
                "evidence_type": item["evidence_type"],
                "evidence_strength": round(item["evidence_strength"], 4),
                "polarity": item["polarity"],
                "severity_weight": item["severity_weight"],
                "type_reliability": item["type_reliability"],
                "base_contribution": round(item["base_contribution"], 5),
                "suppression_multiplier": item["suppression_multiplier"],
                "collinearity_discount": item["collinearity_discount"],
                "final_item_contribution": round(item["adjusted_contribution"], 5),
                "status": item["status"],
                "finding": item["finding"],
                "provenance": item["provenance"]
            })

        contradiction_notes = []
        for c_rel in contradiction_rels:
            contradiction_notes.append({
                "relationship_id": c_rel.get("relationship_id"),
                "source_evidence_id": c_rel.get("source_evidence_id"),
                "target_evidence_id": c_rel.get("target_evidence_id"),
                "description": c_rel.get("description", "Contradiction detected")
            })

        return {
            "risk_score": risk_score,
            "trust_score": trust_score,
            "verdict": verdict,
            "low_telemetry_coverage": low_telemetry,
            "telemetry_coverage": round(coverage, 4),
            "inconsistency_index": inconsistency_index,
            "contradiction_penalty_applied": round(contradiction_penalty_val, 2),
            "aggregation_metrics": {
                "r_plus": round(r_plus, 5),
                "r_minus": round(r_minus, 5),
                "r_net": round(r_net, 5),
                "risk_increasing_clusters_count": len(risk_increasing_clusters),
                "risk_reducing_clusters_count": len(risk_reducing_clusters)
            },
            "scoring_parameters": {
                "kappa": self.kappa,
                "gamma": self.gamma,
                "corroboration_alpha": self.corroboration_alpha,
                "related_dimension_beta": self.related_beta,
                "contradiction_penalty": self.contradiction_penalty,
                "max_contradiction_penalty": self.max_contradiction_penalty,
                "min_telemetry_coverage": self.min_coverage
            },
            "evidence_contributions": evidence_contributions_list,
            "contradiction_notes": contradiction_notes
        }
