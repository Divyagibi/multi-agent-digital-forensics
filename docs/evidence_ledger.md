# Investigation Evidence Ledger & Normalization Layer

## 1. Purpose

The **Evidence Normalization Layer** and **Investigation Evidence Ledger** provide a centralized, deterministic, and traceable repository for forensic observations produced by all 18 autonomous agents in the Multi-Agent Digital Forensics System.

Before this step, each agent emitted evidence adhering to the Common Evidence Schema, but evidence was stored either in isolated agent envelopes or as a flat list without entity canonicalization, provenance graphs, or cross-agent correlation.

The Evidence Ledger solves this by:
* Transforming heterogeneous agent outputs into canonical, normalized investigation records.
* Linking observations across agents through canonical target representations.
* Establishing deterministic relational graphs between evidence items (supporting, contradictory, duplicate, derived, and related dimensions).
* Maintaining rigorous research traceability from final conclusions back to individual agent sensor functions.

---

## 2. Architectural Position

The Evidence Ledger operates as the foundational data plane immediately following raw agent evidence collection:

```
+-------------------------------------------------------------+
|                      18 Forensic Agents                     |
|           (A1: Domain Identity ... A18: QR Analysis)        |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                    Common Evidence Schema                   |
|     (create_evidence_item, build_agent_result validation)   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  Evidence Normalization Layer               |
|      (normalize_target, normalize_evidence_item)            |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 Investigation Evidence Ledger               |
|    (entries, relationships, provenance, canonical target)   |
+-------------------------------------------------------------+
                              |
                              v  [FUTURE STAGES]
+-------------------------------------------------------------+
|                   Trust Calculation Engine                  |
|               (Mathematical Risk & Trust Models)            |
+-------------------------------------------------------------+
                              |
                              v  [FUTURE STAGES]
+-------------------------------------------------------------+
|                 AI Evidence Reasoning Engine                |
|           (Multi-Agent LLM Synthesis & Deep Forensics)      |
+-------------------------------------------------------------+
```

---

## 3. Normalization Process

The normalization process is executed by `services/evidence_normalizer.py`. It is:
* **Deterministic & Reproducible:** Identical agent inputs consistently produce identical ledger entries.
* **Loss-Minimizing:** Raw observation values, category tags, and nested metadata are preserved in the `data` and `value` payload.
* **Non-Destructive:** Original agent results returned to API endpoints remain unmodified.

For every evidence item, the normalizer standardizes:
1. `evidence_id`: Canonical format `E<agent_number>-<index:02d>` (e.g. `E1-01`, `E12-04`).
2. `agent_id` & `agent_name`: Mapped to canonical registry (1–18).
3. `evidence_type`: Controlled vocabulary (`deterministic`, `inference`, `threat_intelligence`, `external_source`, `historical`, `subjective`).
4. `severity`: Controlled scale (`info`, `low`, `medium`, `high`, `critical`).
5. `description` & `finding`: Clear forensic narrative of the observation.
6. `value`: Observed raw or structured metric.
7. `evidence_strength`: Calibrated floating point `[0.0, 1.0]` or `None`.
8. `target`: Canonical target entity object.
9. `provenance`: Originating agent, component, sensor function, and source feed.
10. `status`: Execution state (`success`, `partial`, `unavailable`, `error`, `skipped`).
11. `relationships`: Pointers to correlated cross-agent evidence items.

---

## 4. Ledger Data Model & Structure

A complete Investigation Evidence Ledger object serialized to JSON resembles:

```json
{
  "target": {
    "original_url": "https://example.com/login",
    "normalized_url": "https://example.com/login",
    "scheme": "https",
    "hostname": "example.com",
    "registrable_domain": "example.com",
    "port": null,
    "path": "/login"
  },
  "entries": [
    {
      "evidence_id": "E1-01",
      "agent_id": 1,
      "agent_name": "Domain Identity",
      "evidence_type": "deterministic",
      "severity": "medium",
      "description": "Domain registered recently (15 days ago).",
      "finding": "Domain registered recently (15 days ago).",
      "value": 15,
      "evidence_strength": 0.95,
      "data": {
        "domain_age_days": 15,
        "creation_date": "2026-08-30"
      },
      "target": {
        "original_url": "https://example.com/login",
        "normalized_url": "https://example.com/login",
        "scheme": "https",
        "hostname": "example.com",
        "registrable_domain": "example.com",
        "port": null,
        "path": "/login"
      },
      "provenance": {
        "source_agent": "A1",
        "source_name": "Domain Identity",
        "source_number": 1,
        "source_function": "analyze_domain_identity",
        "source_type": "agent_output",
        "source_detail": "WHOIS/RDAP",
        "agent_status": "success"
      },
      "status": "success",
      "relationships": [
        {
          "relationship_id": "REL-001",
          "target_evidence_id": "E14-01",
          "relationship_type": "supporting"
        }
      ]
    }
  ],
  "relationships": [
    {
      "relationship_id": "REL-001",
      "source_evidence_id": "E1-01",
      "target_evidence_id": "E14-01",
      "relationship_type": "supporting",
      "description": "Cross-agent corroboration: Recent domain registration (A1) corroborated by lack of historical archive footprint (A14).",
      "details": {}
    }
  ],
  "summary": {
    "total_entries": 1,
    "total_relationships": 1,
    "agents_represented": [1],
    "by_severity": { "medium": 1 },
    "by_evidence_type": { "deterministic": 1 },
    "by_relationship_type": { "supporting": 1 },
    "missing_or_unavailable_count": 0
  }
}
```

---

## 5. Evidence Identity

Evidence items maintain a strict identifier format `E<agent_number>-<index:02d>`.
* Unique across an agent's evidence collection.
* Immediately identifies originating agent number (e.g. `E18-02` indicates Agent 18 QR analysis).
* When duplicate evidence entries enter the ledger, unique suffixes (`-DUP2`) are deterministically assigned while retaining `original_evidence_id`.

---

## 6. Target / Entity Normalization

Target normalization via `normalize_target()` decomposes input strings into canonical components:
* `original_url`: Raw string as submitted.
* `normalized_url`: Canonicalized scheme, lowercase host, normalized port, and path.
* `scheme`: `http`, `https`, or `None` if plain domain.
* `hostname`: Lowercase hostname (e.g. `sub.example.com`).
* `registrable_domain`: Base domain extracted using public suffix algorithms (e.g. `example.com`, `example.co.uk`).
* `port`: Explicit integer port (if non-standard) or `None`.
* `path`: Request path or `None` if plain domain was provided.

**Guarantees:**
* Missing components remain `None` (e.g. plain domain inputs do not fabricate `path="/"`, `scheme="http"`).
* Enables reliable cross-agent correlation when one agent processes a full URL (`https://example.com/checkout`) while another queries a base domain (`example.com`).

---

## 7. Provenance & Traceability

Research-grade forensics requires absolute provenance. For every entry, the `provenance` block records:
* `source_agent`: Canonical agent code (e.g. `A9`).
* `source_name`: Full agent title (e.g. `Brand Verification`).
* `source_number`: Numeric agent ID (e.g. `9`).
* `source_function`: Originating inspection routine.
* `source_type`: Data generation category (`agent_output`, `external_feed`, `archive`).
* `source_detail`: Specific sensor, API, or parser (e.g. `VirusTotal`, `Google Safe Browsing`, `OpenPhish`, `Wayback CDX`).
* `agent_status`: Operational status of the agent during execution.

---

## 8. Relational Graph & Relationship Types

The Ledger maintains deterministic cross-agent links using six formal relationship types:

| Relationship Type | Definition | Example |
| :--- | :--- | :--- |
| `same_target` | Evidence items addressing the same canonical entity. | Agent 1 WHOIS and Agent 2 DNS A-record on `example.com`. |
| `supporting` | Independent agents corroborating a forensic hypothesis. | Agent 6 threat intelligence blacklist and Agent 17 malware script flags. |
| `contradiction` | Incompatible or conflicting factual claims across agents. | Agent 12 declared entity country (UK) vs Agent 2 server IP geolocation (India). |
| `duplicate` | Repeated observation across processing stages. | Identical creation timestamp extracted via WHOIS and RDAP. |
| `derived_from` | Causal or data-flow dependency. | Agent 5 URL lexical analysis derived from Agent 18 QR payload extraction. |
| `related_dimension` | Complementary forensic vectors on the same subject. | Agent 4 Website Content and Agent 11 Content Quality analysis. |

---

## 9. Contradiction Preservation Without Scoring

When agents produce conflicting observations (e.g. business claims vs server hosting locations, or WHOIS age vs Wayback archive history):
* The Ledger records a `contradiction` relationship.
* The Ledger **does not** automatically penalize the target or add risk points.
* Scoring interpretation is deferred to the Trust Calculation Engine and AI Evidence Reasoning Engine.

---

## 10. Duplicate Handling & Independent Corroboration

The Ledger cleanly differentiates:
1. **Accidental / Processing Duplicates:** Repeated identical observations from the same agent. Both are retained with unique IDs, linked by `duplicate` relationships, and distinct provenance preserved.
2. **Independent Multi-Source Corroboration:** Two separate agents (e.g. Agent 6 VirusTotal and Agent 17 static malware signatures) observing related threats. These are preserved as independent entries linked by `supporting` relationships.

---

## 11. Missing & Unavailable Data Integrity

A critical tenet of digital forensics is distinguishing **absence of evidence** from **evidence of absence**:
* Missing external telemetry (e.g. Google Reviews API quota exceeded, WHOIS privacy enabled) is tagged with status `unavailable` or `skipped`.
* Telemetry is **never** converted into artificial values (e.g. unavailable reviews is never converted to `0 reviews`).
* Missing data is **never** assigned a high severity or assumed to be malicious.

---

## 12. Intentional Exclusion of Risk & Trust Scoring

The Evidence Ledger is strictly an **evidence organization and correlation system**, not a risk scoring calculator.

The following are **strictly excluded** from this layer:
* No numerical risk weights (e.g. `domain_age < 30 days -> +20 risk`).
* No overall trust score calculations.
* No confidence score for maliciousness verdicts.
* No LLM-based speculative reasoning or hallucinations.

---

## 13. Future Integration with Downstream Stages

The Evidence Ledger serves as the structured input for subsequent architecture stages:
1. **Trust Calculation Engine (Stage 3):** Will consume the Ledger's normalized entries, severity distributions, and supporting/contradictory relationship graph to compute calibrated mathematical trust scores.
2. **AI Evidence Reasoning Engine (Stage 4):** Will consume the structured Ledger to generate synthesized investigation narratives, explaining findings with direct provenance citations back to `evidence_id`.
