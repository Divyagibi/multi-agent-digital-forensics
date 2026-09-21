# Final Core Freeze Specification

**Date**: 2026-09-20  
**Status**: QA-CLOSED & ARCHITECTURALLY FROZEN  
**System**: Multi-Agent URL Digital Forensics & Evidence Analysis System

---

## 1. Frozen Components

The following architectural components are QA-closed and **MUST NOT** be redesigned, retuned, re-weighted, or modified merely to manipulate target scores:

1. **Forensic Agents (A1–A18)**:
   - A1: Domain Identity
   - A2: DNS & Infrastructure
   - A3: SSL/HTTPS
   - A4: Website Content
   - A5: URL Structure
   - A6: Reputation & Threat Intelligence
   - A7: Technical Fingerprinting
   - A8: Website Behavior
   - A9: Brand Verification
   - A10: Visual / UI Analysis
   - A11: Content Quality
   - A12: Contact / Entity Verification
   - A13: OSINT & External Presence
   - A14: Historical / Wayback Analysis
   - A15: User Trust & Sentiment
   - A16: Network Security
   - A17: Malware Indicators
   - A18: QR Forensics / Quishing Analysis
2. **Common Evidence Schema** ([`services/evidence_schema.py`](file:///c:/Users/user/Desktop/digital/services/evidence_schema.py))
3. **Evidence Normalizer** ([`services/evidence_normalizer.py`](file:///c:/Users/user/Desktop/digital/services/evidence_normalizer.py))
4. **Investigation Evidence Ledger** ([`services/evidence_ledger.py`](file:///c:/Users/user/Desktop/digital/services/evidence_ledger.py))
5. **Trust Calculation Engine (TCE)** ([`services/trust_calculation_engine.py`](file:///c:/Users/user/Desktop/digital/services/trust_calculation_engine.py))
6. **TCE Parameters & Polarity Registry** ([`services/tce_config.py`](file:///c:/Users/user/Desktop/digital/services/tce_config.py))
7. **TCE Verdict Thresholds**
8. **Contradiction Detection Rules & Mechanics**
9. **Benchmark Dataset & Evaluation Tooling Infrastructure** ([`tools/benchmark/`](file:///c:/Users/user/Desktop/digital/tools/benchmark))
10. **AERE Mathematical Independence from TCE** (Sovereign TCE principle; AERE is strictly additive qualitative reasoning)
11. **Confidence Engine Mathematical Independence from TCE**

---

## 2. Final Frozen TCE Parameters

All scoring parameters in [`services/tce_config.py`](file:///c:/Users/user/Desktop/digital/services/tce_config.py) are locked:

### Severity Weights ($w_{\text{sev}}$)
- `info`: 0.00
- `low`: 0.15
- `medium`: 0.45
- `high`: 0.75
- `critical`: 1.00

### Evidence Type Reliability ($r_{\text{type}}$)
- `deterministic`: 1.00
- `threat_intelligence`: 0.90
- `external_source`: 0.85
- `historical`: 0.85
- `inference`: 0.70
- `subjective`: 0.50

### Default Strength by Type
- `deterministic`: 1.00
- `threat_intelligence`: 0.70
- `external_source`: 0.60
- `historical`: 0.60
- `inference`: 0.50
- `subjective`: 0.40

### Relational & Aggregation Constants
- **Corroboration Alpha ($\alpha$)**: 0.25 (diminishing return multiplier on secondary cluster items)
- **Related Dimension Beta ($\beta$)**: 0.70 (collinearity discount on secondary dimensions)
- **Duplicate Multiplier**: 0.00 (complete suppression of duplicate findings)
- **Derived Mirror Multiplier**: 0.00 (suppression of direct upstream mirrors)
- **Derived New Analysis Multiplier**: 1.00 (retains independent downstream analysis)
- **Contradiction Penalty ($\Delta_{\text{contra}}$)**: 5.0 points per valid contradiction edge
- **Max Contradiction Penalty**: 10.0 points
- **Saturation Kappa ($\kappa$)**: 1.20 (bounded exponential curve scaling factor)
- **Mitigation Gamma ($\gamma$)**: 0.50 (mitigating evidence mitigation weight)
- **Minimum Telemetry Coverage**: 0.20 (coverage floor for definitive verdict)

---

## 3. Final Verdict Thresholds

Deterministic Risk Score mappings to forensic verdict tiers:

| Risk Score Range | Verdict Classification | Description |
| :--- | :--- | :--- |
| $[0.0, 15.0)$ | **`benign`** | Clean target with standard baseline indicators |
| $[15.0, 35.0)$ | **`low_risk`** | Minor isolated anomalies without malicious intent |
| $[35.0, 60.0)$ | **`suspicious`** | Multiple anomalies or moderate threat flags present |
| $[60.0, 80.0)$ | **`high_risk`** | Strong indicators of deceptive, abusive, or malicious behavior |
| $[80.0, 100.0]$ | **`malicious`** | Confirmed critical threat intel, active phishing, or malware |

*Coverage Gate*: If `telemetry_coverage < 0.20` and no high/critical threat exists, verdict defaults to **`unknown`**.

---

## 4. Canonical Contradiction Rules

Contradictions are strictly evaluated across the Evidence Ledger using three canonical rules:

1. **Geographic Contradiction**:
   - *Source*: Agent 12 (Contact / Entity Verification) declared country.
   - *Target*: Agent 2 (DNS & Infrastructure) server IP geolocation.
   - *Condition*: Declared corporate country differs from resolved server infrastructure country.
2. **Temporal Contradiction**:
   - *Source*: Agent 1 (Domain Identity) WHOIS creation date.
   - *Target*: Agent 14 (Historical Evidence) Wayback Machine archive history.
   - *Condition*: Domain registration age $< 60$ days while historical archive timeline shows $> 5$ years active tenure (drop-catch/domain reuse indicator).
3. **Reputational Contradiction**:
   - *Source*: Agent 12 (Contact / Entity Verification) corporate registry verification.
   - *Target*: Agent 6 (Reputation & Threat Intelligence) security feeds.
   - *Condition*: Verified official corporate registration coexists with active high/critical security blacklist entries.

*Rule Invariant*: Coexistence of ordinary positive evidence ($R^-$) and negative evidence ($R^+$) is standard independent telemetry and must **never** be counted as a contradiction.

---

## 5. Regression Test Baseline

- **Full Suite Discovery**: `python -m unittest discover -s tests`
- **Current Passing Count**: **996 tests**
- **Test Result**: `OK` (0 failures, 0 errors, 100% passing)

---

## 6. Benchmark Infrastructure Freeze

The benchmark dataset, harvesting routines, liveness verifiers, integrity auditors, and evaluation fixtures in [`tools/benchmark/`](file:///c:/Users/user/Desktop/digital/tools/benchmark) are **permanently frozen**. No further benchmark reruns, synthetic ground-truth alterations, or metric recalibrations are permitted.

---
