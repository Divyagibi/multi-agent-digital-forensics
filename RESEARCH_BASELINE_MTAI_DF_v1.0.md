# RESEARCH BASELINE / FREEZE MANIFEST — MTAI-DF v1.0

## 1. Release Information

* **Project**: Multi-Agent URL Digital Forensics & Evidence Analysis System (MTAI-DF)
* **Release**: MTAI-DF v1.0 — Final Research Prototype
* **Release Status**: **RELEASE READY**
* **Git Commit**: `c16b776c645ff9b4cf2a0c50f5b3011e1cafbf4e`
* **Audit Status**: FINAL FREEZE AUDIT — RELEASE READY
* **Test Status**: Tests 1–15 PASS
* **Automated Regression Suite**: **999 / 999 PASS**
* **Failed Tests**: 0
* **Skipped Tests**: 0
* **Benchmark Rerun During Final Validation**: NO
* **Benchmark Modified During Final Validation**: NO

---

## 2. Research System Description

The Multi-Agent URL Digital Forensics & Evidence Analysis System (MTAI-DF) is an evidence-driven, multi-agent digital trust and cybersecurity investigation platform designed for rigorous, automated forensic analysis of web URLs and QR-derived digital artifacts.

Rather than functioning as a black-box or simple binary machine-learning classifier, MTAI-DF implements a modular, transparent, multi-tiered pipeline:
1. **Multi-Agent Evidence Collection**: 18 specialized forensic agents independently collect technical, behavioural, cryptographic, infrastructure, and reputational evidence across distinct forensic dimensions.
2. **Standardized Normalization**: Heterogeneous findings are converted into a standardized Common Evidence Schema.
3. **Canonical Evidence Ledger**: Normalized findings and relationship edges are catalogued in a tamper-resistant, queryable Evidence Ledger.
4. **Deterministic Trust Calculation Engine (TCE)**: A mathematically formal engine aggregates multi-dimensional evidence, enforces saturation bounds, evaluates corroboration and dimension collinearity, penalizes cross-domain contradictions, and computes deterministic Risk, Trust, and Verdict metrics.
5. **AI Evidence Reasoning Engine (AERE)**: A downstream, non-destructive qualitative layer synthesizes evidence-grounded natural-language narratives, highlights investigative gaps, and identifies conflicting signals without altering mathematical scoring.
6. **Confidence Engine**: A deterministic post-hoc module evaluates evidence volume, forensic source diversity, and telemetry completeness to calculate an independent confidence score.
7. **Final Investigator Report**: A unified, forensically sound audit dossier presents complete evidence lineage, risk breakdowns, confidence intervals, and qualitative reasoning to human analysts.

---

## 3. Frozen 18-Agent Forensic Taxonomy

All 18 forensic agents are permanently frozen. Every agent produces structured evidence envelopes conforming to the Common Evidence Schema and **does not independently calculate final Risk, Trust, or Verdict scores**.

1. **A1 — Domain Identity**: Evaluates domain age, registration tenure, registrar reputation, RDAP/WHOIS status, and privacy shielding.
2. **A2 — DNS & Infrastructure**: Resolves A, AAAA, MX, NS, TXT, and CNAME records; detects CDN presence, reverse DNS (PTR), and DNSSEC configuration.
3. **A3 — SSL/TLS Security**: Verifies X.509 certificate chains, issuer authority, expiration timeline, TLS cipher suites, and HSTS deployment.
4. **A4 — Website Content**: Analyzes DOM structure, title/meta tags, language consistency, copyright claims, and broken link ratios.
5. **A5 — URL Structure**: Evaluates hostname length, punycode/IDN homographs, excessive subdomains, IP hostnames, and suspicious query parameters.
6. **A6 — Reputation / Threat Intelligence**: Queries multi-feed threat intelligence (Google Safe Browsing, PhishTank, OpenPhish, AbuseIPDB, URLhaus, Spamhaus) distinguishing verified matches from raw submissions.
7. **A7 — Technology Fingerprinting**: Identifies web servers, frameworks, CMS platforms, JavaScript libraries, and third-party tracking scripts.
8. **A8 — Behavior / Dynamic Scripts**: Analyzes client-side redirects, pop-up triggers, automatic file downloads, credential-harvesting form actions, and hidden input fields.
9. **A9 — Brand Verification**: Detects brand logos, visual layout styling, and candidate brand mentions to evaluate target domain legitimacy versus impersonation targets.
10. **A10 — Visual / UI Forensics**: Captures webpage rendering, extracts text via OCR, identifies trust/payment badges, and flags deceptive design patterns.
11. **A11 — Content Quality**: Performs spelling, grammar, stylistic consistency, urgency detection, unrealistic claim analysis, and duplicate text evaluation.
12. **A12 — Contact / Entity Verification**: Extracts business entity names, physical addresses, phone numbers, contact emails, and corporate registration alignment.
13. **A13 — OSINT & External Presence**: Investigates external social media profiles, developer repositories, discussion forum mentions, and press coverage.
14. **A14 — Historical / Wayback Forensics**: Queries Wayback Machine CDX historical archives to track ownership transitions, domain reuse patterns, and historical tenure claims.
15. **A15 — User Trust & Sentiment**: Aggregates consumer sentiment, community feedback, complaint registers, and third-party review patterns.
16. **A16 — Network Security**: Assesses open port risks, sensitive network services, exposed administration endpoints, and network security posture.
17. **A17 — Malware / Exploit Indicators**: Scans for obfuscated JavaScript, base64 eval unpacking, drive-by download signatures, and known malware vectors.
18. **A18 — QR Forensics / Quishing**: Decodes QR matrices, classifies payloads (URL, WiFi, vCard, SMS, plain text), safely unpacks shorteners, and evaluates visual QR tampering.

---

## 4. Frozen Architecture & Responsibilities

The system follows a strict, unidirectional processing chain:

$$\text{18 Forensic Agents} \longrightarrow \text{Common Evidence Schema} \longrightarrow \text{Evidence Normalizer} \longrightarrow \text{Evidence Ledger}$$
$$\longrightarrow \text{Trust Calculation Engine (TCE)} \longrightarrow \text{AERE Input Builder} \longrightarrow \text{AERE Provider} \longrightarrow \text{AERE Grounding Validator}$$
$$\longrightarrow \text{Confidence Engine} \longrightarrow \text{Final Investigator Report} \longrightarrow \text{Frontend / API}$$

### Layer Responsibilities
* **Forensic Agents (A1–A18)**: Specialized telemetry collectors executing scoped forensic tasks.
* **Common Evidence Schema**: The unified data envelope defining types, severities, polarities, reliabilities, and provenance.
* **Evidence Normalizer**: Validates, sanitizes, and normalizes raw agent payloads into canonical schema items.
* **Evidence Ledger**: The authoritative, queryable graph of forensic findings, relationship edges (duplicates, derived links), and session metadata.
* **Trust Calculation Engine (TCE)**: **The sole mathematical authority** for computing Risk ($0–100\%$), Trust ($0–100\%$), and categorical Verdict.
* **AERE Input Builder**: Constructs sanitized, token-efficient, immutable prompt contexts from the Evidence Ledger and TCE outputs.
* **AERE Provider**: Modular LLM/reasoning provider generating structured forensic explanations and gap analyses.
* **AERE Grounding Validator**: Post-generation validator verifying that 100% of cited Evidence IDs exist in the active ledger.
* **Confidence Engine**: Deterministic evaluator computing overall assessment confidence and dimensional data quality.
* **Final Investigator Report**: Assembles complete forensic findings, visualizations, and audit trails for presentation.
* **Frontend / API**: Delivers real-time telemetry, visual gauges, and interactive reports without client-side score re-computation.

---

## 5. Common Evidence Schema Specification

Every evidence item adheres to the canonical data contract:
* **`evidence_id`**: Unique deterministic identifier formatted as `E<AgentNumber>-<Sequence>` (e.g., `E1-01`, `E6-03`).
* **`agent_name`**: Name of the issuing agent (e.g., `agent6_reputation`).
* **`category`**: Forensic category (e.g., `threat_intelligence`, `domain_identity`, `ssl_security`).
* **`finding`**: Brief machine-readable finding identifier.
* **`description`**: Human-readable narrative describing the specific finding.
* **`value`**: Primary structured value (string, numeric, boolean, or dict).
* **`severity`**: Ordinal severity: `info`, `low`, `medium`, `high`, `critical`.
* **`polarity`**: Directional impact on risk: `risk_increasing` ($+1$), `risk_reducing` ($-1$), `neutral` ($0$).
* **`reliability`**: Evidence source reliability: `deterministic`, `threat_intelligence`, `external_source`, `historical`, `inference`, `subjective`.
* **`strength`**: Normalized numeric weight in range $[0.0, 1.0]$.
* **`timestamp`**: ISO-8601 UTC timestamp of collection.
* **`target`**: Target URL or artifact identifier.
* **`provenance`**: Source attribution (endpoint, certificate serial, DNS record, HTTP status).
* **`relationships`**: Explicit relationship edges (`corroborates`, `contradicts`, `duplicate`, `derived_from`).
* **`metadata`**: Additional raw context and diagnostics.

---

## 6. Evidence Ledger

The [EvidenceLedger](file:///c:/Users/user/Desktop/digital/services/evidence_ledger.py) serves as the canonical repository of facts for every investigation session:
* **Immutability & Integrity**: Findings are appended deterministically; raw provenance is strictly preserved.
* **Deduplication**: Identical findings across overlapping agents are marked with `relationship_type = "duplicate"` and assigned a $0.00$ weight multiplier by TCE.
* **Derived Evidence Tracking**: Dependent findings (e.g., findings derived from upstream DNS or URL data) are tracked via `derived_from` edges to prevent double-counting.
* **Single Source of Truth**: Both TCE scoring and AERE grounding validation query the active session's Evidence Ledger directly.

---

## 7. Frozen TCE Configuration

All parameters, weights, and formulas in [services/tce_config.py](file:///c:/Users/user/Desktop/digital/services/tce_config.py) and [services/trust_calculation_engine.py](file:///c:/Users/user/Desktop/digital/services/trust_calculation_engine.py) are locked.

### Severity Weights ($w_{\text{sev}}$)
* `info`: $0.00$
* `low`: $0.15$
* `medium`: $0.45$
* `high`: $0.75$
* `critical`: $1.00$

### Evidence Type Reliability ($r_{\text{type}}$)
* `deterministic`: $1.00$
* `threat_intelligence`: $0.90$
* `external_source`: $0.85$
* `historical`: $0.85$
* `inference`: $0.70$
* `subjective`: $0.50$

### Default Strength by Type
* `deterministic`: $1.00$
* `threat_intelligence`: $0.70$
* `external_source`: $0.60$
* `historical`: $0.60$
* `inference`: $0.50$
* `subjective`: $0.40$

### Directional Polarity
* `risk_increasing`: $+1$
* `risk_reducing`: $-1$
* `neutral`: $0$

### Relational & Aggregation Constants
* **Duplicate Multiplier**: $0.00$ (complete suppression of duplicated items)
* **Derived Mirror Multiplier**: $0.00$ (suppression of direct upstream mirrors)
* **Derived New Analysis Multiplier**: $1.00$ (retains independent downstream analysis)
* **Related Dimension Beta ($\beta$)**: $0.70$ (collinearity discount on secondary dimensions)
* **Corroboration Alpha ($\alpha$)**: $0.25$ (diminishing return multiplier on secondary cluster items)

### Contradiction Detection & Penalization
* **Inconsistency Index**: $\text{Index}_{\text{contra}} = \min(100, N_{\text{contra}} \times 25)$
* **Contradiction Penalty ($\Delta_{\text{contra}}$)**: $\Delta_{\text{contra}} = \min(10.0, N_{\text{contra}} \times 5.0)$ applied once at aggregate $R^+$.

### Mathematical Risk & Trust Formulation
$$R_{\text{net}} = \max\left(0, R^+ - \gamma \times R^-\right), \quad \text{where } \gamma = 0.50$$
$$\text{Risk} = 100 \times \left(1 - \exp\left(-\frac{R_{\text{net}}}{\kappa}\right)\right), \quad \text{where } \kappa = 1.20$$
$$\text{Trust} = 100 - \text{Risk}$$

### Verdict Classification Thresholds
* $[0.0, 15.0) \longrightarrow$ **`benign`**
* $[15.0, 35.0) \longrightarrow$ **`low_risk`**
* $[35.0, 60.0) \longrightarrow$ **`suspicious`**
* $[60.0, 80.0) \longrightarrow$ **`high_risk`**
* $[80.0, 100.0] \longrightarrow$ **`malicious`**

### Telemetry Coverage Gate
* If $\text{telemetry\_coverage} < 0.20$ ($< 20\%$ active agents reporting):
  - Without high/critical evidence $\longrightarrow$ **`unknown`**
  - With critical threat evidence $\longrightarrow$ **`malicious`** (`low_telemetry_coverage` flag)

---

## 8. AERE Architecture & Grounding Contract

The AI Evidence Reasoning Engine (AERE) operates strictly downstream of TCE:
* **Strictly Qualitative**: AERE generates contextual narratives, hypotheses, and gap analysis; it has zero ability to compute, modify, or override Risk, Trust, or Verdict scores.
* **Evidence Immutability**: AERE cannot create evidence entries or fabricate Evidence IDs.
* **Grounding Validator**: [services/aere_grounding_validator.py](file:///c:/Users/user/Desktop/digital/services/aere_grounding_validator.py) audits generated narratives against the Evidence Ledger.
* **Grounding Status Taxonomy**:
  - `PASSED`: All cited IDs exist in the ledger and text claims have exact token support.
  - `UNCERTAIN`: All cited Evidence IDs are 100% valid and verified in the ledger ($0$ invalid IDs, $0$ fabricated IDs), but natural-language synthesis contains soft lexical variations, un-indexed capital tokens, or numerical expressions without exact 1:1 token matches in raw evidence strings. This is expected by-design behavior for LLM summarization.
  - `FAILED`: Used strictly for invalid Evidence IDs, non-existent ID citations, or severe grounding violations.
* **Provider Fault Tolerance**: In the event of AERE provider downtime or API failure, the mathematical TCE assessment remains 100% operational.

---

## 9. Confidence Engine

The Confidence Engine operates as an independent, deterministic, post-hoc evaluator:
* **Non-LLM & Deterministic**: Evaluates evidence volume, source diversity across the 18 agents, telemetry coverage, and contradiction frequency.
* **Zero Feedback to TCE**: Enabling or disabling the Confidence Engine produces identical Risk, Trust, and Verdict scores.
* **Data Quality Metric**: Provides human investigators with an assessment of whether the forensic telemetry collected was comprehensive, moderate, or sparse.

---

## 10. Security Model

The system enforces multi-layered defensive security controls validated in production:
* **Server-Side Request Forgery (SSRF) Protection**: All 18 network-fetching agents validate destination IPs before socket connection. Strict blocks are enforced on:
  - IPv4 Loopback (`127.0.0.0/8`, `localhost`)
  - RFC1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - IPv6 Loopback (`::1`, `fe80::/10`)
  - Link-Local & Cloud Metadata (`169.254.169.254`, `metadata.google.internal`)
  - Multicast and Broadcast addresses
* **Redirect Validation**: Redirect destinations are re-validated against SSRF policies at every hop (maximum 5 hops).
* **Cross-Site Scripting (XSS) Prevention**: All dynamic values (target URLs, page titles, agent summaries, AERE text) are safely escaped prior to DOM rendering.
* **Safe Code Execution**: No use of `eval()`, `exec()`, `os.system()`, `subprocess`, `shell=True`, or dynamic deserialization in production logic.
* **Resource Limits**: Configured HTTP timeouts (10s), payload limits (10MB), and image/QR dimension constraints.
* **Secrets Management**: Zero hardcoded API keys, private credentials, or debug endpoints.

---

## 11. Session & Pipeline Model

* **Session Isolation**: Each investigation generates a unique UUID session (`session_id`).
* **Cross-Session Barrier**: Agent results, Evidence Ledgers, and reports are partitioned by session ID; zero cross-session evidence contamination occurs.
* **Single Finalization**: Pipeline finalization (`/api/pipeline/finalize`) executes exactly once per session.
* **Persistence & Report Retrieval**: `/api/report` acts as a pure read/retrieval endpoint for completed sessions, generating dossiers without re-triggering the 18-agent pipeline.
* **New Analysis Reset**: Initiating a new investigation cleanly clears UI state, agent cards, evidence ledgers, and score gauges.

---

## 12. Benchmark Freeze (Snapshot & Integrity Hashes)

The benchmark evaluation dataset is permanently frozen to ensure scientific reproducibility:

* **Snapshot ID**: `SNAP-a51ba6748b8e3064`
* **Dataset Hash (SHA-256)**:  
  `a51ba6748b8e3064177d7c281e9490245d39b821836ec5f947b884023be19cb`
* **Records Hash (SHA-256)**:  
  `6a800662a07d2a92b1abfa4e8722ec3fa410817bab2e4f4945ef1c871051a1ab`
* **Manifest Hash (SHA-256)**:  
  `60e1c6dcea61386ee81911c9b56699c8a4402e04088b2ee9888f542e71e02cfe`

### Benchmark Dataset Composition (1,220 Records)
* **OpenPhish Community Feed**: 500 records (Active phishing targets)
* **Tranco Top Curated**: 600 records (High-traffic benign websites)
* **Synthetic QR Forensics Testbed**: 60 records (Controlled QR/quishing payloads)
* **Kaggle QR Phishing Dataset**: 60 records (Real-world malicious QR codes)
* **Evaluation Subsets**:
  - Binary Evaluation Subset: 830 records (620 benign, 210 malicious)
  - Ambiguous / Unverifiable Subset: 390 records

---

## 13. Validation Baseline

* **Validation Stage Tests**: Tests 1–15: **ALL PASS**
* **Automated Unit & Regression Suite**: **999 / 999 PASS** (0 failures, 0 errors, 0 skipped)
* **Historical Baseline Context**: The initial frozen baseline of 996 tests was extended by 3 unit tests in [tests/test_agent6.py](file:///c:/Users/user/Desktop/digital/tests/test_agent6.py) to lock in verified versus unverified PhishTank community submission semantics, establishing the final 999-test suite.

---

## 14. Important Validated Reference Results

These controlled reference cases serve as regression benchmarks for live and fixture execution:

### Case 1: Microsoft (Official Benign)
* **Target**: `https://www.microsoft.com/en-in`
* **Risk Score**: $0.00\%$
* **Trust Score**: $100.00\%$
* **Verdict**: `benign`
* **Telemetry**: 18/18 agents reporting (Coverage = 1.00)
* **Evidence Count**: 147 normalized items

### Case 2: Controlled Phishing Target
* **Target**: `https://www.fake-microsoft-verify.com/`
* **Risk Score**: $52.74\%$
* **Trust Score**: $47.26\%$
* **Verdict**: `suspicious`
* **Grounding Validation**: Validated ($0$ hallucinated IDs, strictly citing `E8-01`, `E9-01`, `E9-03`, `E10-01`)

*(Note: These reference cases demonstrate pipeline behavior and are distinct from full benchmark evaluation metrics).*

---

## 15. Independence Experiments Summary

| Experiment Dimension | Experimental Observation | Mathematical Impact |
| :--- | :--- | :--- |
| **Confidence Engine Independence** | Evaluated with CE enabled vs disabled | Risk, Trust, and Verdict remained identical ($0.0\%$ delta) |
| **AERE Independence** | Evaluated with AERE enabled vs disabled | Risk, Trust, and Verdict remained identical ($0.0\%$ delta) |
| **AERE Grounding Integrity** | Audited Evidence ID citations across runs | 0 fabricated Evidence IDs; 0 cross-session references |
| **Session Isolation** | Evaluated concurrent and sequential runs | 0 cross-session evidence or token leakage |
| **Persistence Integrity** | Repeated `POST /api/report` on completed sessions | 0 agent reruns; 0 finalize reruns; 0 evidence duplication |

---

## 16. Test 15 Final Audit Summary

* **Fresh Application Startup**: PASS (`HTTP 200`, blank URL input, clean dashboard)
* **Benign Live Analysis**: PASS (`https://www.microsoft.com/en-in` $\to$ Risk $0.0\%$, Verdict `benign`)
* **Controlled Phishing Analysis**: PASS (`fake-microsoft-verify.com` $\to$ Risk $52.74\%$, Verdict `suspicious`)
* **QR Regression**: PASS (All 9 scenarios: URL, Phish, Shortener, Multi-hop, WiFi, SMS, vCard, Text, Corrupt)
* **Report Persistence**: PASS (3 sequential requests $\to$ identical data, 0 agent reruns)
* **Session Reset & Isolation**: PASS (UUID isolation verified, 0 state leakage)
* **Frontend / Backend Consistency**: PASS (Exact 1:1 score and verdict alignment)
* **TCE Formula & Weight Freeze**: PASS (100% frozen parameters confirmed)
* **Confidence Engine Independence**: PASS (Zero feedback to scoring)
* **AERE Independence & Grounding**: PASS (Zero feedback to scoring, grounding validator active)
* **Security & SSRF Audit**: PASS (All private/loopback/cloud ranges blocked)
* **Benchmark Integrity**: PASS (Dataset and hashes confirmed unchanged and not rerun)
* **Full Regression Suite**: PASS (999/999 automated tests passing)
* **Architecture Integrity**: PASS (All 18 agents and pipeline boundaries verified)
* **Release Blockers**: **NONE**
* **Final Release Status**: **RELEASE READY**

---

## 17. Known Limitations

To maintain scientific integrity, the known boundaries of the MTAI-DF v1.0 prototype are explicitly stated:
1. **Passive/Static Forensic Scope**: The system emphasizes static, DOM, network, and heuristic forensics; it does not execute full dynamic binary sandboxing of downloaded executables.
2. **External Feed Availability**: Live reputation agents (A6, A13, A14) depend on external third-party API availability and rate limits. When feeds are offline, agents report partial telemetry without failing the entire pipeline.
3. **QR Image Quality**: QR decoding relies on OpenCV and PyZbar; severely distorted, low-resolution, or physically occluded QR codes may fail decode preprocessing.
4. **Natural-Language Grounding Nuances**: AERE grounding validation marks natural language syntheses containing un-indexed soft phrases as `UNCERTAIN` rather than `PASSED` to preserve conservative validation bounds.
5. **Partial Telemetry Under Network Partition**: When internet connectivity is restricted, agents dependent on external lookups yield `skipped` or `restricted` statuses, activating the TCE coverage gate.

---

## 18. Environment & Dependencies

* **Python Runtime**: Python 3.12+ (Validated on Python 3.12.3, Windows 64-bit)
* **Web Framework**: Flask $\ge$ 3.0.0
* **Network & DNS**: `requests` $\ge$ 2.31.0, `dnspython` $\ge$ 2.6.0, `idna` $\ge$ 3.7, `tldextract` $\ge$ 5.1.0
* **HTML & Parsing**: `beautifulsoup4` $\ge$ 4.12.0
* **Cryptography & Security**: `cryptography` $\ge$ 42.0.0
* **Image & QR Processing**: `Pillow` $\ge$ 10.0.0, `opencv-python` $\ge$ 4.8.0, `qrcode` $\ge$ 8.0.0, `numpy` $\ge$ 1.26.0
* **Natural Language & Linguistic Analysis**: `pyspellchecker` $\ge$ 0.8.0, `langdetect` $\ge$ 1.0.9, `phonenumbers` $\ge$ 8.13.0
* **Frontend Stack**: Vanilla HTML5, CSS3 (Glassmorphic dark design system), Vanilla JavaScript (Zero external JS framework dependencies)
* **Storage & Persistence**: In-memory session management with structured JSON report persistence.

---

## 19. Reproduction Rule

To reproduce the MTAI-DF v1.0 research results and benchmark metrics:
1. Use the frozen repository commit: `c16b776c645ff9b4cf2a0c50f5b3011e1cafbf4e`.
2. Use the frozen benchmark snapshot: `SNAP-a51ba6748b8e3064`.
3. Verify all three benchmark SHA-256 hashes against Section 12 before running experiments.
4. Use the frozen TCE configuration, weights, and verdict thresholds defined in Section 7.
5. Execute the documented experimental configuration using `python -m unittest discover -s tests`.
6. Do not modify the 18-agent evidence schemas, polarities, or reliability weights.
7. Do not substitute or alter the benchmark dataset records.
8. Do not mix experimental changes from future iterations with v1.0 results.
9. Clearly label any modified configuration as a new version or experimental variant.

---

## 20. Future Work Boundary

Future research extensions, agent additions, alternative LLM reasoning backends, or modified TCE parameterizations may be developed separately, but **must not overwrite the MTAI-DF v1.0 research baseline**.

Any future modification to:
* TCE scoring formulas, parameters, or thresholds
* Agent evidence semantics or taxonomy
* Common Evidence Schema definitions
* Benchmark dataset composition or hashes
* AERE or Confidence Engine architectures

must be documented under a new experimental configuration and release version (e.g., `v1.1` or `v2.0`).

---

## 21. Final Freeze Statement

**MTAI-DF v1.0 is the frozen final research prototype baseline.**

**The v1.0 core has passed Tests 1–15 and 999/999 automated regression tests with no release blockers.**

**The benchmark snapshot and hashes are frozen.**

**The TCE mathematical configuration is frozen.**

**The architecture and independence boundaries are frozen.**

**Future experiments must be versioned separately and must not overwrite this baseline.**
