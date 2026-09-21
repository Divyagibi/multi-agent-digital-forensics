# Step 6D-7 — Real Benchmark Data Collection & Acquisition Protocol Specification

**Milestone:** Step 6D-7  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Status:** Design & Specification Phase Only (Data Collection Protocol)  
**Implementation Boundary:** Protocol & Acquisition Specification Only — Zero Live Network Requests, Zero Real Data Harvesting, Zero Experiment Execution, Zero Model Tuning, Zero Production Modifications.

---

## 1. Purpose

This specification defines the rigorous, reproducible, auditable, legally compliant, and leakage-controlled protocol for acquiring the real-world benchmark dataset for empirical evaluation of the Multi-Agent Digital Forensics & Digital Trust Investigation System.

The objective is to establish an end-to-end data acquisition workflow that:
1. Identifies and formally approves external sources across malicious, benign, and QR modalities.
2. Acquires candidate artifacts while strictly preserving raw representations and complete provenance.
3. Enforces an impenetrable firewall between candidate harvesting, threat intelligence (TI) overlap tracking, independent ground truth, and internal forensic system analysis.
4. Executes deterministic passive liveness and technical eligibility verification without dynamic execution.
5. Captures independent external ground-truth evidence and structured multi-analyst adjudications.
6. Records point-in-time threat intelligence metadata across seven monitored feeds without converting feed presence into ground truth.
7. Performs identity-aware normalization, QR-to-direct cross-modal linking, deduplication tracking, and group-cluster leakage isolation.
8. Produces raw candidate pools that cleanly hand off into the frozen Step 6D-6 `DatasetAssembler` to obtain `READY_FOR_EXPERIMENT` pre-run gate certification.

---

## 2. Scope & Research Boundaries

### 2.1 In-Scope Acquisition Operations
* **Multi-Modal Harvesting:** Acquisition of web investigation targets across three frozen modalities:
  * `DIRECT_URL`: Direct web target URLs.
  * `QR_IMAGE`: High-resolution, static visual QR barcode image files.
  * `QR_PAYLOAD`: Decoded textual string payloads extracted from QR codes.
* **Approved Source Categorization:** Structured onboarding of candidate feeds, curated benign registries, authoritative incident archives, and research datasets.
* **Provenance & Raw Capture:** Complete retention of source references, harvest timestamps, first-seen timestamps, source record identifiers, and immutable raw content.
* **Passive Liveness Verification:** Offline or bounded passive HTTP retrieval ($\ge 100$ bytes raw body, TLS verification, bounded redirects) without browser automation or active exploitation.
* **Independent Ground-Truth Adjudication:** Systematic derivation of ground truth from $\ge 2$ independent agreeing sources or explicit analyst review, completely isolated from evaluated system outputs.
* **TI Provenance Recording:** Timestamped exposure stratification across the 7 reference feeds (`DIRECT`, `PARTIAL`, `NONE`, `UNKNOWN_UNAVAILABLE`).
* **Handoff to Step 6D-6:** Structured feeding of harvested candidates and verification artifacts to the frozen Step 6D-6 dataset assembly pipeline.

### 2.2 Explicit Prohibitions & Out-of-Scope Activities
* **Zero Live Experiment Execution:** No execution of Full System $M_0$, Baselines $A_0$–$A_4$, or Ablations $M_1$–$M_6$ during data collection.
* **Zero Self-Labeling / System Contamination:** Under no circumstances may system risk scores, trust scores, agent outputs (A1–A18), TCE scores, AERE explanations, or Confidence Engine outputs ($C_{ev}$) define or influence ground truth.
* **Zero Active Detonation / Exploitation:** No malware execution, dynamic sandbox detonation on live targets, vulnerability exploitation, credential submission, or browser automation against target sites.
* **Zero Artificial Class Balancing:** No synthetic generation or targeted over/undersampling to force arbitrary ratios (e.g., 50/50); natural prevalence is strictly preserved.
* **Zero Post-Hoc Data Selection:** Data collection stopping criteria must be established prior to collection and never altered based on observed model performance.
* **Zero Unauthorized Scrapes:** No evasion of rate limits, no bypassing of authentication barriers, and full compliance with terms of service and robots.txt policies.

---

## 3. Relationship to Frozen Methodology

The Step 6D-7 data acquisition protocol directly operationalizes the frozen benchmark pipeline established across Steps 6C and 6D-1 through 6D-6:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             BENCHMARK PIPELINE PROGRESSION                                  │
├─────────────────────────┬─────────────────────────┬─────────────────────────────────────────┤
│ Milestone               │ Frozen Checkpoint       │ Role in Step 6D-7 Data Collection       │
├─────────────────────────┼─────────────────────────┼─────────────────────────────────────────┤
│ Step 6C Tooling         │ Commit: 7df964f         │ Schemas, normalization, QR linking,     │
│                         │                         │ TI recorder, snapshots, manifest, audit │
│ Step 6D-1 Protocol      │ Commit: 7cf7b8a         │ Pre-registered hypotheses, variables,   │
│                         │                         │ partition targets (30/20/30/20)         │
│ Step 6D-2 Harvesting    │ Commit: 615980c         │ Source adapters, CandidateHarvester     │
│ Step 6D-3 Liveness      │ Commit: 28c3e16         │ LivenessEvaluator, >=100 B body rule    │
│ Step 6D-4 Ground Truth  │ Commit: 7cb7a52         │ GroundTruthVerifier, consensus rules    │
│ Step 6D-5 Evaluation    │ Commit: 0160ab0         │ Downstream consumer of locked dataset   │
│ Step 6D-6 Assembly Gate │ Commit: c16b776         │ DatasetAssembler, Pre-Run Gate check    │
│ Step 6D-7 (Current)     │ Specification Phase     │ Real benchmark data collection protocol │
└─────────────────────────┴─────────────────────────┴─────────────────────────────────────────┘
```

---

## 4. Source Approval Framework

Candidate sources must be vetted, documented, and categorized prior to ingestion. A source is **NOT** approved merely because it is publicly accessible.

### 4.1 Approved Source Catalog

| Source Identifier | Category | Input Modality | Primary Role | Access Method / Format | Licensing / Terms | Rate Limit / Polling Policy |
|---|---|---|---|---|---|---|
| `openphish_community` | Public Malicious Feed | `DIRECT_URL` | Candidate Source | Plaintext URL feed / JSON | Open access / attribution | Max 1 req / 6 hrs |
| `urlhaus_recent` | Public Malicious Feed | `DIRECT_URL` | Candidate Source | CSV / JSON export | CC0 / public API | Max 1 req / 10 min |
| `phishtank_verified` | Public Phishing Feed | `DIRECT_URL` | Candidate Source | Developer API / CSV | Developer terms / attribution | Max 1 req / 6 hrs |
| `tranco_top_curated` | Curated Benign Registry | `DIRECT_URL` | Candidate Source | CSV (Tranco Top 1M filtered) | Research open access | Static snapshot download |
| `cisco_umbrella_top` | Curated Benign Registry | `DIRECT_URL` | Candidate Source | CSV Top 1M list | Research open access | Static snapshot download |
| `gov_edu_curated` | Curated Benign Registry | `DIRECT_URL` | Candidate Source | Static curated list (.gov, .edu) | Public domain | Static snapshot |
| `kaggle_qr_phishing` | Research Dataset | `QR_IMAGE`, `QR_PAYLOAD` | Candidate Source | Image directory / CSV manifest | Open research license | Local archive |
| `synthetic_qr_testbed`| Research Dataset | `QR_IMAGE`, `QR_PAYLOAD` | Candidate Source | Generated QR images + ground truth | Research internal artifact | Static local archive |
| `authoritative_takedown`| Incident Records | `DIRECT_URL` | GT Evidence | Registrar / CERT takedown log | Research restricted | Adjudication reference |
| `virustotal_historical` | TI Exposure Feed | `DIRECT_URL` | TI Overlap Metadata | VT v3 REST API | API Terms of Service | Rate-limited API quota |
| `gsb_lookup` | TI Exposure Feed | `DIRECT_URL` | TI Overlap Metadata | Safe Browsing v4 API | API Terms of Service | Rate-limited API quota |
| `abuseipdb_check` | TI Exposure Feed | `DIRECT_URL` | TI Overlap Metadata | AbuseIPDB v2 API | API Terms of Service | Rate-limited API quota |
| `spamhaus_dbl` | TI Exposure Feed | `DIRECT_URL` | TI Overlap Metadata | DNSBL / JSON query | Research access terms | Rate-limited queries |

---

## 5. Source Role Firewall

To maintain unimpeachable scientific validity, every data source is strictly assigned to one or more formal roles, with strict separation between candidate generation, TI overlap observation, independent ground-truth verification, and system analysis.

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SOURCE ROLE FIREWALL                                        │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│  Candidate Sources:                                                                         │
│    OpenPhish, URLhaus, PhishTank, Tranco, Cisco Umbrella, QR Research Datasets               │
│    ROLE: Propose raw candidate targets and raw artifacts. Claims are PROVENANCE ONLY.       │
│                                                                                             │
│  Threat Intelligence Feeds:                                                                 │
│    VirusTotal, GSB, PhishTank, OpenPhish, URLhaus, AbuseIPDB, Spamhaus                       │
│    ROLE: Record point-in-time detection exposure (DIRECT, PARTIAL, NONE). NEVER Ground Truth.│
│                                                                                             │
│  Independent Ground-Truth Sources:                                                          │
│    Authoritative Registries, Verified Takedowns, Trusted Benign Curations, Human Analysts   │
│    ROLE: Assign verified benchmark labels via >=2 source consensus or human adjudication.   │
│                                                                                             │
│  ═════════════════════════════════════════════════════════════════════════════════════════  │
│  PROHIBITED SOURCES (GROUND-TRUTH FIREWALL VIOLATIONS):                                     │
│    - Trust & Credibility Engine (TCE)                                                       │
│    - Automated Evidence Reasoning Engine (AERE)                                             │
│    - Confidence Engine (C_ev)                                                               │
│    - Forensic Agents A1 through A18                                                         │
│    - System Final Verdicts / Risk Scores / Trust Scores                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Formal Separation Invariants
1. **Candidate Claims $\ne$ Ground Truth:** A candidate appearing on a malicious feed (e.g., URLhaus) records that claim in `CandidateProvenance`, but receives `PrimaryOutcome.MALICIOUS` **only** if independently corroborated by Step 6D-4 rules.
2. **TI Presence $\ne$ Ground Truth:** Threat intelligence feed hits represent detection exposure strata for answering RQ2 ($H_2$). Feeds are never automated ground-truth arbiters on their own.
3. **Internal Forensic Engine Independence:** The evaluated Multi-Agent System has zero authority over ground-truth labeling. Internal system diagnostics are rejected with `INTERNAL_SYSTEM_SOURCE_REJECTED`.

---

## 6. Planning Target, Natural Prevalence & Stopping Rules

### 6.1 Target Planning Range ($N \approx 1200$)
* The planning figure of $N \approx 1200$ candidates is a **methodological capacity estimate**, not a hard mathematical requirement.
* **Acceptable Benchmark Planning Range:** $N \in [800, 1500]$ unique, eligible, independently grounded investigation targets.
* **Minimum Usable Threshold:** $N \ge 300$ across all partitions to maintain statistical power for $H_1$–$H_6$ non-parametric hypothesis tests (Mann-Whitney $U$, Wilcoxon signed-rank, DeLong ROC-AUC).
* **Maximum Practical Ceiling:** $N = 2500$ to ensure complete manual auditability and analyst verification coverage.

### 6.2 Natural Prevalence Preservation
* **No Artificial Balancing:** The collection pipeline strictly prohibits synthetically manufacturing or discarding candidates to force arbitrary class prevalence (e.g., 50/50 malicious/benign).
* **Natural Class Distribution:** The dataset reflects the empirical prevalence resulting from approved collection streams.
* **Prevalence Documentation:** The raw collection prevalence, retained benchmark prevalence, and per-partition prevalence are explicitly reported in the assembly manifest.

### 6.3 Objective Stopping Criteria
Collection terminates when any of the following pre-established stopping conditions are met:
1. **Capacity Threshold:** Harvested eligible candidate pool reaches the target planning capacity ($N \approx 1200$ unique verified targets across modalities).
2. **Source Exhaustion:** All approved source feeds within the designated collection window have been completely harvested and processed.
3. **Temporal Cutoff:** The pre-registered collection time window (e.g., 14 calendar days) closes.
4. **Safety / Budget Limit:** External API quotas or liveness verification safety bounds reach predefined caps.

*Crucial Rule:* Collection stopping rules must **NEVER** be based on observed system detection accuracy, baseline performance, or model evaluation metrics.

---

## 7. Raw Artifact Preservation & Immutable Capture

Raw candidate inputs must be captured and stored verbatim before any normalization or transformation takes place.

### 7.1 Artifact Integrity Rules
* **Direct URLs (`DIRECT_URL`):** Retain exact string, casing, scheme, port, path, query parameters, fragments, and percent-encodings.
* **QR Images (`QR_IMAGE`):** Retain original image bytes, exact file format (PNG, JPG, WEBP), dimensions, SHA-256 hash, and acquisition source URI.
* **Decoded QR Payloads (`QR_PAYLOAD`):** Retain exact decoded payload string, character encoding, and decoder metadata.

### 7.2 Identity Derivation Hierarchy
Identity is established deterministically across three decoupled tiers:

$$\text{Artifact ID } (ART\text{-}) \longrightarrow \text{Target ID } (TGT\text{-}) \longrightarrow \text{Group ID } (GRP\text{-})$$

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 IDENTITY HIERARCHY                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Artifact ID (ART-<sha256[:16]>):                                                         │
│    Unique to the exact raw artifact string or image byte representation.                    │
│                                                                                             │
│ 2. Investigation Target ID (TGT-<sha256[:16]>):                                             │
│    Canonicalized investigation endpoint (scheme, host, port, functional path, query).      │
│                                                                                             │
│ 3. Group / Cluster ID (GRP-<sha256[:16]>):                                                  │
│    Broader domain / organizational grouping used for cross-partition leakage prevention.    │
│                                                                                             │
│ 4. Benchmark Record ID (REC-<sha256[:16]>):                                                 │
│    Unique identifier for the finalized benchmark record tuple in the locked dataset.        │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Provenance & Timestamp Recording Policy

Complete provenance tracking is required for every harvested candidate.

### 8.1 Required Provenance Fields
Each candidate record must capture:
* `source_name`: Standardized identifier of the approved source feed.
* `source_record_id`: Native record identifier from the source (e.g., URLhaus ID, PhishTank submission ID).
* `source_reference`: External URL, API endpoint, or file path where the record was acquired.
* `harvest_timestamp`: ISO 8601 UTC timestamp of harvesting execution.
* `first_observed_timestamp`: ISO 8601 UTC timestamp when the source first observed the target.
* `license_or_access_notes`: Explicit licensing, attribution, and terms-of-access notes.

### 8.2 Timestamp Policy & Missing Value Semantics
* **No Timestamp Fabrication:** If a source does not supply a first-observed timestamp, the field must remain empty string `""` (or `None`). It must **never** be backfilled with the harvest timestamp or fabricated.
* **Temporal Ordering for Partitions:** Candidates possessing validated `first_observed_timestamp` values are sorted chronologically to populate the `PROSPECTIVE_HOLDOUT` partition with the most recent 20% of data.
* **Missing Timestamp Handling:** Candidates lacking source timestamps are partitioned deterministically across `DEVELOPMENT_CALIBRATION`, `VALIDATION`, and `FINAL_TEST` using stable group-hash partitioning, but are ineligible for the prospective holdout.

---

## 9. Passive Liveness & Technical Eligibility Protocol

All web targets must undergo passive liveness evaluation according to the frozen Step 6D-3 standard.

### 9.1 Technical Eligibility Criteria
* **Raw HTTP Response Body:** $\ge 100$ bytes of content received.
* **TLS / SSL Validation:** Strict certificate verification enabled (no untrusted self-signed bypasses in automated collection).
* **Redirect Limits:** Maximum 5 HTTP redirects followed; complete redirect chain recorded.
* **Timeout Bounds:** Connection timeout 10.0s, read timeout 15.0s.
* **Response Size Cap:** Truncated after 5.0 MB to prevent resource exhaustion.
* **Non-Network Schemes:** Unsupported non-HTTP QR payload schemes (`mailto:`, `smsto:`, `wifi:`, `tel:`, `facetime:`, `geo:`) are marked as technically eligible non-network targets and handled safely without network polling.

### 9.2 Liveness Safety Invariants
* **Zero Active Interaction:** Zero form submission, zero credential entry, zero JavaScript execution, zero browser automation against untrusted targets.
* **Liveness Failure $\ne$ Benign:** An unreachable target (HTTP 404, 500, DNS NXDOMAIN, connection timeout) receives `liveness_status = FAILED` and is excluded from the active evaluation pool. It must **never** be labeled as `BENIGN`.

---

## 10. Independent Ground-Truth Verification Workflow

Ground truth must be assigned strictly through independent external evidence and human adjudication according to the frozen Step 6D-4 protocol.

### 10.1 Ground-Truth Derivation Rules
1. **Multi-Source Consensus:** $\ge 2$ independent, agreeing, approved verification sources (e.g., authoritative registry + confirmed CERT takedown) establish `VERIFIED` status with `HIGH` confidence.
2. **Single-Source Evidence:** A single uncorroborated external source produces `AMBIGUOUS` verification status or `MEDIUM`/`LOW` confidence.
3. **Disputed Claims:** Contradictory evidence across sources (e.g., one feed claims Malicious, another indicates Benign official domain) produces `DISPUTED` status.
4. **Analyst Human Adjudication:** Disputed or complex records may be resolved into `VERIFIED` ground truth **only** through an explicit `AdjudicationRecord` authored by a human forensic analyst citing verifiable evidence.
5. **Absence $\ne$ Benign:** The absence of threat listings across feeds does **NOT** establish a `BENIGN` label. Benign ground truth requires positive verification (e.g., authoritative domain registry, government directory, curated high-reputation domain).

### 10.2 Ground-Truth Confidence Semantics
* Verification confidence is strictly qualitative: `HIGH`, `MEDIUM`, `LOW`.
* Floating-point numbers, calibrated posterior probabilities, and model confidence scores are strictly prohibited.

---

## 11. Threat Intelligence Exposure Recording

Point-in-time observations across seven reference threat intelligence feeds are recorded strictly as evaluation metadata.

### 11.1 Monitored Feeds
1. `VirusTotal` (v3 API)
2. `GoogleSafeBrowsing` (v4 API)
3. `PhishTank` (API / Database dump)
4. `OpenPhish` (Community feed)
5. `URLhaus` (API / Database dump)
6. `AbuseIPDB` (v2 Check API)
7. `Spamhaus` (DBL / Zero-Reputation domain check)

### 11.2 Exposure Strata
* `DIRECT`: Exact matching URL/domain observation recorded in $\ge 1$ feed prior to the benchmark evaluation timestamp.
* `PARTIAL`: Related infrastructure, parent domain, or IP observation recorded, but no direct URL match.
* `NONE`: Zero positive threat listings recorded across all monitored feeds at the time of retrieval.
* `UNKNOWN_UNAVAILABLE`: Feed was unreachable, rate-limited, or unmonitored for the target.

*Invariant:* `NONE` and `UNKNOWN_UNAVAILABLE` signify absence of external feed detection; they do **NOT** imply that a target is benign.

---

## 12. QR & Direct Cross-Modal Relationship Linking

Cross-modal investigation targets must maintain explicit relational links across modalities while remaining distinct records.

### 12.1 Relationship Model
* `QR_IMAGE` $\longrightarrow$ decoded to $\longrightarrow$ `QR_PAYLOAD` $\longrightarrow$ normalized to $\longrightarrow$ canonical `TGT-`
* `DIRECT_URL` $\longrightarrow$ normalized to $\longrightarrow$ canonical `TGT-`
* If a `QR_IMAGE` or `QR_PAYLOAD` resolves to the same target URL as a `DIRECT_URL` candidate, both artifacts retain their unique `ART-` and `REC-` IDs, but are explicitly linked via `related_records` and `qr_metadata`.

### 12.2 Cross-Partition QR Leakage Rule
* A QR artifact and its corresponding direct URL artifact **MUST** be placed in the **SAME** evaluation partition.
* Cross-partition placement of linked QR and direct artifacts is a **CRITICAL** leakage violation that blocks the dataset.

---

## 13. Deterministic Partitioning & Leakage Prevention

Dataset partition assignment follows the pre-registered ratios defined in Step 6D-1:

| Evaluation Partition | Target Share | Eligibility Criteria | Exposure Allowed During Research |
|---|---|---|---|
| `DEVELOPMENT_CALIBRATION` | 30% | Random stratified cluster split | Open for hyperparameter calibration & baseline setup |
| `VALIDATION` | 20% | Random stratified cluster split | Model selection & ablation validation |
| `FINAL_TEST` | 30% | Random stratified cluster split | Locked: Evaluated once, zero tuning |
| `PROSPECTIVE_HOLDOUT` | 20% | Chronologically most recent 20% | Locked: Temporal generalization test, zero tuning |

### 13.1 Leakage Prevention Rules
1. **Target Leakage (`CROSS_PARTITION_TARGET_LEAKAGE`):** The exact same canonical target ID (`TGT-`) must never appear in multiple partitions.
2. **Group / Cluster Leakage (`CROSS_PARTITION_GROUP_LEAKAGE`):** Targets sharing the same base domain or organizational group ID (`GRP-`) are assigned to the same partition via group-cluster hashing.
3. **QR / Direct Leakage (`QR_DIRECT_CROSS_PARTITION_LEAKAGE`):** Linked QR artifacts and direct URL representations must never be split across partitions.
4. **Temporal Leakage (`TEMPORAL_LEAKAGE`):** No future information, future TI logs, or post-observation takedown notices may be utilized to evaluate historical candidates.

---

## 14. Availability Failures & Deterministic Error Handling

External feed outages, rate limits, and network anomalies must be handled deterministically without data corruption:

| Failure Scenario | Deterministic Protocol Action |
|---|---|
| Source feed unreachable / HTTP 5xx | Record `RetrievalStatus.UNAVAILABLE`, log diagnostic, retry with exponential backoff (max 3), skip if unresolvable. |
| API Rate Limit Exceeded | Record `RetrievalStatus.RATE_LIMITED`, pause execution for rate-limit reset window; do not forge empty results. |
| Malformed Feed Schema / Missing Fields | Record `RetrievalStatus.FAILED`, log schema parsing error, reject candidate with audit trace. |
| Liveness Timeout / Connection Refused | Record `LivenessStatus.FAILED`, retain candidate in raw pool, exclude from eligible benchmark evaluation set. |
| Ground Truth Unavailable / Uncorroborated | Mark `VerificationStatus.UNVERIFIABLE` / `AMBIGUOUS`; record remains eligible for ambiguity analysis or is excluded from primary metric scoring. |
| Target Domain Lacks Timestamps | Exclude candidate from `PROSPECTIVE_HOLDOUT`; allocate deterministically to development/validation/test partitions. |

---

## 15. Reproducibility & Audit Trail

To ensure scientific reproducibility, every data collection run must generate an immutable, self-contained audit archive.

### 15.1 Collection Archive Manifest (`collection_manifest.json`)
The collection archive must record:
* Collection Session ID (UUIDv4)
* UTC Start and End Timestamps
* Exact versions/hashes of all source adapters and harvest configurations
* Total candidates harvested, accepted, rejected, and deduplicated
* Breakdown by Modality (`DIRECT_URL`, `QR_IMAGE`, `QR_PAYLOAD`)
* Breakdown by Source Feed
* Ground-truth verification consensus statistics
* TI exposure distribution
* Cryptographic SHA-256 hash of all raw candidate files and intermediate artifacts

---

## 16. Legal, Safety & Privacy Boundaries

Data collection must strictly conform to cybersecurity research ethics, institutional guidelines, and legal standards.

### 16.1 Safety Mandates
* **No Active Telemetry:** Zero live exploit execution, zero form submission, zero automated interaction with authentication or payment portals.
* **Passive Traffic Only:** HTTP requests during liveness checking must present a standard research User-Agent header identifying the research project with contact information.
* **Rate-Limit Compliance:** Polling intervals must respect external feed API rate limits and terms of service.

### 16.2 Privacy & PII Protection
* **Target Minimization:** Data harvesting focuses strictly on threat infrastructure and public benign websites.
* **PII Redaction:** Any personal email addresses, phone numbers, or user tokens accidentally captured in URL query parameters or QR payloads must be scrubbed or masked in public research reports.
* **Research-Only Storage:** Raw forensic artifacts must be stored in access-controlled, encrypted local storage.

---

## 17. Quality Control & Step 6D-6 Handoff

Prior to transitioning the collected data into the experimental pipeline, the candidate pool must undergo automated quality verification.

### 17.1 Quality Control Checks
* **Schema Conformance:** 100% of candidate records must validate against `tools.benchmark.schemas`.
* **Identity Integrity:** All `ART-`, `TGT-`, `GRP-`, and `REC-` hashes must compute correctly and deterministically.
* **Provenance Completeness:** Every record must have an approved `source_name` and `harvest_timestamp`.
* **Zero Self-Contamination:** Automated scan confirms zero entries originating from internal forensic engines.

### 17.2 Clean Handoff to Step 6D-6 `DatasetAssembler`
```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             STEP 6D-7 TO STEP 6D-6 HANDOFF                                  │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                             │
│   Step 6D-7 Data Acquisition                                                                │
│   (Raw Candidates + Liveness Results + GT Adjudications + TI Overlaps)                      │
│                                │                                                            │
│                                ▼                                                            │
│   Step 6D-6 DatasetAssembler.assemble_dataset()                                             │
│   (Normalization, Linking, GT Attachment, Partitioning, Snapshot Generation)                │
│                                │                                                            │
│                                ▼                                                            │
│   Step 6D-6 DatasetAssembler.evaluate_gate()                                                │
│   (Integrity Audit, Leakage Verification, Pre-Run Gate Certification)                       │
│                                │                                                            │
│                                ▼                                                            │
│   READY_FOR_EXPERIMENT Status Achieved                                                      │
│                                                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 18. Final Collection Checklist

Before initiating real benchmark data collection, the research team must confirm:
- [ ] All source adapters are registered and tested with local mock inputs.
- [ ] Source API keys (if applicable) are configured with active rate-limiting handlers.
- [ ] Passive liveness bounds ($\ge 100$ B, TLS enabled, 5 redirects, 10s/15s timeouts) are active.
- [ ] Ground-truth verification sources ($\ge 2$ independent agreeing sources) are cataloged.
- [ ] Threat intelligence recording for all 7 feeds is configured as evaluation metadata only.
- [ ] Group-cluster leakage prevention rules are active.
- [ ] Pre-registered partition targets (30/20/30/20) are locked.
- [ ] Storage volume for raw QR images and candidate pools is initialized.
- [ ] Collection stopping criteria are registered.
- [ ] Final handoff target is set to the frozen Step 6D-6 `DatasetAssembler`.
