# Step 6D-6 — Experimental Dataset Assembly & Pre-Run Gate Specification

**Milestone:** Step 6D-6  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Status:** Frozen Design Specification (Dataset Assembly & Pre-Run Gate Only)  
**Implementation Boundary:** Design & Specification Only — No Dataset Harvesting, No Experiment Execution, No Model Tuning, No Production Modifications.

---

## 1. Purpose and Scope

This document specifies the canonical, reproducible, leakage-controlled, and independently grounded process that transforms the outputs of the frozen benchmark infrastructure (Steps 6C and 6D-1 through 6D-5) into the **Final Locked Experimental Dataset** and defines the **Pre-Run Gate** required before executing benchmark experiments.

### 1.1 In-Scope Objectives
* **Pipeline Synthesis:** Detail the deterministic, multi-stage pipeline connecting Candidate Harvesting (6D-2), Passive Liveness & Eligibility (6D-3), Ground-Truth Verification (6D-4), Target Normalization & QR Relationship Linking (6C-2/6C-3), TI Temporal Metadata Recording (6C-5), Leakage-Safe Partitioning (6D-1), Snapshot & Manifest Generation (6C-6), and Integrity Auditing (6C-7).
* **Ground-Truth & TI Firewalls:** Formally enforce that ground truth is derived strictly from independent external evidence and human adjudication, completely isolated from system outputs, with threat intelligence treated as provenance/overlap metadata rather than ground truth.
* **Leakage-Safe Partitioning & Identity Hierarchy:** Enforce three-tier identity segregation (`ART-`, `TGT-`, `GRP-`, `REC-`) across four evaluation partitions (`DEVELOPMENT_CALIBRATION`, `VALIDATION`, `FINAL_TEST`, `PROSPECTIVE_HOLDOUT`) with explicit isolation of QR/direct relationships.
* **Pre-Run Gate Criteria:** Define the deterministic quality gates for transitioning the dataset status to `READY_FOR_EXPERIMENT` or blocking it as `BLOCKED_FROM_EXPERIMENT`.

### 1.2 Out-of-Scope Constraints (Explicit Prohibitions)
* **No Experiment Execution:** Step 6D-6 does not execute full system $M_0$, baselines $A_0$–$A_4$, or ablations $M_1$–$M_6$.
* **No Post-Hoc Tuning:** Step 6D-6 does not tune TCE weights, non-linear parameters ($\kappa, \alpha, \beta$), Confidence Engine prior/thresholds ($C_{ev} \ge 35$), AERE prompts, LLM models, or baseline heuristics.
* **No Artificial Rebalancing:** Step 6D-6 does not manufacture synthetic records to achieve arbitrary class balance (50/50) or force the planned target size ($N \approx 1200$).
* **No Active Telemetry / Exploitation:** Step 6D-6 performs zero dynamic payload detonation, browser automation, form submission, or live network probing.
* **No Production Code Modification:** Production application code (`app.py`, `agents/*`, `services/*`, `templates/*`, `static/*`) remains completely untouched.

---

## 2. Relationship to Frozen Steps 6D-1 Through 6D-5

Step 6D-6 serves as the assembly and validation bridge that connects the previously frozen components:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             BENCHMARK PIPELINE PROGRESSION                                  │
├─────────────────────────┬─────────────────────────┬─────────────────────────────────────────┤
│ Milestone               │ Frozen Checkpoint       │ Role in Step 6D-6                       │
├─────────────────────────┼─────────────────────────┼─────────────────────────────────────────┤
│ Step 6C Tooling         │ Commit: 7df964f         │ Data schemas, normalization, QR links,  │
│                         │                         │ TI recorder, snapshots, manifest, audit │
│ Step 6D-1 Protocol      │ Commit: 7cf7b8a         │ Pre-registered research protocol, $H_1$–│
│                         │                         │ $H_6$, partitions, metric definitions    │
│ Step 6D-2 Harvesting    │ Commit: 615980c         │ Source adapters, raw candidate pool     │
│ Step 6D-3 Liveness      │ Commit: 28c3e16         │ Passive HTTP $\ge 100$ B eligibility    │
│ Step 6D-4 Ground Truth  │ Commit: 7cb7a52         │ Independent ground-truth verifier       │
│ Step 6D-5 Evaluation    │ Commit: 0160ab0         │ Downstream consumer of locked dataset   │
│ Step 6D-6 (Current)     │ Design Phase            │ Assembly pipeline & pre-run gate spec   │
└─────────────────────────┴─────────────────────────┴─────────────────────────────────────────┘
```

---

## 3. Input Artifacts and Dependencies

The dataset assembly process consumes the following raw and external input artifacts:

1. **Raw Harvested Candidates (`raw_candidates.jsonl`):**
   * Emitted by `tools/benchmark/harvester.py` from approved public repositories, research collections, benign directories, and QR image collections.
   * Format: Serialized `RawCandidate` objects with raw URL/payload strings, image filepaths, and harvest provenance.
2. **Passive Liveness Telemetry (`liveness_results.jsonl`):**
   * Emitted by `tools/benchmark/liveness.py` containing passive HTTP response byte counts, TLS validation states, redirect chains, and status codes.
3. **Independent Verification Records & Adjudication Logs (`ground_truth_adjudications.json`):**
   * External reference data and multi-analyst consensus logs structured as `VerificationEvidenceItem` and `AdjudicationRecord` objects.
4. **Controlled TI Overlap Observations (`ti_overlap_records.jsonl`):**
   * Controlled feed observations from the 7 monitored feeds (`VirusTotal`, `GoogleSafeBrowsing`, `PhishTank`, `OpenPhish`, `URLhaus`, `AbuseIPDB`, `Spamhaus`) with observation timestamps.
5. **Static QR Barcode Files (`data/raw_qr_images/`):**
   * High-resolution, passive QR image artifacts (`QR_IMAGE`) and decoded textual payload representations (`QR_PAYLOAD`).

---

## 4. End-to-End Dataset Assembly Pipeline

The assembly pipeline executes as a deterministic, multi-stage state machine:

```text
Stage 1: Ingestion & Raw Validation
  │ (Ingests RawCandidates from Step 6D-2)
  ▼
Stage 2: Passive Liveness & Technical Eligibility
  │ (Applies Step 6D-3 criteria: HTTP body >= 100B, TLS verification, safe non-network QR)
  ▼
Stage 3: Normalization & Identity Graph Construction
  │ (Applies Step 6C-2 normalization; derives ART-, TGT-, GRP-, REC- IDs)
  ▼
Stage 4: QR & Direct Cross-Modal Relationship Linking
  │ (Applies Step 6C-3; explicitly binds QR artifacts to canonical targets)
  ▼
Stage 5: Independent Ground-Truth Adjudication Attachment
  │ (Applies Step 6D-4 multi-source consensus; populates GroundTruth; isolates system)
  ▼
Stage 6: Threat Intelligence Provenance & Exposure Stratification
  │ (Applies Step 6C-5; assigns DIRECT, PARTIAL, NONE, UNKNOWN_UNAVAILABLE strata)
  ▼
Stage 7: Ambiguity Segregation & Exclusion Tracking
  │ (Identifies AMBIGUOUS/DISPUTED records; logs explicit exclusion reasons)
  ▼
Stage 8: Leakage-Safe Stratified Partition Assignment
  │ (Assigns 30/20/30/20 splits ensuring zero cross-partition TGT-/GRP-/QR leakage)
  ▼
Stage 9: Canonical Serialization & Cryptographic Snapshot Generation
  │ (Writes records.jsonl and manifest.json using deterministic UTF-8 serialization)
  ▼
Stage 10: Final Pre-Run Integrity Audit & Gate Verification
  │ (Executes Step 6C-7 IntegrityAuditor; issues READY_FOR_EXPERIMENT or BLOCKED)
  ▼
[LOCKED EXPERIMENTAL BENCHMARK SNAPSHOT]
```

---

## 5. Candidate Inclusion and Exclusion Rules

Every harvested candidate must undergo explicit, auditable filtering. Candidates are never discarded silently.

### 5.1 Inclusion Criteria
A candidate is retained in the canonical experimental dataset if and only if:
1. It possesses valid source provenance and retrieval timestamps.
2. It satisfies technical eligibility (passive liveness $\ge 100$ bytes for `DIRECT_URL` or valid static asset for `QR_IMAGE`/`QR_PAYLOAD`).
3. It normalizes to a valid investigation target identity (`TGT-<hash>`).
4. It is independently verified by external references (`VERIFIED`) or explicitly documented in the ambiguity pool (`AMBIGUOUS`).
5. It is assigned to a valid evaluation partition without cross-partition target or group leakage.

### 5.2 Exclusion Classification & Tracking
Excluded candidates are recorded in an auditable exclusion ledger with one of the following explicit reason codes:
* `EXCLUDED_LIVENESS_BODY_TOO_SMALL`: HTTP response body $< 100$ bytes.
* `EXCLUDED_LIVENESS_NETWORK_FAILURE`: Unreachable host, DNS failure, or connection timeout.
* `EXCLUDED_LIVENESS_TLS_FAILURE`: TLS certificate validation failed under default verification policy.
* `EXCLUDED_MALFORMED_URL`: String failed RFC 3986 / WHATWG canonical parsing.
* `EXCLUDED_UNSUPPORTED_SCHEME`: Non-HTTP scheme on a direct URL candidate (`javascript:`, `data:`, `file:`).
* `EXCLUDED_DUPLICATE_TARGET_WITHIN_SPLIT`: Redundant duplicate target within the same candidate source where deduplication policy mandates single representative entry.
* `EXCLUDED_UNRESOLVED_CONTRADICTION`: Conflicting external ground truth where multi-analyst adjudication was unavailable and ambiguity retention budget is exceeded.
* `EXCLUDED_PARTITION_LEAKAGE_CONFLICT`: Candidate could not be allocated to a partition without violating group-level or QR-pairing isolation constraints.

---

## 6. Liveness Eligibility Rules

Conforms strictly to the frozen Step 6D-3 specification:

1. **Direct Web URLs (`DIRECT_URL`):**
   * Must return raw HTTP response body $\ge 100$ bytes on passive HTTP GET/HEAD retrieval.
   * `verify_tls=True` enforced; TLS validation failures mark candidate as ineligible (`tls_status="failed"`).
   * Maximum redirect depth bounded to 3; full `redirect_chain` retained in `LivenessMetadata`.
   * HTTP error status codes (e.g. 404, 500) with bodies $\ge 100$ bytes remain technically eligible but are label-neutral.
2. **QR Barcode Images (`QR_IMAGE`):**
   * Static image files are classified as `LivenessStatus.NOT_APPLICABLE` and `EligibilityStatus.ELIGIBLE` with reason `NON_NETWORK_MODALITY`.
   * No network retrieval or dynamic barcode decoding is performed during the liveness phase.
3. **Decoded QR Payloads (`QR_PAYLOAD`):**
   * Non-network schemes (`mailto:`, `wifi:`, `smsto:`, `tel:`, `data:`, `intent:`) are safely classified as `LivenessStatus.NOT_APPLICABLE` and `EligibilityStatus.NOT_APPLICABLE` (`UNSUPPORTED_SCHEME`).
   * HTTP/HTTPS QR payloads are evaluated under standard HTTP liveness rules if evaluated as network targets.
4. **Liveness Firewall:**
   * Liveness failure or network timeout **NEVER** generates a `BENIGN` or `MALICIOUS` ground-truth label.
   * Liveness metadata is stored strictly in `BenchmarkRecord.liveness`.

---

## 7. Ground-Truth Attachment and Firewall

Conforms strictly to the frozen Step 6D-4 specification:

### 7.1 Ground-Truth Isolation Invariants
* **Zero System Contamination:** Under no circumstances may system verdicts, TCE risk scores, AERE reasoning outputs, Confidence Engine scores ($C_{ev}$), or investigator reports contribute to `BenchmarkRecord.ground_truth`.
* **Prohibited Source Detection:** Any verification source referencing `TCE`, `AERE`, `ConfidenceEngine`, `ReportGenerator`, or `Agent 1`..`Agent 18` is rejected automatically with finding code `INTERNAL_SYSTEM_SOURCE_REJECTED`.
* **Discrete Qualitative Confidence:** Ground-truth confidence must be strictly discrete (`HIGH`, `MEDIUM`, `LOW`). Floating-point probability representations are rejected by schema validators.

### 7.2 Multi-Source Consensus Rules
* **Verified Outcome (`VERIFIED`):** Requires $\ge 2$ independent, agreeing external sources (e.g. Authoritative Registry + Curated Threat Repository).
* **Single-Source Outcome:** An uncorroborated single source receives qualitative confidence `MEDIUM` or `LOW` and verification status `AMBIGUOUS` unless explicitly confirmed by multi-analyst adjudication.
* **Provider Independence:** Mirror feeds or multiple submissions to the same underlying vendor collapse into a single provider claim.

---

## 8. Ambiguity and Dispute Handling

1. **Ambiguity Preservation:** Candidates with conflicting independent evidence (e.g., source A indicates malicious, source B indicates benign) that cannot be resolved via authoritative registry/adjudication are assigned:
   * `primary_outcome = PrimaryOutcome.AMBIGUOUS`
   * `verification_status = VerificationStatus.DISPUTED`
2. **Ambiguity Pool Accounting:** Ambiguous records are retained in the benchmark dataset within the explicit Ambiguity Pool.
3. **Evaluation Exclusion Guarantee:** Downstream binary evaluation metrics in Step 6D-5 strictly exclude `AMBIGUOUS` records from binary confusion matrix calculations and report them explicitly in `excluded_ambiguous_count`.
4. **No Silent Benign Conversion:** Lack of conclusive malicious evidence never defaults to `BENIGN`.

---

## 9. Threat Intelligence Temporal Metadata Handling

Conforms strictly to Step 6C-5 (`ti_overlap_recorder.py`) and Step 6D-1:

### 9.1 Feed Recording & Non-Equivalence Principle
* For each candidate, presence or absence across the 7 monitored feeds (`VirusTotal`, `GoogleSafeBrowsing`, `PhishTank`, `OpenPhish`, `URLhaus`, `AbuseIPDB`, `Spamhaus`) is recorded with exact query timestamps.
* **Fundamental Invariant:**
  $$\text{TI Absence (NONE)} \not\equiv \text{Benign}, \quad \text{TI Absence} \not\equiv \text{Safe}, \quad \text{TI Absence} \not\equiv \text{Zero-Day}$$

### 9.2 Stratum Assignment
* `DIRECT`: Direct positive observation for the exact target URL/hash recorded prior to evaluation.
* `PARTIAL`: Positive observation recorded on the parent domain, IP address, or related infrastructure.
* `NONE`: Zero positive threat detections recorded across all monitored feeds at observation time.
* `UNKNOWN_UNAVAILABLE`: Monitored feeds were unreachable, rate-limited, or unqueried.

### 9.3 Temporal Anti-Leakage Rule
* TI queries must reflect feed state *at or prior to candidate harvest/observation timestamp*. Future TI detections (after observation cutoff) must not contaminate historical partitions.

---

## 10. Identity Hierarchy

The dataset strictly maintains the four-level identity architecture defined in Step 6C-1:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Artifact Identity (ART-<sha256[:16]>)                         │
│ - Hash of raw input representation (URL string, QR image bytes)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ normalizes to
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Investigation Target Identity (TGT-<sha256[:16]>)              │
│ - Hash of canonical normalized URL endpoint                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ clusters by
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Grouping / Leakage Identity (GRP-<sha256[:16]>)                │
│ - Hash of registered domain (eTLD+1) or IP /24 subnet                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ binds ART + TGT
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Composite Record Identity (REC-<sha256[:16]>)                          │
│ - Unique benchmark dataset row identifier                              │
└────────────────────────────────────────────────────────────────────────┘
```

* **Target vs. Group Distinction:** Distinct endpoints on the same registered domain (e.g. `https://example.com/login` vs `https://example.com/about`) have distinct `TGT-` identifiers but share a `GRP-` identifier. Target identities are never collapsed into domain identities.

---

## 11. Deduplication Policy

1. **Exact Artifact Duplication (`ART-`):** Identical raw artifacts from the same source within the same harvest batch are deduplicated, retaining the earliest observation timestamp.
2. **Multi-Source Ingestion:** When identical targets (`TGT-`) appear across multiple harvest feeds, a single canonical `BenchmarkRecord` is generated, with all contributing sources preserved in `CandidateProvenance.contributing_sources`.
3. **Cross-Modality Retention:** A direct URL artifact and a QR image artifact pointing to the same canonical target (`TGT-`) are **both retained** as separate records (`REC-01` and `REC-02`) with distinct artifact IDs (`ART-01` and `ART-02`) to enable cross-modal comparison ($H_4$).

---

## 12. QR and Direct Relationship Policy

Conforms strictly to Step 6C-3 (`qr_relationships.py`):

1. **Relationship Representation:** When a QR artifact decodes to an investigation target that is also present as a direct URL artifact, both records are populated with `QRRelationshipMetadata`:
   * `paired_record_id`: ID of the corresponding counterpart record.
   * `relationship_type`: `DIRECT_TO_QR`, `QR_TO_DIRECT`, or `SYNTHETIC_PAIR`.
   * `canonical_target_id`: Identical `TGT-<hash>` shared by both records.
2. **Co-Partitioning Invariant:** Paired QR and direct records pointing to the same canonical target **MUST be assigned to the same evaluation partition**. Placing a direct URL in `DEVELOPMENT_CALIBRATION` and its QR counterpart in `FINAL_TEST` triggers a critical leakage violation (`QR_DIRECT_CROSS_PARTITION_LEAKAGE`).

---

## 13. Partition Assignment Procedure

Dataset partition assignment executes according to the frozen four-way distribution:

```text
┌──────────────────────────────┬────────────────────────┬──────────────────────────────────────┐
│ Partition                    │ Target Proportion      │ Operational Role                     │
├──────────────────────────────┼────────────────────────┼──────────────────────────────────────┤
│ DEVELOPMENT_CALIBRATION      │ 30%                    │ Heuristic analysis, prompt review    │
│ VALIDATION                   │ 20%                    │ Intermediate verification            │
│ FINAL_TEST                   │ 30%                    │ One-shot final evaluation (Locked)   │
│ PROSPECTIVE_HOLDOUT          │ 20%                    │ Forward-in-time evaluation (Locked)  │
└──────────────────────────────┴────────────────────────┴──────────────────────────────────────┘
```

### 13.1 Assignment Algorithm
1. **Temporal Segregation:** Candidates harvested chronologically after the temporal cutoff timestamp are automatically segregated into `PROSPECTIVE_HOLDOUT`.
2. **Group-Level Cluster Allocation:** Remaining historical candidates are grouped by `GRP-<hash>` (eTLD+1 / subnet). All targets within a group cluster are assigned atomically to a single partition to minimize cross-partition infrastructure correlation.
3. **Stratification Constraints:** Group allocation algorithm balances:
   * Class ratio (`BENIGN` vs. `MALICIOUS`)
   * Modality distribution (`DIRECT_URL`, `QR_IMAGE`, `QR_PAYLOAD`)
   * Threat category representation across historical splits.

---

## 14. Temporal Holdout Procedure

1. **Cutoff Timestamp:** A strict, pre-registered timestamp $T_{\text{cutoff}}$ separates historical data from prospective data.
2. **Prospective Integrity:**
   * All records in `PROSPECTIVE_HOLDOUT` must have `first_observed_timestamp` $> T_{\text{cutoff}}$.
   * No prospective records may be viewed, calibrated against, or used for prompt/heuristic tuning.
3. **Evaluation Protocol:** Evaluator tests prospective records strictly out-of-sample to measure temporal detection decay ($H_2$).

---

## 15. Leakage Detection and Prevention

The dataset assembly layer integrates Step 6C-7 (`integrity_auditor.py`) to enforce zero tolerance for critical leakage:

| Leakage Dimension | Severity | Auditor Action | Pre-Run Gate Impact |
| :--- | :--- | :--- | :--- |
| `CROSS_PARTITION_TARGET_LEAKAGE` | `CRITICAL` | Same `TGT-` found in $>1$ partition | `BLOCKED_FROM_EXPERIMENT` |
| `QR_DIRECT_CROSS_PARTITION_LEAKAGE` | `CRITICAL` | Paired QR and Direct records in different partitions | `BLOCKED_FROM_EXPERIMENT` |
| `CROSS_PARTITION_GROUP_OVERLAP` | `WARNING` | Same `GRP-` found in $>1$ partition | Permitted if targets distinct; logged in manifest |
| `EXACT_ARTIFACT_DUPLICATE` | `WARNING` | Same `ART-` duplicated across records | Logged in manifest; reviewed by auditor |
| `PROSPECTIVE_CHRONOLOGY_VIOLATION` | `CRITICAL` | Holdout record timestamp $\le T_{\text{cutoff}}$ | `BLOCKED_FROM_EXPERIMENT` |

---

## 16. Snapshot Generation

Conforms strictly to Step 6C-6 (`snapshot_writer.py`):

1. **Artifact Structure:** A locked benchmark snapshot comprises:
   * `records.jsonl`: Line-delimited canonical JSON records, ordered deterministically by `record_id`.
   * `manifest.json`: Snapshot metadata, cryptographic hashes, partition counts, and audit logs.
2. **Directory Layout:**
   ```text
   data/snapshots/SNAP-<dataset_hash[:16]>/
   ├── records.jsonl
   └── manifest.json
   ```

---

## 17. Hash and Integrity Rules

Snapshot integrity is validated via the strict four-tier cryptographic hierarchy:

```text
Tier 1: Record SHA-256 Digest
  │ sha256(canonical_json(record)) for each record
  ▼
Tier 2: Records File Hash (records_file_hash)
  │ sha256(records.jsonl byte stream)
  ▼
Tier 3: Dataset Cryptographic Hash (dataset_hash)
  │ sha256(concatenated sorted record hashes)
  ▼
Tier 4: Manifest Hash (manifest_hash)
  │ sha256(canonical_json(manifest without manifest_hash field))
```

* **Deterministic Serialization:** Canonical JSON uses UTF-8 encoding, sorted keys, no trailing whitespace, and ASCII-safe string escaping (`separators=(',', ':')`).

---

## 18. Dataset Manifest Requirements

Conforms strictly to `BenchmarkManifest` in Step 6C-1:

The `manifest.json` file must record:
* `snapshot_id`: `SNAP-<dataset_hash[:16]>`
* `created_at`: ISO-8601 UTC timestamp
* `protocol_version`: `Step 6D-1 (Frozen)`
* `total_records`: Exact integer count of retained records
* `partition_counts`: Breakdown across the 4 partitions
* `modality_counts`: Breakdown across `DIRECT_URL`, `QR_IMAGE`, `QR_PAYLOAD`
* `ground_truth_counts`: Breakdown across `BENIGN`, `MALICIOUS`, `AMBIGUOUS`
* `threat_category_counts`: Breakdown across the secondary threat taxonomy
* `ti_exposure_counts`: Breakdown across `DIRECT`, `PARTIAL`, `NONE`, `UNKNOWN_UNAVAILABLE`
* `dataset_hash`: 64-character hex SHA-256 digest
* `records_file_hash`: 64-character hex SHA-256 digest
* `manifest_hash`: 64-character hex SHA-256 digest
* `integrity_audit_summary`: Findings summary from `IntegrityAuditor`

---

## 19. Dataset-Level Quality Gates

Before a snapshot is considered for evaluation, it must satisfy seven structural quality gates:

1. **Schema Conformity Gate:** 100% of records validate against `BenchmarkRecord` schema.
2. **Identity Integrity Gate:** 100% of records possess valid, correctly formatted `ART-`, `TGT-`, `GRP-`, and `REC-` hashes.
3. **Liveness Gate:** 100% of retained `DIRECT_URL` records meet the passive $\ge 100$ byte threshold.
4. **Ground-Truth Independence Gate:** Zero verification evidence items reference internal system components.
5. **Leakage Gate:** Zero critical target or cross-modal partition leaks.
6. **Temporal Gate:** 100% of `PROSPECTIVE_HOLDOUT` records strictly post-date $T_{\text{cutoff}}$.
7. **Cryptographic Consistency Gate:** Byte-level recomputation of all SHA-256 digests matches `manifest.json` exactly.

---

## 20. READY_FOR_EXPERIMENT Criteria

A benchmark dataset snapshot is designated **`READY_FOR_EXPERIMENT`** if and only if all of the following conditions are simultaneously satisfied:

* [x] Dataset is serialized as an immutable snapshot (`records.jsonl` + `manifest.json`).
* [x] Full test suite passes 100% of unit, schema, and auditor tests.
* [x] `IntegrityAuditor` reports **0 CRITICAL findings** and **0 ERROR findings**.
* [x] Any WARNING findings (e.g. group overlap) have documented justifications in the manifest.
* [x] All 4 partitions contain eligible records conforming to protocol requirements.
* [x] Independent ground truth is 100% populated with qualitative confidence (`HIGH`, `MEDIUM`, `LOW`).
* [x] `AMBIGUOUS` records are segregated in the Ambiguity Pool and tagged for binary metric exclusion.
* [x] Threat intelligence temporal exposure strata are fully populated without future leakage.
* [x] Cryptographic digests (`record_hash`, `records_file_hash`, `dataset_hash`, `manifest_hash`) re-verify with zero discrepancies.
* [x] No system parameter tuning has occurred against `FINAL_TEST` or `PROSPECTIVE_HOLDOUT`.

---

## 21. BLOCKED_FROM_EXPERIMENT Criteria

A dataset snapshot is immediately designated **`BLOCKED_FROM_EXPERIMENT`** if any of the following conditions exist:

* [ ] Any `CRITICAL` or `ERROR` audit finding emitted by `IntegrityAuditor`.
* [ ] Any record containing `CROSS_PARTITION_TARGET_LEAKAGE` ($>1$ partition for the same `TGT-`).
* [ ] Any record containing `QR_DIRECT_CROSS_PARTITION_LEAKAGE`.
* [ ] Any ground-truth evidence item derived from internal system components (`TCE`, `AERE`, `CE`, `Agents`).
* [ ] Any continuous float probability found in `ground_truth.confidence`.
* [ ] Any `PROSPECTIVE_HOLDOUT` candidate timestamped before $T_{\text{cutoff}}$.
* [ ] Any cryptographic hash mismatch between files and manifest.
* [ ] Incomplete or missing provenance attribution in any record.
* [ ] Evidence of post-hoc threshold or model tuning using test/holdout splits.

---

## 22. Reproducibility Requirements

1. **Deterministic Regeneration:** Given the identical input feeds and random seed, the assembly pipeline must output the identical byte-for-byte `records.jsonl` and `manifest.json` files.
2. **Stable Sorting:**
   * Records in `records.jsonl` are sorted lexicographically by `record_id`.
   * Finding lists in `manifest.json` are sorted by severity, finding code, and entity IDs.
3. **Environment Independence:** Tooling relies exclusively on Python standard library primitives for serialization to ensure cross-platform reproducibility across Windows, Linux, and macOS.

---

## 23. Safety and Legal Boundaries

1. **Passive Containment:** The assembly pipeline performs zero live payload execution, active vulnerability scanning, credential harvesting simulation, form submission, or exploit delivery.
2. **QR Scheme Safety:** Non-HTTP QR payload strings (`smsto:`, `tel:`, `wifi:`, `intent:`) remain inert text and are never passed to operating system URI dispatchers.
3. **Defanged Presentation:** In reports and logs, all malicious URLs and IP addresses are rendered defanged (`hxxps://`, `[.]`).

---

## 24. Failure Handling

1. **Harvest Ingestion Failures:** Network timeouts or malformed feed responses during candidate harvesting are logged in `SourceHarvestReport` and do not abort the pipeline; unavailable sources are flagged as `UNAVAILABLE`.
2. **Liveness Retrieval Failures:** Unreachable hosts or TLS failures mark candidates as `INELIGIBLE` without throwing unhandled exceptions.
3. **Integrity Violations:** Any detected critical integrity violation immediately halts the Pre-Run Gate and prevents snapshot locking.

---

## 25. Auditability and Logging

1. **Assembly Run Log:** Every assembly invocation produces a structured log recording input parameters, source hashes, processing duration, candidate throughput, and filtering tallies.
2. **Exclusion Ledger:** Complete machine-readable record of every discarded or filtered candidate with explicit failure codes.
3. **Manifest Traceability:** The final `manifest.json` embeds a full audit trail linking the snapshot back to source repository commits and harvest timestamps.

---

## 26. Reporting Requirements

The final dataset assembly report must output:
* **Candidate Funnel Summary:**
  * Raw candidates harvested ($N_{\text{raw}}$)
  * Candidates passing passive liveness ($N_{\text{live}}$)
  * Unique investigation targets after deduplication ($N_{\text{unique\_tgt}}$)
  * Ground-truth verified candidates ($N_{\text{verified}}$)
  * Disputed / Ambiguous candidates in pool ($N_{\text{ambiguous}}$)
  * Final retained benchmark records ($N_{\text{retained}}$)
* **Partition Breakdown:** Counts and percentages for `DEVELOPMENT_CALIBRATION`, `VALIDATION`, `FINAL_TEST`, and `PROSPECTIVE_HOLDOUT`.
* **Modality Breakdown:** Counts for `DIRECT_URL`, `QR_IMAGE`, `QR_PAYLOAD`.
* **TI Exposure Breakdown:** Counts for `DIRECT`, `PARTIAL`, `NONE`, `UNKNOWN_UNAVAILABLE`.
* **Integrity Audit Report:** Full finding counts from `IntegrityAuditor`.
* **Pre-Run Gate Status:** Final determination (`READY_FOR_EXPERIMENT` or `BLOCKED_FROM_EXPERIMENT`).

---

## 27. Exact Pre-Run Checklist

Before running experimental evaluations in Step 6D-5 on the assembled dataset, the researcher must verify:

```text
[ ] 1. Step 6D-1 experimental protocol is frozen and locked (Commit: 7cf7b8a).
[ ] 2. Step 6D-2 candidate harvesting is frozen and locked (Commit: 615980c).
[ ] 3. Step 6D-3 passive liveness & eligibility is frozen and locked (Commit: 28c3e16).
[ ] 4. Step 6D-4 independent ground-truth verification is frozen and locked (Commit: 7cb7a52).
[ ] 5. Step 6D-5 experimental evaluation engine is frozen and locked (Commit: 0160ab0).
[ ] 6. Assembly pipeline has executed cleanly without unhandled exceptions.
[ ] 7. records.jsonl and manifest.json are generated and cryptographically valid.
[ ] 8. IntegrityAuditor has executed and returned 0 CRITICAL and 0 ERROR findings.
[ ] 9. Ground-truth firewall is verified (0 internal system sources).
[ ] 10. Threat-intelligence firewall is verified (NONE != Benign).
[ ] 11. Zero cross-partition target leakage exists.
[ ] 12. Zero QR/direct cross-partition leakage exists.
[ ] 13. Prospective holdout data is strictly post-cutoff and untouched by calibration.
[ ] 14. Ambiguous records are segregated into the Ambiguity Pool.
[ ] 15. Pre-Run Gate status is officially declared: READY_FOR_EXPERIMENT.
```
