# Benchmark Tooling Specification: Schemas, Identity Model, & Deterministic Serialization

**Milestone:** Step 6C-1  
**Project:** Multi-Agent Digital Forensics & Digital Trust Investigation System  
**Status:** Implemented (Design Proposal & Specification)  

---

## 1. Executive Summary & Design Boundaries

This document defines the canonical **Benchmark Tooling Specification** for the experimental evaluation phase of the Multi-Agent Digital Forensics System. 

### Step 6C-1 Scope Boundary
* **Implemented in Step 6C-1:**
  * Canonical benchmark data model (`BenchmarkRecord`, `GroundTruth`, `CandidateProvenance`, `TIOverlapMetadata`, `LivenessMetadata`, `QRRelationshipMetadata`, `EvaluationMetadata`, `BenchmarkManifest`).
  * Three-tier cryptographic identity hierarchy (`ART-`, `TGT-`, `GRP-`) plus composite record identity (`REC-`).
  * Controlled vocabularies and enums (modality, threat taxonomy, verification status, qualitative confidence, TI feed status, evaluation partitions).
  * Deterministic serialization protocol and SHA-256 cryptographic digest calculation.
  * Structural schema validation rules.
  * Comprehensive unit tests in `tests/test_benchmark_tooling/test_benchmark_schemas.py`.
* **Explicitly Out of Scope (Deferred to Later Sub-stages):**
  * Candidate harvesting & ingestion (Step 6C-2).
  * URL normalization, deduplication, and eTLD+1 leakage auditing (Step 6C-2 & 6C-7).
  * QR decoding and image linking (Step 6C-3).
  * Ground-truth multi-analyst adjudication workflows (Step 6C-4).
  * Live Threat Intelligence feed polling (Step 6C-5).
  * Benchmark snapshot and manifest builder (Step 6C-6).
  * Experiment runner and evaluation pipeline (Step 6D).

---

## 2. Benchmark Schema vs. Production Forensic Evidence Distinction

A fundamental architectural principle of this system is the **strict segregation** between experimental benchmark records and production forensic evidence:

| Dimension | Production Forensic Evidence (`EvidenceSchema`) | Benchmark Dataset Record (`BenchmarkRecord`) |
| :--- | :--- | :--- |
| **Domain** | Internal investigation results from agents A1–A18. | External ground-truth evaluation metadata. |
| **Identifiers** | Evidence IDs (`E1-01`, `E2-01`, `E16-01`, etc.). | Deterministic entity IDs (`ART-`, `TGT-`, `GRP-`, `REC-`). |
| **Coupling** | Direct input to TCE, AERE, CE, and Report Generator. | Zero imports or couplings to production engines. |
| **Ground Truth** | System-inferred trust scores ($T \in [0, 100]$). | Human/consensus ground truth labels (`BENIGN`, `MALICIOUS`, `AMBIGUOUS`). |
| **Confidence** | TCE score confidence ($c_{composite} \in [0, 1]$). | Discrete qualitative adjudication strength (`HIGH`, `MEDIUM`, `LOW`). |

---

## 3. Three-Tier Identity Model

To prevent data leakage, preserve artifact-target relationships, and enable robust cross-split isolation, entity identifiers are structured across three distinct tiers:

```text
┌────────────────────────────────────────────────────────┐
│  Tier 1: Artifact Identity (ART-<sha256[:16]>)        │
│  - Exact observed raw artifact (URL string, QR image)   │
└──────────────────────────┬─────────────────────────────┘
                           │ decodes / normalizes to
                           ▼
┌────────────────────────────────────────────────────────┐
│  Tier 2: Investigation Target Identity (TGT-<sha256>) │
│  - Canonical normalized URL/target analyzed by agents │
└──────────────────────────┬─────────────────────────────┘
                           │ groups by eTLD+1 / IP
                           ▼
┌────────────────────────────────────────────────────────┐
│  Tier 3: Grouping / Leakage Identity (GRP-<sha256>)    │
│  - eTLD+1 domain / IP subnet for partition isolation   │
└────────────────────────────────────────────────────────┘
```

1. **Tier 1 — Artifact Identity (`ART-<hash>`):** Computed deterministically from `modality` and the exact raw content/bytes. Preserves whether an observation originated from a direct URL string, raw QR PNG image, or decoded QR payload.
2. **Tier 2 — Investigation Target Identity (`TGT-<hash>`):** Computed deterministically from the canonical normalized URL string (`https://bank.example.com/login`). Ensures different functional endpoints on the same domain retain distinct target identities.
3. **Tier 3 — Grouping / Leakage Identity (`GRP-<hash>`):** Computed deterministically from the registered domain (`eTLD+1`) or IP subnet. Used to enforce group-level partitioning and prevent near-duplicate leakage between calibration, validation, and test splits.
4. **Record Identity (`REC-<hash>`):** Deterministic composite hash combining `TGT-<hash>` and `ART-<hash>`.

---

## 4. Controlled Vocabularies & Ground-Truth Independence

### 4.1 Modality
* `DIRECT_URL`: Directly supplied web URL string.
* `QR_IMAGE`: Raw image file containing a QR code barcode.
* `QR_PAYLOAD`: Decoded payload extracted from a QR code artifact.

### 4.2 Primary Ground-Truth Outcomes
* `BENIGN`: Verified legitimate target.
* `MALICIOUS`: Verified malicious target matching one or more threat categories.
* `AMBIGUOUS`: Target whose maliciousness or legitimacy cannot be definitively established.

### 4.3 Secondary Threat Taxonomy (Step 6B)
* `CREDENTIAL_PHISHING`
* `BRAND_IMPERSONATION`
* `SCAM_FRAUD`
* `MALWARE_DISTRIBUTION`
* `DRIVE_BY_EXPLOIT`
* `TECH_SUPPORT_FRAUD`
* `QUISHING`
* `OTHER`

### 4.4 Verification Status & Qualitative Adjudication Confidence
* **Status:** `verified`, `ambiguous`, `disputed`, `unverifiable`, `unavailable`.
* **Confidence Policy:** Strictly discrete qualitative confidence (`HIGH`, `MEDIUM`, `LOW`). Float values (such as `1.0` or `0.95`) are explicitly rejected during schema validation. Verification confidence represents human/consensus adjudication certainty, not statistical or posterior probability.

---

## 5. Threat Intelligence (TI) Overlap Semantics

The benchmark schema tracks candidate presence across 7 threat intelligence feeds:
1. `VirusTotal`
2. `GoogleSafeBrowsing`
3. `PhishTank`
4. `OpenPhish`
5. `URLhaus`
6. `AbuseIPDB`
7. `Spamhaus`

### Critical Semantic Rules:
* **Negative Observation:** Status `negative_observation` indicates that a query was made and the target was not present on the blocklist. It **MUST NOT** be interpreted as "clean" or "benign".
* **Missing/Unavailable Observation:** Status `unavailable`, `unknown`, or `not_checked` reflects feed service status or lack of query. It **MUST NOT** be treated as a negative signal.
* **Separation from Ground Truth:** TI feed observations are experimental provenance data used to analyze overlap and coverage gaps. They do not constitute ground-truth labels.

---

## 6. Liveness & Passive Telemetry Semantics

The `LivenessMetadata` schema captures pre-investigation network availability:
* `http_status` (int, e.g. 200, 404)
* `dns_resolved` (bool)
* `tls_status` (str, e.g. "verified", "failed", "untested")
* `response_body_size_bytes` (int)
* `resolved_ip` (str)
* `redirect_chain` (list of str)
* `eligibility_status` (str)

**Semantic Guardrail:** HTTP 404 or TLS verification failure reflects transport state at observation time and does **NOT** determine whether a site is benign or malicious.

---

## 7. Deterministic Serialization & Hashing Protocol

To ensure reproducible benchmark dataset storage across platforms and runs, `canonicalize_record()` enforces the following deterministic serialization pipeline:

1. **Dataclass & Enum Conversion:** Enums are converted to their `.value` strings; dataclasses are recursively transformed into dictionaries.
2. **Alphabetical Key Sorting:** All dictionary keys at all nesting depths are sorted alphabetically (`sort_keys=True`).
3. **Separator Compaction:** Compact JSON separators `(`,`, `:`)` eliminate non-essential whitespace.
4. **UTF-8 Encoding:** Unicode characters are preserved via `ensure_ascii=False` (raw UTF-8).
5. **Float Normalization:** Floating-point fields are discouraged; if encountered, integers are formatted as `int` and floats are formatted with fixed non-trailing decimal notation.
6. **Trailing Newline:** Serialized record strings end with a single Unix newline (`\n`) for standard JSONL dataset parsing.
7. **Record Hashing:** `hash_canonical_record(record)` computes the cryptographic SHA-256 digest of the canonical UTF-8 bytes.

---

## 8. Structural Schema Validation

The `validate_benchmark_record()` function validates:
* Regex compliance of deterministic IDs (`REC-`, `ART-`, `TGT-`, `GRP-`).
* Membership in controlled enums.
* Disallowance of numeric/float confidence values.
* Reviewer count ($\ge 1$).
* QR modality and relationship metadata consistency.
* Partition and exclusion enum compliance.

---

## 9. Safety & Research Integrity Guarantees

1. **No External Network Activity:** Step 6C-1/6C-2 make zero network calls, DNS queries, or TI API requests.
2. **No Malware Execution:** No binary execution or live target detonation is performed.
3. **No Circular Evaluation:** Benchmark schemas do not read or depend on A1–A18 agent outputs or TCE scores.

---

## 10. Normalization, Deduplication, Grouping & Leakage Detection (Step 6C-2)

### 10.1 Investigation Target Normalization Principles
* **Scheme Policy:** Normalizes scheme to lowercase (`http`, `https`). Preserves `http` vs `https` as distinct investigation targets unless unified by experimental design.
* **Hostname & Port Normalization:** Lowercases hostnames and strips trailing dots (`example.com.` $\to$ `example.com`). Standard default ports (`:80` for http, `:443` for https) are stripped from target URLs; non-standard ports (e.g. `:8443`) are strictly preserved.
* **Path Normalization:** Resolves RFC 3986 dot segments (`/a/./b/../c` $\to$ `/a/c`) and collapses redundant slashes (`//` $\to$ `/`). Functional endpoint paths (`/login`, `/account`, `/download.apk`) are preserved as distinct targets.
* **Query Parameter Policy:** Deterministically sorts query parameters by key and value while preserving all parameters and token values. Different query parameters retain distinct target identities.
* **Fragment Policy:** Strips client-side fragments (`#section`) from the canonical URL for investigation target identity while storing them in the metadata `fragment` attribute.
* **IDN & Punycode:** Preserves Punycode domain representations (`xn--...`) without lossy conversions.

### 10.2 Distinct Concepts: Identity vs. Grouping vs. Deduplication vs. Leakage
1. **Artifact Identity (`ART-`):** Exactly identical observed input string or image bytes.
2. **Investigation Target Identity (`TGT-`):** Canonical normalized URL.
3. **Grouping / Leakage Identity (`GRP-`):** Registered domain (`eTLD+1`) or IP subnet (`/24` for IPv4, `/48` for IPv6).
4. **Duplicate Classification:**
   * `EXACT_ARTIFACT`: Same artifact ID.
   * `SAME_TARGET`: Distinct artifacts resolving to the identical target ID (e.g., QR payload vs direct URL).
   * `SAME_GROUP`: Distinct targets residing within the same registered domain or subnet.
   * `DISTINCT`: Completely separate entities.
5. **Cross-Split Leakage Detection (`detect_cross_split_leakage`):** Identifies target-level or group-level overlap across differing experimental partitions (e.g., `development_calibration` vs `final_test`).

### 10.3 Loss-Minimization & Ground-Truth Independence
* **No Silent Deletion:** `deduplicate_records()` retains all input records in `retained_records` while producing full diagnostic clusters.
* **Label Independence:** Changing ground-truth classifications (`BENIGN` $\to$ `MALICIOUS`) or Threat Intelligence feed observations never alters target normalization, target IDs, group IDs, or duplicate relationships.

---

## 11. QR / Direct URL Relationship Handling (Step 6C-3)

### 11.1 QR Semantics & Modality Preservation
* **Modality Invariant:** A record with `InputModality.QR_PAYLOAD` retains its modality and distinct `ART-<hash>` artifact identity even when its payload is an HTTP URL identical to a `DIRECT_URL` record.
* **No Image Decoding in Step 6C-3:** Operates on already-supplied text payloads. Records with `InputModality.QR_IMAGE` and no decoded payload resolve to `UNRESOLVED_IMAGE`.

### 11.2 Target Resolution
* **Web Payloads:** If the QR payload is an HTTP(S) URL, it is normalized via canonical Step 6C-2 `normalize_investigation_target()`, yielding identical target identity (`TGT-<hash>`) and grouping identity (`GRP-<hash>`) as a corresponding direct URL.
* **Non-Web Payloads:** Payloads using non-HTTP schemes (`smsto:`, `mailto:`, `intent:`, `wifi:`, or plain text) are classified as `NON_URL_PAYLOAD` with `is_http_url=False` and `resolved_target_id=None`. They are not executed, transformed into HTTP requests, or assigned synthetic classifications.

### 11.3 Pairwise QR / Direct Relationship Types
Implemented in `analyze_qr_direct_relationship()`:
1. `QR_DIRECT_SAME_TARGET`: QR payload and direct URL resolve to the identical normalized target (`same_target=True`, `same_artifact=False`).
2. `QR_DIRECT_SAME_GROUP`: QR payload and direct URL resolve to different endpoints/paths within the same registered domain or IP subnet (`same_target=False`, `same_group=True`).
3. `QR_DIRECT_DIFFERENT_TARGET`: QR payload and direct URL point to disjoint targets and domains (`same_target=False`, `same_group=False`).
4. `QR_IMAGE_UNRESOLVED`: QR image artifact has no decoded payload for target comparison.
5. `QR_NON_URL_PAYLOAD`: QR payload is a non-web scheme or plain text.

### 11.4 Cross-Split Leakage Exposure
* Exposes `is_cross_split_leakage=True` if a QR record and Direct URL record share a target or registered domain across distinct partitions (e.g. `development_calibration` vs `final_test`) without deciding retention or exclusion.

---

## 12. Independent Ground-Truth Verification (Step 6C-4)

### 12.1 Independent Verification Principle
* **Strict Evaluation Segregation:** The benchmark ground truth is strictly independent of the forensic system being evaluated. System outputs (TCE scores, AERE reasoning answers, Confidence Engine metrics, or Final Investigator Reports) are explicitly rejected as verification evidence and **CANNOT** define or overwrite ground truth.
* **Absence != Benign:** The absence of a target from threat intelligence feeds or blocklists does not establish a `BENIGN` classification. Uncorroborated records remain `AMBIGUOUS` with status `UNVERIFIABLE` in the ambiguity pool.

### 12.2 Verification Outcomes & Taxonomy
* **Primary Outcomes:** `BENIGN`, `MALICIOUS`, `AMBIGUOUS`.
* **Secondary Threat Taxonomy:** `CREDENTIAL_PHISHING`, `BRAND_IMPERSONATION`, `SCAM_FRAUD`, `MALWARE_DISTRIBUTION`, `DRIVE_BY_EXPLOIT`, `TECH_SUPPORT_FRAUD`, `QUISHING`, `OTHER`.
* **Verification Status:** `VERIFIED`, `AMBIGUOUS`, `DISPUTED`, `UNVERIFIABLE`, `UNAVAILABLE`.
* **Qualitative Confidence:** Strictly qualitative discrete values (`HIGH`, `MEDIUM`, `LOW`); continuous probability numbers are prohibited.

### 12.3 Multi-Source Corroboration & Adjudication Flow
1. **Multi-Source Corroboration:** $\ge 2$ independent authoritative sources in consensus produce `VERIFIED` status with `HIGH` confidence.
2. **Conflicting Evidence:** If sources simultaneously assert `MALICIOUS` and `BENIGN`, status is marked `DISPUTED` and outcome remains `AMBIGUOUS`.
3. **Analyst Adjudication:** An explicit `AdjudicationRecord` by human reviewers resolves disputes and assigns canonical ground truth with complete audit rationale.
4. **Identity & Partition Preservation:** Attaching verified ground truth preserves `record_id`, `artifact_id`, `target_id`, `evaluation.group_id`, and `evaluation.temporal_partition`.

---

## 13. Threat Intelligence (TI) Overlap Metadata Recording (Step 6C-5)

### 13.1 Seven Supported Monitored Feeds
The benchmark schema explicitly records exposure across exactly seven named threat intelligence feeds:
1. `VirusTotal`
2. `GoogleSafeBrowsing`
3. `PhishTank`
4. `OpenPhish`
5. `URLhaus`
6. `AbuseIPDB`
7. `Spamhaus`

### 13.2 Observation Status Semantics
* `NONE` (`negative_observation`): No positive detection was retrieved from this monitored source at the observation time. (Strictly does **NOT** mean clean, safe, or benign).
* `DIRECT` (`positive_observation`): Target was positively and directly reported in the specified source with supporting provenance.
* `PARTIAL`: Target or related infrastructure was observed in monitored feed data without exact direct source confirmation.
* `UNKNOWN_UNAVAILABLE`: Source query failed, timed out, or source was unmonitored at observation time.

### 13.3 Temporal Metadata & Exposure Tracking
* `first_feed_seen_at`: Earliest known observation in monitored feed history (used for temporal leakage auditing).
* `observation_time`: Point-in-time when benchmark collection process queried or observed the feed state.
* `retrieved_at`: Timestamp when the observation was extracted into the benchmark storage.
* **No "Zero-Day" Claim:** The tooling exposes factual lack of positive detections (`feed_count_positive = 0`) without fabricating universal claims of globally undiscovered threats.

### 13.4 Target Attachment & Ground-Truth Independence
* Attached directly to canonical `target_id` (so QR and Direct URL records pointing to the same normalized target share consistent target-level TI metadata while preserving distinct `artifact_id` values).
* Modifying TI metadata never alters `GroundTruth.primary_outcome`, `VerificationStatus`, or `evaluation.temporal_partition`.

---

## 14. Reproducible Benchmark Snapshot & Manifest (Step 6C-6)

### 14.1 Purpose & Integrity Boundaries
* **Reproducibility Guarantee:** Provides cryptographic integrity verification for freezing benchmark records prior to experimental execution.
* **Integrity Hashing:** SHA-256 is used to detect modifications to serialized benchmark records and manifests; it is not presented as proof that underlying external labels are truthful.
* **Non-Interference:** The snapshot layer does not create, modify, or infer ground truth or risk scores.

### 14.2 Snapshot File Structure
```text
benchmark_snapshot/
    records.jsonl   # Canonical line-delimited UTF-8 JSON records (ordered by record_id ascending)
    manifest.json   # Deterministic manifest containing record hash index and dataset integrity hashes
```

### 14.3 Cryptographic Hashing Hierarchy
1. **Record Hash (`record_hash`):** SHA-256 digest computed over the canonical UTF-8 serialized `BenchmarkRecord` string (with trailing `\n`).
2. **Records File Hash (`records_file_hash`):** Hexadecimal SHA-256 digest computed over the exact byte stream of `records.jsonl`.
3. **Dataset Integrity Hash (`dataset_hash`):** Deterministic SHA-256 digest computed over all newline-joined `record_hash`es in canonical order:
   $$\text{dataset\_hash} = \text{SHA-256}(\text{record\_hash}_1 \parallel \text{"\\n"} \parallel \dots \parallel \text{record\_hash}_n \parallel \text{"\\n"})$$
4. **Manifest Hash (`manifest_hash`):** SHA-256 digest computed over the canonical serialized JSON of `manifest.json` sans the `manifest_hash` key (eliminating circular self-inclusion).
5. **Snapshot Identifier (`snapshot_id`):** Derived deterministically as `SNAP-<dataset_hash[:16]>`.

### 14.4 Invariance & Determinism
* **Input-Order Independence:** Shuffling input record arrays (`[A, B, C]` vs `[C, A, B]`) produces identical canonical record ordering and identical dataset hashes.
* **Path & Environment Independence:** Snapshot contents, manifests, and hashes are completely independent of local directory paths, operating systems, and clock time.

---

## 15. Cross-Split Leakage, Temporal Exposure, Identity, and Snapshot Integrity Audit (Step 6C-7)

### 15.1 Objective & Foundational Principles
The benchmark integrity audit layer provides an independent, offline diagnostic engine designed to verify the structural, identity, temporal, and cryptographic integrity of benchmark datasets and frozen snapshot releases.

> **Methodological Mandate:**
> The audit identifies structural, temporal, identity, and snapshot-integrity conditions that may affect benchmark validity. It does not create or modify ground truth and does not automatically remove or repair records.
>
> Threat-intelligence exposure is recorded as provenance metadata. Absence of a positive observation does not establish benignity or universal zero-day status.

### 15.2 Audit Scope & Diagnostic Categories
The auditor evaluates four primary categories of potential anomalies:

1. **Identity & Duplication Integrity:**
   * `DUPLICATE_RECORD_ID` (`CRITICAL`): Duplicate `record_id` strings across multiple records.
   * `EXACT_ARTIFACT_DUPLICATE` (`WARNING`): Multiple records sharing identical `artifact_id` and raw observed artifact bytes.
   * `SAME_TARGET_SAME_PARTITION` (`INFO`): Multiple records pointing to the same normalized target within the same temporal partition.
   * `TARGET_ID_CONTENT_CONFLICT` (`ERROR`): Identical `target_id` associated with conflicting canonical target information.

2. **Cross-Partition Leakage:**
   * `CROSS_PARTITION_TARGET_LEAKAGE` (`CRITICAL`): Identical canonical `target_id` occurring across distinct evaluation partitions (e.g. `development_calibration` and `final_test`).
   * `CROSS_PARTITION_GROUP_OVERLAP` (`WARNING`): Distinct targets sharing the same `group_id` (registered domain eTLD+1 or IP subnet) present in different partitions.
   * `QR_DIRECT_CROSS_PARTITION_LEAKAGE` (`CRITICAL`): A QR artifact and a Direct URL artifact share the same canonical `target_id` but reside in different evaluation partitions.
   * `QR_DIRECT_SAME_TARGET_SAME_PARTITION` (`INFO`): A QR artifact and a Direct URL artifact share a target within the same partition.
   * `AMBIGUOUS_OR_UNRESOLVED_INPUT` (`INFO`): QR images without decodable payloads preserved as ambiguous inputs.

3. **Temporal TI Exposure & Provenance Consistency:**
   * `PRIOR_RECORDED_TI_EXPOSURE` (`INFO`): Earliest documented TI feed observation (`first_feed_seen_at`) precedes the benchmark observation point or evaluation cutoff.
   * `TEMPORAL_METADATA_INCONSISTENCY` (`ERROR`): Chronological contradictions (e.g. `first_feed_seen_at > observation_time`, `retrieved_at < observation_time`, or invalid ISO-8601 formatting).
   * **Semantic Preservation:** `NONE` is strictly distinct from `UNKNOWN_UNAVAILABLE`, and `NONE` does not define benignity or zero-day status.

4. **Cryptographic Snapshot & Manifest Integrity:**
   * `SNAPSHOT_FILE_HASH_MISMATCH` (`CRITICAL`): SHA-256 digest of `records.jsonl` does not match `manifest.records_file_hash`.
   * `DATASET_HASH_MISMATCH` (`CRITICAL`): Recomputed dataset-level cryptographic hash does not match `manifest.dataset_hash`.
   * `MANIFEST_HASH_MISMATCH` (`CRITICAL`): Recomputed manifest non-circular hash does not match `manifest.manifest_hash`.
   * `RECORD_HASH_MISMATCH` (`CRITICAL`): Recomputed individual record SHA-256 does not match the manifest index.
   * `RECORD_COUNT_MISMATCH` (`CRITICAL`): Line count of `records.jsonl` does not match `manifest.record_count`.
   * `MANIFEST_MISSING_RECORD` (`CRITICAL`): Record in dataset missing from manifest record index.
   * `MANIFEST_UNEXPECTED_RECORD` (`CRITICAL`): Record listed in manifest index missing from dataset.
   * `PARTITION_COUNT_MISMATCH` (`ERROR`): Distribution of partition counts does not match manifest.
   * `MODALITY_COUNT_MISMATCH` (`ERROR`): Distribution of modality counts does not match manifest.
   * `GROUND_TRUTH_COUNT_MISMATCH` (`ERROR`): Distribution of ground-truth counts does not match manifest.
   * `TI_EXPOSURE_COUNT_MISMATCH` (`ERROR`): Summary of TI exposure counts does not match manifest.

### 15.3 Controlled Severities and Statuses
* **Finding Severities:** `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
* **Overall Status:**
  * `PASS`: No violations or only informational observations detected.
  * `PASS_WITH_WARNINGS`: Diagnostic conditions present (e.g., cross-partition group overlaps or artifact duplicates) requiring experimental protocol review, but without cryptographic corruption or target leakage into protected partitions.
  * `FAIL`: Cryptographic hash mismatch, corrupted record schema, duplicate record IDs, or cross-split target leakage detected.

### 15.4 Deterministic Finding Ordering & Immutability
* **Stable Sort Key:** Findings are deterministically sorted by severity rank (`CRITICAL` $\rightarrow$ `ERROR` $\rightarrow$ `WARNING` $\rightarrow$ `INFO`), finding code, sorted `record_ids`, sorted `target_ids`, sorted `group_ids`, sorted `partitions`, and message.
* **Input-Order Independence:** Permutations of record collections produce identical finding sets in identical order.
* **No Automatic Repair:** The auditor never mutates input records, partitions, labels, or manifest files.
* **Offline Boundary:** Zero network access, zero production pipeline imports.

---

## 16. Candidate Harvesting & Raw Candidate Pool (Step 6D-2)

### 16.1 Objective & Methodological Firewalls
The candidate harvesting layer (`tools/benchmark/harvester.py`) aggregates raw potential benchmark inputs from approved, documented sources (public malicious feeds, phishing datasets, research collections, benign curated lists, and static QR image archives).

* **Ground-Truth Firewall:** The harvester gathers raw inputs and preserves source claims as descriptive metadata. It **NEVER** assigns `BENIGN` or `MALICIOUS` ground-truth labels, which are strictly owned by Step 6D-4 independent verification.
* **Production Segregation:** Zero imports or dependencies on TCE, AERE, Confidence Engine, or Agents A1–A18.
* **Loss-Minimizing Provenance:** Candidates across all sources are retained with complete source attribution (`source_name`, `source_record_id`, `source_reference`, `first_observed_timestamp`, `harvest_timestamp`). Exact duplicates across sources are counted in diagnostics but preserved in the raw pool.
* **Raw Artifact Preservation:** Raw observed URLs (with casing, ports, queries, and fragments intact), QR image paths, and raw barcode payload text are preserved verbatim without premature canonicalization.
* **Research Safety:** Operates passively without dynamic browser automation, JavaScript execution, login attempts, or local malware detonation. Non-HTTP schemes (`mailto:`, `wifi:`, `smsto:`, `intent:`) are stored as passive text.

### 16.2 Source Adapter Architecture
* `BaseSourceAdapter`: Abstract interface defining uniform `harvest(source_input) -> Tuple[List[RawCandidate], SourceHarvestReport]`.
* `TextListFeedAdapter`: Ingests newline-delimited URL or payload feeds.
* `JSONFeedAdapter`: Ingests JSON arrays and JSONL feeds with customizable schema field mapping.
* `CSVFeedAdapter`: Ingests tabular CSV data with customizable column mapping.
* `QRImageSourceAdapter`: Ingests directories or manifests of static QR barcode image files (`QR_IMAGE`).
* `QRPayloadSourceAdapter`: Ingests extracted text payloads (`QR_PAYLOAD`).
* `CustomSourceAdapter`: Wraps custom parsing callables.
* `CandidateHarvester`: Orchestrator managing multiple adapters, tracking source availability/errors, and aggregating `HarvestingResult`.

---

## 17. Passive Liveness & Candidate Eligibility (Step 6D-3)

### 17.1 Purpose & Methodological Guarantees
The passive liveness and candidate eligibility layer (`tools/benchmark/liveness.py`) deterministically evaluates harvested candidate inputs to determine whether they meet the technical criteria for downstream benchmark processing.

> **CRITICAL METHODOLOGICAL MANDATES:**
> 1. **Liveness/eligibility is not ground truth.**
> 2. **HTTP availability or response-body size must not be interpreted as benign or malicious ground truth.**
> 3. HTTP 200 $\neq$ Benign; HTTP 404 $\neq$ Malicious; HTTP 500 $\neq$ Malicious; Timeout $\neq$ Benign; Empty body $\neq$ Malicious.
> 4. Threat-feed presence or absence must NEVER be consulted during liveness evaluation.
> 5. Zero ground-truth labels (`PrimaryOutcome.BENIGN`, `PrimaryOutcome.MALICIOUS`, `PrimaryOutcome.AMBIGUOUS`) are assigned in this stage.

### 17.2 Liveness Criterion ($\ge 100$ Bytes Raw Body)
For `DIRECT_URL` candidates:
* **Passive HTTP/HTTPS Retrieval:** Evaluated using bounded HTTP GET/HEAD streaming.
* **Criterion:** A candidate is deemed `LIVE` and `ELIGIBLE` if the raw HTTP response body contains at least **100 bytes** ($\ge 100$ bytes).
* **Body $< 100$ Bytes:** Classified as `NOT_LIVE` and `INELIGIBLE` (`BODY_BELOW_THRESHOLD` or `EMPTY_BODY`). Crucially, a response body below 100 bytes does **not** become malicious.
* **Status Code Independence:** Status codes (e.g. 200, 404, 500) are recorded purely as telemetry; an HTTP 404 or 500 response with $\ge 100$ bytes satisfies the liveness byte criterion while remaining label-agnostic.

### 17.3 Transport, TLS, and Network Safety
* **Default TLS Verification:** TLS certificate validation is enabled by default (`verify_tls=True`). Certificate validation failures are recorded as `TLS_VERIFICATION_FAILED` (`tls_status="failed"`). No silent fallback to unverified TLS or automatic insecure retries is permitted.
* **Bounded Redirects:** Follows a bounded redirect policy (default `max_redirects=3`). Complete redirect histories are recorded (`redirect_chain`) without collapsing or mutating the original candidate artifact identity.
* **Bounded Resources:** Network operations enforce strict socket timeouts (default 5.0s) and bounded response stream consumption (default 1 MB max read) to prevent resource exhaustion.
* **Passive Only:** Zero headless browser automation, zero JavaScript execution, zero DOM rendering, zero form submission, zero port scanning, zero vulnerability probing, and zero crawling.

### 17.4 Modality Handling & Scheme Safety
* **`QR_IMAGE` Modality:** Static image files represent passive artifacts. The liveness layer does **not** decode QR barcodes or execute payloads. Assigned `LivenessStatus.NOT_APPLICABLE` and `EligibilityStatus.ELIGIBLE` with reason `NON_NETWORK_MODALITY`.
* **`QR_PAYLOAD` Modality:** Static payload strings. Non-HTTP schemes (`mailto:`, `smsto:`, `tel:`, `wifi:`, `data:`, `javascript:`, `file:`, `intent:`) are safely classified as `LivenessStatus.NOT_APPLICABLE` and `EligibilityStatus.NOT_APPLICABLE` with `UNSUPPORTED_SCHEME`. Zero OS handler invocations, zero URI launching, and zero dynamic execution.
* **HTTP/HTTPS QR Payloads:** Preserved as static target URLs for downstream stages without active browser detonation.

### 17.5 Controlled Vocabularies & Serialization
* `LivenessStatus`: `LIVE`, `NOT_LIVE`, `UNKNOWN`, `NOT_APPLICABLE`.
* `EligibilityStatus`: `ELIGIBLE`, `INELIGIBLE`, `UNKNOWN`, `NOT_APPLICABLE`.
* `LivenessFailureReason`: `NONE`, `BODY_BELOW_THRESHOLD`, `EMPTY_BODY`, `HTTP_ERROR`, `DNS_FAILURE`, `CONNECTION_TIMEOUT`, `CONNECTION_REFUSED`, `TLS_VERIFICATION_FAILED`, `MALFORMED_URL`, `UNSUPPORTED_SCHEME`, `NON_NETWORK_MODALITY`, `RETRIEVAL_ERROR`, `UNAVAILABLE`, `MISSING_ARTIFACT`.
* `Schema Interoperability`: Converts directly into canonical `LivenessMetadata` for downstream `BenchmarkRecord` construction.

---

## 18. Independent Ground-Truth Verification (Step 6D-4)

### 18.1 Purpose & Core Methodological Mandates
The independent ground-truth verification layer (`tools/benchmark/ground_truth_verifier.py`) establishes verified benchmark labels solely through independent external evidence and explicit analyst adjudication.

> **CRITICAL METHODOLOGICAL MANDATES:**
> 1. **Ground truth is established independently of the system under evaluation.**
> 2. **System-generated verdicts, risk scores, trust scores, AERE outputs, Confidence Engine outputs, and investigator reports are not valid ground-truth sources.**
> 3. **Threat-intelligence presence or absence is not, by itself, equivalent to benchmark ground truth.**
> 4. **Absence of threat detection $\neq$ Benign.** Lack of malicious evidence or feed absence never implies benign status.
> 5. **Qualitative confidence only:** Verification confidence is strictly qualitative (`HIGH`, `MEDIUM`, `LOW`). Floating-point probabilities or statistical confidences are rejected.
> 6. **Natural prevalence preserved:** No synthetic class rebalancing or artificial 50/50 padding.

### 18.2 Independent Source Types & Provenance
Approved external verification source types:
* `AUTHORITATIVE_REGISTRY`: Official registrar, TLD registry, or ICANN records.
* `CURATED_THREAT_FEED`: Verified threat repositories (e.g. curated feeds, APWG).
* `INCIDENT_TAKEDOWN_RECORD`: Verified incident response, abuse desk, or law enforcement takedown notices.
* `ANALYST_MANUAL_REVIEW`: Independent expert forensic examination.
* `OFFICIAL_ORGANIZATION_RECORD`: Verified corporate or governmental entity records.
* `MALWARE_SANDBOX_DETONATION`: Independent sandbox detonation telemetry.
* `TRUSTED_BENIGN_CURATION`: Highly curated authoritative benign corpora (e.g., Tranco top lists).
* `DOM_CERT_ANALYSIS`: Cryptographic certificate authority transparency logs.
* `COMMUNITY_CONSENSUS`: Multi-analyst consensus platforms.

### 18.3 Multi-Source Consensus & Conflict Handling
* **Consensus Rule ($\ge 2$ Independent Sources):** When $\ge 2$ genuinely independent external sources agree on an outcome (`MALICIOUS` or `BENIGN`), the record is assigned `VerificationStatus.VERIFIED` with qualitative `VerificationConfidence.HIGH`.
* **Single Source Evidence:** An uncorroborated single source receives `VerificationStatus.AMBIGUOUS` or qualitative `VerificationConfidence.MEDIUM` / `LOW`.
* **Duplicate / Mirrored Sources:** Multiple observations from the same provider or duplicate feed submissions collapse into a single provider claim and do not satisfy the multi-source independence threshold.
* **Conflicting Evidence:** If independent sources disagree (e.g. MALICIOUS vs BENIGN), the record is classified as `PrimaryOutcome.AMBIGUOUS` and `VerificationStatus.DISPUTED`. All conflicting references are preserved in `supporting_references` and `contradictory_references`.

### 18.4 Human Analyst Adjudication
Disputed or ambiguous candidates may be resolved through explicit human analyst review (`AdjudicationRecord`):
* Requires `reviewer_id`, `adjudicated_outcome`, `adjudicated_categories`, `rationale`, `adjudication_timestamp`, and `confidence`.
* Adjudication is strictly decoupled from the automated analysis pipeline under evaluation.

### 18.5 Self-Labeling Protection & Guardrails
* Rejects any verification source referencing internal system components (`TCE`, `AERE`, `ConfidenceEngine`, `ReportGenerator`, `analysis_pipeline`, `Agent 1`..`Agent 18`).
* Rejected internal sources trigger the diagnostic code `INTERNAL_SYSTEM_SOURCE_REJECTED` and are excluded from consensus evaluation.

### 18.6 Modality Separation & Ambiguity Pool
* Preserves the structural boundaries between `QR_IMAGE`, `QR_PAYLOAD`, and `DIRECT_URL`. Non-HTTP QR schemes (`mailto:`, `wifi:`, `smsto:`, `intent:`) remain passive data and are not automatically labeled malicious.
* Ambiguous and unverifiable records are retained in the canonical dataset's ambiguity pool rather than discarded or artificially forced into binary labels.

---

## 19. Experimental Benchmark Evaluation Layer (Step 6D-5)

### 19.1 Purpose & Experimental Architecture
The experimental evaluation layer (`tools/benchmark/evaluator.py`) evaluates canonical benchmark predictions against frozen ground truth across all experimental conditions defined in the research protocol:
* **Main Pipeline:** `M0` (Full Multi-Agent Digital Forensics System).
* **Baselines:** `A0` (Static Lexical Heuristics), `A1` (Standalone Threat-Intelligence Feed Aggregate), `A2` (Unweighted Majority Voting), `A3` (Linear Additive Risk), `A4` (Standalone Monolithic Zero-Shot LLM).
* **Ablation Conditions:** `M1` (A6 TI ablated), `M2` (A18 QR ablated), `M3` (A8 Dynamic Script ablated), `M4` (A9/A10 Brand & Visual ablated), `M5` (TCE Synergy ablated), `M6` (AERE Grounding Validator ablated).

### 19.2 Protocol Invariants & Guardrails
* **Ground-Truth Immutability:** Benchmark ground truth is read-only. AMBIGUOUS ground-truth records are strictly excluded from binary classification metrics and counted transparently in `excluded_ambiguous_count`.
* **Partition Isolation:** Evaluates `DEVELOPMENT_CALIBRATION` (30%), `VALIDATION` (20%), `FINAL_TEST` (30%), and `PROSPECTIVE_HOLDOUT` (20%) strictly out-of-sample without parameter leakage.
* **$5 \times 2$ Risk Band Contingency Table:** Evaluates full distribution across the five frozen TCE risk bands (`benign` $[0, 15)$, `low_risk` $[15, 35)$, `suspicious` $[35, 60)$, `high_risk` $[60, 80)$, `malicious` $[80, 100]$).
* **Threat-Flagging Decision Boundary:** Positive class mapped to $R \ge 35.0$ (Suspicious $\cup$ High Risk $\cup$ Malicious); Negative class mapped to $R < 35.0$ (Benign $\cup$ Low Risk).
* **Selective Classification & Abstention:** Evaluates Confidence Engine routing ($C_{ev} < 35.0$ as human investigator review abstention) and conditional balanced accuracy on retained cases ($C_{ev} \ge 35.0$).
* **AERE Grounding Fidelity:** Tracks distribution of reasoning claims across `GROUNDED`, `PARTIALLY_GROUNDED`, `UNGROUNDED`, and `UNCERTAIN`.
* **Incremental Diagnostic Contribution (IDC):** Computes $\text{IDC}_k = \text{Metric}(M_0) - \text{Metric}(M_k)$ as descriptive ablation diagnostic contribution (non-causal).

### 19.3 Statistical Procedures
* **95% Bootstrap Confidence Intervals:** Non-parametric bootstrap resampling ($B = 1000$ resamples with replacement, seed-controlled).
* **Hypothesis Testing:** Paired McNemar tests (for binary classification shifts) and Wilcoxon signed-rank tests (for continuous risk score shifts).
* **Effect Sizes:** Cohen's $d$ and Odds Ratios with Haldane-Anscombe zero-cell correction.
* **Reproducibility:** Serializes complete machine-readable `BenchmarkEvaluationSuiteResult` dictionaries with dataset and manifest cryptographic digests.

---

## 20. Experimental Dataset Assembly & Pre-Run Gate (Step 6D-6)

### 20.1 Purpose & Orchestration Layer
The dataset assembly layer (`tools/benchmark/dataset_assembler.py`) orchestrates the components of the frozen benchmark tooling (Steps 6C and 6D-1 through 6D-5) into a unified, reproducible dataset assembly engine and pre-run validation gate:
* **Input Ingestion:** Ingests raw candidate artifacts from Step 6D-2 without live harvesting.
* **Eligibility Integration:** Incorporates passive liveness telemetry from Step 6D-3 ($\ge 100$ byte threshold, default TLS verification).
* **Identity & Normalization:** Applies Step 6C-2 canonical normalization and computes the four-level identity hierarchy (`ART-`, `TGT-`, `GRP-`, `REC-`).
* **Cross-Modal Linking:** Integrates Step 6C-3 QR relationship linking with co-partitioning constraints.
* **Ground-Truth Attachment:** Attaches independent multi-source verification from Step 6D-4 with zero internal system contamination.
* **Threat Intelligence Metadata:** Attaches Step 6C-5 controlled TI overlap observations ($\text{NONE} \not\equiv \text{Benign}$).
* **Ambiguity Preservation:** Retains disputed and unverifiable candidates in the Ambiguity Pool.
* **Deterministic Partitioning:** Allocates records across `DEVELOPMENT_CALIBRATION` (30%), `VALIDATION` (20%), `FINAL_TEST` (30%), and `PROSPECTIVE_HOLDOUT` (20%) using deterministic group-cluster hashing.
* **Snapshot Generation & Integrity Auditing:** Serializes `records.jsonl` and `manifest.json` via Step 6C-6 and verifies integrity via Step 6C-7 `IntegrityAuditor`.

### 20.2 Pre-Run Quality Gates
Evaluates strict quality criteria and emits a definitive status:
* **`READY_FOR_EXPERIMENT`:** 100% schema-valid records, valid identity prefixes, verified ground truth, 0 critical/error audit findings, zero cross-partition target leakage, zero cross-partition QR/direct leakage, and verified cryptographic snapshot digests.
* **`BLOCKED_FROM_EXPERIMENT`:** Immediate blocking upon any critical leakage, ground-truth self-labeling, prospective chronology violations, or hash mismatches.

---

## 21. Real Benchmark Data Collection & Acquisition Layer (Step 6D-8)

### 21.1 Architectural Purpose & Guarantees
The benchmark data acquisition layer (`tools/benchmark/data_collector.py`) orchestrates the controlled, reproducible, and auditable gathering of real-world candidate artifacts across approved source feeds:
* **Source Role Firewall:** Formally segregates candidate sources, TI exposure feeds, independent ground-truth sources, and internal forensic analysis engines. Prohibits self-labeling and role conflation.
* **Provenance & Raw Capture:** Preserves exact raw artifact representations (`DIRECT_URL`, `QR_IMAGE`, `QR_PAYLOAD`), harvest timestamps, and source record references.
* **Passive Liveness Integration:** Leverages Step 6D-3 `PassiveLivenessEvaluator` ($\ge 100$ B body threshold, TLS verification enabled, bounded redirects) without dynamic execution or browser automation.
* **PII Sanitization:** Masks sensitive query tokens (`password`, `token`, `api_key`, `email`) while preserving URL structure.
* **Objective Stopping Rules:** Enforces capacity ceiling ($N \approx 1200$ planning target, max ceiling 2500), source exhaustion, temporal cutoffs, and safety limits without post-hoc performance bias.
* **Step 6D-6 Handoff:** Provides `handoff_to_dataset_assembler()` to transition collection results into the dataset assembly pipeline and achieve `READY_FOR_EXPERIMENT` pre-run gate validation.






