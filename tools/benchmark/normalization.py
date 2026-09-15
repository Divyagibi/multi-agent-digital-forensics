"""Benchmark Normalization, Deduplication, Grouping, and Leakage Detection Layer.

Step 6C-2: Normalization, Deduplication & Grouping.

This module provides deterministic URL/target normalization, three-tier entity
identity resolution, group/eTLD+1 extraction, duplicate classification, and
cross-partition leakage auditing for benchmark datasets.

Architectural Guarantees:
- Zero Network / API Calls: Operates strictly offline on supplied text and metadata.
- Ground-Truth Independence: Label changes never alter identity, grouping, or duplication.
- Threat-Intelligence Independence: TI feed states never define duplication.
- Loss-Minimizing: All input records are preserved; duplicates are classified, not silently dropped.
- Functional Target Preservation: Distinct functional paths and query parameters are preserved.
- Zero Coupling: Zero imports from production forensic analysis or decision engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import urllib.parse

from .schemas import (
    InputModality,
    TemporalPartition,
    DuplicateStatus,
    BenchmarkRecord,
    compute_artifact_id,
    compute_target_id,
    compute_group_id,
    compute_record_id,
)

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


# =====================================================================
# Normalized Target Representation
# =====================================================================

@dataclass(frozen=True)
class NormalizedTarget:
    """Canonical representation of an investigated target URL or network entity."""
    original_input: str
    canonical_url: str
    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: Optional[str]
    registrable_domain: Optional[str]
    grouping_key: str
    target_id: str
    group_id: str
    is_ip: bool = False
    is_ambiguous: bool = False
    notes: str = ""


# =====================================================================
# Target Normalization Implementation
# =====================================================================

def _normalize_dot_segments(path: str) -> str:
    """Standard RFC 3986 dot segment resolution."""
    if not path:
        return "/"
    
    # Preserve leading slash
    has_leading = path.startswith("/")
    segments = path.split("/")
    output_segments: List[str] = []
    
    for seg in segments:
        if seg == "" or seg == ".":
            continue
        elif seg == "..":
            if output_segments:
                output_segments.pop()
        else:
            output_segments.append(seg)
            
    res = "/" + "/".join(output_segments) if has_leading else "/".join(output_segments)
    if path.endswith("/") and not res.endswith("/"):
        res += "/"
    return res if res else "/"


def _extract_domain_and_group(hostname: str) -> Tuple[Optional[str], str, bool]:
    """Extract registered domain (eTLD+1) or IP grouping key deterministically."""
    clean_host = hostname.strip().lower().rstrip(".")
    
    # Check if host is an IP address
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        is_ip = True
        if isinstance(ip_obj, ipaddress.IPv4Address):
            # Group IPv4 by /24 network
            network = ipaddress.IPv4Network(f"{clean_host}/24", strict=False)
            grouping_key = str(network)
        else:
            # Group IPv6 by /48 network
            network = ipaddress.IPv6Network(f"{clean_host}/48", strict=False)
            grouping_key = str(network)
        return None, grouping_key, is_ip
    except ValueError:
        is_ip = False

    # Extract eTLD+1
    if _HAS_TLDEXTRACT:
        extracted = tldextract.extract(clean_host)
        if extracted.domain and extracted.suffix:
            reg_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            return reg_domain, reg_domain, is_ip
        elif extracted.domain:
            reg_domain = extracted.domain.lower()
            return reg_domain, reg_domain, is_ip
        elif extracted.suffix:
            # e.g., localhost or internal domain
            reg_domain = clean_host
            return reg_domain, reg_domain, is_ip

    # Conservative fallback if tldextract is unavailable
    parts = clean_host.split(".")
    if len(parts) >= 2:
        reg_domain = ".".join(parts[-2:])
    else:
        reg_domain = clean_host
    return reg_domain, reg_domain, is_ip


def normalize_investigation_target(target_input: str) -> NormalizedTarget:
    """Produce a deterministic, canonical representation of an investigation target.

    Normalization Rules:
    - Scheme: Lowercase (default 'http' if not specified; 'http' and 'https' remain distinct).
    - Hostname: Lowercase, trailing dot stripped, IDN/Punycode preserved in canonical form.
    - Port: Standard ports (80 for http, 443 for https) stripped; non-standard ports preserved.
    - Path: Dot segments normalized, multiple redundant slashes collapsed, empty path becomes '/'.
    - Query: Query parameters sorted deterministically by key and value; parameter values preserved.
    - Fragment: Stripped from canonical_url as fragments are client-side only, but preserved in fragment field.
    - Target ID: Computed deterministically as TGT-<sha256[:16]> of canonical_url.
    - Group ID: Computed deterministically as GRP-<sha256[:16]> of eTLD+1 or IP subnet.

    Information Preservation Guarantee:
    Distinct functional endpoints (/login vs /account vs /download.apk, or ?v=1 vs ?v=2)
    are NEVER collapsed into the same target identity.
    """
    raw_str = (target_input or "").strip()
    if not raw_str:
        tgt_id = compute_target_id("")
        grp_id = compute_group_id("")
        return NormalizedTarget(
            original_input=raw_str,
            canonical_url="",
            scheme="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment=None,
            registrable_domain=None,
            grouping_key="",
            target_id=tgt_id,
            group_id=grp_id,
            is_ip=False,
            is_ambiguous=True,
            notes="Empty target input",
        )

    # Check scheme prefix
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_str))
    parse_url = raw_str if has_scheme else f"http://{raw_str}"

    try:
        parsed = urllib.parse.urlsplit(parse_url)
    except Exception as e:
        tgt_id = compute_target_id(raw_str.lower())
        grp_id = compute_group_id(raw_str.lower())
        return NormalizedTarget(
            original_input=raw_str,
            canonical_url=raw_str.lower(),
            scheme="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment=None,
            registrable_domain=None,
            grouping_key=raw_str.lower(),
            target_id=tgt_id,
            group_id=grp_id,
            is_ip=False,
            is_ambiguous=True,
            notes=f"URL parsing exception: {str(e)}",
        )

    # Scheme
    scheme = parsed.scheme.lower() if parsed.scheme else "http"

    # Hostname & Port
    netloc = parsed.netloc
    hostname = ""
    port: Optional[int] = None
    
    if netloc:
        # Check for port in netloc
        if "@" in netloc:
            # Userinfo stripped for target identity
            netloc = netloc.split("@", 1)[1]
            
        if ":" in netloc and not netloc.endswith("]"):
            # Potential port (handle IPv6 bracket notation)
            host_part, port_str = netloc.rsplit(":", 1)
            try:
                p_val = int(port_str)
                # Keep port only if non-default
                if (scheme == "http" and p_val != 80) or (scheme == "https" and p_val != 443):
                    port = p_val
                elif p_val not in (80, 443):
                    port = p_val
                hostname = host_part.strip().lower().rstrip(".")
            except ValueError:
                hostname = netloc.strip().lower().rstrip(".")
        else:
            hostname = netloc.strip().lower().rstrip(".")
    elif parsed.path and not has_scheme:
        # Path might have received host when scheme was missing
        hostname = parsed.path.strip().lower().rstrip(".")

    # Grouping & Registrable Domain
    reg_domain, grouping_key, is_ip = _extract_domain_and_group(hostname)

    # Path Normalization
    raw_path = parsed.path if has_scheme else ""
    if not raw_path or raw_path == "":
        normalized_path = "/"
    else:
        # Collapse multi-slashes
        collapsed = re.sub(r"/+", "/", raw_path)
        normalized_path = _normalize_dot_segments(collapsed)
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path

    # Query Normalization
    normalized_query = ""
    if parsed.query:
        # Parse and sort parameters deterministically
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        # Sort by key then value
        sorted_pairs = sorted(query_pairs, key=lambda kv: (kv[0], kv[1]))
        normalized_query = urllib.parse.urlencode(sorted_pairs)

    # Fragment
    fragment = parsed.fragment if parsed.fragment else None

    # Reconstruct Canonical URL (without fragment)
    netloc_canonical = hostname
    if port is not None:
        netloc_canonical = f"{hostname}:{port}"
        
    canonical_url = f"{scheme}://{netloc_canonical}{normalized_path}"
    if normalized_query:
        canonical_url += f"?{normalized_query}"

    target_id = compute_target_id(canonical_url)
    group_id = compute_group_id(grouping_key)

    return NormalizedTarget(
        original_input=raw_str,
        canonical_url=canonical_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=normalized_path,
        query=normalized_query,
        fragment=fragment,
        registrable_domain=reg_domain,
        grouping_key=grouping_key,
        target_id=target_id,
        group_id=group_id,
        is_ip=is_ip,
        is_ambiguous=False,
    )


# =====================================================================
# Duplicate & Overlap Classification
# =====================================================================

class OverlapType(str, Enum):
    """Categorization of record overlap or leakage."""
    EXACT_ARTIFACT = "EXACT_ARTIFACT"
    SAME_TARGET = "SAME_TARGET"
    SAME_GROUP = "SAME_GROUP"
    DISTINCT = "DISTINCT"


@dataclass(frozen=True)
class DuplicateRelation:
    """Pairwise relationship between two benchmark records."""
    record_id_a: str
    record_id_b: str
    overlap_type: OverlapType
    is_exact_artifact_duplicate: bool
    is_same_target: bool
    is_same_group: bool
    is_cross_split_leakage: bool
    reason: str


@dataclass(frozen=True)
class LeakageFinding:
    """Structured report of cross-partition dataset leakage."""
    record_id_a: str
    record_id_b: str
    partition_a: str
    partition_b: str
    overlap_type: OverlapType
    entity_key: str
    description: str


@dataclass(frozen=True)
class DeduplicationResult:
    """Structured result of benchmark dataset deduplication and auditing."""
    total_records: int
    unique_artifacts_count: int
    unique_targets_count: int
    unique_groups_count: int
    exact_artifact_duplicates: List[DuplicateRelation] = field(default_factory=list)
    same_target_relations: List[DuplicateRelation] = field(default_factory=list)
    same_group_relations: List[DuplicateRelation] = field(default_factory=list)
    leakage_findings: List[LeakageFinding] = field(default_factory=list)
    retained_records: List[BenchmarkRecord] = field(default_factory=list)
    diagnostics: Dict[str, Any] = field(default_factory=dict)


def classify_relation(record_a: BenchmarkRecord, record_b: BenchmarkRecord) -> DuplicateRelation:
    """Deterministically classify the relationship between two BenchmarkRecords."""
    is_exact_artifact = (record_a.artifact_id == record_b.artifact_id)
    is_same_tgt = (record_a.target_id == record_b.target_id)
    is_same_grp = (record_a.evaluation.group_id == record_b.evaluation.group_id)

    part_a = record_a.evaluation.temporal_partition
    part_b = record_b.evaluation.temporal_partition
    is_cross_split = (
        part_a is not None and part_b is not None and part_a != part_b and (is_same_tgt or is_same_grp)
    )

    if is_exact_artifact:
        overlap = OverlapType.EXACT_ARTIFACT
        reason = "Identical artifact ID and observed input"
    elif is_same_tgt:
        overlap = OverlapType.SAME_TARGET
        reason = "Distinct artifacts pointing to identical normalized target"
    elif is_same_grp:
        overlap = OverlapType.SAME_GROUP
        reason = "Distinct targets sharing registered domain (eTLD+1) or IP subnet"
    else:
        overlap = OverlapType.DISTINCT
        reason = "Distinct targets and distinct grouping domains"

    return DuplicateRelation(
        record_id_a=record_a.record_id,
        record_id_b=record_b.record_id,
        overlap_type=overlap,
        is_exact_artifact_duplicate=is_exact_artifact,
        is_same_target=is_same_tgt,
        is_same_group=is_same_grp,
        is_cross_split_leakage=is_cross_split,
        reason=reason,
    )


def detect_cross_split_leakage(records: List[BenchmarkRecord]) -> List[LeakageFinding]:
    """Scan a collection of BenchmarkRecords for cross-partition data leakage.

    Audits:
    - Target Leakage: Same target_id present across two different partitions.
    - Group/Domain Leakage: Same group_id (eTLD+1/subnet) present across different partitions.
    - Artifact Duplicate Leakage: Same artifact_id present across partitions.
    """
    findings: List[LeakageFinding] = []
    
    # Map target_id -> list of records
    target_map: Dict[str, List[BenchmarkRecord]] = {}
    # Map group_id -> list of records
    group_map: Dict[str, List[BenchmarkRecord]] = {}
    # Map artifact_id -> list of records
    artifact_map: Dict[str, List[BenchmarkRecord]] = {}

    for rec in records:
        if rec.evaluation.temporal_partition is None:
            continue
        target_map.setdefault(rec.target_id, []).append(rec)
        group_map.setdefault(rec.evaluation.group_id, []).append(rec)
        artifact_map.setdefault(rec.artifact_id, []).append(rec)

    # 1. Target Overlap Leakage
    seen_target_pairs: Set[Tuple[str, str]] = set()
    for tgt_id, rec_list in target_map.items():
        for i in range(len(rec_list)):
            for j in range(i + 1, len(rec_list)):
                r1, r2 = rec_list[i], rec_list[j]
                p1 = r1.evaluation.temporal_partition
                p2 = r2.evaluation.temporal_partition
                if p1 != p2:
                    pair_key = (min(r1.record_id, r2.record_id), max(r1.record_id, r2.record_id))
                    if pair_key not in seen_target_pairs:
                        seen_target_pairs.add(pair_key)
                        findings.append(
                            LeakageFinding(
                                record_id_a=r1.record_id,
                                record_id_b=r2.record_id,
                                partition_a=str(p1.value if hasattr(p1, "value") else p1),
                                partition_b=str(p2.value if hasattr(p2, "value") else p2),
                                overlap_type=OverlapType.SAME_TARGET,
                                entity_key=tgt_id,
                                description=f"Cross-partition target leakage between {p1} and {p2}",
                            )
                        )

    # 2. Group Overlap Leakage (eTLD+1 / subnet)
    seen_group_pairs: Set[Tuple[str, str]] = set()
    for grp_id, rec_list in group_map.items():
        for i in range(len(rec_list)):
            for j in range(i + 1, len(rec_list)):
                r1, r2 = rec_list[i], rec_list[j]
                p1 = r1.evaluation.temporal_partition
                p2 = r2.evaluation.temporal_partition
                if p1 != p2:
                    pair_key = (min(r1.record_id, r2.record_id), max(r1.record_id, r2.record_id))
                    # Only add if not already flagged as direct target overlap
                    if pair_key not in seen_target_pairs and pair_key not in seen_group_pairs:
                        seen_group_pairs.add(pair_key)
                        findings.append(
                            LeakageFinding(
                                record_id_a=r1.record_id,
                                record_id_b=r2.record_id,
                                partition_a=str(p1.value if hasattr(p1, "value") else p1),
                                partition_b=str(p2.value if hasattr(p2, "value") else p2),
                                overlap_type=OverlapType.SAME_GROUP,
                                entity_key=grp_id,
                                description=f"Cross-partition eTLD+1/group leakage between {p1} and {p2}",
                            )
                        )

    return findings


def deduplicate_records(records: List[BenchmarkRecord]) -> DeduplicationResult:
    """Analyze benchmark records for exact artifact duplicates, same targets, and group clusters.

    CRITICAL PRESERVATION GUARANTEE:
    - Input records are NEVER deleted or silently altered.
    - All input records are retained in the result.
    - Detailed relationship and leakage diagnostics are compiled for downstream auditing.
    """
    exact_artifacts: List[DuplicateRelation] = []
    same_targets: List[DuplicateRelation] = []
    same_groups: List[DuplicateRelation] = []

    unique_artifacts: Set[str] = set()
    unique_targets: Set[str] = set()
    unique_groups: Set[str] = set()

    for rec in records:
        unique_artifacts.add(rec.artifact_id)
        unique_targets.add(rec.target_id)
        unique_groups.add(rec.evaluation.group_id)

    # Pairwise relationship classification
    n = len(records)
    for i in range(n):
        for j in range(i + 1, n):
            rel = classify_relation(records[i], records[j])
            if rel.is_exact_artifact_duplicate:
                exact_artifacts.append(rel)
            elif rel.is_same_target:
                same_targets.append(rel)
            elif rel.is_same_group:
                same_groups.append(rel)

    leakage_findings = detect_cross_split_leakage(records)

    diagnostics = {
        "exact_artifact_duplicate_count": len(exact_artifacts),
        "same_target_multi_artifact_count": len(same_targets),
        "same_group_cluster_count": len(same_groups),
        "leakage_finding_count": len(leakage_findings),
    }

    return DeduplicationResult(
        total_records=len(records),
        unique_artifacts_count=len(unique_artifacts),
        unique_targets_count=len(unique_targets),
        unique_groups_count=len(unique_groups),
        exact_artifact_duplicates=exact_artifacts,
        same_target_relations=same_targets,
        same_group_relations=same_groups,
        leakage_findings=leakage_findings,
        retained_records=list(records),
        diagnostics=diagnostics,
    )
