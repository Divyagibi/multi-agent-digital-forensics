"""
services/tce_config.py
======================
Centralized Configuration & Parameter Registry for the Trust Calculation Engine (TCE).

Contains all mathematical constants, severity weights, reliability multipliers,
and declarative polarity mappings for deterministic trust and risk evaluation.

NOTE: All numerical parameters represent declared heuristic prototype parameters
subject to empirical evaluation and calibration on labeled digital forensics benchmarks.
Structural parameters (such as duplicate suppression) are fixed by architectural design.
"""

from typing import Dict, Any, List, Set


# =====================================================================
# 1. SEVERITY WEIGHTS (Initial Heuristic)
# =====================================================================
SEVERITY_WEIGHTS: Dict[str, float] = {
    "info": 0.00,
    "low": 0.15,
    "medium": 0.45,
    "high": 0.75,
    "critical": 1.00,
}


# =====================================================================
# 2. EVIDENCE TYPE RELIABILITY (Initial Heuristic)
# =====================================================================
TYPE_RELIABILITY: Dict[str, float] = {
    "deterministic": 1.00,
    "threat_intelligence": 0.90,
    "external_source": 0.85,
    "historical": 0.85,
    "inference": 0.70,
    "subjective": 0.50,
}


# =====================================================================
# 3. MISSING STRENGTH DEFAULTS (Initial Heuristic)
# =====================================================================
DEFAULT_STRENGTH_BY_TYPE: Dict[str, float] = {
    "deterministic": 1.00,
    "threat_intelligence": 0.70,
    "external_source": 0.60,
    "historical": 0.60,
    "inference": 0.50,
    "subjective": 0.40,
}


# =====================================================================
# 4. RELATIONAL & AGGREGATION PARAMETERS
# =====================================================================
CORROBORATION_ALPHA: float = 0.25               # Empirically calibratable
RELATED_DIMENSION_BETA: float = 0.70            # Initial heuristic

DUPLICATE_MULTIPLIER: float = 0.00              # Structural (suppresses secondary duplicates)
DERIVED_MIRROR_MULTIPLIER: float = 0.00         # Structural (suppresses semantic mirrors)
DERIVED_NEW_ANALYSIS_MULTIPLIER: float = 1.00   # Structural (retains new downstream analyses)

CONTRADICTION_PENALTY: float = 5.0              # Initial heuristic (per contradiction)
MAX_CONTRADICTION_PENALTY: float = 10.0         # Initial heuristic (maximum total penalty)

SATURATION_KAPPA: float = 1.20                  # Empirically calibratable
MITIGATION_GAMMA: float = 0.50                  # Empirically calibratable

MIN_TELEMETRY_COVERAGE: float = 0.20            # Structural (coverage threshold)


# =====================================================================
# 5. VERDICT THRESHOLDS (Initial Prototype Boundaries)
# =====================================================================
VERDICT_THRESHOLDS: Dict[str, float] = {
    "benign": 15.0,
    "suspicious": 35.0,
    "high_risk": 60.0,
    "malicious": 80.0,
}


# =====================================================================
# 6. DECLARATIVE POLARITY TAXONOMY
# =====================================================================
# Categorical rules for mapping evidence items to explicit forensic direction:
# - risk_increasing (+1.0)
# - risk_reducing   (-1.0)
# - neutral         ( 0.0)
# Unmapped categories default to neutral (0.0).

POLARITY_RULES: Dict[str, Set[str]] = {
    "risk_increasing": {
        # Threat intel & malware
        "threat_intel_blocklist", "malware_signature_match", "phishing_feed_match",
        "suspicious_executable_download", "cryptominer_detected", "obfuscated_javascript",
        "blacklist_entry", "known_malicious_ip",
        # Behavioral & phishing
        "fake_login_form", "credential_harvesting", "hidden_form_fields",
        "automatic_client_redirect", "forced_file_download", "popup_flood",
        # Brand impersonation & visual
        "brand_name_impersonation", "brand_logo_mismatch", "brand_domain_mismatch",
        "typosquatting_detected", "combosquatting_detected", "homograph_punycode",
        # Content & Deception
        "urgency_manipulation_keywords", "scam_fraud_keywords", "ai_generated_phishing_text",
        "unrealistic_claims", "duplicate_scam_template",
        # Technical & Domain anomalies
        "domain_age_young", "domain_registered_recently", "dnssec_disabled",
        "self_signed_certificate", "expired_certificate", "invalid_certificate_chain",
        "open_sensitive_port", "missing_security_headers", "excessive_subdomains",
        "url_shortener_redirect"
    },
    "risk_reducing": {
        # Long establishment & legitimate tenure
        "domain_age_established", "domain_age_mature", "long_term_archive_tenure",
        "historical_continuity_verified", "whois_verified_registrant",
        # Security infrastructure
        "ev_ssl_certificate_verified", "valid_ca_signed_certificate", "hsts_preloaded",
        "dnssec_enabled_and_valid", "strict_csp_configured", "strict_cors_configured",
        # Verified business & corporate presence
        "company_registration_verified", "tax_registration_verified", "gst_vat_verified",
        "physical_address_verified", "phone_verified", "social_presence_verified",
        "established_brand_official_domain", "positive_consumer_reputation"
    },
    "neutral": {
        # Standard baseline telemetry
        "standard_port_open", "page_language_detected", "server_banner_detected",
        "framework_detected", "meta_title_present", "meta_description_present",
        "content_length_normal", "cookie_banner_present", "clean_dns_resolution",
        "standard_tls_version", "qr_format_parsed", "analytics_tracker_detected"
    }
}


def resolve_evidence_polarity(finding_category: str, finding_text: str = "") -> str:
    """
    Deterministically resolve evidence polarity from declarative taxonomy.
    If the category is unmapped, safely returns 'neutral' (non-scoreable).
    """
    cat = (finding_category or "").strip().lower()
    
    # 1. Direct category match
    if cat in POLARITY_RULES["risk_increasing"]:
        return "risk_increasing"
    if cat in POLARITY_RULES["risk_reducing"]:
        return "risk_reducing"
    if cat in POLARITY_RULES["neutral"]:
        return "neutral"

    # 2. Check for explicit prefix/pattern matches in taxonomy
    for inc_cat in POLARITY_RULES["risk_increasing"]:
        if inc_cat in cat:
            return "risk_increasing"

    for red_cat in POLARITY_RULES["risk_reducing"]:
        if red_cat in cat:
            return "risk_reducing"

    # 3. Fallback: unmapped items are safely neutral
    return "neutral"
