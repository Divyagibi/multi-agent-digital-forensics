# Multi-Agent Digital Forensics System — Common Evidence Schema

## Overview & Architectural Principles

The **Common Evidence Schema** defines a standardized, research-grade data structure for forensic evidence items collected across all **18 specialized forensic agents (A1–A18)**.

### Core Principles
1. **Decoupled Architecture:** Forensic agents function strictly as **Evidence Collectors** ("What did we observe?"). Agents do NOT compute final trust scores, risk scores, or site-level safety verdicts. Those responsibilities belong exclusively to the downstream Trust Calculation Engine and AI Reasoning Engine.
2. **Deterministic & Unique Identification:** Every evidence observation is assigned a deterministic identifier formatted as `E<agent_number>-<index:02d>` (e.g., `E1-01`, `E6-04`, `E18-05`).
3. **Source Attribution:** Every evidence record is explicitly attributed to its ground-truth source tool, resolver, or external service (e.g., `RDAP / WHOIS`, `DNS Resolver`, `TLS Socket`, `VirusTotal`, `QR Image Decoder`).
4. **Controlled Vocabularies:** Evidence type, severity, and agent status are validated against strict enumeration sets.
5. **Calibrated Evidence Strength:** For inference and heuristic findings, an optional `evidence_strength` metric in the continuous range `[0.0, 1.0]` indicates analytical confidence.

---

## 1. Controlled Vocabularies

### 1.1 Evidence Types (`type`)
| Type | Description |
| :--- | :--- |
| `deterministic` | Direct, verifiable measurements (e.g., DNS A records, TLS version, HTTP status code). |
| `inference` | Analytical inferences or heuristic deductions (e.g., brand similarity, open redirect candidate). |
| `threat_intelligence` | Matches against threat feeds and blocklists (e.g., VirusTotal, Safe Browsing, PhishTank). |
| `external_source` | Third-party public registries and OSINT (e.g., corporate registries, social platforms). |
| `historical` | Historical timeline and archive records (e.g., Wayback Machine snapshots). |
| `subjective` | Qualitative sentiment or crowd-sourced feedback (e.g., Trustpilot, review complaints). |

### 1.2 Severities (`severity`)
| Severity | Description |
| :--- | :--- |
| `info` | Informational or neutral baseline telemetry (e.g., domain registered, server header present). |
| `low` | Minor anomaly or sub-optimal configuration (e.g., missing security headers, weak cipher). |
| `medium` | Moderately suspicious characteristic (e.g., recent domain registration, URL shortener). |
| `high` | Strong forensic indicator of risk (e.g., brand name mismatch, open redirect, hidden parameters). |
| `critical` | Direct malicious match (e.g., active malware download, confirmed phishing blocklist entry). |

### 1.3 Agent Execution Statuses (`status`)
`success` | `completed` | `partial` | `error` | `skipped` | `unavailable` | `restricted`

---

## 2. Canonical Agent Registry (A1 – A18)

| Agent ID | Agent Number | Canonical Name | Core Scope & Responsibilities |
| :--- | :---: | :--- | :--- |
| **A1** | 1 | Domain Identity | Domain registration, RDAP/WHOIS, age & registrar |
| **A2** | 2 | DNS & Infrastructure | A, AAAA, MX, NS, TXT, CNAME, DNSSEC, CDN & IP |
| **A3** | 3 | SSL/HTTPS | TLS version, X509 certificates, cipher suites & HSTS |
| **A4** | 4 | Website Content | Metadata, company detection, policy pages & broken links |
| **A5** | 5 | URL Structure | Lexical features, Punycode, homograph & redirects |
| **A6** | 6 | Reputation & Threat Intelligence | VirusTotal, Safe Browsing, PhishTank, OpenPhish, AbuseIPDB, URLHaus & Blocklists |
| **A7** | 7 | Technical Fingerprinting | Web server, CMS, frameworks, JS libraries, analytics, trackers, admin panels & directories |
| **A8** | 8 | Website Behavior | Automatic redirects, popups, forced downloads, JS indicators, forms & fake login |
| **A9** | 9 | Brand Verification | Logo, favicon, brand name, trademark references, color theme, layout & official domain comparison |
| **A10** | 10 | Visual/UI Analysis | Screenshot, OCR text, trust badges, payment logos, reviews & suspicious UI patterns |
| **A11** | 11 | Content Quality | Grammar, spelling, AI-generated indicators, duplicate text, unrealistic claims, urgency & scam keywords |
| **A12** | 12 | Contact Verification | Email, phone, physical address, Google Maps, social media, GSTIN/VAT & business registry verification |
| **A13** | 13 | External Presence / OSINT | LinkedIn, Facebook, X/Twitter, Instagram, GitHub, Reddit, News, Reviews & Forums |
| **A14** | 14 | Historical Evidence | Wayback Machine archives, content evolution, ownership & DNS infrastructure timeline |
| **A15** | 15 | User Trust Signals | Trustpilot, Google Reviews, Reddit discussions, scam complaints, consumer forums, testimonials & cross-source corroboration |
| **A16** | 16 | Network Security | Open ports, HTTP & security headers, CSP, CORS configuration, X-Frame-Options & server fingerprinting |
| **A17** | 17 | Malware Indicators | Malicious downloads, suspicious scripts, drive-by patterns, cryptomining & obfuscated JavaScript |
| **A18** | 18 | QR Analysis | Decodes QR payloads, extracts embedded URLs, inspects redirect chains, shorteners & parameters |

---

## 3. Data Specification & JSON Examples

### 3.1 Individual Evidence Item (`create_evidence_item`)
```json
{
  "evidence_id": "E18-03",
  "type": "threat_intelligence",
  "finding": "URL shortening service utilization in QR payload",
  "value": "bit.ly",
  "severity": "medium",
  "source": "Domain / Shortener Analyzer",
  "evidence_strength": 0.6,
  "metadata": {
    "provider": "bit.ly",
    "detected": true
  }
}
```

### 3.2 Standard Agent Output Envelope (`build_agent_result`)
```json
{
  "agent": "Domain Identity",
  "agent_id": "A1",
  "agent_name": "Domain Identity",
  "agent_number": 1,
  "status": "completed",
  "target": "example.com",
  "data": {
    "domain_name": "example.com",
    "domain_age_days": 10540,
    "registrar": "IANA",
    "privacy_protected": false
  },
  "evidence": [
    {
      "evidence_id": "E1-01",
      "type": "deterministic",
      "finding": "Domain age in days",
      "value": 10540,
      "severity": "info",
      "source": "RDAP / WHOIS",
      "evidence_strength": 0.9,
      "metadata": { "creation_date": "1995-08-14" }
    }
  ],
  "errors": [],
  "trust_score": null,
  "risk_score": null,
  "verdict": "not_calculated",
  "legacy": {
    "trust_score": null,
    "risk_score": null,
    "verdict": "not_calculated",
    "notice": "Agent-level scores are legacy/preliminary. Final trust calculation is handled by the Trust Calculation Engine."
  }
}
```

---

## 4. Usage in Python

```python
from services.evidence_schema import create_evidence_item, build_agent_result, validate_agent_result

# 1. Construct individual evidence item
item = create_evidence_item(
    agent_id="A1",
    index=1,
    finding="Domain age in days",
    value=365,
    severity="info",
    source="RDAP / WHOIS",
    evidence_type="deterministic",
    evidence_strength=0.9
)

# 2. Build complete agent result
result = build_agent_result(
    agent_identifier="A1",
    target="https://example.com",
    status="completed",
    data={"domain_age_days": 365},
    evidence=[item],
    errors=[]
)

# 3. Validate result
is_valid, errors = validate_agent_result(result)
assert is_valid, f"Validation errors: {errors}"
```
