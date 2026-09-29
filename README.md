
# MTAI-DF: Multi-Agent URL Digital Forensics and Evidence Analysis System

### An Explainable Multi-Agent Framework for Digital Trust Investigation

MTAI-DF is an evidence-driven digital forensic investigation system designed to analyze suspicious URLs and QR-code-based threats. It uses 18 specialized forensic agents to collect, analyze, and correlate security evidence from multiple sources.

Unlike traditional phishing detection systems that rely primarily on individual indicators or classification models, MTAI-DF combines multi-source forensic evidence, deterministic risk assessment, evidence-grounded explanations, and independent confidence evaluation.

## Key Features

- URL and QR-code-based forensic investigation
- 18 specialized forensic agents
- Multi-source evidence collection and correlation
- Centralized Evidence Ledger
- Deterministic Risk Score, Trust Score, and Verdict
- Evidence-grounded explanations
- Independent investigation confidence assessment
- Structured forensic investigation reports
- Modular Python and Flask architecture

## System Architecture

The investigation follows this workflow:

1. **User Input:** Submit a URL or upload a QR-code image.
2. **Forensic Investigation:** Execute 18 specialized agents.
3. **Evidence Processing:** Normalize and correlate the collected evidence.
4. **Evidence Ledger:** Store structured findings and their relationships.
5. **Trust Calculation Engine:** Calculate Risk Score, Trust Score, and Verdict.
6. **AERE:** Generate evidence-based explanations.
7. **Confidence Engine:** Evaluate the completeness and reliability of the investigation.
8. **Report Generation:** Present a structured forensic investigation report.

## The 18 Forensic Agents

| Agent | Name |
|---|---|
| A1 | Domain Identity |
| A2 | DNS & Infrastructure |
| A3 | SSL/TLS Security |
| A4 | Website Content Analysis |
| A5 | URL Structure Analysis |
| A6 | Reputation & Threat Intelligence |
| A7 | Technical Fingerprinting |
| A8 | Website Behavior Analysis |
| A9 | Brand Verification |
| A10 | Visual/UI Analysis |
| A11 | Content Quality Analysis |
| A12 | Contact/Entity Verification |
| A13 | OSINT Investigation |
| A14 | Historical/Wayback Analysis |
| A15 | User Trust & Sentiment |
| A16 | Network Security |
| A17 | Malware/Exploit Indicators |
| A18 | QR Forensics / Quishing Analysis |

## Core Modules

### 1. Multi-Agent Forensic Investigation

The 18 agents independently investigate different aspects of a submitted URL or QR code and generate structured forensic evidence.

### 2. Evidence Normalization and Ledger

The Common Evidence Schema standardizes findings from different agents.

The centralized Evidence Ledger maintains evidence identifiers, sources, provenance, severity, and relationships such as duplication, corroboration, and contradiction.

### 3. Trust Calculation Engine (TCE)

TCE performs deterministic risk assessment using evidence severity, strength, reliability, polarity, and relationships.

It generates:

- Risk Score
- Trust Score
- Verdict

The possible verdicts are Benign, Low Risk, Suspicious, High Risk, and Malicious. Insufficient evidence is handled separately.

### 4. AI-Based Evidence Reasoning and Explanation (AERE)

AERE produces structured explanations of forensic findings, evidence chains, contradictions, alternative hypotheses, and investigation gaps.

Contract validation and grounding validation help prevent unsupported explanations.

**Current implementation:** AERE uses an offline deterministic MockProvider. The architecture supports future integration with real LLM providers.

### 5. Confidence Engine and Final Report

The Confidence Engine independently evaluates evidence completeness, reliability, corroboration, contradictions, provenance, and explanation grounding.

The final report combines the forensic evidence, TCE results, AERE explanations, and confidence assessment.

## Technologies Used

- **Backend:** Python, Flask
- **Frontend:** Web technologies
- **HTTP and Web Analysis:** Requests, BeautifulSoup
- **Domain and Network Analysis:** RDAP, DNS, SSL/TLS
- **External Intelligence:** Supported threat-intelligence APIs
- **Data Exchange:** JSON
- **Architecture:** Modular multi-agent system

## API Overview

The Flask backend provides individual endpoints for the forensic agents.

```text
/api/agent1
/api/agent2
...
/api/agent18
```

The `/api/pipeline/finalize` endpoint combines collected agent outputs and performs subsequent evidence processing and analysis.

## Project Status

The core multi-agent investigation pipeline has been developed, including evidence collection, normalization, risk assessment, explanation validation, and confidence evaluation.

The current AERE implementation operates through an offline MockProvider. Connecting and evaluating a real LLM provider is a future development objective.

## Security and Responsible Use

MTAI-DF is intended for defensive cybersecurity research and digital forensic investigation.

The system incorporates URL validation, SSRF protection, request timeouts, redirect restrictions, and response-size limits.

Forensic agents perform passive investigation and avoid unauthorized access, exploit execution, and submission of sensitive website forms.

**Important:** Do not commit API keys, access tokens, passwords, `.env` files, or confidential investigation results to this repository.

## Future Scope

- Integration with real LLM providers
- Expanded forensic intelligence sources
- Persistent investigation storage
- Further evaluation using diverse threat scenarios
- Improved investigation reporting and visualization

## Academic Project

**Project:** MTAI-DF — Multi-Agent URL Digital Forensics and Evidence Analysis System

**Developed by:** Divya Binu

**Programme:** M.Tech in Computer Science and Information Systems

**Institution:** Rajagiri School of Engineering & Technology

**Purpose:** Academic research and digital forensic investigation.
