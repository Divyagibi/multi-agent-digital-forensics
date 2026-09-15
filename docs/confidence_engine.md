# Step 4B — Deterministic Confidence Engine (DHCI) Documentation

## 1. Overview & System Role

The **Confidence Engine** (Deterministic Heuristic Confidence Index / DHCI) is a post-hoc, additive, diagnostic subsystem designed to evaluate the **epistemic quality of collected forensic evidence** ($\mathcal{C}_{\text{ev}}$) and the **structural fidelity of automated reasoning** ($\mathcal{C}_{\text{interp}}$).

```
+-----------------------------------------------------------------------------+
|                          18 FORENSIC AGENTS (A1–A18)                        |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                      EVIDENCE LEDGER & NORMALIZER                           |
+-----------------------------------------------------------------------------+
                                      |
                   +------------------+------------------+
                   |                                     |
                   v                                     v
+------------------------------------+ +------------------------------------+
|  TRUST CALCULATION ENGINE (TCE)    | |  AERE REASONING ENGINE (AERE)      |
|  (Sole authority for risk/trust/   | |  (Qualitative structured reasoning |
|   verdict)                         | |   & claim citation diagnostics)    |
+------------------------------------+ +------------------------------------+
                   |                                     |
                   | (Contextual Metadata Only)          | (Grounding & Validation
                   |                                     |  Diagnostics)
                   +------------------+------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                      CONFIDENCE ENGINE (CE) [DHCI]                          |
|  - Telemetry Coverage (Phi_cov)                                            |
|  - Intrinsic Reliability (Phi_rel)                                         |
|  - Graph Corroboration (Phi_cor) [7 Operational Clusters]                  |
|  - Contradiction Penalty (Phi_contra)                                      |
|  - Structural Provenance Audit Gate (G_prov)                               |
|  - Interpretation Fidelity (C_interp)                                      |
|  - Composite Overall Confidence (C_overall)                                |
|  - Prototype Abstention & Workflow Review Flags                            |
+-----------------------------------------------------------------------------+
```

### Core Invariants:
1. **TCE Sovereignty:** TCE remains the **sole mathematical authority** for `risk_score`, `trust_score`, and `verdict`. Confidence Engine never recalculates or modifies TCE outputs.
2. **Deterministic & Non-LLM Execution:** Zero LLM calls, zero natural language interpretation, zero network calls.
3. **Epistemic vs. Threat Distinction:** *"Grounding validity is not truth, and confidence is not probability."*
4. **Zero Active Evidence Guard:** $|\mathcal{E}_{\text{active}}| = 0 \implies \mathcal{C}_{\text{ev}} = 0.0$ and $\mathcal{C}_{\text{overall}} = 0.0$.
5. **No Autonomous Enforcement:** Abstention recommendations are prototype workflow review flags, never autonomous enforcement authorization.

---

## 2. Seven Operational Source Clusters

All 18 forensic agents are partitioned into exactly seven disjoint clusters for dependency and collinearity control:

| Cluster Identifier | Cluster Name | Member Agents | Scope & Modality |
| :--- | :--- | :--- | :--- |
| $\mathcal{K}_{\text{InfraNet}}$ | Infrastructure & Network | A1 (`Domain`), A2 (`DNS`), A5 (`URL`), A16 (`Network Security`) | Authoritative DNS, WHOIS, lexical features, open ports, and transport security headers. |
| $\mathcal{K}_{\text{Crypto}}$ | Cryptographic & Transport | A3 (`SSL/HTTPS`) | TLS connection, X.509 cert chains, cipher suites, and validity. |
| $\mathcal{K}_{\text{IntelMalw}}$ | Threat Intel & Malware | A6 (`Reputation`), A17 (`Malware Indicators`) | Multi-source reputation feeds, blocklists, YARA static signatures. |
| $\mathcal{K}_{\text{ContentTech}}$ | Content & Technology | A4 (`Content`), A7 (`Technical Fingerprinting`), A11 (`Content Quality`) | DOM structure, CMS/framework fingerprinting, text quality, scam keywords. |
| $\mathcal{K}_{\text{BehavVisual}}$ | Behavioral & Visual UI | A8 (`Behavior`), A9 (`Brand`), A10 (`Visual/UI`) | Dynamic JS heuristics, form harvesting, logo/favicon matching, screenshots, OCR. |
| $\mathcal{K}_{\text{OSINTTrust}}$ | OSINT, History & Trust | A12 (`Contact`), A13 (`OSINT`), A14 (`History`), A15 (`User Trust`) | Contact validation, social presence, Wayback Machine archives, consumer reviews. |
| $\mathcal{K}_{\text{QR}}$ | Physical & QR Modality | A18 (`QR Analysis`) | 2D barcode payload extraction, visual obfuscation, error correction parsing. |

---

## 3. Mathematical Formulation

### 3.1 Telemetry Coverage ($\Phi_{\text{cov}}$)
$$\Phi_{\text{cov}} = \begin{cases} \left(\dfrac{\text{observed\_applicable}}{\text{applicable}}\right) \times 100.0 & \text{if } \text{applicable} > 0 \\ 0.0 & \text{if } \text{applicable} = 0 \end{cases}$$
- Standard URL & QR with URL: `applicable = 18`
- QR plain text non-URL: `applicable = 1`

### 3.2 Intrinsic Reliability ($\Phi_{\text{rel}}$)
$$\Phi_{\text{rel}} = \begin{cases} \dfrac{\sum_{e \in \mathcal{E}_{\text{active}}} \left( w_{\text{type}}(e) \cdot s_e \right)}{\sum_{e \in \mathcal{E}_{\text{active}}} s_e} \times 100.0 & \text{if } |\mathcal{E}_{\text{active}}| > 0 \\ 0.0 & \text{if } |\mathcal{E}_{\text{active}}| = 0 \end{cases}$$
Priors ($w_{\text{type}}$): `deterministic = 1.00`, `external_source = 0.85`, `threat_intelligence = 0.80`, `historical = 0.70`, `inference = 0.50`, `subjective = 0.30`.

### 3.3 Graph Corroboration ($\Phi_{\text{cor}}$)
$$\Phi_{\text{cor}} = \begin{cases} 0.0 & \text{if } N_{\text{concordant\_clusters}} < 2 \\ 100.0 \times \left(1.0 - e^{-0.45 \cdot N_{\text{concordant\_clusters}}}\right) & \text{if } N_{\text{concordant\_clusters}} \ge 2 \end{cases}$$

### 3.4 Contradiction Penalty ($\Phi_{\text{contra}}$)
$$\Phi_{\text{contra}} = 100.0 \times \max\left(0.0, 1.0 - 2.0 \cdot \gamma_{\text{contra}}\right)$$
$$\gamma_{\text{contra}} = \dfrac{|\mathcal{E}_{\text{contradicted}}|}{|\mathcal{E}_{\text{active}}|}$$

### 3.5 Evidence Confidence Synthesis ($\mathcal{C}_{\text{ev}}$)
$$\mathcal{C}_{\text{ev}} = \begin{cases} 0.0 & \text{if } |\mathcal{E}_{\text{active}}| = 0 \\ \mathcal{G}_{\text{prov}} \times \left(0.40 \cdot \Phi_{\text{cov}} + 0.30 \cdot \Phi_{\text{rel}} + 0.30 \cdot \Phi_{\text{cor}}\right) \times \left(\dfrac{\Phi_{\text{contra}}}{100.0}\right) & \text{if } |\mathcal{E}_{\text{active}}| > 0 \end{cases}$$

### 3.6 Interpretation Fidelity Confidence ($\mathcal{C}_{\text{interp}}$)
$$\mathcal{C}_{\text{interp}} = \begin{cases} 100.0 \times \rho_{\text{ground}} & \text{if } \text{ReasoningStatus} = \text{"success"} \\ 50.0 & \text{if } \text{ReasoningStatus} = \text{"fallback"} \quad [\text{UNCALIBRATED POLICY PRIOR}] \\ 0.0 & \text{if } \text{ReasoningStatus} \in \{\text{"rejected"}, \text{"error"}\} \end{cases}$$

### 3.7 Composite Overall Confidence ($\mathcal{C}_{\text{overall}}$)
$$\mathcal{C}_{\text{overall}} = \mathcal{C}_{\text{ev}} \times \left[ 0.30 + 0.70 \cdot \left(\frac{\mathcal{C}_{\text{interp}}}{100.0}\right) \right]$$

---

## 4. Usage Example

```python
from services.evidence_ledger import EvidenceLedger
from services.confidence_engine import ConfidenceEngine

ledger = EvidenceLedger(target="https://example.com")
# ... agents add entries to ledger ...
ledger.correlate_relationships()

engine = ConfidenceEngine()
output = engine.evaluate_confidence(
    ledger=ledger,
    aere_result=aere_res,
    tce_result=tce_res,
    pipeline_session=session
)

print(f"Evidence Confidence: {output.evidence_confidence}")
print(f"Interpretation Confidence: {output.interpretation_confidence}")
print(f"Composite Confidence: {output.composite_confidence}")
print(f"Abstention Reason: {output.abstention_reason}")
```
