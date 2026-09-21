"""
Central Forensics Pipeline Controller
Multi-Agent Digital Forensics System

Manages the end-to-end execution workflow for both manual URLs and QR code image inputs.
Maintains the unified target principle:
- Manual URL -> URL -> Agents 1–17 (+ Agent 18 URL inspection) -> Central Evidence Store -> Evidence Ledger -> TCE -> AERE
- QR Image   -> Agent 18 (Decode) -> Extracted URL -> Agents 1–17 (+ Agent 18 QR Evidence) -> Central Evidence Store -> Evidence Ledger -> TCE -> AERE
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union

# Import all isolated agent engines with their exact function names
from agents.agent1_domain import analyze_domain
from agents.agent2_dns import analyze_dns
from agents.agent3_ssl import analyze_ssl
from agents.agent4_content import analyze_content
from agents.agent5_url import analyze_url
from agents.agent6_reputation import analyze_reputation
from agents.agent7_fingerprinting import analyze_fingerprint
from agents.agent8_behavior import analyze_behavior
from agents.agent9_brand import analyze_brand
from agents.agent10_visual import analyze_visual
from agents.agent11_content_quality import analyze_content_quality
from agents.agent12_contact import analyze_contact
from agents.agent13_osint import analyze_osint
from agents.agent14_history import analyze_history
from agents.agent15_trust import analyze_user_trust
from agents.agent16_network import analyze_network_security
from agents.agent17_malware import analyze_malware_indicators
from agents.agent18_qr import analyze_qr, decode_qr_image, extract_embedded_url
from services.evidence_ledger import EvidenceLedger
from services.trust_calculation_engine import TrustCalculationEngine
from services.aere_input_builder import build_aere_input_payload
from services.aere_reasoning_engine import AEREReasoningEngine
from services.aere_provider import MockProvider


# Mapping of Agent Number to its analysis function
AGENT_RUNNERS = {
    1: analyze_domain,
    2: analyze_dns,
    3: analyze_ssl,
    4: analyze_content,
    5: analyze_url,
    6: analyze_reputation,
    7: analyze_fingerprint,
    8: analyze_behavior,
    9: analyze_brand,
    10: analyze_visual,
    11: analyze_content_quality,
    12: analyze_contact,
    13: analyze_osint,
    14: analyze_history,
    15: analyze_user_trust,
    16: analyze_network_security,
    17: analyze_malware_indicators,
    18: analyze_qr
}


def run_single_agent(agent_id: int, target_url: str, **kwargs) -> Dict[str, Any]:
    """
    Run a specific agent on the target URL without duplicating logic.
    """
    runner = AGENT_RUNNERS.get(agent_id)
    if not runner:
        return {
            "agent_id": agent_id,
            "status": "error",
            "error": f"Agent {agent_id} is not registered."
        }

    try:
        if agent_id == 18:
            # Agent 18 can take either url or image_input
            image_input = kwargs.get("image_input")
            return runner(image_input=image_input, url=target_url)
        else:
            return runner(target_url)
    except Exception as e:
        return {
            "agent": f"Agent {agent_id}",
            "agent_id": agent_id,
            "status": "error",
            "errors": [{"component": f"agent{agent_id}", "error": f"Execution failed: {str(e)}"}],
            "trust_score": None,
            "risk_score": None,
            "verdict": "not_calculated"
        }


def process_qr_upload(image_input: Union[str, bytes]) -> Dict[str, Any]:
    """
    Decode an uploaded QR code and extract the target URL.
    Returns the initial QR decoding result and extracted URL for the pipeline.
    """
    decoding_info = decode_qr_image(image_input)
    if not decoding_info.get("decoded"):
        return {
            "success": False,
            "decoded": False,
            "error": decoding_info.get("error", "QR code could not be decoded."),
            "target_url": None,
            "data_type": "none",
            "payload": None
        }

    payload = decoding_info.get("decoded_data", "")
    target_url, is_url = extract_embedded_url(payload)

    return {
        "success": True,
        "decoded": True,
        "payload": payload,
        "data_type": decoding_info.get("data_type", "TEXT"),
        "is_url": is_url,
        "target_url": target_url if is_url else None,
        "qr_version": decoding_info.get("qr_version", "unknown"),
        "error_correction_level": decoding_info.get("error_correction_level", "unknown")
    }


def create_analysis_session(
    input_type: str,
    original_input: str,
    target_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Initialize a common analysis object structure.
    """
    session_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    return {
        "session_id": session_id,
        "input_type": input_type,  # 'url' or 'qr'
        "original_input": original_input,
        "target_url": target_url or (original_input if input_type == "url" else None),
        "created_at": created_at,
        "status": "initialized",
        "agents": {f"agent{i}": None for i in range(1, 19)},
        "all_evidence": [],
        "evidence_ledger": None,
        "tce_summary": None,
        "trust_score": None,
        "risk_score": None,
        "verdict": "not_calculated",
        "aere": None
    }


def _execute_aere_reasoning_layer(
    ledger: EvidenceLedger,
    tce_res: Dict[str, Any],
    target: Optional[Union[str, Dict[str, Any]]],
    session_id: Optional[str],
    aere_provider: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Internal helper to mediate and execute the AERE Reasoning Engine orchestration layer.
    Ensures complete failure isolation so AERE exceptions cannot corrupt or abort the pipeline.
    """
    try:
        aere_input = build_aere_input_payload(
            ledger=ledger,
            tce_result=tce_res,
            target=target,
            investigation_id=session_id
        )
        provider = aere_provider if aere_provider is not None else MockProvider()
        reasoning_engine = AEREReasoningEngine(provider=provider, max_regeneration_attempts=1)
        return reasoning_engine.execute_reasoning(aere_input)
    except Exception as aere_err:
        return {
            "status": "fallback",
            "aere_output": None,
            "candidate_output": None,
            "tce_preserved": True,
            "tce_result": tce_res,
            "grounding_report": None,
            "failure": {
                "stage": "pipeline_integration_exception",
                "reason": str(aere_err),
                "attempts_conducted": 0,
                "max_regeneration_attempts": 1,
                "invalid_evidence_ids": [],
                "affected_claims": []
            },
            "execution_metadata": {
                "engine_version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "provider_name": "unknown",
                "model_id": None,
                "generation_temperature": None,
                "attempt_count": 0,
                "max_regeneration_attempts": 1,
                "input_contract_valid": False,
                "output_contract_valid": False,
                "grounding_validation_status": None,
                "failure_stage": "pipeline_integration_exception",
                "fallback_used": True,
                "attempt_history": []
            }
        }


def finalize_session_from_agent_results(
    target_url: str,
    agent_results: Dict[Union[str, int], Any],
    input_type: str = "url",
    original_input: Optional[str] = None,
    session_id: Optional[str] = None,
    aere_provider: Optional[Any] = None,
    enable_aere: bool = True
) -> Dict[str, Any]:
    """
    Finalize an authoritative investigation session from already-collected agent findings.
    Performs normalization, Evidence Ledger construction, relationship correlation,
    TCE Trust & Risk calculation, and AERE qualitative reasoning WITHOUT re-executing Agents 1–18.
    """
    session = create_analysis_session(
        input_type=input_type,
        original_input=original_input or target_url,
        target_url=target_url
    )
    if session_id:
        session["session_id"] = session_id

    # Normalize agent keys (support 'agent1', '1', 1, 'A01', etc.)
    for i in range(1, 19):
        agent_key = f"agent{i}"
        val = (
            agent_results.get(agent_key) or
            agent_results.get(str(i)) or
            agent_results.get(i) or
            agent_results.get(f"A{i}") or
            agent_results.get(f"A{String(i).zfill(2)}" if False else None)
        )
        session["agents"][agent_key] = val

    # Aggregate all evidence items into central store & Evidence Ledger
    all_evidence = []
    ledger = EvidenceLedger(target=target_url)

    for i in range(1, 19):
        agent_data = session["agents"].get(f"agent{i}")
        if agent_data and isinstance(agent_data, dict):
            ev_list = agent_data.get("evidence", [])
            if isinstance(ev_list, list):
                all_evidence.extend(ev_list)
            ledger.add_entries_from_agent(agent_data)

    ledger.correlate_relationships()

    # Calculate Trust & Risk via deterministic TCE (Sole authority)
    tce = TrustCalculationEngine()
    tce_res = tce.calculate_trust(ledger)

    session["all_evidence"] = all_evidence
    session["evidence_ledger"] = ledger.to_dict()
    session["tce_summary"] = tce_res
    session["status"] = "completed"
    session["trust_score"] = tce_res["trust_score"]
    session["risk_score"] = tce_res["risk_score"]
    session["verdict"] = tce_res["verdict"]

    # Execute AERE Evidence Reasoning Layer (Additive, Sovereign TCE)
    if enable_aere:
        session["aere"] = _execute_aere_reasoning_layer(
            ledger=ledger,
            tce_res=tce_res,
            target=target_url,
            session_id=session.get("session_id"),
            aere_provider=aere_provider
        )
    else:
        session["aere"] = None

    return session


def run_full_pipeline(
    input_data: Union[str, bytes],
    input_type: str = "url",
    aere_provider: Optional[Any] = None,
    enable_aere: bool = True
) -> Dict[str, Any]:
    """
    Execute the entire 18-agent forensic analysis pipeline.
    Ensures that if input is QR, the extracted URL becomes the target for Agents 1–17.
    Normalizes evidence, constructs Investigation Evidence Ledger, calculates Trust/Risk,
    and executes AERE Evidence Reasoning as an additive qualitative layer.
    """
    target_url = None
    agent18_result = None

    if input_type == "qr":
        # Decode QR first
        qr_init = process_qr_upload(input_data)
        if not qr_init["success"] or not qr_init["decoded"]:
            session = create_analysis_session(input_type="qr", original_input="[QR Image]", target_url=None)
            session["status"] = "error"
            session["error"] = qr_init.get("error", "QR decoding failed.")
            return session

        if not qr_init["is_url"] or not qr_init["target_url"]:
            session = create_analysis_session(input_type="qr", original_input=qr_init["payload"], target_url=None)
            session["status"] = "completed_non_url"
            session["message"] = "QR code contains plain text rather than a web URL."
            # Run Agent 18 QR-specific analysis
            session["agents"]["agent18"] = analyze_qr(image_input=input_data)
            ledger = EvidenceLedger(target=qr_init["payload"])
            ledger.add_entries_from_agent(session["agents"]["agent18"])
            ledger.correlate_relationships()
            session["evidence_ledger"] = ledger.to_dict()
            tce = TrustCalculationEngine()
            tce_res = tce.calculate_trust(ledger)
            session["tce_summary"] = tce_res
            session["trust_score"] = tce_res["trust_score"]
            session["risk_score"] = tce_res["risk_score"]
            session["verdict"] = tce_res["verdict"]

            if enable_aere:
                session["aere"] = _execute_aere_reasoning_layer(
                    ledger=ledger,
                    tce_res=tce_res,
                    target=qr_init["payload"],
                    session_id=session.get("session_id"),
                    aere_provider=aere_provider
                )
            else:
                session["aere"] = None

            return session

        target_url = qr_init["target_url"]
        agent18_result = analyze_qr(image_input=input_data)
        session = create_analysis_session(input_type="qr", original_input=qr_init["payload"], target_url=target_url)

    else:
        target_url = str(input_data).strip()
        session = create_analysis_session(input_type="url", original_input=target_url, target_url=target_url)
        agent18_result = analyze_qr(url=target_url)

    session["status"] = "running"
    session["target_url"] = target_url

    # Execute Agents 1–17 on the target URL
    for i in range(1, 18):
        agent_key = f"agent{i}"
        session["agents"][agent_key] = run_single_agent(i, target_url)

    # Attach Agent 18 result
    session["agents"]["agent18"] = agent18_result

    return finalize_session_from_agent_results(
        target_url=target_url,
        agent_results=session["agents"],
        input_type=input_type,
        original_input=session["original_input"],
        session_id=session["session_id"],
        aere_provider=aere_provider,
        enable_aere=enable_aere
    )

