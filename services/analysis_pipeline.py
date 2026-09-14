"""
Central Forensics Pipeline Controller
Multi-Agent Digital Forensics System

Manages the end-to-end execution workflow for both manual URLs and QR code image inputs.
Maintains the unified target principle:
- Manual URL -> URL -> Agents 1–17 (+ Agent 18 URL inspection) -> Central Evidence Store
- QR Image   -> Agent 18 (Decode) -> Extracted URL -> Agents 1–17 (+ Agent 18 QR Evidence) -> Central Evidence Store
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
        "verdict": "not_calculated"
    }


def run_full_pipeline(
    input_data: Union[str, bytes],
    input_type: str = "url"
) -> Dict[str, Any]:
    """
    Execute the entire 18-agent forensic analysis pipeline.
    Ensures that if input is QR, the extracted URL becomes the target for Agents 1–17.
    Normalizes evidence, constructs Investigation Evidence Ledger, and calculates Trust/Risk.
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

    # Aggregate all evidence items into central store
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

    # Calculate Trust & Risk via TCE
    tce = TrustCalculationEngine()
    tce_res = tce.calculate_trust(ledger)

    session["all_evidence"] = all_evidence
    session["evidence_ledger"] = ledger.to_dict()
    session["tce_summary"] = tce_res
    session["status"] = "completed"
    session["trust_score"] = tce_res["trust_score"]
    session["risk_score"] = tce_res["risk_score"]
    session["verdict"] = tce_res["verdict"]

    return session
