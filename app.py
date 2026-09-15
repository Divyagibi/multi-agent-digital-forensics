from flask import Flask, request, jsonify, render_template

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
from services.analysis_pipeline import run_full_pipeline, process_qr_upload, run_single_agent
from services.report_generator import generate_investigator_report

app = Flask(__name__)


@app.route("/")
def home():
    """
    Serve the main multi-agent digital forensics dashboard.
    """
    return render_template("index.html")


@app.route("/api/agent1", methods=["POST"])
def agent1_domain_endpoint():
    """
    Endpoint for Agent 1: Domain Identity
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_domain(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 1: {str(e)}"]
        }), 500


@app.route("/api/agent2", methods=["POST"])
def agent2_dns_endpoint():
    """
    Endpoint for Agent 2: DNS & Infrastructure
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_dns(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 2: {str(e)}"]
        }), 500


@app.route("/api/agent3", methods=["POST"])
def agent3_ssl_endpoint():
    """
    Endpoint for Agent 3: SSL / HTTPS Security
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_ssl(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 3: {str(e)}"]
        }), 500


@app.route("/api/agent4", methods=["POST"])
def agent4_content_endpoint():
    """
    Endpoint for Agent 4: Website Content Analysis
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_content(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 4: {str(e)}"]
        }), 500


@app.route("/api/agent5", methods=["POST"])
def agent5_url_endpoint():
    """
    Endpoint for Agent 5: URL Structure Analysis
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_url(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 5: {str(e)}"]
        }), 500


@app.route("/api/agent6", methods=["POST"])
def agent6_reputation_endpoint():
    """
    Endpoint for Agent 6: Reputation & Threat Intelligence
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_reputation(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 6",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 6: {str(e)}"]
        }), 500


@app.route("/api/agent7", methods=["POST"])
def agent7_fingerprint_endpoint():
    """
    Endpoint for Agent 7: Technical Fingerprinting
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_fingerprint(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 7",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 7: {str(e)}"]
        }), 500


@app.route("/api/agent8", methods=["POST"])
def agent8_behavior_endpoint():
    """
    Endpoint for Agent 8: Website Behavior Analysis
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_behavior(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 8",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 8: {str(e)}"]
        }), 500


@app.route("/api/agent9", methods=["POST"])
def agent9_brand_endpoint():
    """
    Endpoint for Agent 9: Brand Verification
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_brand(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 9",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 9: {str(e)}"]
        }), 500


@app.route("/api/agent10", methods=["POST"])
def agent10_visual_endpoint():
    """
    Endpoint for Agent 10: Visual & UI Analysis
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_visual(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 10",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 10: {str(e)}"]
        }), 500


@app.route("/api/agent11", methods=["POST"])
def agent11_content_quality_endpoint():
    """
    Endpoint for Agent 11: Content Quality Analysis
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_content_quality(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 11",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 11: {str(e)}"]
        }), 500





@app.route("/api/agent12", methods=["POST"])
def agent12_contact_endpoint():
    """
    Endpoint for Agent 12: Contact Verification
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_contact(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 12",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 12: {str(e)}"]
        }), 500


@app.route("/api/agent13", methods=["POST"])
def agent13_osint_endpoint():
    """
    Endpoint for Agent 13: External Presence / OSINT Agent
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_osint(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 13",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 13: {str(e)}"]
        }), 500


@app.route("/api/agent14", methods=["POST"])
def agent14_history_endpoint():
    """
    Endpoint for Agent 14: Historical Evidence Agent
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_history(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 14",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 14: {str(e)}"]
        }), 500


@app.route("/api/agent15", methods=["POST"])
def agent15_trust_endpoint():
    """
    Endpoint for Agent 15: User Trust Signals Agent
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_user_trust(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 15",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 15: {str(e)}"]
        }), 500


@app.route("/api/agent16", methods=["POST"])
def agent16_network_endpoint():
    """
    Endpoint for Agent 16: Network Security Analysis Agent
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_network_security(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 16",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 16: {str(e)}"]
        }), 500


@app.route("/api/agent17", methods=["POST"])
def agent17_malware_endpoint():
    """
    Endpoint for Agent 17: Malware Indicators Analysis Agent
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        result = analyze_malware_indicators(url.strip())
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 17",
            "status": "error",
            "data": {},
            "errors": [f"Server internal error in Agent 17: {str(e)}"]
        }), 500


@app.route("/api/agent18", methods=["POST"])
def agent18_qr_endpoint():
    """
    Endpoint for Agent 18: QR Code Analysis Agent
    Accepts JSON with 'url' or 'qr_image' (base64 or path), or multipart form upload.
    """
    url = None
    image_input = None

    if request.is_json:
        data = request.get_json() or {}
        url = data.get("url")
        image_input = data.get("qr_image") or data.get("image")
    else:
        url = request.form.get("url")
        if "qr_image" in request.files:
            file = request.files["qr_image"]
            if file and file.filename:
                image_input = file.read()

    if not url and not image_input:
        return jsonify({"error": "Either URL or QR image is required"}), 400

    try:
        result = analyze_qr(image_input=image_input, url=url.strip() if url else None)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "agent": "Agent 18",
            "status": "error",
            "errors": [{"component": "agent18", "error": f"Server internal error in Agent 18: {str(e)}"}],
            "trust_score": None,
            "risk_score": None,
            "verdict": "not_calculated"
        }), 500


@app.route("/api/analyze-qr", methods=["POST"])
def analyze_qr_endpoint():
    """
    Endpoint for uploading and decoding a QR code image.
    Returns decoded data, extracted target URL, and initial format analysis.
    """
    image_input = None

    if "qr_image" in request.files:
        file = request.files["qr_image"]
        if file and file.filename:
            image_input = file.read()
    elif request.is_json:
        data = request.get_json() or {}
        image_input = data.get("qr_image") or data.get("image")
    elif "qr_image" in request.form:
        image_input = request.form.get("qr_image")

    if not image_input:
        return jsonify({"success": False, "error": "QR image file or base64 data is required."}), 400

    try:
        result = process_qr_upload(image_input)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            "success": False,
            "decoded": False,
            "error": f"Error processing QR image: {str(e)}"
        }), 500


@app.route("/api/pipeline/run", methods=["POST"])
@app.route("/api/analyze/full", methods=["POST"])
def pipeline_run_endpoint():
    """
    Unified endpoint to execute the full 18-agent pipeline for URL or QR code.
    Returns session object containing agent results, central evidence, and Evidence Ledger.
    """
    input_type = "url"
    input_data = None

    if "qr_image" in request.files:
        file = request.files["qr_image"]
        if file and file.filename:
            input_data = file.read()
            input_type = "qr"
    elif request.is_json:
        data = request.get_json() or {}
        if data.get("qr_image") or data.get("image"):
            input_data = data.get("qr_image") or data.get("image")
            input_type = "qr"
        elif data.get("url"):
            input_data = data.get("url")
            input_type = "url"

    if not input_data:
        return jsonify({"error": "Target URL or QR image is required"}), 400

    try:
        session = run_full_pipeline(input_data=input_data, input_type=input_type)
        return jsonify(session)
    except Exception as e:
        return jsonify({"error": f"Pipeline execution failed: {str(e)}"}), 500


@app.route("/api/evidence-ledger", methods=["POST"])
def evidence_ledger_endpoint():
    """
    Endpoint to retrieve only the normalized Evidence Ledger for a target.
    """
    data = request.get_json() or {}
    url = data.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "URL is required"}), 400

    try:
        session = run_full_pipeline(input_data=url.strip(), input_type="url")
        return jsonify(session.get("evidence_ledger", {}))
    except Exception as e:
        return jsonify({"error": f"Evidence Ledger generation failed: {str(e)}"}), 500


@app.route("/api/report", methods=["POST"])
def report_endpoint():
    """
    Endpoint to generate the Final Investigator Report (Step 5B).
    Accepts either an existing completed session or a target url/qr_image.
    Returns the serialized InvestigatorReportPayload JSON.
    """
    data = request.get_json() or {}
    session = data.get("session")

    if not session:
        url = data.get("url")
        qr_image = data.get("qr_image")
        if qr_image:
            session = run_full_pipeline(input_data=qr_image, input_type="qr")
        elif url:
            session = run_full_pipeline(input_data=url.strip(), input_type="url")
        else:
            return jsonify({"error": "Session, URL, or QR image is required"}), 400

    confidence_payload = data.get("confidence_payload") or session.get("confidence")

    try:
        report = generate_investigator_report(session=session, confidence_payload=confidence_payload)
        return jsonify(report.to_dict())
    except Exception as e:
        return jsonify({"error": f"Investigator Report generation failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )