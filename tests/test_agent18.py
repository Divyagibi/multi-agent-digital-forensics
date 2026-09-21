import unittest
from unittest.mock import patch, MagicMock
import json
import io
import qrcode
from PIL import Image

from agents.agent18_qr import (
    analyze_qr,
    decode_qr_image,
    extract_embedded_url,
    normalize_qr_url,
    trace_redirect_chain,
    detect_shortened_url,
    inspect_hidden_parameters,
    analyze_qr_modifications,
    compile_qr_evidence
)
from services.analysis_pipeline import (
    process_qr_upload,
    create_analysis_session,
    run_single_agent,
    run_full_pipeline
)
from app import app


def _create_qr_image_bytes(data: str) -> bytes:
    """Helper to generate a valid QR code in memory as PNG bytes."""
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestAgent18QR(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    # 1. QR Decoding: Valid URL QR Code
    def test_qr_decoding_valid_url(self):
        url = "https://example.com/login?id=123"
        img_bytes = _create_qr_image_bytes(url)
        res = decode_qr_image(img_bytes)

        self.assertTrue(res["decoded"])
        self.assertEqual(res["decoded_data"], url)
        self.assertEqual(res["data_type"], "URL")
        self.assertIsNotNone(res["points"])

    # 2. QR Decoding: Plain Text (No URL)
    def test_qr_decoding_plain_text(self):
        text = "Order #98421 Verified"
        img_bytes = _create_qr_image_bytes(text)
        res = decode_qr_image(img_bytes)

        self.assertTrue(res["decoded"])
        self.assertEqual(res["decoded_data"], text)
        self.assertEqual(res["data_type"], "TEXT")

        ext_url, is_url = extract_embedded_url(text)
        self.assertFalse(is_url)
        self.assertIsNone(ext_url)

    # 3. QR Decoding: Wi-Fi and SMS Data Types
    def test_qr_decoding_special_types(self):
        wifi_data = "WIFI:S:MyGuestNetwork;T:WPA;P:SuperSecretPass;;"
        wifi_bytes = _create_qr_image_bytes(wifi_data)
        res_wifi = decode_qr_image(wifi_bytes)
        self.assertTrue(res_wifi["decoded"])
        self.assertEqual(res_wifi["data_type"], "WIFI_CONFIG")

        sms_data = "SMSTO:+1234567890:Hello there"
        sms_bytes = _create_qr_image_bytes(sms_data)
        res_sms = decode_qr_image(sms_bytes)
        self.assertTrue(res_sms["decoded"])
        self.assertEqual(res_sms["data_type"], "SMS")

    # 4. Embedded URL Extraction Patterns
    def test_embedded_url_extraction_patterns(self):
        # Direct URL
        url1, is_url1 = extract_embedded_url("https://example.org/path")
        self.assertTrue(is_url1)
        self.assertEqual(url1, "https://example.org/path")

        # URL= prefix
        url2, is_url2 = extract_embedded_url("URL:https://security.example.com/verify")
        self.assertTrue(is_url2)
        self.assertEqual(url2, "https://security.example.com/verify")

        # Text with embedded URL
        url3, is_url3 = extract_embedded_url("Please visit https://portal.company.test/login for details")
        self.assertTrue(is_url3)
        self.assertEqual(url3, "https://portal.company.test/login")

        # Plain text without URL
        url4, is_url4 = extract_embedded_url("Invoice #4401 Paid in Full")
        self.assertFalse(is_url4)
        self.assertIsNone(url4)

    # 5. URL Normalization
    def test_url_normalization(self):
        norm = normalize_qr_url("https://sub.example.com:8443/login?redirect=https%3A%2F%2Fother.com&ref=qr#section1")
        self.assertEqual(norm["scheme"], "https")
        self.assertEqual(norm["hostname"], "sub.example.com")
        self.assertEqual(norm["domain"], "example.com")
        self.assertEqual(norm["port"], 8443)
        self.assertEqual(norm["path"], "/login")
        self.assertEqual(norm["fragment"], "section1")
        self.assertIn("redirect", norm["query_params"])
        self.assertIn("ref", norm["query_params"])

    # 6. Shortened URL Detection
    def test_shortened_url_detection(self):
        short1 = detect_shortened_url("bit.ly", "bit.ly")
        self.assertTrue(short1["detected"])
        self.assertEqual(short1["provider"], "bit.ly")
        self.assertEqual(short1["risk_indicator"], "url_shortener")

        short2 = detect_shortened_url("tinyurl.com", "tinyurl.com")
        self.assertTrue(short2["detected"])
        self.assertEqual(short2["provider"], "tinyurl.com")

        normal = detect_shortened_url("example.com", "example.com")
        self.assertFalse(normal["detected"])
        self.assertIsNone(normal["provider"])

    # 7. Hidden Parameters & Open-Redirect Inspection
    def test_hidden_parameters_open_redirect(self):
        query_params = {
            "redirect": "https://malicious.example.com/steal",
            "next": "/account/dashboard",
            "token": "YWxlcnQoMSk=",  # Base64 string
            "view": "grid"
        }
        findings = inspect_hidden_parameters(query_params, "redirect=https://malicious.example.com/steal&next=/account/dashboard&token=YWxlcnQoMSk=&view=grid")
        self.assertGreaterEqual(len(findings), 2)
        param_names = [f["parameter_name"] for f in findings]
        self.assertIn("redirect", param_names)
        self.assertIn("token", param_names)

    # 8. Redirect Chain Tracing (Mocked HTTP Hops)
    @patch("agents.agent18_qr.requests.Session.get")
    def test_redirect_chain_tracing(self, mock_get):
        # Hop 1: 301 to https://example.com
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {"Location": "https://example.com"}

        # Hop 2: 302 to https://example.com/dashboard
        resp2 = MagicMock()
        resp2.status_code = 302
        resp2.headers = {"Location": "https://example.com/dashboard"}

        # Hop 3: 200 Final
        resp3 = MagicMock()
        resp3.status_code = 200
        resp3.headers = {}

        mock_get.side_effect = [resp1, resp2, resp3]

        chain = trace_redirect_chain("https://bit.ly/test1234")
        self.assertEqual(chain["redirect_count"], 2)
        self.assertTrue(chain["has_redirects"])
        self.assertEqual(chain["final_url"], "https://example.com/dashboard")
        self.assertEqual(len(chain["redirect_chain"]), 3)
        self.assertEqual(chain["redirect_chain"][0], "https://bit.ly/test1234")
        self.assertEqual(chain["redirect_chain"][1], "https://example.com")
        self.assertEqual(chain["redirect_chain"][2], "https://example.com/dashboard")

    # 9. QR Modification Analysis Heuristics
    def test_qr_modifications_heuristics(self):
        img_bytes = _create_qr_image_bytes("https://example.com/test")
        mod_res = analyze_qr_modifications(img_bytes, points=[[0, 0], [10, 0], [10, 10], [0, 10]])
        self.assertIn(mod_res["status"], ["not_detected", "suspected", "detected", "unknown"])
        self.assertEqual(mod_res["finder_patterns_integrity"], "valid")

    # 10. Standardized Evidence Compilation
    def test_compile_qr_evidence(self):
        qr_dec = {"decoded": True, "data_type": "URL", "payload": "https://bit.ly/test"}
        embedded_url = {"detected": True, "url": "https://bit.ly/test"}
        redirect_data = {"has_redirects": True, "redirect_count": 1, "redirect_chain": ["https://bit.ly/test", "https://example.com"]}
        shortened_data = {"detected": True, "provider": "bit.ly"}
        hidden_params = [{"parameter_name": "dest", "decoded_value": "https://bad.com", "type": "open_redirect_candidate"}]
        mod_analysis = {"status": "not_detected", "indicators": []}
        error_correction = {"version": 1, "level": "M"}

        evidence = compile_qr_evidence(
            qr_dec, embedded_url, redirect_data, shortened_data,
            hidden_params, mod_analysis, error_correction
        )
        self.assertGreaterEqual(len(evidence), 5)
        categories = [e["category"] for e in evidence]
        self.assertIn("qr_format_parsed", categories)
        self.assertIn("url_shortener_redirect", categories)
        self.assertIn("automatic_client_redirect", categories)
        self.assertIn("hidden_redirect_parameter", categories)
        self.assertIn("clean_qr_image_structure", categories)

    # 11. Full Agent 18 Analysis with QR Image
    def test_analyze_qr_with_image(self):
        url = "https://example.com/portal?ref=qr"
        img_bytes = _create_qr_image_bytes(url)
        res = analyze_qr(image_input=img_bytes)

        self.assertEqual(res["agent"], "Agent 18")
        self.assertEqual(res["agent_id"], 18)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["qr_decoding"]["decoded"])
        self.assertEqual(res["embedded_url"]["url"], url)
        self.assertIn("legacy", res)
        self.assertIsNone(res["legacy"]["trust_score"])
        self.assertIsNone(res["legacy"]["risk_score"])
        self.assertEqual(res["legacy"]["verdict"], "not_calculated")

    # 12. Full Agent 18 Analysis with Direct URL
    def test_analyze_qr_with_direct_url(self):
        url = "https://tinyurl.com/abc1234?redirect=https%3A%2F%2Fother.test"
        res = analyze_qr(url=url)

        self.assertEqual(res["agent"], "Agent 18")
        self.assertEqual(res["agent_id"], 18)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["shortened_url"]["detected"])
        self.assertEqual(res["shortened_url"]["provider"], "tinyurl.com")
        self.assertGreaterEqual(len(res["hidden_parameters"]), 1)

    # 13. Agent 18 Missing Input Handling
    def test_analyze_qr_missing_input(self):
        res = analyze_qr(image_input=None, url=None)
        self.assertEqual(res["status"], "error")
        self.assertGreaterEqual(len(res["errors"]), 1)

    # 14. Unreadable Image Input Handling
    def test_analyze_qr_unreadable_image(self):
        # Create non-QR blank image
        img = Image.new("RGB", (100, 100), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        res = analyze_qr(image_input=buf.getvalue())

        self.assertEqual(res["status"], "error")
        self.assertFalse(res["qr_decoding"]["decoded"])

    # 15. Pipeline: Process QR Upload
    def test_pipeline_process_qr_upload(self):
        url = "https://auth.company.test/login"
        img_bytes = _create_qr_image_bytes(url)
        proc = process_qr_upload(img_bytes)

        self.assertTrue(proc["success"])
        self.assertTrue(proc["decoded"])
        self.assertTrue(proc["is_url"])
        self.assertEqual(proc["target_url"], url)

    # 16. Pipeline: Create Analysis Session
    def test_pipeline_create_session(self):
        session = create_analysis_session(input_type="qr", original_input="https://test.com", target_url="https://test.com")
        self.assertEqual(session["input_type"], "qr")
        self.assertEqual(session["target_url"], "https://test.com")
        self.assertEqual(len(session["agents"]), 18)
        self.assertEqual(session["status"], "initialized")

    # 17. Pipeline: Run Single Agent
    def test_pipeline_run_single_agent(self):
        res18 = run_single_agent(18, "https://example.com")
        self.assertEqual(res18["agent"], "Agent 18")

        res_invalid = run_single_agent(99, "https://example.com")
        self.assertEqual(res_invalid["status"], "error")

    # 18. Pipeline: Full Pipeline Execution with QR Image
    @patch("services.analysis_pipeline.run_single_agent")
    def test_pipeline_run_full_pipeline_qr(self, mock_single):
        mock_single.return_value = {
            "status": "completed",
            "evidence": [{"category": "test", "observation": "sample evidence"}]
        }
        url = "https://target-site.test/app"
        img_bytes = _create_qr_image_bytes(url)
        session = run_full_pipeline(input_data=img_bytes, input_type="qr")

        self.assertEqual(session["status"], "completed")
        self.assertEqual(session["input_type"], "qr")
        self.assertEqual(session["target_url"], url)
        self.assertIsNotNone(session["trust_score"])
        self.assertIsNotNone(session["risk_score"])
        self.assertIn(session["verdict"], ["benign", "low_risk", "suspicious", "high_risk", "malicious", "unknown"])
        self.assertIsNotNone(session["agents"]["agent18"])
        self.assertGreaterEqual(len(session["all_evidence"]), 1)

    # 19. Pipeline: Full Pipeline Execution with Plain Text QR
    def test_pipeline_run_full_pipeline_plain_text_qr(self):
        text = "Just plain invoice text"
        img_bytes = _create_qr_image_bytes(text)
        session = run_full_pipeline(input_data=img_bytes, input_type="qr")

        self.assertEqual(session["status"], "completed_non_url")
        self.assertIsNone(session["target_url"])
        self.assertIn("plain text", session["message"])
        # Agents 1–17 should not be run
        self.assertIsNone(session["agents"]["agent1"])
        # Agent 18 should still be available
        self.assertIsNotNone(session["agents"]["agent18"])

    # 20. API Endpoint: POST /api/agent18 (JSON with URL)
    def test_api_agent18_json_url(self):
        response = self.app.post(
            "/api/agent18",
            data=json.dumps({"url": "https://example.com/checkout"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["agent"], "Agent 18")
        self.assertEqual(data["agent_id"], 18)

    # 21. API Endpoint: POST /api/agent18 (Multipart QR Upload)
    def test_api_agent18_multipart_upload(self):
        img_bytes = _create_qr_image_bytes("https://verified-pay.test")
        data = {
            "qr_image": (io.BytesIO(img_bytes), "qrcode.png")
        }
        response = self.app.post(
            "/api/agent18",
            data=data,
            content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 200)
        res_json = json.loads(response.data)
        self.assertEqual(res_json["agent"], "Agent 18")
        self.assertTrue(res_json["qr_decoding"]["decoded"])
        self.assertEqual(res_json["embedded_url"]["url"], "https://verified-pay.test")

    # 22. API Endpoint: POST /api/analyze-qr (Success)
    def test_api_analyze_qr_success(self):
        img_bytes = _create_qr_image_bytes("https://demo-site.test/login?src=qr")
        data = {
            "qr_image": (io.BytesIO(img_bytes), "sample_qr.png")
        }
        response = self.app.post(
            "/api/analyze-qr",
            data=data,
            content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 200)
        res_json = json.loads(response.data)
        self.assertTrue(res_json["success"])
        self.assertTrue(res_json["decoded"])
        self.assertTrue(res_json["is_url"])
        self.assertEqual(res_json["target_url"], "https://demo-site.test/login?src=qr")

    # 23. API Endpoint: POST /api/analyze-qr (Missing Image)
    def test_api_analyze_qr_missing_image(self):
        response = self.app.post(
            "/api/analyze-qr",
            data={},
            content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 400)
        res_json = json.loads(response.data)
        self.assertFalse(res_json["success"])

    # 24. API Endpoint: POST /api/pipeline/run
    @patch("services.analysis_pipeline.run_single_agent")
    def test_api_pipeline_run(self, mock_single):
        mock_single.return_value = {
            "status": "completed",
            "evidence": [{"category": "domain", "observation": "Domain is active"}]
        }
        response = self.app.post(
            "/api/pipeline/run",
            data=json.dumps({"url": "https://company.test"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        res_json = json.loads(response.data)
        self.assertEqual(res_json["status"], "completed")
        self.assertEqual(res_json["target_url"], "https://company.test")

    # 25. Evidence Type Classification (deterministic / inference, never fake threat_intelligence)
    def test_evidence_type_deterministic_and_not_threat_intelligence(self):
        res = analyze_qr(url="https://bit.ly/test-url")
        evidence = res.get("evidence", [])
        self.assertGreaterEqual(len(evidence), 1)
        for ev in evidence:
            self.assertIn(
                ev.get("type"),
                ["deterministic", "inference"],
                f"Static A18 evidence must be deterministic or inference: {ev}"
            )
            self.assertNotEqual(
                ev.get("type"),
                "threat_intelligence",
                f"Local heuristic must not claim external threat_intelligence: {ev}"
            )

    # 26. SSRF Protection in HTTP Redirect Tracing (private, loopback, metadata blocked)
    def test_ssrf_protection_in_redirect_tracing(self):
        # 127.0.0.1
        res_loopback = trace_redirect_chain("http://127.0.0.1:8080/admin")
        self.assertEqual(res_loopback["redirect_count"], 0)
        self.assertTrue(any("restricted/private IP" in err for err in res_loopback["errors"]))

        # 10.0.0.1
        res_private = trace_redirect_chain("http://10.0.0.1/internal")
        self.assertEqual(res_private["redirect_count"], 0)
        self.assertTrue(any("restricted/private IP" in err for err in res_private["errors"]))

        # 169.254.169.254 (cloud metadata)
        res_meta = trace_redirect_chain("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(res_meta["redirect_count"], 0)
        self.assertTrue(any("restricted/private IP" in err for err in res_meta["errors"]))

    # 27. QR Decoding Failure Severity & Category
    def test_qr_decoding_failure_is_info_neutral(self):
        # Non-QR image
        img = Image.new("RGB", (100, 100), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        res = analyze_qr(image_input=buf.getvalue())

        evidence = res.get("evidence", [])
        dec_ev = [e for e in evidence if e.get("index") == 1 or "decoding" in e.get("finding", "").lower()]
        self.assertTrue(len(dec_ev) > 0)
        for e in dec_ev:
            self.assertEqual(e.get("severity"), "info")
            self.assertEqual(e.get("category"), "qr_format_parsed")

    # 28. High-Risk URI Schemes (javascript:, data:, file:)
    def test_high_risk_uri_schemes(self):
        js_data = "javascript:alert(document.cookie)"
        js_bytes = _create_qr_image_bytes(js_data)
        res_js = decode_qr_image(js_bytes)
        self.assertTrue(res_js["decoded"])
        self.assertEqual(res_js["data_type"], "HIGH_RISK_URI")

        ext_url, is_url = extract_embedded_url(js_data)
        self.assertFalse(is_url)
        self.assertIsNone(ext_url)

        file_data = "file:///etc/shadow"
        file_bytes = _create_qr_image_bytes(file_data)
        res_file = decode_qr_image(file_bytes)
        self.assertTrue(res_file["decoded"])
        self.assertEqual(res_file["data_type"], "HIGH_RISK_URI")

    # 29. Deep Link Schemes (intent://, market://)
    def test_deep_link_schemes(self):
        intent_data = "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end"
        intent_bytes = _create_qr_image_bytes(intent_data)
        res_intent = decode_qr_image(intent_bytes)
        self.assertTrue(res_intent["decoded"])
        self.assertEqual(res_intent["data_type"], "DEEP_LINK")

    # 30. JSON and Benign Non-URL Payloads
    def test_json_and_geolocation_payloads(self):
        json_data = '{"action": "checkin", "location_id": 9941}'
        json_bytes = _create_qr_image_bytes(json_data)
        res_json = decode_qr_image(json_bytes)
        self.assertTrue(res_json["decoded"])
        self.assertEqual(res_json["data_type"], "JSON")

        geo_data = "geo:37.7749,-122.4194"
        geo_bytes = _create_qr_image_bytes(geo_data)
        res_geo = decode_qr_image(geo_bytes)
        self.assertTrue(res_geo["decoded"])
        self.assertEqual(res_geo["data_type"], "GEOLOCATION")

    # 31. False Positive Prevention for Legitimate Payloads
    def test_benign_payload_false_positive_prevention(self):
        bank_url = "https://www.chase.com/personal/banking"
        res = analyze_qr(url=bank_url)
        evidence = res.get("evidence", [])
        for ev in evidence:
            if ev.get("category") in ("clean_qr_destination", "clean_http_route", "clean_query_parameters", "clean_qr_image_structure", "qr_format_parsed"):
                self.assertEqual(ev.get("severity"), "info")

    # 32. TCE Category & Polarity Resolution
    def test_tce_explicit_category_resolution(self):
        from services.tce_config import resolve_evidence_polarity

        # Risk-increasing categories
        self.assertEqual(resolve_evidence_polarity("url_shortener_redirect"), "risk_increasing")
        self.assertEqual(resolve_evidence_polarity("automatic_client_redirect"), "risk_increasing")
        self.assertEqual(resolve_evidence_polarity("hidden_redirect_parameter"), "risk_increasing")
        self.assertEqual(resolve_evidence_polarity("qr_visual_modification"), "risk_increasing")

        # Neutral categories
        self.assertEqual(resolve_evidence_polarity("qr_format_parsed"), "neutral")
        self.assertEqual(resolve_evidence_polarity("clean_qr_destination"), "neutral")
        self.assertEqual(resolve_evidence_polarity("clean_http_route"), "neutral")
        self.assertEqual(resolve_evidence_polarity("clean_query_parameters"), "neutral")
        self.assertEqual(resolve_evidence_polarity("clean_qr_image_structure"), "neutral")


if __name__ == "__main__":
    unittest.main()

