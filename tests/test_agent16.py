"""
Unit tests for Agent 16: Network Security Analysis Agent
Tests passive open ports check, HTTP headers, security headers (HSTS, CSP, XFO, etc.),
CORS configuration, server fingerprinting, private IP validation, and Flask API endpoint.
"""

import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from agents.agent16_network import (
    analyze_network_security,
    _normalize_target,
    _is_private_or_restricted_ip,
    _resolve_target_ip,
    check_open_ports,
    fetch_http_headers,
    parse_hsts_header,
    parse_csp_header,
    parse_x_frame_options,
    parse_x_xss_protection,
    extract_security_headers,
    analyze_cors_configuration,
    fingerprint_server_technologies,
    compile_network_evidence
)
from app import app


class TestAgent16NetworkSecurity(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. Target Normalization
    def test_01_target_normalization(self):
        res = _normalize_target("https://www.example.com:8443/test?param=1")
        self.assertEqual(res["scheme"], "https")
        self.assertEqual(res["hostname"], "www.example.com")
        self.assertEqual(res["port"], 8443)
        self.assertTrue("example.com" in res["domain"])

    def test_02_target_normalization_no_scheme(self):
        res = _normalize_target("example.com")
        self.assertEqual(res["scheme"], "https")
        self.assertEqual(res["hostname"], "example.com")
        self.assertEqual(res["domain"], "example.com")

    def test_03_invalid_target_normalization(self):
        res = _normalize_target("")
        self.assertEqual(res["hostname"], "")

    # 2. Private IP & SSRF Protection
    def test_04_private_ip_detection(self):
        self.assertTrue(_is_private_or_restricted_ip("127.0.0.1"))
        self.assertTrue(_is_private_or_restricted_ip("10.0.0.5"))
        self.assertTrue(_is_private_or_restricted_ip("192.168.1.1"))
        self.assertTrue(_is_private_or_restricted_ip("172.16.0.1"))
        self.assertTrue(_is_private_or_restricted_ip("169.254.169.254"))
        self.assertFalse(_is_private_or_restricted_ip("93.184.216.34"))
        self.assertFalse(_is_private_or_restricted_ip("8.8.8.8"))

    @patch("agents.agent16_network.socket.gethostbyname")
    def test_05_resolve_target_ip_private_restriction(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "192.168.1.50"
        ip, err = _resolve_target_ip("internal-service.local")
        self.assertEqual(ip, "192.168.1.50")
        self.assertEqual(err, "target_restricted")

    @patch("agents.agent16_network.socket.gethostbyname", side_effect=socket.gaierror("Name not found"))
    def test_06_resolve_target_ip_dns_failure(self, mock_gethostbyname):
        ip, err = _resolve_target_ip("nonexistent-domain-xyz-99.fake")
        self.assertIsNone(ip)
        self.assertIn("DNS resolution failure", err)

    # 3. Open Ports Check
    @patch("agents.agent16_network.socket.socket")
    def test_07_check_open_ports_open_and_closed(self, mock_socket_cls):
        mock_sock = MagicMock()
        # Mock connect_ex: 80 open (0), 443 open (0), 8080 closed (111), 8443 filtered (10060)
        def fake_connect_ex(addr):
            port = addr[1]
            if port in (80, 443):
                return 0
            elif port == 8080:
                return 111
            return 10060
        mock_sock.connect_ex.side_effect = fake_connect_ex
        mock_socket_cls.return_value = mock_sock

        ports = check_open_ports("example.com", "93.184.216.34")
        self.assertEqual(ports["80"]["state"], "open")
        self.assertEqual(ports["443"]["state"], "open")
        self.assertEqual(ports["8080"]["state"], "closed")
        self.assertEqual(ports["8443"]["state"], "filtered")

    # 4. HTTP Headers & Redirects
    @patch("agents.agent16_network.requests.head")
    def test_08_fetch_http_headers_success(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/"
        mock_resp.headers = {
            "Content-Type": "text/html; charset=UTF-8",
            "Server": "nginx/1.24.0",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
        }
        mock_resp.history = []
        mock_head.return_value = mock_resp

        data, errors = fetch_http_headers("https://example.com")
        self.assertEqual(data["status_code"], 200)
        self.assertTrue(data["https_reachable"])
        self.assertEqual(data["headers"]["Server"], "nginx/1.24.0")
        self.assertEqual(len(errors), 0)

    @patch("agents.agent16_network.requests.head")
    def test_09_fetch_http_headers_with_redirect(self, mock_head):
        r1 = MagicMock()
        r1.url = "http://example.com"
        r1.status_code = 301
        r1.headers = {"Location": "https://example.com/"}

        r2 = MagicMock()
        r2.url = "https://example.com/"
        r2.status_code = 200
        r2.headers = {"Content-Type": "text/html"}
        r2.history = [r1]

        mock_head.return_value = r2

        data, errors = fetch_http_headers("http://example.com")
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["redirect_count"], 1)
        self.assertTrue("https://example.com/" in data["final_url"])

    # 5. Security Headers - HSTS
    def test_10_hsts_header_present(self):
        hsts = parse_hsts_header("max-age=63072000; includeSubDomains; preload")
        self.assertTrue(hsts["present"])
        self.assertEqual(hsts["max_age"], 63072000)
        self.assertTrue(hsts["include_subdomains"])
        self.assertTrue(hsts["preload"])

    def test_11_hsts_header_absent(self):
        hsts = parse_hsts_header(None)
        self.assertFalse(hsts["present"])
        self.assertIsNone(hsts["max_age"])

    # 6. Security Headers - CSP
    def test_12_csp_header_present_and_parsed(self):
        csp_val = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; frame-ancestors 'none'"
        csp = parse_csp_header(csp_val)
        self.assertTrue(csp["present"])
        self.assertIn("default-src", csp["directives"])
        self.assertIn("script-src", csp["directives"])
        self.assertIn("frame-ancestors", csp["directives"])
        self.assertTrue(any("unsafe-inline" in obs for obs in csp["observations"]))
        self.assertTrue(any("frame-ancestors" in obs for obs in csp["observations"]))

    def test_13_csp_header_absent(self):
        csp = parse_csp_header(None)
        self.assertFalse(csp["present"])
        self.assertEqual(len(csp["directives"]), 0)

    # 7. Security Headers - X-Frame-Options
    def test_14_x_frame_options_present(self):
        xfo = parse_x_frame_options("DENY")
        self.assertTrue(xfo["present"])
        self.assertEqual(xfo["value"], "DENY")
        self.assertTrue("prevents" in xfo["interpretation"].lower())

    def test_15_x_frame_options_absent_with_csp_fallback(self):
        xfo = parse_x_frame_options(None, csp_frame_ancestors=True)
        self.assertFalse(xfo["present"])
        self.assertTrue("superseding" in xfo["interpretation"].lower())

    # 8. Security Headers - X-XSS-Protection
    def test_16_x_xss_protection_present(self):
        xxss = parse_x_xss_protection("1; mode=block")
        self.assertTrue(xxss["present"])
        self.assertEqual(xxss["value"], "1; mode=block")
        self.assertTrue("mode=block" in xxss["interpretation"].lower())

    def test_17_x_xss_protection_absent(self):
        xxss = parse_x_xss_protection(None)
        self.assertFalse(xxss["present"])
        self.assertIsNone(xxss["value"])

    # 9. CORS Configuration
    @patch("agents.agent16_network.requests.get")
    def test_18_cors_wildcard_configuration(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
        }
        mock_get.return_value = mock_resp

        base_h = {"Access-Control-Allow-Origin": "*"}
        cors, errs = analyze_cors_configuration("https://example.com", base_h)
        self.assertTrue(cors["present"])
        self.assertEqual(cors["mode"], "wildcard")
        self.assertEqual(cors["allow_origin"], "*")
        self.assertFalse(cors["potential_cors_misconfiguration"])

    @patch("agents.agent16_network.requests.get")
    def test_19_cors_misconfiguration_wildcard_with_credentials(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        mock_get.return_value = mock_resp

        base_h = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        cors, errs = analyze_cors_configuration("https://example.com", base_h)
        self.assertTrue(cors["potential_cors_misconfiguration"])

    # 10. Server Fingerprinting & Information Disclosure
    def test_20_server_fingerprinting_version_disclosure(self):
        headers = {
            "Server": "Apache/2.4.57 (Ubuntu)",
            "X-Powered-By": "PHP/8.2.10",
            "Via": "1.1 vegur"
        }
        data = fingerprint_server_technologies(headers)
        self.assertEqual(data["server"], "Apache/2.4.57 (Ubuntu)")
        self.assertEqual(data["powered_by"], "PHP/8.2.10")
        self.assertTrue(data["information_disclosure"])
        self.assertEqual(len(data["version_disclosures"]), 2)
        self.assertIn("Apache/2.4.57 (Ubuntu)", data["technologies"])

    def test_21_server_fingerprinting_absent(self):
        headers = {"Content-Type": "text/html"}
        data = fingerprint_server_technologies(headers)
        self.assertIsNone(data["server"])
        self.assertFalse(data["information_disclosure"])

    # 11. Full Analysis Entrypoint Flow
    @patch("agents.agent16_network._resolve_target_ip")
    @patch("agents.agent16_network.check_open_ports")
    @patch("agents.agent16_network.fetch_http_headers")
    def test_22_analyze_network_security_full_flow(self, mock_fetch, mock_ports, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", None)
        mock_ports.return_value = {
            "80": {"port": 80, "state": "open", "protocol": "tcp", "service_guess": "HTTP"},
            "443": {"port": 443, "state": "open", "protocol": "tcp", "service_guess": "HTTPS"}
        }
        mock_fetch.return_value = ({
            "status_code": 200,
            "final_url": "https://example.com/",
            "headers": {
                "Server": "nginx/1.24.0",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'"
            },
            "redirect_count": 0,
            "redirect_chain": ["https://example.com/"],
            "https_reachable": True,
            "http_reachable": True,
            "http_to_https_redirect": True
        }, [])

        result = analyze_network_security("https://example.com")
        self.assertIn(result["agent"], ("Network Security", "Agent 16"))
        self.assertEqual(result["status"], "completed")
        self.assertIn("open_ports", result)
        self.assertIn("http_headers", result)
        self.assertIn("security_headers", result)
        self.assertIn("csp", result)
        self.assertIn("cors", result)
        self.assertIn("server_fingerprinting", result)
        self.assertTrue(len(result["evidence"]) > 0)

    # 12. Restricted IP Handling
    @patch("agents.agent16_network._resolve_target_ip")
    def test_23_analyze_network_security_private_ip_restriction(self, mock_resolve):
        mock_resolve.return_value = ("127.0.0.1", "target_restricted")
        result = analyze_network_security("http://localhost:8080")
        self.assertEqual(result["status"], "restricted")
        self.assertEqual(result["error"], "Target resolved to a private or restricted IP address range.")

    # 13. Invalid Input
    def test_24_invalid_url_input(self):
        result = analyze_network_security("")
        self.assertEqual(result["status"], "error")
        self.assertTrue(len(result["errors"]) > 0)

    # 14. Flask Endpoint Success
    @patch("agents.agent16_network.analyze_network_security")
    def test_25_flask_endpoint_success(self, mock_analyze):
        mock_analyze.return_value = {
            "agent": "Agent 16",
            "status": "completed",
            "input": {"original_url": "https://example.com", "hostname": "example.com"},
            "open_ports": {"443": {"state": "open"}},
            "http_headers": {"status_code": 200},
            "security_headers": {},
            "evidence": [],
            "trust_score": None,
            "risk_score": None,
            "verdict": "not_calculated",
            "errors": [],
            "checked_at": "2026-09-04T00:00:00Z"
        }

        response = self.app.post(
            "/api/agent16",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn(data["agent"], ("Network Security", "Agent 16"))
        self.assertEqual(data["status"], "completed")

    # 15. Flask Endpoint Missing URL
    def test_26_flask_endpoint_missing_url(self):
        response = self.app.post(
            "/api/agent16",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main()
