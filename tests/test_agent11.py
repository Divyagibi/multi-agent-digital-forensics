"""
Unit Tests for Agent 11: Content Quality Analysis
Covers all 24 acceptance criteria with robust offline mocks.
"""

import unittest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup

from agents.agent11_content_quality import (
    analyze_content_quality,
    _normalize_url,
    _extract_registered_domain,
    _extract_visible_text,
    _detect_language,
    _analyze_grammar,
    _analyze_spelling,
    _analyze_ai_content,
    _analyze_duplicate_content,
    _analyze_content_similarity,
    _detect_unrealistic_claims,
    _detect_urgency_language,
    _detect_scam_keywords,
    SCAM_KEYWORDS_DATA
)

# Mock HTML Fixtures
MOCK_SCAM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Claim Your Guaranteed 100% Profit Prize</title>
</head>
<body>
    <h1>Congratulations! You have been selected!</h1>
    <p>This company provide guaranteed 100% profit with zero risk investment.</p>
    <p>Earn $10,000 in one day with no risk trading.</p>
    <p>Act now! Your account will be deleted in 10 minutes if you do not verify your account immediately.</p>
    <p>Please enter your login verification credentials and confirm your password.</p>
    <p>This company provide guaranteed 100% profit with zero risk investment.</p>
</body>
</html>
"""

MOCK_AI_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Exploring Digital Modernity</title>
</head>
<body>
    <h1>In today's fast-paced digital world</h1>
    <p>In today's digital landscape, we delve into a rich tapestry of modern interconnected systems and technologies.</p>
    <p>Furthermore, it is essential to seamlessly integrate diverse paradigms as a testament to transformative journeys.</p>
    <p>Navigating the complexities of distributed infrastructure plays a crucial role in modern enterprise operations.</p>
    <p>It is important to remember that taking a holistic approach facilitates optimal scalability and security.</p>
</body>
</html>
"""

MOCK_CLEAN_ENGLISH_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Standard Engineering Documentation</title>
</head>
<body>
    <h1>System Architecture Overview</h1>
    <p>This repository provides a set of distributed forensic evidence collection agents.</p>
    <p>Each agent runs independently and outputs structured JSON observations without assigning final verdicts.</p>
    <p>Users can query individual endpoints via HTTP POST requests.</p>
</body>
</html>
"""

MOCK_GERMAN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Offizielle Dokumentation</title>
</head>
<body>
    <h1>Willkommen auf unserer offiziellen Webseite</h1>
    <p>Wir bieten innovative Softwarelösungen für Unternehmen weltweit an.</p>
    <p>Unsere Systeme gewährleisten höchste Sicherheit und Zuverlässigkeit für alle Geschäftsprozesse.</p>
</body>
</html>
"""


class TestAgent11ContentQuality(unittest.TestCase):
    """Test suite for Agent 11: Content Quality Analysis."""

    def test_01_valid_website_content_analysis(self):
        """Test 1: Full content quality analysis on a mock deceptive page."""
        with patch("agents.agent11_content_quality.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            mock_resp = MagicMock()
            mock_resp.url = "https://crypto-doubler-giveaway.xyz"
            mock_resp.encoding = "utf-8"
            mock_resp.iter_content.return_value = [MOCK_SCAM_HTML.encode("utf-8")]
            mock_session.get.return_value = mock_resp

            result = analyze_content_quality("https://crypto-doubler-giveaway.xyz")
            self.assertIn(result["agent"], ("Content Quality", "Agent 11"))
            self.assertEqual(result["status"], "completed")
            self.assertGreater(result["content_extraction"]["word_count"], 10)
            self.assertEqual(result["language"]["detected"], "en")
            self.assertTrue(result["unrealistic_claims"]["detected"])
            self.assertTrue(result["urgency_language"]["detected"])
            self.assertTrue(result["scam_keywords"]["detected"])
            self.assertTrue(len(result["evidence"]) > 0)

    def test_02_invalid_url(self):
        """Test 2: Empty or invalid URL returns structured error response."""
        result = analyze_content_quality("")
        self.assertEqual(result["status"], "error")
        self.assertIn("URL is required", result["errors"][0])

    def test_03_empty_webpage_text(self):
        """Test 3: Webpage with no text handled gracefully."""
        soup = BeautifulSoup("<html><body></body></html>", "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        self.assertEqual(stats["word_count"], 0)
        self.assertEqual(len(paras), 0)

    def test_04_html_with_normal_text(self):
        """Test 4: Extract clean text and compute statistics correctly."""
        soup = BeautifulSoup(MOCK_CLEAN_ENGLISH_HTML, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        self.assertGreater(stats["word_count"], 15)
        self.assertGreater(stats["sentence_count"], 1)
        self.assertGreater(stats["average_sentence_length"], 5.0)

    def test_05_grammar_errors_detection(self):
        """Test 5: Detect subject-verb agreement error ('this company provide')."""
        sents = ["This company provide best financial service in the market."]
        res, ev = _analyze_grammar(sents, "en")
        self.assertGreater(res["error_count"], 0)
        self.assertTrue(len(res["examples"]) > 0)

    def test_06_spelling_errors_detection(self):
        """Test 6: Detect misspelled words ('verfication', 'recieve')."""
        text = "Please complete your verfication to recieve your prize."
        res, ev = _analyze_spelling(text, "en")
        self.assertGreater(res["error_count"], 0)
        words_found = [e["word"] for e in res["examples"]]
        self.assertTrue(any("verfication" in w or "recieve" in w for w in words_found))

    def test_07_correct_english_text(self):
        """Test 7: Clean English text has zero or minimal false grammar errors."""
        sents = ["The system operates reliably under standard network conditions."]
        res, ev = _analyze_grammar(sents, "en")
        self.assertEqual(res["error_count"], 0)

    def test_08_non_english_text_handling(self):
        """Test 8: German text is detected and skips English-specific grammar penalties."""
        soup = BeautifulSoup(MOCK_GERMAN_HTML, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        lang_info = _detect_language(raw_text)
        self.assertEqual(lang_info["detected"], "de")

        grammar_res, g_ev = _analyze_grammar(sents, "de")
        self.assertEqual(grammar_res["status"], "limited_non_english")

    def test_09_ai_like_text_detection(self):
        """Test 9: Detect formulaic AI clichés and sentence uniformity."""
        soup = BeautifulSoup(MOCK_AI_HTML, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        res, ev = _analyze_ai_content(sents, raw_text)
        self.assertTrue(res["possible_ai_content"])
        self.assertIn(res["indicator_strength"], ["medium", "high"])
        self.assertTrue(len(res["indicators"]) > 0)

    def test_10_normal_human_text_assessment(self):
        """Test 10: Natural technical writing marked with low AI strength."""
        soup = BeautifulSoup(MOCK_CLEAN_ENGLISH_HTML, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        res, ev = _analyze_ai_content(sents, raw_text)
        self.assertFalse(res["possible_ai_content"])
        self.assertEqual(res["indicator_strength"], "low")

    def test_11_duplicate_paragraphs_detection(self):
        """Test 11: Identify duplicated paragraphs on page."""
        paras = [
            "This company provide guaranteed 100% profit with zero risk investment.",
            "Some other middle section paragraph describing services.",
            "This company provide guaranteed 100% profit with zero risk investment.",
        ]
        res, ev = _analyze_duplicate_content(paras)
        self.assertTrue(len(res["duplicate_sections"]) > 0)
        self.assertEqual(res["duplicate_sections"][0]["occurrences"], 2)

    def test_12_no_duplicate_content(self):
        """Test 12: Unique paragraphs produce empty duplicate sections."""
        paras = [
            "First unique paragraph with distinct content.",
            "Second unique paragraph with different content."
        ]
        res, ev = _analyze_duplicate_content(paras)
        self.assertEqual(len(res["duplicate_sections"]), 0)

    def test_13_unrealistic_financial_claims(self):
        """Test 13: Detect guaranteed profit and zero-risk claims."""
        sents = [
            "We offer a guaranteed 100% profit on every deposit.",
            "Participate in zero risk trading with guaranteed returns."
        ]
        res, ev = _detect_unrealistic_claims(sents)
        self.assertTrue(res["detected"])
        self.assertEqual(len(res["claims"]), 2)

    def test_14_normal_financial_text_no_false_positive(self):
        """Test 14: Educational / normal financial text is not flagged."""
        sents = [
            "Investing in stock markets carries inherent financial risks.",
            "Please read the regulatory prospectus before opening an account."
        ]
        res, ev = _detect_unrealistic_claims(sents)
        self.assertFalse(res["detected"])
        self.assertEqual(len(res["claims"]), 0)

    def test_15_urgency_language_detection(self):
        """Test 15: Detect threat-based and time-pressure urgency phrases."""
        sents = [
            "Your account will be deleted in 10 minutes.",
            "Act now before the offer expires today."
        ]
        res, ev = _detect_urgency_language(sents)
        self.assertTrue(res["detected"])
        cats = [i["category"] for i in res["instances"]]
        self.assertIn("threat-based urgency", cats)
        self.assertIn("time pressure", cats)

    def test_16_no_urgency_language(self):
        """Test 16: Regular informational text has no urgency flags."""
        sents = ["Our office hours are Monday through Friday from 9 AM to 5 PM."]
        res, ev = _detect_urgency_language(sents)
        self.assertFalse(res["detected"])
        self.assertEqual(len(res["instances"]), 0)

    def test_17_scam_keywords_matching(self):
        """Test 17: Detect multi-category scam keywords."""
        text = "Please verify your account and confirm your password for your investment opportunity."
        sents = ["Please verify your account and confirm your password for your investment opportunity."]
        res, ev = _detect_scam_keywords(text, sents)
        self.assertTrue(res["detected"])
        kws = [m["keyword"] for m in res["matches"]]
        self.assertTrue(any("verify your account" in k or "confirm your password" in k for k in kws))

    def test_18_innocent_keyword_context(self):
        """Test 18: Unmatched keywords result in no flags."""
        text = "Learn more about open source software engineering and code standards."
        sents = ["Learn more about open source software engineering and code standards."]
        res, ev = _detect_scam_keywords(text, sents)
        self.assertFalse(res["detected"])

    def test_19_content_similarity_template(self):
        """Test 19: High similarity match against known giveaway template."""
        text = "To celebrate our milestone we are giving away 5000 BTC. Send between 0.1 and 10 BTC to the address below and get double in return immediately."
        res, ev = _analyze_content_similarity(text)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(len(res["matches"]) > 0)
        self.assertGreaterEqual(res["matches"][0]["similarity_score"], 0.25)

    def test_20_page_timeout_handling(self):
        """Test 20: Handle network timeout gracefully."""
        with patch("agents.agent11_content_quality.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            import requests
            mock_session.get.side_effect = requests.exceptions.Timeout("Read timeout")

            result = analyze_content_quality("https://slow-site.com")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)
            self.assertIn("timed out", result["errors"][0])

    def test_21_connection_failure(self):
        """Test 21: Handle connection error gracefully."""
        with patch("agents.agent11_content_quality.requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = Exception("Connection refused")

            result = analyze_content_quality("https://unreachable-site.org")
            self.assertEqual(result["status"], "completed")
            self.assertTrue(len(result["errors"]) > 0)

    def test_22_large_webpage_text_truncation(self):
        """Test 22: Very large textual content is truncated safely."""
        huge_html = "<html><body><p>" + ("Important sentence word analysis. " * 5000) + "</p></body></html>"
        soup = BeautifulSoup(huge_html, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        self.assertLessEqual(len(raw_text), 100000)

    def test_23_javascript_content_extraction(self):
        """Test 23: Clean text extraction strips raw script tags."""
        html_with_js = "<html><head><script>var x = 100; function test(){}</script></head><body><p>Visible heading text.</p></body></html>"
        soup = BeautifulSoup(html_with_js, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        self.assertNotIn("var x", raw_text)
        self.assertIn("Visible heading text.", raw_text)

    def test_24_malformed_html_handling(self):
        """Test 24: Parse malformed and unclosed HTML without error."""
        malformed = "<div><p>This company provide guaranteed returns<p><span>Act now"
        soup = BeautifulSoup(malformed, "html.parser")
        raw_text, paras, sents, stats = _extract_visible_text(soup)
        self.assertIn("guaranteed returns", raw_text)


if __name__ == "__main__":
    unittest.main()
