"""
Agent 11 — Content Quality Analysis
Evidence collection module for linguistic analysis, spelling/grammar checks,
AI-generated content indicators, duplicate content, content similarity,
unrealistic claims, urgency language, and scam keyword detection.

Strictly passive forensic evidence collection.
DO NOT calculate Trust/Risk score, phishing probability, or final verdict.
"""

import ipaddress
import collections
import datetime
import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    from spellchecker import SpellChecker
    _SPELLCHECKER_AVAILABLE = True
except ImportError:
    _SPELLCHECKER_AVAILABLE = False

try:
    from langdetect import detect_langs
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _LANGDETECT_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable constants & limits
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2MB HTML limit
MAX_TEXT_LENGTH = 100000              # 100K characters text limit
REQUEST_TIMEOUT = 10                   # 10 seconds timeout

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_safe_url(url: str) -> bool:
    """Check if URL is safe to fetch (blocks SSRF, private IPs, loopback, cloud metadata)."""
    if not url:
        return False
    if url.startswith("data:image/"):
        return True
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower()
        if hostname in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
            return False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False
        except ValueError:
            pass
        return True
    except Exception:
        return False

# =====================================================================
# LOAD REFERENCE DATASETS (data/scam_keywords.json)
# =====================================================================
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

def _load_json_reference(filename: str) -> Dict[str, List[str]]:
    path = os.path.join(_DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

SCAM_KEYWORDS_DATA = _load_json_reference("scam_keywords.json")

# Common tech/domain words and recognized brands to exclude from spellchecking
EXCLUDED_SPELL_WORDS: Set[str] = {
    "login", "signin", "signup", "auth", "logout", "http", "https", "url", "uri",
    "api", "sdk", "json", "html", "css", "xml", "php", "sql", "cdn", "dns", "ssl",
    "tls", "whois", "rdap", "favicon", "jpeg", "webp", "png", "svg", "ico",
    "microsoft", "google", "paypal", "apple", "amazon", "netflix", "meta", "facebook",
    "instagram", "whatsapp", "chase", "bofa", "adobe", "linkedin", "dropbox",
    "binance", "coinbase", "crypto", "bitcoin", "ethereum", "btc", "eth", "usdt",
    "app", "online", "dashboard", "portal", "user", "admin", "config", "copyright"
}

# Reference scam template corpus for similarity matching
REFERENCE_SCAM_SNIPPETS = [
    {
        "reference": "boilerplate_crypto_giveaway",
        "title": "Crypto Giveaway Scam Template",
        "text": "To celebrate our milestone we are giving away 5000 BTC. Send between 0.1 and 10 BTC to the address below and get double in return immediately."
    },
    {
        "reference": "boilerplate_urgent_account_lock",
        "title": "Account Suspension Phish Template",
        "text": "Your account has been restricted due to unauthorized login attempts. Immediate action required. Please verify your identity within 24 hours to prevent permanent account deletion."
    },
    {
        "reference": "boilerplate_fake_tech_support",
        "title": "Tech Support Ransom Template",
        "text": "Critical alert: Spyware and trojan infected your system. Do not turn off your computer or your hard drive will be wiped. Call toll free support now."
    }
]

# =====================================================================
# HELPER UTILITIES
# =====================================================================

def _normalize_url(url: str) -> str:
    """Normalize input URL to include scheme."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def _extract_registered_domain(url: str) -> str:
    """Safely extract registered domain name."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return ""
        if _TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(hostname)
            reg_dom = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', '')
            if reg_dom:
                return reg_dom.lower()
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def _fetch_webpage_safe(url: str, session: requests.Session) -> Tuple[Optional[str], Optional[str], Optional[BeautifulSoup], List[str]]:
    """Fetch HTML page safely with strict size, SSRF and timeout limits."""
    errors = []
    if not _is_safe_url(url):
        errors.append("Blocked potentially unsafe/private URL (SSRF protection)")
        return None, url, None, errors

    try:
        resp = session.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            verify=True,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        try:
            resp = session.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            errors.append(f"HTTP connection failed: {str(e)}")
            return None, url, None, errors
    except requests.exceptions.Timeout:
        errors.append(f"Webpage request timed out after {REQUEST_TIMEOUT}s")
        return None, url, None, errors
    except Exception as e:
        errors.append(f"Failed to fetch webpage: {str(e)}")
        return None, url, None, errors

    final_url = resp.url or url
    if not _is_safe_url(final_url):
        errors.append("Redirected to potentially unsafe/private URL (SSRF protection)")
        return None, final_url, None, errors

    try:
        content_chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=8192):
            content_chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded >= MAX_HTML_SIZE:
                errors.append(f"HTML response exceeded {MAX_HTML_SIZE} bytes; truncated")
                break
        html_bytes = b"".join(content_chunks)
        encoding = resp.encoding or "utf-8"
        html_text = html_bytes.decode(encoding, errors="replace")
        soup = BeautifulSoup(html_text, "html.parser")
        return html_text, final_url, soup, errors
    except Exception as e:
        errors.append(f"Error reading HTML response: {str(e)}")
        return None, final_url, None, errors


# =====================================================================
# 1. TEXT EXTRACTION & CONTENT STATISTICS
# =====================================================================

def _extract_visible_text(soup: Optional[BeautifulSoup]) -> Tuple[str, List[str], List[str], Dict[str, Any]]:
    """
    Extract visible textual content, stripping scripts, styles, hidden elements.
    Returns (raw_clean_text, list_of_paragraphs, list_of_sentences, statistics_dict).
    """
    if not soup:
        return "", [], [], {"word_count": 0, "sentence_count": 0, "paragraph_count": 0, "average_sentence_length": 0.0}

    # Clone soup to avoid mutating original
    soup_copy = BeautifulSoup(str(soup), "html.parser")

    # Remove non-content elements
    for element in soup_copy(["script", "style", "noscript", "template", "svg", "meta", "link"]):
        element.extract()

    # Extract distinct paragraphs and sections
    paragraphs = []
    for tag in soup_copy.find_all(["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div", "span", "blockquote"]):
        txt = tag.get_text(separator=" ", strip=True)
        if len(txt) > 20 and txt not in paragraphs:
            # Check if this tag has child block elements to avoid duplicate nested extractions
            if not tag.find(["p", "div", "section"]):
                paragraphs.append(txt)

    # Full text extraction
    raw_text = soup_copy.get_text(separator=" ", strip=True)
    raw_text = re.sub(r"\s+", " ", raw_text).strip()
    if len(raw_text) > MAX_TEXT_LENGTH:
        raw_text = raw_text[:MAX_TEXT_LENGTH]

    # Split into sentences using punctuation boundaries
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", raw_text) if len(s.strip()) > 3]

    words = re.findall(r"\b[A-Za-z0-9'-]+\b", raw_text)
    word_count = len(words)
    sentence_count = len(sentences)
    paragraph_count = len(paragraphs)
    avg_sentence_len = round(word_count / max(1, sentence_count), 1)

    statistics = {
        "word_count": word_count,
        "sentence_count": sentence_count,
        "paragraph_count": paragraph_count,
        "average_sentence_length": avg_sentence_len,
    }

    return raw_text, paragraphs, sentences, statistics


# =====================================================================
# 2. LANGUAGE DETECTION
# =====================================================================

def _detect_language(text: str) -> Dict[str, Any]:
    """Detect dominant language and confidence using langdetect."""
    if not text or len(text.strip()) < 15 or not _LANGDETECT_AVAILABLE:
        return {
            "detected": "en",
            "confidence": 1.0,
            "status": "default_or_unavailable"
        }
    try:
        langs = detect_langs(text)
        if langs:
            primary = langs[0]
            return {
                "detected": primary.lang,
                "confidence": round(primary.prob, 2),
                "status": "detected"
            }
    except Exception:
        pass

    return {
        "detected": "en",
        "confidence": 0.8,
        "status": "fallback"
    }


# =====================================================================
# 3. GRAMMAR ANALYSIS (HEURISTIC RULE-BASED ENGINE)
# =====================================================================

def _analyze_grammar(sentences: List[str], lang: str) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze grammar issues in English text using pattern rules."""
    grammar_data = {
        "status": "completed",
        "error_count": 0,
        "examples": [],
    }
    evidence_list = []

    if lang != "en":
        grammar_data["status"] = "limited_non_english"
        return grammar_data, evidence_list

    if not sentences:
        return grammar_data, evidence_list

    # Common grammar error patterns
    grammar_rules = [
        (r"\b(this|that|each|every)\s+([a-z]+s)\b(?!\s+(?:is|has|was))", "Plural noun after singular determiner"),
        (r"\b(this|that)\s+([a-z]+)\s+(provide|give|offer|make|have|do|send|receive|require)\b", "Subject-verb agreement (singular subject with base plural verb)"),
        (r"\b(we|they|you)\s+(is|was|has)\b", "Subject-verb agreement (plural subject with singular verb)"),
        (r"\b(more|most)\s+(better|faster|cheaper|easier|harder|simpler)\b", "Double comparative / superlative"),
        (r"\b(to)\s+([a-z]+ing)\b(?!\s+(?:account|payment|process))", "Infinitive verb form error ('to' followed by gerund)"),
        (r"\b(did|does|do)\s+not\s+([a-z]+ed)\b", "Auxiliary verb tense error (did not + past tense)"),
        (r"\b(an)\s+([b-df-hj-np-tv-z][a-z]+)\b", "Incorrect article 'an' before consonant sound"),
        (r"\b(a)\s+([aeiou][a-z]+)\b", "Incorrect article 'a' before vowel sound"),
    ]

    detected_errors = []
    for sentence in sentences[:50]:  # Inspect first 50 sentences
        clean_sent = sentence.strip()
        for pat, issue in grammar_rules:
            match = re.search(pat, clean_sent, re.IGNORECASE)
            if match:
                err_example = {
                    "text": clean_sent,
                    "issue": issue,
                    "matched_segment": match.group(0),
                }
                detected_errors.append(err_example)
                break  # one error per sentence for clean accounting

    grammar_data["error_count"] = len(detected_errors)
    grammar_data["examples"] = detected_errors[:5]

    if detected_errors:
        evidence_list.append(f"Grammar analysis detected {len(detected_errors)} possible grammatical irregularities")

    return grammar_data, evidence_list


# =====================================================================
# 4. SPELLING ANALYSIS
# =====================================================================

def _analyze_spelling(text: str, lang: str) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze spelling mistakes using pyspellchecker with whitelist filters."""
    spelling_data = {
        "status": "completed",
        "error_count": 0,
        "examples": [],
    }
    evidence_list = []

    if lang != "en" or not _SPELLCHECKER_AVAILABLE:
        spelling_data["status"] = "not_available" if not _SPELLCHECKER_AVAILABLE else "limited_non_english"
        return spelling_data, evidence_list

    if not text:
        return spelling_data, evidence_list

    try:
        spell = SpellChecker()
        words = re.findall(r"\b[A-Za-z]{4,}\b", text)  # words with 4+ letters
        unique_words = set(w.lower() for w in words)

        # Filter out numbers, URLs, tech exclusions
        filtered_words = [w for w in unique_words if w not in EXCLUDED_SPELL_WORDS]

        # Check misspelled
        unknown_words = spell.unknown(filtered_words)

        examples = []
        for word in list(unknown_words)[:10]:
            # Get top candidates
            candidates = list(spell.candidates(word) or [])[:3]
            if candidates:
                examples.append({
                    "word": word,
                    "suggestions": candidates,
                })

        spelling_data["error_count"] = len(unknown_words)
        spelling_data["examples"] = examples

        if len(unknown_words) > 0:
            evidence_list.append(f"Spelling analysis identified {len(unknown_words)} possible spelling errors")

        return spelling_data, evidence_list
    except Exception as e:
        spelling_data["status"] = "error"
        spelling_data["error"] = str(e)
        return spelling_data, evidence_list


# =====================================================================
# 5. AI-GENERATED CONTENT DETECTION
# =====================================================================

def _analyze_ai_content(sentences: List[str], text: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Analyze textual characteristics commonly associated with formulaic AI-generated content.
    Never states AI generation with certainty; reports indicator strength.
    """
    ai_data = {
        "status": "analyzed",
        "possible_ai_content": False,
        "indicator_strength": "low",
        "indicators": [],
    }
    evidence_list = []

    if not text or len(sentences) < 3:
        return ai_data, evidence_list

    indicators = []
    score = 0

    # 1. Formulaic AI transition phrases
    ai_phrases = [
        r"\bin today's (?:fast-paced )?digital (?:world|landscape|age)\b",
        r"\bdelve into\b",
        r"\btapestry of\b",
        r"\btestament to\b",
        r"\bseamlessly (?:integrate|navigate|connect)\b",
        r"\bnavigating the complexities of\b",
        r"\bit is important to remember\b",
        r"\bfurthermore, it is essential\b",
        r"\bplays a crucial role\b",
        r"\btransformative journey\b",
        r"\bholistic approach\b",
    ]

    matched_phrases = []
    for pat in ai_phrases:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            matched_phrases.append(m.group(0))

    if len(matched_phrases) >= 2:
        score += 3
        indicators.append(f"Presence of formulaic AI transition clichés ({', '.join(matched_phrases[:3])})")

    # 2. Sentence Length Variance / Perplexity Uniformity
    sent_lengths = [len(s.split()) for s in sentences if len(s.split()) > 3]
    if len(sent_lengths) >= 5:
        mean_len = sum(sent_lengths) / len(sent_lengths)
        variance = sum((l - mean_len) ** 2 for l in sent_lengths) / len(sent_lengths)
        std_dev = math.sqrt(variance)

        # Unusually low variance indicates robotic uniformity
        if std_dev < 3.5 and 15 <= mean_len <= 25:
            score += 2
            indicators.append("Unusually uniform sentence length distribution (low structural variance)")

    # 3. Lexical Diversity (Type-Token Ratio)
    words = [w.lower() for w in re.findall(r"\b[A-Za-z]+\b", text)]
    if len(words) >= 50:
        ttr = len(set(words)) / len(words)
        if 0.45 <= ttr <= 0.65 and len(matched_phrases) >= 1:
            score += 1

    # Determine strength
    if score >= 4:
        ai_data["possible_ai_content"] = True
        ai_data["indicator_strength"] = "high"
    elif score >= 2:
        ai_data["possible_ai_content"] = True
        ai_data["indicator_strength"] = "medium"
    else:
        ai_data["possible_ai_content"] = False
        ai_data["indicator_strength"] = "low"

    ai_data["indicators"] = indicators

    if indicators:
        evidence_list.append(f"AI-like writing characteristics observed ({ai_data['indicator_strength']} strength: {'; '.join(indicators)})")

    return ai_data, evidence_list


# =====================================================================
# 6. DUPLICATE CONTENT ANALYSIS
# =====================================================================

def _analyze_duplicate_content(paragraphs: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Identify duplicate paragraphs or repeated text sections."""
    duplicate_data = {
        "status": "completed",
        "duplicate_sections": [],
    }
    evidence_list = []

    if not paragraphs:
        return duplicate_data, evidence_list

    # Clean and normalize paragraphs
    norm_paras = [re.sub(r"\s+", " ", p).strip().lower() for p in paragraphs if len(p.split()) >= 5]
    counts = collections.Counter(norm_paras)

    duplicates = []
    for text, count in counts.items():
        if count >= 2:
            duplicates.append({
                "text": text[:120] + ("..." if len(text) > 120 else ""),
                "occurrences": count,
            })

    duplicate_data["duplicate_sections"] = duplicates

    if duplicates:
        evidence_list.append(f"Duplicate content detected: {len(duplicates)} repeated section(s) found on page")

    return duplicate_data, evidence_list


# =====================================================================
# 7. CONTENT SIMILARITY / PLAGIARISM HEURISTIC
# =====================================================================

def _analyze_content_similarity(text: str) -> Tuple[Dict[str, Any], List[str]]:
    """Compute n-gram Jaccard similarity against reference templates."""
    similarity_data = {
        "status": "completed",
        "matches": [],
    }
    evidence_list = []

    if not text or len(text.split()) < 10:
        return similarity_data, evidence_list

    def get_ngrams(s: str, n: int = 3) -> Set[str]:
        words = re.findall(r"\b\w+\b", s.lower())
        return set(" ".join(words[i:i+n]) for i in range(len(words) - n + 1))

    text_ngrams = get_ngrams(text)
    if not text_ngrams:
        return similarity_data, evidence_list

    for ref in REFERENCE_SCAM_SNIPPETS:
        ref_ngrams = get_ngrams(ref["text"])
        if not ref_ngrams:
            continue
        intersection = text_ngrams.intersection(ref_ngrams)
        union = text_ngrams.union(ref_ngrams)
        sim_score = len(intersection) / max(1, len(union))

        if sim_score >= 0.25:  # Noticeable overlap with boilerplate scam template
            match_entry = {
                "reference": ref["reference"],
                "title": ref["title"],
                "similarity_score": round(sim_score, 2),
                "matched_section": "Content Body",
            }
            similarity_data["matches"].append(match_entry)
            evidence_list.append(f"High content similarity ({int(sim_score * 100)}%) to '{ref['title']}' template")

    if not similarity_data["matches"]:
        similarity_data["status"] = "analyzed_no_matches"

    return similarity_data, evidence_list


# =====================================================================
# 8. UNREALISTIC CLAIMS DETECTION
# =====================================================================

def _detect_unrealistic_claims(sentences: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Detect exaggerated or impossible claims."""
    claims_data = {
        "detected": False,
        "claims": [],
    }
    evidence_list = []

    claim_rules = [
        (r"\b(guaranteed\s+100%\s+profit|guaranteed\s+returns?|100%\s+daily\s+profit)\b", "Unrealistic financial return", "Promises guaranteed monetary return with no investment risk"),
        (r"\b(earn\s+(?:\$|₹|€)?\s*10[,0-9]+\s+(?:in|within)\s+(?:one|1)\s+day)\b", "High-yield rapid return", "Promises extreme daily monetary gains"),
        (r"\b(zero\s+risk\s+investment|no\s+risk\s+trading|risk[- ]free\s+guarantee)\b", "Zero-risk investment claim", "Falsely claims financial investment carries zero risk"),
        (r"\b(100%\s+(?:cure|success\s+rate\s+guaranteed)|miracle\s+cure)\b", "Unsubstantiated medical/success guarantee", "Claims 100% cure or miracle success"),
        (r"\b(become\s+(?:a\s+)?millionaire\s+(?:overnight|instantly|in\s+days))\b", "Instant wealth claim", "Promises instant wealth generation"),
        (r"\b(government\s+approved\s+(?:grant|giveaway|bonus))\b", "Unverified government endorsement", "Claims official government backing for monetary distribution"),
    ]

    detected = []
    for sent in sentences:
        for pat, ind_type, reason in claim_rules:
            match = re.search(pat, sent, re.IGNORECASE)
            if match:
                claim_entry = {
                    "text": sent.strip(),
                    "indicator": ind_type,
                    "reason": reason,
                    "severity": "HIGH",
                }
                detected.append(claim_entry)
                evidence_list.append(f"Unrealistic claim: '{match.group(0)}' ({reason})")
                break

    claims_data["detected"] = len(detected) > 0
    claims_data["claims"] = detected

    return claims_data, evidence_list


# =====================================================================
# 9. URGENCY LANGUAGE DETECTION
# =====================================================================

def _detect_urgency_language(sentences: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Identify time-pressure and threat-based urgency language."""
    urgency_data = {
        "detected": False,
        "instances": [],
    }
    evidence_list = []

    urgency_patterns = [
        (r"\b(account\s+will\s+be\s+(?:deleted|suspended|terminated|permanently\s+closed))\b", "threat-based urgency", "HIGH"),
        (r"\b(immediate\s+action\s+required|respond\s+within\s+\d+\s+(?:minutes?|hours?))\b", "time pressure", "HIGH"),
        (r"\b(act\s+now|hurry\s+up|last\s+chance|offer\s+expires\s+today|only\s+\d+\s+minutes?\s+remaining)\b", "time pressure", "MEDIUM"),
        (r"\b(don't\s+miss\s+out|limited\s+time\s+offer|claim\s+before\s+it's\s+gone)\b", "marketing urgency", "LOW"),
    ]

    instances = []
    for sent in sentences:
        for pat, cat, sev in urgency_patterns:
            match = re.search(pat, sent, re.IGNORECASE)
            if match:
                inst_entry = {
                    "text": sent.strip(),
                    "category": cat,
                    "matched_phrase": match.group(0),
                    "severity": sev,
                }
                instances.append(inst_entry)
                evidence_list.append(f"Urgency language ({cat}): '{match.group(0)}'")
                break

    urgency_data["detected"] = len(instances) > 0
    urgency_data["instances"] = instances

    return urgency_data, evidence_list


# =====================================================================
# 10. SCAM KEYWORDS (CONTEXT-AWARE)
# =====================================================================

def _detect_scam_keywords(text: str, sentences: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Detect scam keywords across categories using sentence context."""
    scam_data = {
        "detected": False,
        "matches": [],
    }
    evidence_list = []

    if not text:
        return scam_data, evidence_list

    keywords_dict = SCAM_KEYWORDS_DATA or {
        "financial": ["guaranteed profit", "double your money", "zero risk investment"],
        "credential": ["verify your account", "confirm your password", "account suspended"],
        "prize_lottery": ["congratulations you won", "claim your prize", "lottery winner"],
        "urgency": ["act now", "immediate action required", "offer expires today"],
        "tech_support": ["virus detected", "call microsoft support", "toll free number"],
    }

    matches = []
    for category, kw_list in keywords_dict.items():
        for kw in kw_list:
            pat = r"\b" + re.escape(kw) + r"\b"
            if re.search(pat, text, re.IGNORECASE):
                # Find contextual sentence
                context_sentence = ""
                for sent in sentences:
                    if re.search(pat, sent, re.IGNORECASE):
                        context_sentence = sent.strip()
                        break

                matches.append({
                    "keyword": kw,
                    "category": category,
                    "context": context_sentence or f"Keyword '{kw}' detected in page text",
                    "severity": "HIGH" if category in ("credential", "financial", "tech_support") else "MEDIUM",
                })
                evidence_list.append(f"Scam keyword [{category}]: '{kw}'")

    scam_data["detected"] = len(matches) > 0
    scam_data["matches"] = matches

    return scam_data, evidence_list


# =====================================================================
# MAIN ENTRYPOINT
# =====================================================================

def analyze_content_quality(url: str) -> Dict[str, Any]:
    """
    Main entry point for Agent 11: Content Quality Analysis.
    Collects passive forensic evidence regarding textual quality, grammar, spelling,
    AI-generated content indicators, duplicate text, unrealistic claims, urgency language,
    and context-aware scam keywords.
    """
    print("[Agent 11] Starting content quality analysis...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    forensic_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 11] Invalid URL provided.")
        extra = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "content_extraction": {"status": "error", "word_count": 0, "sentence_count": 0, "paragraph_count": 0},
            "language": {"detected": "unknown", "confidence": 0.0},
            "content_statistics": {"word_count": 0, "sentence_count": 0, "average_sentence_length": 0.0},
            "grammar_analysis": {"status": "not_available", "error_count": 0, "examples": []},
            "spelling_analysis": {"status": "not_available", "error_count": 0, "examples": []},
            "ai_content_analysis": {"status": "not_available", "possible_ai_content": False, "indicator_strength": "low", "indicators": []},
            "duplicate_content": {"status": "not_available", "duplicate_sections": []},
            "content_similarity": {"status": "not_available", "matches": []},
            "unrealistic_claims": {"detected": False, "claims": []},
            "urgency_language": {"detected": False, "instances": []},
            "scam_keywords": {"detected": False, "matches": []},
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A11",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra,
        )

    print("[Agent 11] Normalizing URL...")
    normalized_url = _normalize_url(url)
    submitted_domain = _extract_registered_domain(normalized_url)

    # Initialize session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    print("[Agent 11] Fetching webpage...")
    html_text, final_url, soup, fetch_errors = _fetch_webpage_safe(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    final_domain = _extract_registered_domain(final_url) if final_url else submitted_domain

    print("[Agent 11] Extracting visible text...")
    raw_text, paragraphs, sentences, statistics = _extract_visible_text(soup)

    print("[Agent 11] Detecting language...")
    lang_info = _detect_language(raw_text)
    detected_lang = lang_info.get("detected", "en")

    print("[Agent 11] Checking grammar...")
    grammar_result, grammar_ev = _analyze_grammar(sentences, detected_lang)
    forensic_evidence.extend(grammar_ev)

    print("[Agent 11] Checking spelling...")
    spelling_result, spelling_ev = _analyze_spelling(raw_text, detected_lang)
    forensic_evidence.extend(spelling_ev)

    print("[Agent 11] Analyzing possible AI-like characteristics...")
    ai_result, ai_ev = _analyze_ai_content(sentences, raw_text)
    forensic_evidence.extend(ai_ev)

    print("[Agent 11] Checking duplicate content...")
    duplicate_result, duplicate_ev = _analyze_duplicate_content(paragraphs)
    forensic_evidence.extend(duplicate_ev)

    print("[Agent 11] Checking content similarity...")
    similarity_result, similarity_ev = _analyze_content_similarity(raw_text)
    forensic_evidence.extend(similarity_ev)

    print("[Agent 11] Detecting unrealistic claims...")
    claims_result, claims_ev = _detect_unrealistic_claims(sentences)
    forensic_evidence.extend(claims_ev)

    print("[Agent 11] Detecting urgency language...")
    urgency_result, urgency_ev = _detect_urgency_language(sentences)
    forensic_evidence.extend(urgency_ev)

    print("[Agent 11] Detecting scam keywords...")
    scam_result, scam_ev = _detect_scam_keywords(raw_text, sentences)
    forensic_evidence.extend(scam_ev)

    print("[Agent 11] Generating evidence...")
    # Build structured evidence items
    structured_evidence = []

    # E11-01: Extracted Content & Language
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=1,
        finding="Visible textual content volume and primary language classification",
        value=f"{statistics['word_count']} words, language: {detected_lang}",
        severity="info",
        source="DOM Text Extraction",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata={"statistics": statistics, "language": lang_info},
        category="page_language_detected"
    ))

    # E11-02: Grammar & Spelling Analysis
    err_count = grammar_result.get("error_count", 0) + spelling_result.get("error_count", 0)
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=2,
        finding="Spelling and grammatical consistency inspection in visible page prose",
        value=err_count,
        severity="medium" if err_count >= 3 else ("low" if err_count > 0 else "info"),
        source="Spellchecker & Grammar Heuristics",
        evidence_type="deterministic",
        evidence_strength=0.5 if err_count >= 3 else 0.1,
        metadata={"grammar": grammar_result, "spelling": spelling_result},
        category="page_language_detected"
    ))

    # E11-03: AI / Formulaic Content Indicators
    ai_strong = ai_result.get("possible_ai_content") and ai_result.get("indicator_strength") in ("medium", "high")
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=3,
        finding="Text exhibits characteristics associated with formulaic or template-like language generation",
        value=ai_result.get("indicator_strength", "low"),
        severity="medium" if ai_strong else "info",
        source="Stylometric AI Heuristics",
        evidence_type="inference",
        evidence_strength=0.6 if ai_strong else 0.1,
        metadata=ai_result,
        category="ai_generated_phishing_text" if ai_strong else "page_language_detected"
    ))

    # E11-04: Duplicate Content
    dup_secs = duplicate_result.get("duplicate_sections", [])
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=4,
        finding="Repeated paragraph blocks and duplicate content section detection",
        value=len(dup_secs),
        severity="medium" if len(dup_secs) > 0 else "info",
        source="Text Token Hashing",
        evidence_type="deterministic",
        evidence_strength=0.5 if len(dup_secs) > 0 else 0.05,
        metadata=duplicate_result,
        category="duplicate_scam_template" if len(dup_secs) > 0 else "page_language_detected"
    ))

    # E11-05: Known Scam Template Similarity
    sim_matches = similarity_result.get("matches", [])
    max_sim = max([m.get("similarity_score", 0.0) for m in sim_matches], default=0.0)
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=5,
        finding="Textual similarity to known deceptive or scam boilerplate template patterns",
        value=max_sim,
        severity="high" if max_sim >= 0.25 else "info",
        source="Jaccard Corpus Similarity",
        evidence_type="inference",
        evidence_strength=float(max_sim) if max_sim > 0 else None,
        metadata=similarity_result,
        category="duplicate_scam_template" if max_sim >= 0.25 else "page_language_detected"
    ))

    # E11-06: Unrealistic Claims
    has_claims = bool(claims_result.get("detected"))
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=6,
        finding="Unrealistic financial promises and zero-risk guarantee claim patterns",
        value=claims_result.get("claims", []),
        severity="high" if has_claims else "info",
        source="Financial Claim Pattern Heuristics",
        evidence_type="inference",
        evidence_strength=0.85 if has_claims else 0.05,
        metadata=claims_result,
        category="unrealistic_claims" if has_claims else "page_language_detected"
    ))

    # E11-07: Urgency Language
    instances = urgency_result.get("instances", [])
    has_coercive_urgency = any(
        inst.get("severity") in ("HIGH", "MEDIUM") and inst.get("category") != "marketing urgency"
        for inst in instances
    )
    has_urgency = bool(instances)
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=7,
        finding="High-pressure urgency language and coercive timeline indicators",
        value=instances,
        severity="high" if has_coercive_urgency else "info",
        source="Urgency Phrase Lexicon",
        evidence_type="inference",
        evidence_strength=0.8 if has_coercive_urgency else 0.05,
        metadata=urgency_result,
        category="urgency_manipulation_keywords" if has_coercive_urgency else "page_language_detected"
    ))

    # E11-08: Scam Keywords
    has_scam = bool(scam_result.get("detected"))
    structured_evidence.append(create_evidence_item(
        agent_id="A11",
        index=8,
        finding="Scam, credential-harvesting, and deceptive call-to-action keyword matches",
        value=scam_result.get("matches", []),
        severity="critical" if has_scam else "info",
        source="Scam Keyword Dataset",
        evidence_type="threat_intelligence",
        evidence_strength=0.9 if has_scam else 0.05,
        metadata=scam_result,
        category="scam_fraud_keywords" if has_scam else "page_language_detected"
    ))

    print("[Agent 11] Content quality analysis completed.")

    data_payload = {
        "content_extraction": {
            "status": "completed" if raw_text else "empty",
            "word_count": statistics["word_count"],
            "sentence_count": statistics["sentence_count"],
            "paragraph_count": statistics["paragraph_count"],
        },
        "language": lang_info,
        "content_statistics": statistics,
        "grammar_analysis": grammar_result,
        "spelling_analysis": spelling_result,
        "ai_content_analysis": ai_result,
        "duplicate_content": duplicate_result,
        "content_similarity": similarity_result,
        "unrealistic_claims": claims_result,
        "urgency_language": urgency_result,
        "scam_keywords": scam_result,
        "evidence": forensic_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url or normalized_url,
            "domain": final_domain or submitted_domain,
        },
        "content_extraction": data_payload["content_extraction"],
        "language": lang_info,
        "content_statistics": statistics,
        "grammar_analysis": grammar_result,
        "spelling_analysis": spelling_result,
        "ai_content_analysis": ai_result,
        "duplicate_content": duplicate_result,
        "content_similarity": similarity_result,
        "unrealistic_claims": claims_result,
        "urgency_language": urgency_result,
        "scam_keywords": scam_result,
        "evidence": forensic_evidence,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A11",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
