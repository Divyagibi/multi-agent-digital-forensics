"""
Agent 10 — Visual & UI Analysis
Evidence collection module for visual and user-interface inspection:
screenshot capture, OCR text extraction, trust badges, payment logos,
reviews analysis, visual consistency, and suspicious design patterns.

Strictly passive forensic evidence collection.
DO NOT calculate Trust/Risk score, phishing probability, or final verdict.
"""

import datetime
import io
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import pytesseract
    _PYTESSERACT_AVAILABLE = True
except ImportError:
    _PYTESSERACT_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable constants & limits
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2MB HTML limit
MAX_IMAGE_SIZE = 1 * 1024 * 1024       # 1MB image limit
REQUEST_TIMEOUT = 10                   # 10 seconds timeout

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# =====================================================================
# LOAD REFERENCE DATASETS (data/trusted_badges.json, data/payment_logos.json)
# =====================================================================
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

def _load_json_reference(filename: str) -> List[Dict[str, Any]]:
    path = os.path.join(_DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

TRUSTED_BADGES_DATA = _load_json_reference("trusted_badges.json")
PAYMENT_LOGOS_DATA = _load_json_reference("payment_logos.json")

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
    """Safely extract registered domain name (e.g., example.com)."""
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
    """Fetch HTML page safely with strict size and timeout limits."""
    errors = []
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
# 1. SCREENSHOT CAPTURE & PLAYWRIGHT RENDERING
# =====================================================================

def _capture_screenshot(url: str) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Attempt headless browser rendering and screenshot capture."""
    screenshot_analysis = {
        "status": "not_available",
        "screenshot_captured": False,
        "width": None,
        "height": None,
        "error": None,
    }

    if not _PLAYWRIGHT_AVAILABLE:
        screenshot_analysis["error"] = "Playwright browser automation not installed or unavailable"
        return screenshot_analysis, None

    try:
        with sync_playwright() as p:
            # Launch chromium in headless mode
            browser = p.chromium.launch(headless=True, timeout=10000)
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=DEFAULT_HEADERS["User-Agent"]
            )
            page = context.new_page()
            page.set_default_timeout(REQUEST_TIMEOUT * 1000)
            page.goto(url, wait_until="load", timeout=REQUEST_TIMEOUT * 1000)
            page.wait_for_timeout(1000)  # Short controlled wait for dynamic elements
            screenshot_bytes = page.screenshot(type="png", full_page=False)
            browser.close()

            screenshot_analysis["status"] = "completed"
            screenshot_analysis["screenshot_captured"] = True
            screenshot_analysis["width"] = 1920
            screenshot_analysis["height"] = 1080
            return screenshot_analysis, screenshot_bytes
    except Exception as e:
        err_msg = str(e)
        if "Executable doesn't exist" in err_msg or "playwright install" in err_msg:
            screenshot_analysis["error"] = "Browser binaries not installed (run 'playwright install chromium')"
        else:
            screenshot_analysis["error"] = f"Screenshot capture failed: {err_msg}"
        return screenshot_analysis, None


# =====================================================================
# 2. OCR TEXT EXTRACTION
# =====================================================================

def _extract_ocr_text(screenshot_bytes: Optional[bytes]) -> Dict[str, Any]:
    """Run Tesseract OCR on rendered screenshot if available."""
    ocr_result = {
        "status": "not_available",
        "text": "",
        "detected_terms": [],
    }

    if not screenshot_bytes or not _PYTESSERACT_AVAILABLE or not _PIL_AVAILABLE:
        if not _PYTESSERACT_AVAILABLE:
            ocr_result["error"] = "pytesseract library not installed"
        elif not screenshot_bytes:
            ocr_result["error"] = "No screenshot available for OCR"
        return ocr_result

    try:
        image = Image.open(io.BytesIO(screenshot_bytes))
        # Attempt OCR text extraction
        extracted_text = pytesseract.image_to_string(image)
        raw_text = extracted_text.strip()

        # Identify key security/urgency terms from OCR output
        detected_terms = []
        target_patterns = [
            r"\b100% secure\b", r"\bverified payment\b", r"\bssl secure\b",
            r"\btrusted by\b", r"\bmoney back guarantee\b", r"\bofficial partner\b",
            r"\bact now\b", r"\blimited time offer\b", r"\bsecurity threat\b",
            r"\bimmediate action\b", r"\bverified by visa\b", r"\bpaypal verified\b"
        ]
        for pat in target_patterns:
            matches = re.findall(pat, raw_text, re.IGNORECASE)
            for m in matches:
                if m.title() not in detected_terms:
                    detected_terms.append(m.title())

        ocr_result["status"] = "completed"
        ocr_result["text"] = raw_text
        ocr_result["detected_terms"] = detected_terms
        return ocr_result
    except Exception as e:
        ocr_result["status"] = "not_available"
        ocr_result["error"] = f"OCR engine error: {str(e)}"
        return ocr_result


# =====================================================================
# 3. FAKE / UNVERIFIED TRUST BADGES
# =====================================================================

def _detect_trust_badges(
    soup: Optional[BeautifulSoup],
    ocr_text: str,
    base_url: str
) -> Tuple[Dict[str, Any], List[str]]:
    """Detect security/trust badges and assess verification evidence."""
    badges_result = {
        "detected": [],
        "suspicious_indicators": [],
    }
    evidence_list = []

    if not soup:
        return badges_result, evidence_list

    # Combine reference badges
    reference_badges = TRUSTED_BADGES_DATA or [
        {"name": "Norton Secured", "keywords": ["norton", "verisign"], "verification_url_patterns": ["trustseal.norton.com"]},
        {"name": "McAfee SECURE", "keywords": ["mcafee", "mcafee secure"], "verification_url_patterns": ["mcafeesecure.com"]},
        {"name": "BBB Accredited", "keywords": ["bbb", "better business bureau"], "verification_url_patterns": ["bbb.org"]},
        {"name": "100% Secure Seal", "keywords": ["100% secure", "ssl secure", "guaranteed safe"], "verification_url_patterns": []},
    ]

    # Search in HTML <img>, <svg>, <a> tags
    for img in soup.find_all(["img", "svg", "div", "span"]):
        src = img.get("src") or img.get("data-src") or ""
        alt = (img.get("alt") or "").strip()
        title = (img.get("title") or "").strip()
        classes = " ".join(img.get("class", [])) if isinstance(img.get("class"), list) else str(img.get("class") or "")
        combined_text = f"{src} {alt} {title} {classes}".lower()

        parent_a = img.find_parent("a")
        link_href = parent_a.get("href", "") if parent_a else ""

        for badge_ref in reference_badges:
            badge_name = badge_ref.get("name", "Trust Seal")
            keywords = badge_ref.get("keywords", [])

            if any(kw in combined_text for kw in keywords):
                # Found candidate badge
                verification_patterns = badge_ref.get("verification_url_patterns", [])
                is_linked = bool(link_href and link_href != "#" and not link_href.startswith("javascript:"))
                
                verification_status = "unverified"
                if is_linked:
                    if any(p in link_href.lower() for p in verification_patterns):
                        verification_status = "verified_official_link"
                    else:
                        verification_status = "potentially_suspicious"
                else:
                    verification_status = "potentially_suspicious"

                badge_entry = {
                    "badge_name": badge_name,
                    "text": alt or title or badge_name,
                    "image_url": urljoin(base_url, src) if src else None,
                    "link_url": link_href if is_linked else None,
                    "verification": verification_status,
                }

                # Avoid duplicate entries
                if not any(b["badge_name"] == badge_name and b["image_url"] == badge_entry["image_url"] for b in badges_result["detected"]):
                    badges_result["detected"].append(badge_entry)
                    if verification_status in ("potentially_suspicious", "unverified"):
                        indicator = f"Trust badge '{badge_name}' detected but lacks verified official verification hyperlink"
                        if indicator not in badges_result["suspicious_indicators"]:
                            badges_result["suspicious_indicators"].append(indicator)
                        evidence_list.append(indicator)
                    else:
                        evidence_list.append(f"Trust badge '{badge_name}' detected with verification link ({link_href})")

    # Also check OCR text for unanchored security claims
    if ocr_text:
        for badge_ref in reference_badges:
            for kw in badge_ref.get("keywords", []):
                if kw in ocr_text.lower():
                    if not any(kw in b["text"].lower() for b in badges_result["detected"]):
                        badge_entry = {
                            "badge_name": badge_ref.get("name", kw.title()),
                            "text": kw.title(),
                            "image_url": None,
                            "source": "OCR",
                            "verification": "unverified",
                        }
                        badges_result["detected"].append(badge_entry)
                        evidence_list.append(f"Security claim '{kw}' detected visually via OCR (unverified)")

    return badges_result, evidence_list


# =====================================================================
# 4. FAKE / UNVERIFIED PAYMENT LOGOS
# =====================================================================

def _detect_payment_logos(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str],
    ocr_text: str,
    base_url: str
) -> Tuple[Dict[str, Any], List[str]]:
    """Detect payment logos and analyze whether genuine payment checkout exists."""
    payment_result = {
        "detected": [],
        "suspicious_indicators": [],
    }
    evidence_list = []

    if not soup:
        return payment_result, evidence_list

    raw_html_lower = (html_text or "").lower()

    payment_refs = PAYMENT_LOGOS_DATA or [
        {"name": "Visa", "keywords": ["visa", "verified by visa"], "checkout_indicators": ["visa", "card-number"]},
        {"name": "Mastercard", "keywords": ["mastercard", "master card"], "checkout_indicators": ["mastercard"]},
        {"name": "PayPal", "keywords": ["paypal", "pay with paypal"], "checkout_indicators": ["paypal.com/sdk", "paypal-button"]},
        {"name": "Stripe", "keywords": ["stripe", "powered by stripe"], "checkout_indicators": ["js.stripe.com"]},
        {"name": "Apple Pay", "keywords": ["apple pay", "applepay"], "checkout_indicators": ["apple-pay-button"]},
        {"name": "Google Pay", "keywords": ["google pay", "gpay"], "checkout_indicators": ["pay.google.com/gp/p/js/pay.js"]},
    ]

    for pref in payment_refs:
        pname = pref.get("name", "")
        keywords = pref.get("keywords", [pname.lower()])
        checkout_inds = pref.get("checkout_indicators", [])

        # Check in HTML images/classes/alt
        detected_in_html = False
        img_src_found = None
        for img in soup.find_all(["img", "svg", "i"]):
            src = img.get("src") or img.get("data-src") or ""
            alt = img.get("alt") or ""
            classes = " ".join(img.get("class", [])) if isinstance(img.get("class"), list) else str(img.get("class") or "")
            combined = f"{src} {alt} {classes}".lower()
            if any(kw in combined for kw in keywords):
                detected_in_html = True
                img_src_found = urljoin(base_url, src) if src else None
                break

        # Check in OCR text
        detected_in_ocr = bool(ocr_text and any(kw in ocr_text.lower() for kw in keywords))

        if detected_in_html or detected_in_ocr:
            # Check if genuine checkout mechanism exists
            has_checkout_integration = any(ci in raw_html_lower for ci in checkout_inds)

            verification_status = "active_checkout_mechanism_detected" if has_checkout_integration else "unverified_static_logo"

            entry = {
                "name": pname,
                "detected": True,
                "source": "HTML Image" if detected_in_html else "OCR",
                "image_url": img_src_found,
                "has_checkout_integration": has_checkout_integration,
                "verification": verification_status,
            }

            payment_result["detected"].append(entry)

            if not has_checkout_integration:
                indicator = f"Payment logo '{pname}' displayed as static visual with no integrated checkout mechanism"
                payment_result["suspicious_indicators"].append(indicator)
                evidence_list.append(indicator)
            else:
                evidence_list.append(f"Payment logo '{pname}' detected with corresponding checkout integration indicators")

    return payment_result, evidence_list


# =====================================================================
# 5. FAKE / SUSPICIOUS REVIEWS ANALYSIS
# =====================================================================

def _analyze_reviews(soup: Optional[BeautifulSoup]) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze customer reviews/testimonials for suspicious repetition or generic patterns."""
    reviews_data = {
        "detected": False,
        "review_count_visible": 0,
        "average_rating_visible": None,
        "suspicious_indicators": [],
    }
    evidence_list = []

    if not soup:
        return reviews_data, evidence_list

    # Search for testimonial/review containers
    review_elements = []
    for elem in soup.find_all(["div", "section", "article", "li"]):
        class_name = " ".join(elem.get("class", [])) if isinstance(elem.get("class"), list) else str(elem.get("class") or "")
        elem_id = str(elem.get("id") or "")
        if re.search(r"\b(review|testimonial|feedback|rating|customer-quote)\b", f"{class_name} {elem_id}", re.IGNORECASE):
            if elem.find(["p", "span", "q"]):
                review_elements.append(elem)

    if not review_elements:
        return reviews_data, evidence_list

    reviews_data["detected"] = True
    reviews_data["review_count_visible"] = len(review_elements)

    # Extract review texts and reviewer names
    review_texts = []
    avatar_urls = []
    generic_names = ["john doe", "jane doe", "customer", "user", "anonymous", "client 1", "test user"]
    generic_name_count = 0

    for rev in review_elements[:20]:
        text = rev.get_text(separator=" ", strip=True)
        if len(text) > 10:
            review_texts.append(text.lower())
        for img in rev.find_all("img"):
            src = img.get("src") or ""
            if src:
                avatar_urls.append(src)
        for gen_name in generic_names:
            if gen_name in text.lower():
                generic_name_count += 1

    # Check for duplicate review texts
    unique_texts = set(review_texts)
    if len(review_texts) > len(unique_texts):
        indicator = "Potentially suspicious review pattern detected: identical review wording repeated across multiple entries"
        reviews_data["suspicious_indicators"].append(indicator)
        evidence_list.append(indicator)

    # Check for duplicate avatar images
    unique_avatars = set(avatar_urls)
    if len(avatar_urls) > len(unique_avatars) and len(avatar_urls) >= 2:
        indicator = "Potentially suspicious review pattern detected: identical avatar profile images repeated across different reviews"
        reviews_data["suspicious_indicators"].append(indicator)
        evidence_list.append(indicator)

    # Check for generic names
    if generic_name_count >= 2:
        indicator = "Potentially suspicious review pattern detected: generic placeholder reviewer names detected"
        reviews_data["suspicious_indicators"].append(indicator)
        evidence_list.append(indicator)

    # Check for star ratings
    stars = soup.find_all(string=re.compile(r"5(?:\.0)?\s*/\s*5|★★★★★|5\s*stars?", re.IGNORECASE))
    if stars:
        reviews_data["average_rating_visible"] = "5.0"

    evidence_list.append(f"Customer reviews detected ({len(review_elements)} visible review elements)")

    return reviews_data, evidence_list


# =====================================================================
# 6. VISUAL CONSISTENCY ANALYSIS
# =====================================================================

def _analyze_visual_consistency(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Inspect visual design consistency (fonts, buttons, image dimensions)."""
    consistency_data = {
        "status": "not_available",
        "indicators": [],
    }
    evidence_list = []

    if not soup or not html_text:
        return consistency_data, evidence_list

    consistency_data["status"] = "analyzed"

    # 1. Font families check
    font_families = set(re.findall(r"font-family\s*:\s*([^;}{]+)", html_text, re.IGNORECASE))
    if len(font_families) > 5:
        ind = f"High typography fragmentation detected ({len(font_families)} distinct font-family declarations)"
        consistency_data["indicators"].append(ind)
        evidence_list.append(ind)
    else:
        consistency_data["indicators"].append("Typography demonstrates normal font-family consistency")

    # 2. Button styling
    buttons = soup.find_all(["button", "a"])
    cta_buttons = [b for b in buttons if re.search(r"\b(btn|button|cta|submit)\b", " ".join(b.get("class", [])) if isinstance(b.get("class"), list) else str(b.get("class") or ""), re.IGNORECASE)]
    if len(cta_buttons) >= 2:
        consistency_data["indicators"].append("Primary interactive buttons use standardized UI styling classes")

    # 3. Image aspect ratio / low resolution checks
    distorted_images = 0
    for img in soup.find_all("img")[:15]:
        width_attr = img.get("width")
        height_attr = img.get("height")
        if width_attr and height_attr:
            try:
                w, h = float(width_attr), float(height_attr)
                if (w > 300 and h < 20) or (h > 300 and w < 20):
                    distorted_images += 1
            except ValueError:
                pass

    if distorted_images > 0:
        ind = f"Potentially distorted or misaligned image elements detected ({distorted_images} images with extreme aspect ratio)"
        consistency_data["indicators"].append(ind)
        evidence_list.append(ind)

    return consistency_data, evidence_list


# =====================================================================
# 7. SUSPICIOUS DESIGN PATTERNS
# =====================================================================

def _detect_suspicious_patterns(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str],
    ocr_text: str
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Identify deceptive or high-pressure UI design patterns."""
    patterns = []
    evidence_list = []

    if not soup:
        return patterns, evidence_list

    full_text = f"{soup.get_text(separator=' ', strip=True)} {ocr_text}".lower()

    # 1. Urgency Patterns
    urgency_triggers = [
        ("Act Now!", r"\b(act now|hurry up|only \d+ (?:minutes?|seconds?|hours?) remaining|offer expires (?:today|now))\b"),
        ("Countdown Timer", r"\b(countdown|ends in \d\d:\d\d|time remaining)\b"),
        ("Immediate Expiration", r"\b(valid only today|claim your prize within \d+ (?:minutes|hours))\b"),
    ]
    for label, pat in urgency_triggers:
        match = re.search(pat, full_text)
        if match:
            item = {
                "pattern": "urgency",
                "evidence": f"Urgency trigger detected: '{match.group(0)}'",
                "source": "OCR/Text"
            }
            patterns.append(item)
            evidence_list.append(f"Suspicious design pattern (Urgency): '{match.group(0)}'")

    # 2. Fear / Intimidation Patterns
    fear_triggers = [
        ("Account Deletion Threat", r"\b(your account will be (?:deleted|suspended|terminated)|account closure warning)\b"),
        ("Security Threat Warning", r"\b(security threat detected|virus detected|critical security alert|system compromised)\b"),
        ("Immediate Action Required", r"\b(immediate action required|mandatory verification required|urgent update required)\b"),
    ]
    for label, pat in fear_triggers:
        match = re.search(pat, full_text)
        if match:
            item = {
                "pattern": "fear",
                "evidence": f"Fear/threat trigger detected: '{match.group(0)}'",
                "source": "OCR/Text"
            }
            patterns.append(item)
            evidence_list.append(f"Suspicious design pattern (Fear/Intimidation): '{match.group(0)}'")

    # 3. Fake Scarcity Patterns
    scarcity_triggers = [
        ("Stock Scarcity", r"\b(only \d+ items? (?:left|remaining)|almost sold out)\b"),
        ("Social Proof Scarcity", r"\b(\d+ people (?:are )?viewing this (?:right now|item|page))\b"),
    ]
    for label, pat in scarcity_triggers:
        match = re.search(pat, full_text)
        if match:
            item = {
                "pattern": "fake_scarcity",
                "evidence": f"Scarcity trigger detected: '{match.group(0)}'",
                "source": "OCR/Text"
            }
            patterns.append(item)
            evidence_list.append(f"Suspicious design pattern (Fake Scarcity): '{match.group(0)}'")

    # 4. Deceptive Buttons / CTAs
    for btn in soup.find_all(["button", "a"]):
        btn_text = btn.get_text(separator=" ", strip=True).lower()
        href = (btn.get("href") or "").lower()
        if re.search(r"\b(download|continue|start now|install)\b", btn_text):
            if any(login_kw in href for login_kw in ["login", "signin", "auth", "payment", "checkout"]):
                item = {
                    "pattern": "deceptive_button",
                    "evidence": f"Button labelled '{btn_text}' directs to unexpected endpoint '{href}'",
                    "source": "HTML DOM"
                }
                patterns.append(item)
                evidence_list.append(f"Deceptive CTA: Button labelled '{btn_text}' targets authentication/payment route '{href}'")

    # 5. Credential-Focused Visual UI
    has_pwd = bool(soup.find("input", attrs={"type": "password"}))
    has_card = bool(soup.find("input", attrs={"name": re.compile(r"card|cvv|ccnum|exp", re.IGNORECASE)}))
    if has_pwd or has_card:
        item = {
            "pattern": "credential_focused_ui",
            "evidence": "Prominent credential / payment card entry fields visually featured in main viewport",
            "source": "HTML DOM"
        }
        patterns.append(item)
        evidence_list.append("Credential-focused UI: Direct credential/card input fields visually featured")

    return patterns, evidence_list


# =====================================================================
# MAIN ENTRYPOINT
# =====================================================================

def analyze_visual(url: str) -> Dict[str, Any]:
    """
    Main entry point for Agent 10: Visual & UI Analysis.
    Performs safe screenshot capture, OCR text extraction, trust badge verification,
    payment logo inspection, review authenticity checks, visual consistency audit,
    and suspicious design pattern detection.
    """
    print("[Agent 10] Starting visual analysis...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    forensic_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 10] Invalid URL provided.")
        extra = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "screenshot_analysis": {"status": "not_available", "screenshot_captured": False, "error": "URL is required"},
            "ocr": {"status": "not_available", "text": "", "detected_terms": []},
            "trust_badges": {"detected": [], "suspicious_indicators": []},
            "payment_logos": {"detected": [], "suspicious_indicators": []},
            "reviews": {"detected": False, "review_count_visible": 0, "suspicious_indicators": []},
            "visual_consistency": {"status": "not_available", "indicators": []},
            "suspicious_design_patterns": [],
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A10",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra,
        )

    print("[Agent 10] Normalizing URL...")
    normalized_url = _normalize_url(url)
    submitted_domain = _extract_registered_domain(normalized_url)

    # Initialize session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    # Fetch webpage safely
    html_text, final_url, soup, fetch_errors = _fetch_webpage_safe(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    final_domain = _extract_registered_domain(final_url) if final_url else submitted_domain

    print("[Agent 10] Rendering webpage...")
    print("[Agent 10] Capturing screenshot...")
    screenshot_result, screenshot_bytes = _capture_screenshot(final_url or normalized_url)

    print("[Agent 10] Running OCR...")
    ocr_result = _extract_ocr_text(screenshot_bytes)
    ocr_raw_text = ocr_result.get("text", "")

    print("[Agent 10] Detecting trust badges...")
    badges_result, badges_evidence = _detect_trust_badges(soup, ocr_raw_text, final_url or normalized_url)
    forensic_evidence.extend(badges_evidence)

    print("[Agent 10] Detecting payment logos...")
    payment_result, payment_evidence = _detect_payment_logos(soup, html_text, ocr_raw_text, final_url or normalized_url)
    forensic_evidence.extend(payment_evidence)

    print("[Agent 10] Analyzing reviews...")
    reviews_result, reviews_evidence = _analyze_reviews(soup)
    forensic_evidence.extend(reviews_evidence)

    print("[Agent 10] Checking visual consistency...")
    consistency_result, consistency_evidence = _analyze_visual_consistency(soup, html_text)
    forensic_evidence.extend(consistency_evidence)

    print("[Agent 10] Detecting suspicious design patterns...")
    patterns_result, patterns_evidence = _detect_suspicious_patterns(soup, html_text, ocr_raw_text)
    forensic_evidence.extend(patterns_evidence)

    print("[Agent 10] Generating evidence...")
    # Build structured evidence items
    structured_evidence = []

    # E10-01: Screenshot Capture
    if screenshot_result.get("screenshot_captured"):
        structured_evidence.append(create_evidence_item(
            agent_id="A10",
            index=1,
            finding="Viewport rendering captured successfully",
            value=f"{screenshot_result.get('width')}x{screenshot_result.get('height')}",
            severity="info",
            source="Playwright / Headless Browser",
            evidence_type="deterministic",
            evidence_strength=0.1,
            metadata={"screenshot_analysis": screenshot_result}
        ))
    else:
        structured_evidence.append(create_evidence_item(
            agent_id="A10",
            index=1,
            finding="Viewport screenshot unavailable",
            value=screenshot_result.get("error", "Unknown"),
            severity="low",
            source="Playwright / Headless Browser",
            evidence_type="deterministic",
            evidence_strength=0.2,
            metadata={"screenshot_analysis": screenshot_result}
        ))

    # E10-02: OCR Text & Detected Terms
    has_ocr = ocr_result.get("status") == "completed" and bool(ocr_result.get("detected_terms"))
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=2,
        finding="OCR extracted text and detected security/urgency terms",
        value=ocr_result.get("detected_terms", []),
        severity="medium" if has_ocr else "info",
        source="Tesseract OCR",
        evidence_type="deterministic",
        evidence_strength=0.6 if has_ocr else 0.1,
        metadata=ocr_result
    ))

    # E10-03: Trust Badges
    has_bad_badges = bool(badges_result.get("suspicious_indicators"))
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=3,
        finding="Trust badge presence and verification status",
        value=badges_result.get("detected", []),
        severity="high" if has_bad_badges else "info",
        source="HTML DOM Inspection",
        evidence_type="deterministic",
        evidence_strength=0.75 if has_bad_badges else 0.2,
        metadata=badges_result
    ))

    # E10-04: Payment Logos
    has_bad_payments = bool(payment_result.get("suspicious_indicators"))
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=4,
        finding="Payment logo presence and checkout integration",
        value=payment_result.get("detected", []),
        severity="high" if has_bad_payments else "info",
        source="HTML & Checkout Analysis",
        evidence_type="deterministic",
        evidence_strength=0.8 if has_bad_payments else 0.2,
        metadata=payment_result
    ))

    # E10-05: Reviews & Testimonials
    has_bad_reviews = bool(reviews_result.get("suspicious_indicators"))
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=5,
        finding="Customer testimonials and review authenticity heuristics",
        value=reviews_result.get("review_count_visible", 0),
        severity="high" if has_bad_reviews else "info",
        source="Testimonial DOM Heuristics",
        evidence_type="inference",
        evidence_strength=0.7 if has_bad_reviews else 0.1,
        metadata=reviews_result
    ))

    # E10-06: Visual Consistency
    has_distorted = any("distorted" in ind.lower() or "fragmentation" in ind.lower() for ind in consistency_result.get("indicators", []))
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=6,
        finding="Visual layout and typography consistency",
        value=consistency_result.get("indicators", []),
        severity="medium" if has_distorted else "info",
        source="CSS / Layout Analysis",
        evidence_type="deterministic",
        evidence_strength=0.5 if has_distorted else 0.1,
        metadata=consistency_result
    ))

    # E10-07: Deceptive Design Patterns
    has_patterns = bool(patterns_result)
    structured_evidence.append(create_evidence_item(
        agent_id="A10",
        index=7,
        finding="Deceptive and high-pressure UI design patterns",
        value=[p.get("pattern", "unknown") for p in patterns_result],
        severity="high" if has_patterns else "info",
        source="Dark Pattern Heuristics",
        evidence_type="inference",
        evidence_strength=0.85 if has_patterns else 0.05,
        metadata={"patterns": patterns_result}
    ))

    print("[Agent 10] Visual analysis completed.")

    data_payload = {
        "screenshot_analysis": screenshot_result,
        "ocr": ocr_result,
        "trust_badges": badges_result,
        "payment_logos": payment_result,
        "reviews": reviews_result,
        "visual_consistency": consistency_result,
        "suspicious_design_patterns": patterns_result,
        "evidence": forensic_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url or normalized_url,
            "domain": final_domain or submitted_domain,
        },
        "screenshot_analysis": screenshot_result,
        "ocr": ocr_result,
        "trust_badges": badges_result,
        "payment_logos": payment_result,
        "reviews": reviews_result,
        "visual_consistency": consistency_result,
        "suspicious_design_patterns": patterns_result,
        "evidence": forensic_evidence,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A10",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
