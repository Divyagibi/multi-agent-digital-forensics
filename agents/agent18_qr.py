"""
Agent 18 — QR Code Analysis Agent
Multi-Agent Digital Forensics System

Strictly an EVIDENCE COLLECTION module for analyzing QR codes and QR-derived URLs.
Collects:
- QR Decoding & Payload Extraction
- Embedded URL Detection & Normalization
- Safe HTTP Redirect Chain Tracing
- Shortened URL / Shortener Service Detection
- Hidden & Open-Redirect Query Parameter Inspection
- QR Image Modification & Overlay Heuristics
- QR Error Correction Level & Format Analysis
- Source-Attributed Forensic Evidence Records

IMPORTANT:
- Operates as an EVIDENCE COLLECTION AGENT.
- Does NOT calculate the final Trust Score (trust_score: null).
- Does NOT calculate the final Risk Score (risk_score: null).
- Does NOT give a malicious/safe verdict (verdict: "not_calculated").
- Does NOT execute untrusted content, JavaScript, downloads, or shell commands.
"""

import os
import re
import io
import base64
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union

import requests
from PIL import Image

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import numpy as np
    import cv2
    _OPENCV_AVAILABLE = True
except ImportError:
    _OPENCV_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# =====================================================================
# CONFIGURATION & CONSTANTS
# =====================================================================

MAX_REDIRECTS = 10
REDIRECT_TIMEOUT_SECONDS = 5
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

COMMON_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "clck.ru", "v.gd",
    "shorte.st", "adf.ly", "bc.vc", "shorturl.at", "bl.ink", "hyperurl.co",
    "trib.al", "qr.ae", "ift.tt", "trib.al", "s.id", "soo.gd", "snip.ly"
}

SUSPICIOUS_PARAM_KEYS = {
    "redirect", "redirect_url", "redirect_to", "return", "return_url",
    "returnurl", "url", "next", "target", "dest", "destination",
    "callback", "goto", "link", "out", "r", "u", "uri", "continue",
    "relay", "feed", "view", "forward", "endpoint", "checkout_url"
}

URL_REGEX = re.compile(
    r"(?:https?://|ftp://|www\.)[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
    re.IGNORECASE
)


# =====================================================================
# 1. QR DECODING ENGINE
# =====================================================================

def decode_qr_image(image_input: Union[str, bytes, io.BytesIO]) -> Dict[str, Any]:
    """
    Decode QR code payload from image path, raw bytes, or base64 string.
    Applies multi-pass preprocessing (grayscale, adaptive thresholding, scaling)
    to handle QR codes embedded in complex or low-contrast backgrounds.
    """
    result = {
        "decoded": False,
        "decoded_data": None,
        "data_type": "none",
        "qr_version": "unknown",
        "error_correction_level": "unknown",
        "points": None,
        "error": None
    }

    if not _OPENCV_AVAILABLE:
        result["error"] = "OpenCV is not available for QR decoding."
        return result

    try:
        # Load image into PIL / OpenCV format
        pil_image = None
        if isinstance(image_input, str):
            if image_input.startswith("data:image/") and ";base64," in image_input:
                b64_data = image_input.split(";base64,")[1]
                pil_image = Image.open(io.BytesIO(base64.b64decode(b64_data)))
            elif os.path.exists(image_input):
                pil_image = Image.open(image_input)
            else:
                # Try raw base64 decode
                try:
                    pil_image = Image.open(io.BytesIO(base64.b64decode(image_input)))
                except Exception:
                    result["error"] = f"Image file not found: {image_input}"
                    return result
        elif isinstance(image_input, (bytes, bytearray)):
            pil_image = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, io.BytesIO):
            pil_image = Image.open(image_input)

        if not pil_image:
            result["error"] = "Unable to parse image data."
            return result

        # Convert to RGB numpy array
        rgb_img = pil_image.convert("RGB")
        img_np = np.array(rgb_img)
        bgr_img = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        gray_img = cv2.cvtColor(bgr_img, cv2.COLOR_BGR2GRAY)

        detector = cv2.QRCodeDetector()

        # Multi-pass decoding strategies
        passes = [
            ("original_bgr", bgr_img),
            ("grayscale", gray_img),
            ("equalized", cv2.equalizeHist(gray_img)),
            ("threshold_otsu", cv2.threshold(gray_img, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]),
            ("adaptive_thresh", cv2.adaptiveThreshold(gray_img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10)),
            ("scaled_up_2x", cv2.resize(gray_img, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)),
            ("scaled_down_0.5x", cv2.resize(gray_img, (0, 0), fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA))
        ]

        decoded_text = ""
        points = None
        straight_qrcode = None

        for pass_name, proc_img in passes:
            try:
                val, pts, qrcode_mat = detector.detectAndDecode(proc_img)
                if val and len(val.strip()) > 0:
                    decoded_text = val.strip()
                    points = pts.tolist() if pts is not None else None
                    straight_qrcode = qrcode_mat
                    break
            except Exception:
                continue

        if not decoded_text:
            result["error"] = "QR code could not be decoded from the provided image."
            return result

        result["decoded"] = True
        result["decoded_data"] = decoded_text
        result["points"] = points

        # Determine data type
        extracted_url, is_url = extract_embedded_url(decoded_text)
        if is_url:
            result["data_type"] = "URL"
        elif decoded_text.lower().startswith("wifi:"):
            result["data_type"] = "WIFI_CONFIG"
        elif decoded_text.lower().startswith("smsto:") or decoded_text.lower().startswith("sms:"):
            result["data_type"] = "SMS"
        elif decoded_text.lower().startswith("mailto:") or "@" in decoded_text and " " not in decoded_text:
            result["data_type"] = "EMAIL"
        elif decoded_text.lower().startswith("tel:"):
            result["data_type"] = "TELEPHONE"
        elif decoded_text.lower().startswith("mecard:") or decoded_text.lower().startswith("begin:vcard"):
            result["data_type"] = "VCARD"
        else:
            result["data_type"] = "TEXT"

        # Heuristic error correction & version estimation if straight_qrcode matrix exists
        if straight_qrcode is not None and hasattr(straight_qrcode, "shape"):
            dim = straight_qrcode.shape[0]
            if dim >= 21:
                est_version = int((dim - 21) / 4) + 1
                result["qr_version"] = est_version

        return result

    except Exception as e:
        result["error"] = f"Decoding exception: {str(e)}"
        return result


# =====================================================================
# 2. EMBEDDED URL DETECTION & NORMALIZATION
# =====================================================================

def extract_embedded_url(payload: str) -> Tuple[Optional[str], bool]:
    """
    Extract the actual target URL from raw QR payload.
    Handles raw URLs, URL=..., URI:..., and text containing URLs.
    """
    if not payload or not isinstance(payload, str):
        return None, False

    clean_payload = payload.strip()

    # Check for direct URL prefixes
    if re.match(r"^https?://", clean_payload, re.IGNORECASE):
        return clean_payload, True

    if clean_payload.lower().startswith("url:") or clean_payload.lower().startswith("url="):
        candidate = clean_payload[4:].strip()
        if re.match(r"^https?://", candidate, re.IGNORECASE):
            return candidate, True
        elif candidate.startswith("www."):
            return "https://" + candidate, True

    if clean_payload.lower().startswith("uri:") or clean_payload.lower().startswith("uri="):
        candidate = clean_payload[4:].strip()
        if re.match(r"^https?://", candidate, re.IGNORECASE):
            return candidate, True

    if clean_payload.startswith("www."):
        return "https://" + clean_payload, True

    # Search for embedded URL pattern inside text
    match = URL_REGEX.search(clean_payload)
    if match:
        url_match = match.group(0)
        if not re.match(r"^https?://", url_match, re.IGNORECASE):
            url_match = "https://" + url_match
        return url_match, True

    return None, False


def normalize_qr_url(url: str, original_payload: Optional[str] = None) -> Dict[str, Any]:
    """
    Normalize URL and extract structured URL components.
    Preserves original payload.
    """
    url = (url or "").strip()
    if not url:
        return {
            "original_payload": original_payload or "",
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "domain": "",
            "port": None,
            "path": "/",
            "query": "",
            "fragment": "",
            "query_params": {}
        }

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        scheme = (parsed.scheme or "https").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path or "/"
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        # Extract registered domain
        domain = hostname
        if _TLDEXTRACT_AVAILABLE and hostname:
            ext = tldextract.extract(hostname)
            reg_dom = getattr(ext, "top_domain_under_public_suffix", "")
            if reg_dom:
                domain = reg_dom.lower()
            elif ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}".lower()
        elif hostname:
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])

        # Parse query params into dict
        query_params = {}
        if query:
            parsed_qs = urllib.parse.parse_qs(query, keep_blank_values=True)
            for k, v in parsed_qs.items():
                query_params[k] = v if len(v) > 1 else (v[0] if v else "")

        normalized_url = urllib.parse.urlunparse((
            scheme,
            f"{hostname}:{port}" if port and port not in (80, 443) else hostname,
            path,
            parsed.params,
            query,
            fragment
        ))

        return {
            "original_payload": original_payload or url,
            "normalized_url": normalized_url,
            "scheme": scheme,
            "hostname": hostname,
            "domain": domain,
            "port": port,
            "path": path,
            "query": query,
            "fragment": fragment,
            "query_params": query_params
        }

    except Exception:
        return {
            "original_payload": original_payload or url,
            "normalized_url": url,
            "scheme": "https",
            "hostname": "",
            "domain": "",
            "port": None,
            "path": "/",
            "query": "",
            "fragment": "",
            "query_params": {}
        }


# =====================================================================
# 3. REDIRECT CHAIN TRACING (SAFE STATIC ANALYSIS)
# =====================================================================

def trace_redirect_chain(
    initial_url: str,
    max_redirects: int = MAX_REDIRECTS,
    timeout: int = REDIRECT_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Safely traces the HTTP redirect chain of the QR-derived URL without executing content.
    Follows redirects up to max_redirects limit with timeout.
    """
    result = {
        "initial_url": initial_url,
        "final_url": initial_url,
        "redirect_chain": [initial_url],
        "redirect_count": 0,
        "has_redirects": False,
        "hops": [],
        "errors": []
    }

    if not initial_url or not re.match(r"^https?://", initial_url, re.IGNORECASE):
        return result

    current_url = initial_url
    session = requests.Session()
    session.headers.update({"User-Agent": "DigitalForensicsAgent/1.0"})

    for hop_idx in range(max_redirects):
        try:
            resp = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                stream=True
            )
            status = resp.status_code
            location = resp.headers.get("Location")

            hop_entry = {
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": status,
                "location_header": location
            }
            result["hops"].append(hop_entry)

            # Check if status code is redirect
            if status in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current_url, location)
                result["redirect_chain"].append(next_url)
                current_url = next_url
            else:
                break

        except requests.exceptions.RequestException as e:
            result["errors"].append(f"Redirect trace stopped at hop {hop_idx + 1}: {str(e)}")
            break
        except Exception as e:
            result["errors"].append(f"Unexpected error at hop {hop_idx + 1}: {str(e)}")
            break

    result["final_url"] = current_url
    result["redirect_count"] = max(0, len(result["redirect_chain"]) - 1)
    result["has_redirects"] = result["redirect_count"] > 0
    return result


# =====================================================================
# 4. SHORTENED URL DETECTION
# =====================================================================

def detect_shortened_url(hostname: str, domain: str) -> Dict[str, Any]:
    """
    Detect if the URL uses a known URL shortening provider.
    """
    is_shortener = False
    provider = None

    host_lower = (hostname or "").lower()
    dom_lower = (domain or "").lower()

    for short_domain in COMMON_SHORTENER_DOMAINS:
        if host_lower == short_domain or dom_lower == short_domain or host_lower.endswith("." + short_domain):
            is_shortener = True
            provider = short_domain
            break

    return {
        "detected": is_shortener,
        "provider": provider,
        "risk_indicator": "url_shortener" if is_shortener else None
    }


# =====================================================================
# 5. HIDDEN & OPEN-REDIRECT PARAMETER INSPECTION
# =====================================================================

def inspect_hidden_parameters(query_params: Dict[str, Any], query_string: str) -> List[Dict[str, Any]]:
    """
    Inspect query parameters for open redirects, Base64 strings, nested URLs, and tracking parameters.
    """
    findings = []

    for key, value in query_params.items():
        key_lower = key.lower()
        val_str = str(value) if value is not None else ""

        # Check for open redirect key names
        is_redirect_key = key_lower in SUSPICIOUS_PARAM_KEYS or any(k in key_lower for k in ("redirect", "return", "callback", "dest"))
        
        # Check if value is a URL
        is_url_val = bool(re.match(r"^https?://", val_str, re.IGNORECASE) or val_str.startswith("//") or val_str.startswith("www."))
        
        # Check if value is URL-encoded URL
        decoded_val = urllib.parse.unquote(val_str)
        is_encoded_url = decoded_val != val_str and bool(re.match(r"^https?://", decoded_val, re.IGNORECASE))

        # Check if value is Base64 encoded URL or text
        is_base64 = False
        b64_decoded_val = None
        if len(val_str) >= 8 and len(val_str) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", val_str):
            try:
                decoded_bytes = base64.b64decode(val_str, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text.strip()) > 3:
                    is_base64 = True
                    b64_decoded_val = decoded_text
            except Exception:
                pass

        if is_redirect_key or is_url_val or is_encoded_url or is_base64:
            param_type = "open_redirect_candidate" if (is_redirect_key or is_url_val or is_encoded_url) else "encoded_parameter"
            findings.append({
                "parameter_name": key,
                "parameter_value": val_str[:200],
                "decoded_value": (decoded_val if is_encoded_url else b64_decoded_val) or val_str,
                "type": param_type,
                "is_redirect_key": is_redirect_key,
                "is_nested_url": is_url_val or is_encoded_url,
                "is_base64_encoded": is_base64,
                "observation": f"Parameter '{key}' contains nested target or encoded redirect payload."
            })

    return findings


# =====================================================================
# 6. QR MODIFICATION & VISUAL HEURISTICS
# =====================================================================

def analyze_qr_modifications(
    image_input: Optional[Union[str, bytes, io.BytesIO]],
    points: Optional[List[Any]] = None
) -> Dict[str, Any]:
    """
    Heuristically analyze QR code image for potential visual modifications, overlays, or damage.
    """
    result = {
        "status": "unknown",
        "indicators": [],
        "has_overlay_detected": False,
        "contrast_uniformity": "unknown",
        "finder_patterns_integrity": "unknown"
    }

    if not _OPENCV_AVAILABLE or image_input is None:
        return result

    try:
        pil_image = None
        if isinstance(image_input, str):
            if image_input.startswith("data:image/") and ";base64," in image_input:
                b64_data = image_input.split(";base64,")[1]
                pil_image = Image.open(io.BytesIO(base64.b64decode(b64_data)))
            elif os.path.exists(image_input):
                pil_image = Image.open(image_input)
            else:
                try:
                    pil_image = Image.open(io.BytesIO(base64.b64decode(image_input)))
                except Exception:
                    return result
        elif isinstance(image_input, (bytes, bytearray)):
            pil_image = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, io.BytesIO):
            pil_image = Image.open(image_input)

        if not pil_image:
            return result

        img_np = np.array(pil_image.convert("RGB"))
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        # Check center region for non-QR color overlay / custom logo
        h, w = gray.shape
        center_region = gray[int(h * 0.35):int(h * 0.65), int(w * 0.35):int(w * 0.65)]
        
        # Calculate variance of center vs outer region
        center_std = np.std(center_region) if center_region.size > 0 else 0
        overall_std = np.std(gray) if gray.size > 0 else 0

        indicators = []
        status = "not_detected"

        # Check if points were detected
        if points is not None:
            result["finder_patterns_integrity"] = "valid"
        else:
            result["finder_patterns_integrity"] = "partially_degraded"

        # Heuristic check for center logo/overlay
        if abs(center_std - overall_std) > 35:
            result["has_overlay_detected"] = True
            indicators.append("Visual variance detected in central region (consistent with logo overlay or artwork embedding).")
            status = "detected"
        elif abs(center_std - overall_std) > 20:
            indicators.append("Minor visual texture variation detected in center region.")
            status = "suspected"

        result["status"] = status
        result["indicators"] = indicators
        return result

    except Exception:
        result["status"] = "unknown"
        return result


# =====================================================================
# 7. STANDARDIZED EVIDENCE COMPILATION
# =====================================================================

def compile_qr_evidence(
    qr_decoding: Dict[str, Any],
    embedded_url: Dict[str, Any],
    redirect_data: Dict[str, Any],
    shortened_data: Dict[str, Any],
    hidden_params: List[Dict[str, Any]],
    mod_analysis: Dict[str, Any],
    error_correction: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Compile standardized, source-traceable forensic evidence observations for Agent 18.
    Adheres strictly to the research-grade Common Evidence Schema format (E18-XX).
    """
    evidence = []

    # 1. QR Decoding Evidence (E18-01)
    if qr_decoding.get("decoded"):
        evidence.append(create_evidence_item(
            agent_id="A18",
            index=1,
            finding="QR code payload extraction and data type classification",
            value=qr_decoding.get("data_type"),
            severity="info",
            source="QR Image Decoder",
            evidence_type="deterministic",
            evidence_strength=0.1,
            metadata=qr_decoding,
            category="qr_decoding"
        ))
    else:
        evidence.append(create_evidence_item(
            agent_id="A18",
            index=1,
            finding="QR code decoding failed or unreadable payload",
            value=qr_decoding.get("error", "unreadable image"),
            severity="high",
            source="QR Image Decoder",
            evidence_type="deterministic",
            evidence_strength=0.8,
            metadata=qr_decoding,
            category="qr_decoding"
        ))

    # 2. Embedded URL Evidence (E18-02)
    has_url = embedded_url.get("detected", False)
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=2,
        finding="Embedded web URL identification within QR payload",
        value=embedded_url.get("url"),
        severity="info",
        source="QR Payload Parser",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=embedded_url,
        category="embedded_url"
    ))

    # 3. URL Shortener Evidence (E18-03)
    has_shortener = shortened_data.get("detected", False)
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=3,
        finding="URL shortening service utilization in QR payload",
        value=shortened_data.get("provider") if has_shortener else "Direct Domain",
        severity="medium" if has_shortener else "info",
        source="Domain / Shortener Analyzer",
        evidence_type="threat_intelligence",
        evidence_strength=0.6 if has_shortener else 0.1,
        metadata=shortened_data,
        category="url_shortener"
    ))

    # 4. Redirect Chain Evidence (E18-04)
    redir_count = redirect_data.get("redirect_count", redirect_data.get("count", 0))
    has_redirects = redirect_data.get("has_redirects", False) or redir_count > 0
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=4,
        finding="Multi-hop HTTP redirection chain execution",
        value=redir_count,
        severity="medium" if has_redirects else "info",
        source="HTTP Redirect Tracer",
        evidence_type="deterministic",
        evidence_strength=0.6 if has_redirects else 0.1,
        metadata=redirect_data,
        category="redirect_chain"
    ))

    # 5. Hidden Parameter & Open-Redirect Evidence (E18-05)
    has_open_redir = len(hidden_params) > 0
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=5,
        finding="Open-redirect and hidden query parameter inspection",
        value=[p.get("parameter_name") for p in hidden_params],
        severity="high" if has_open_redir else "info",
        source="URL Query Parser",
        evidence_type="inference",
        evidence_strength=0.85 if has_open_redir else 0.05,
        metadata={"hidden_parameters": hidden_params},
        category="hidden_parameters"
    ))

    # 6. QR Modification Evidence (E18-06)
    mod_status = mod_analysis.get("status", "unknown")
    is_modified = mod_status in ("detected", "suspected")
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=6,
        finding="Visual alteration and physical sticker/overlay analysis",
        value=mod_status,
        severity="high" if is_modified else "info",
        source="QR Image Distortion Analyzer",
        evidence_type="inference",
        evidence_strength=0.8 if is_modified else 0.1,
        metadata=mod_analysis,
        category="modification_analysis"
    ))

    # 7. Error Correction Evidence (E18-07)
    evidence.append(create_evidence_item(
        agent_id="A18",
        index=7,
        finding="QR code version and Reed-Solomon error correction level",
        value=f"Version: {error_correction.get('version')}, Level: {error_correction.get('level')}",
        severity="info",
        source="QR Format Parser",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=error_correction,
        category="error_correction"
    ))

    return evidence


# =====================================================================
# 8. MAIN AGENT ENTRYPOINT
# =====================================================================

def analyze_qr(
    image_input: Optional[Union[str, bytes, io.BytesIO]] = None,
    url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main forensic analysis pipeline for Agent 18.
    Accepts either a QR image (path/bytes/base64) OR a direct URL string.
    Returns complete structured evidence adhering to Common Evidence Schema.
    """
    checked_at = datetime.now(timezone.utc).isoformat()
    errors: List[Dict[str, str]] = []

    qr_decoding_res = {
        "decoded": False,
        "payload": None,
        "data_type": "none"
    }

    embedded_url_res = {
        "detected": False,
        "url": None
    }

    redirect_res = {
        "count": 0,
        "urls": [],
        "initial_url": None,
        "final_url": None,
        "has_redirects": False
    }

    shortened_res = {
        "detected": False,
        "provider": None
    }

    hidden_parameters_res: List[Dict[str, Any]] = []

    modification_res = {
        "status": "unknown",
        "indicators": []
    }

    error_correction_res = {
        "level": "unknown",
        "version": "unknown"
    }

    normalized_url_info: Dict[str, Any] = {}
    target_url_to_analyze: Optional[str] = None
    raw_payload_text: Optional[str] = None

    # Path A: User supplied QR image
    if image_input is not None:
        dec_info = decode_qr_image(image_input)
        if dec_info.get("decoded"):
            raw_payload_text = dec_info.get("decoded_data")
            qr_decoding_res["decoded"] = True
            qr_decoding_res["payload"] = raw_payload_text
            qr_decoding_res["data_type"] = dec_info.get("data_type", "TEXT")
            error_correction_res["version"] = dec_info.get("qr_version", "unknown")
            error_correction_res["level"] = dec_info.get("error_correction_level", "unknown")

            # Check embedded URL
            ext_url, is_url = extract_embedded_url(raw_payload_text)
            if is_url and ext_url:
                embedded_url_res["detected"] = True
                embedded_url_res["url"] = ext_url
                target_url_to_analyze = ext_url
            else:
                embedded_url_res["detected"] = False
                embedded_url_res["url"] = None

            # Modification analysis
            mod_data = analyze_qr_modifications(image_input, dec_info.get("points"))
            modification_res["status"] = mod_data.get("status", "unknown")
            modification_res["indicators"] = mod_data.get("indicators", [])

        else:
            errors.append({"component": "qr_decoder", "error": dec_info.get("error", "QR code could not be decoded.")})

    # Path B: Direct URL provided
    elif url is not None and isinstance(url, str) and url.strip():
        target_url_to_analyze = url.strip()
        raw_payload_text = url.strip()
        qr_decoding_res["decoded"] = True
        qr_decoding_res["payload"] = url.strip()
        qr_decoding_res["data_type"] = "URL"
        embedded_url_res["detected"] = True
        embedded_url_res["url"] = url.strip()

    else:
        errors.append({"component": "input", "error": "No QR image or URL provided."})

    # If an embedded or target URL exists, trace redirects & analyze parameters
    if target_url_to_analyze:
        normalized_url_info = normalize_qr_url(target_url_to_analyze, raw_payload_text)
        norm_url = normalized_url_info.get("normalized_url", target_url_to_analyze)

        # Shortener check
        short_info = detect_shortened_url(
            normalized_url_info.get("hostname", ""),
            normalized_url_info.get("domain", "")
        )
        shortened_res["detected"] = short_info.get("detected", False)
        shortened_res["provider"] = short_info.get("provider")

        # Hidden parameters check
        hidden_parameters_res = inspect_hidden_parameters(
            normalized_url_info.get("query_params", {}),
            normalized_url_info.get("query", "")
        )

        # Trace redirect chain safely
        redir_trace = trace_redirect_chain(norm_url)
        redirect_res["count"] = redir_trace.get("redirect_count", 0)
        redirect_res["urls"] = redir_trace.get("redirect_chain", [norm_url])
        redirect_res["initial_url"] = redir_trace.get("initial_url", norm_url)
        redirect_res["final_url"] = redir_trace.get("final_url", norm_url)
        redirect_res["has_redirects"] = redir_trace.get("has_redirects", False)
        if redir_trace.get("errors"):
            for err in redir_trace["errors"]:
                errors.append({"component": "redirect_tracer", "error": err})

    # Compile standardized evidence list
    evidence_list = compile_qr_evidence(
        qr_decoding=qr_decoding_res,
        embedded_url=embedded_url_res,
        redirect_data=redirect_res,
        shortened_data=shortened_res,
        hidden_params=hidden_parameters_res,
        mod_analysis=modification_res,
        error_correction=error_correction_res
    )

    status = "completed" if (qr_decoding_res["decoded"] or not errors) else "error"

    data_payload = {
        "input_type": "qr_image" if image_input is not None else "url",
        "original_qr_payload": raw_payload_text,
        "normalized_url": normalized_url_info.get("normalized_url"),
        "final_url": redirect_res.get("final_url") or normalized_url_info.get("normalized_url"),
        "qr_decoding": qr_decoding_res,
        "embedded_url": embedded_url_res,
        "url_normalization": normalized_url_info,
        "redirect_chain": redirect_res,
        "shortened_url": shortened_res,
        "hidden_parameters": hidden_parameters_res,
        "modification_analysis": modification_res,
        "error_correction": error_correction_res,
        "evidence": evidence_list,
    }

    extra_fields = {
        **data_payload,
        "agent": "Agent 18",
        "agent_id": 18,
        "checked_at": checked_at
    }

    target_desc = target_url_to_analyze or "qr_image_input"

    return build_agent_result(
        agent_identifier="A18",
        target=target_desc,
        status=status,
        data=data_payload,
        evidence=evidence_list,
        errors=errors,
        extra_fields=extra_fields,
    )
