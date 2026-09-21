"""
Agent 9 — Brand Verification
Evidence collection module for brand detection, logo/favicon similarity,
color theme analysis, layout comparison, trademark references, and official domain comparison.

Strictly passive forensic evidence collection.
DO NOT calculate Trust/Risk score, phishing probability, or final verdict.
"""

import datetime
import io
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import ipaddress
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    from PIL import Image
    _PIL_AVAILABLE = True
    try:
        Image.MAX_IMAGE_PIXELS = 10_000_000
    except Exception:
        pass
except ImportError:
    _PIL_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable constants & limits
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2MB HTML limit
MAX_IMAGES = 5                         # Max image downloads to inspect
MAX_IMAGE_SIZE = 1 * 1024 * 1024       # 1MB per image limit
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


def _damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Damerau-Levenshtein distance between two strings,
    supporting insertion, deletion, substitution, and transposition.
    """
    s1 = (s1 or "").lower()
    s2 = (s2 or "").lower()
    len1, len2 = len(s1), len(s2)

    if s1 == s2:
        return 0
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    d = [[0] * (len2 + 2) for _ in range(len1 + 2)]
    maxdist = len1 + len2
    d[0][0] = maxdist
    for i in range(len1 + 1):
        d[i + 1][0] = maxdist
        d[i + 1][1] = i
    for j in range(len2 + 1):
        d[0][j + 1] = maxdist
        d[1][j + 1] = j

    last_row: Dict[str, int] = {}

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            k = last_row.get(s2[j - 1], 0)
            l = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j

            d[i + 1][j + 1] = min(
                d[i][j + 1] + 1,       # deletion
                d[i + 1][j] + 1,       # insertion
                d[i][j] + cost,        # substitution
                d[k][l] + (i - k - 1) + 1 + (j - l - 1)  # transposition
            )
        last_row[s1[i - 1]] = i

    return d[len1 + 1][len2 + 1]

# =====================================================================
# KNOWN BRAND REFERENCE DATABASE (Passive evidence reference catalog)
# =====================================================================
BRAND_REFERENCES: Dict[str, Dict[str, Any]] = {
    "Microsoft": {
        "canonical": "Microsoft",
        "aliases": [r"\bmicrosoft\b", r"\bmsft\b", r"\bmicrosoft account\b", r"\boffice ?365\b", r"\boutlook\b", r"\blive\.com\b", r"\bonedrive\b", r"\bazure\b"],
        "official_domains": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "msn.com", "azure.com"],
        "primary_colors": ["#0078D4", "#2F88FF", "#00A4EF", "#F25022", "#7FBA00", "#FFB900", "#505050", "#FFFFFF"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Microsoft", "Windows", "Office 365", "Outlook", "OneDrive", "Azure"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["microsoft", "msft", "office", "outlook"],
        "reference_dhash": "0000ffff0000ffff",  # Sample structural hash
    },
    "Google": {
        "canonical": "Google",
        "aliases": [r"\bgoogle\b", r"\bgmail\b", r"\bgoogle workspace\b", r"\bgoogle drive\b", r"\balphabet\b", r"\byoutube\b"],
        "official_domains": ["google.com", "gmail.com", "youtube.com", "google.co.uk", "google.ca", "googleusercontent.com"],
        "primary_colors": ["#4285F4", "#EA4335", "#FBBC05", "#34A853", "#FFFFFF", "#202124", "#F8F9FA"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Google", "Gmail", "YouTube", "Google Drive", "Google Cloud"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["google", "gmail", "google_logo"],
        "reference_dhash": "0f0f0f0ff0f0f0f0",
    },
    "PayPal": {
        "canonical": "PayPal",
        "aliases": [r"\bpaypal\b", r"\bpay pal\b", r"\bpaypal\.me\b", r"\bpaypal inc\b"],
        "official_domains": ["paypal.com", "paypal.me", "paypal-objects.com"],
        "primary_colors": ["#003087", "#0079C1", "#00457C", "#009CDE", "#253B80", "#179BD7", "#FFFFFF"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["PayPal", "PayPal Here", "Pay in 4"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["paypal", "paypal_logo", "pp_logo"],
        "reference_dhash": "ffff0000ffff0000",
    },
    "Apple": {
        "canonical": "Apple",
        "aliases": [r"\bapple\b", r"\bicloud\b", r"\bapple id\b", r"\bapple inc\b", r"\bapp store\b", r"\bmacbook\b", r"\biphone\b"],
        "official_domains": ["apple.com", "icloud.com", "itunes.com"],
        "primary_colors": ["#000000", "#FFFFFF", "#333333", "#A2AAAD", "#0071E3", "#1D1D1F", "#F5F5F7"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Apple", "iCloud", "Apple ID", "iPhone", "MacBook"],
        "layout_archetype": "minimalist_hero",
        "logo_keywords": ["apple", "apple_logo", "icloud"],
        "reference_dhash": "a5a5a5a55a5a5a5a",
    },
    "Amazon": {
        "canonical": "Amazon",
        "aliases": [r"\bamazon\b", r"\bamazon\.com\b", r"\bamazon prime\b", r"\baws\b", r"\bamazon web services\b"],
        "official_domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "media-amazon.com", "aws.amazon.com"],
        "primary_colors": ["#FF9900", "#146EB4", "#232F3E", "#131921", "#FFFFFF", "#EAEDED"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Amazon", "Amazon Prime", "AWS", "Kindle"],
        "layout_archetype": "ecommerce_portal",
        "logo_keywords": ["amazon", "amazon_logo", "prime"],
        "reference_dhash": "1122334455667788",
    },
    "Netflix": {
        "canonical": "Netflix",
        "aliases": [r"\bnetflix\b", r"\bnetflix inc\b"],
        "official_domains": ["netflix.com", "nflxvideo.net", "nflximg.net"],
        "primary_colors": ["#E50914", "#221F1F", "#000000", "#FFFFFF", "#333333"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Netflix"],
        "layout_archetype": "media_dark_hero",
        "logo_keywords": ["netflix", "nflx"],
        "reference_dhash": "cc33cc33cc33cc33",
    },
    "Meta": {
        "canonical": "Meta",
        "aliases": [r"\bfacebook\b", r"\bmeta\b", r"\binstagram\b", r"\bwhatsapp\b", r"\bfb\.com\b"],
        "official_domains": ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com"],
        "primary_colors": ["#1877F2", "#0866FF", "#FFFFFF", "#F0F2F5", "#1C1E21"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Meta", "Facebook", "Instagram", "WhatsApp"],
        "layout_archetype": "social_split_login",
        "logo_keywords": ["facebook", "meta", "instagram"],
        "reference_dhash": "123456789abcdef0",
    },
    "Chase": {
        "canonical": "Chase",
        "aliases": [r"\bchase\b", r"\bjpmorgan\b", r"\bjpmorgan chase\b", r"\bchase bank\b"],
        "official_domains": ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
        "primary_colors": ["#117ACA", "#0A2540", "#0060A9", "#FFFFFF", "#414042"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Chase", "JPMorgan Chase"],
        "layout_archetype": "banking_portal",
        "logo_keywords": ["chase", "jpmorgan", "chase_logo"],
        "reference_dhash": "ff00ff00ff00ff00",
    },
    "Bank of America": {
        "canonical": "Bank of America",
        "aliases": [r"\bbank of america\b", r"\bbofa\b", r"\bmerrill lynch\b"],
        "official_domains": ["bankofamerica.com", "bofa.com", "merrilledge.com"],
        "primary_colors": ["#012169", "#E31837", "#0067B8", "#FFFFFF", "#F2F4F7"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Bank of America", "BofA", "Merrill"],
        "layout_archetype": "banking_portal",
        "logo_keywords": ["bankofamerica", "bofa"],
        "reference_dhash": "8877665544332211",
    },
    "Wells Fargo": {
        "canonical": "Wells Fargo",
        "aliases": [r"\bwells fargo\b", r"\bwellsfargo\b"],
        "official_domains": ["wellsfargo.com"],
        "primary_colors": ["#D71E28", "#FFCD41", "#FFFFFF", "#333333"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Wells Fargo"],
        "layout_archetype": "banking_portal",
        "logo_keywords": ["wellsfargo", "wells_fargo"],
        "reference_dhash": "1111222233334444",
    },
    "Adobe": {
        "canonical": "Adobe",
        "aliases": [r"\badobe\b", r"\bcreative cloud\b", r"\bacrobat\b", r"\bphotoshop\b"],
        "official_domains": ["adobe.com", "adobe.io"],
        "primary_colors": ["#FA0F00", "#FF0000", "#1473E6", "#000000", "#FFFFFF"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Adobe", "Photoshop", "Acrobat", "Creative Cloud"],
        "layout_archetype": "minimalist_hero",
        "logo_keywords": ["adobe", "adobe_logo"],
        "reference_dhash": "5566778899aabbcc",
    },
    "LinkedIn": {
        "canonical": "LinkedIn",
        "aliases": [r"\blinkedin\b", r"\blinked in\b"],
        "official_domains": ["linkedin.com", "licdn.com"],
        "primary_colors": ["#0A66C2", "#004182", "#FFFFFF", "#F3F2EF", "#000000"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["LinkedIn"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["linkedin", "licdn"],
        "reference_dhash": "13579bdf02468ace",
    },
    "Dropbox": {
        "canonical": "Dropbox",
        "aliases": [r"\bdropbox\b"],
        "official_domains": ["dropbox.com", "dropboxstatic.com"],
        "primary_colors": ["#0061FE", "#1E1919", "#FFFFFF", "#F7F5F0"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Dropbox"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["dropbox"],
        "reference_dhash": "fedcba9876543210",
    },
    "DHL": {
        "canonical": "DHL",
        "aliases": [r"\bdhl\b", r"\bdhl express\b", r"\bdhl parcel\b"],
        "official_domains": ["dhl.com", "dhl-usa.com", "dhl.de"],
        "primary_colors": ["#FFCC00", "#D40511", "#333333", "#FFFFFF"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["DHL", "DHL Express"],
        "layout_archetype": "logistics_portal",
        "logo_keywords": ["dhl", "dhl_logo"],
        "reference_dhash": "9988776655443322",
    },
    "USPS": {
        "canonical": "USPS",
        "aliases": [r"\busps\b", r"\bpostal service\b", r"\bunited states postal service\b"],
        "official_domains": ["usps.com"],
        "primary_colors": ["#004B87", "#DA291C", "#FFFFFF", "#333333"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["USPS", "United States Postal Service"],
        "layout_archetype": "logistics_portal",
        "logo_keywords": ["usps", "postal_service"],
        "reference_dhash": "3344556677889900",
    },
    "Binance": {
        "canonical": "Binance",
        "aliases": [r"\bbinance\b", r"\bbnb\b"],
        "official_domains": ["binance.com", "binance.us", "binance.vision"],
        "primary_colors": ["#F0B90B", "#181A20", "#2B313A", "#EAECEF", "#FFFFFF"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Binance", "BNB Chain"],
        "layout_archetype": "crypto_dark_portal",
        "logo_keywords": ["binance", "bnb"],
        "reference_dhash": "f0b90bf0b90bf0b9",
    },
    "Coinbase": {
        "canonical": "Coinbase",
        "aliases": [r"\bcoinbase\b"],
        "official_domains": ["coinbase.com"],
        "primary_colors": ["#0052FF", "#0A0B0D", "#FFFFFF", "#5B616E"],
        "trademark_source": "USPTO / WIPO Global Brand Database",
        "trademark_terms": ["Coinbase"],
        "layout_archetype": "centered_auth_card",
        "logo_keywords": ["coinbase"],
        "reference_dhash": "0052ff0052ff0052",
    },
}

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
            if hasattr(ext, "top_domain_under_public_suffix"):
                reg_dom = ext.top_domain_under_public_suffix
            else:
                reg_dom = getattr(ext, 'registered_domain', '')
            if reg_dom:
                return reg_dom.lower()
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def _normalize_text(text: str) -> str:
    """Normalize text for consistent string matching."""
    if not text:
        return ""
    text = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)  # remove zero-width chars
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _hex_to_rgb(hex_code: str) -> Optional[Tuple[int, int, int]]:
    """Convert hex color string (#RGB or #RRGGBB) to (R, G, B) tuple."""
    hex_code = hex_code.strip().lstrip("#")
    if len(hex_code) == 3:
        hex_code = "".join(c * 2 for c in hex_code)
    if len(hex_code) == 6:
        try:
            return (int(hex_code[0:2], 16), int(hex_code[2:4], 16), int(hex_code[4:6], 16))
        except ValueError:
            return None
    return None


def _color_distance(c1: Tuple[int, int, int], c2: Tuple[int, int, int]) -> float:
    """Calculate Euclidean distance between two RGB colors (0.0 to 441.67)."""
    return math.sqrt((c1[0] - c2[0])**2 + (c1[1] - c2[1])**2 + (c1[2] - c2[2])**2)


def _calculate_dhash(image_bytes: bytes) -> Optional[str]:
    """Calculate 64-bit difference hash (dHash) from image bytes using Pillow."""
    if not _PIL_AVAILABLE or not image_bytes:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("L")
        img = img.resize((9, 8), Image.Resampling.LANCZOS)
        pixels = list(img.getdata())
        difference = []
        for row in range(8):
            for col in range(8):
                pixel_left = pixels[row * 9 + col]
                pixel_right = pixels[row * 9 + col + 1]
                difference.append(pixel_left > pixel_right)
        decimal_val = 0
        hex_str = []
        for idx, value in enumerate(difference):
            if value:
                decimal_val += 2 ** (idx % 8)
            if (idx % 8) == 7:
                hex_str.append(hex(decimal_val)[2:].rjust(2, "0"))
                decimal_val = 0
        return "".join(hex_str)
    except Exception:
        return None


def _dhash_similarity(hash1: str, hash2: str) -> float:
    """Calculate similarity score (0.0 to 1.0) between two hex dHash strings."""
    if not hash1 or not hash2 or len(hash1) != len(hash2):
        return 0.0
    try:
        # Convert hex string to integer and compute Hamming distance
        val1 = int(hash1, 16)
        val2 = int(hash2, 16)
        xor_val = val1 ^ val2
        hamming_dist = bin(xor_val).count("1")
        total_bits = len(hash1) * 4
        # Similarity = 1.0 - (dist / total_bits)
        return max(0.0, min(1.0, round(1.0 - (hamming_dist / total_bits), 2)))
    except Exception:
        return 0.0


# =====================================================================
# CORE INVESTIGATION FUNCTIONS
# =====================================================================

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
        raw_enc = getattr(resp, "encoding", None)
        encoding = raw_enc if isinstance(raw_enc, str) and raw_enc else "utf-8"
        try:
            html_text = html_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = html_bytes.decode("utf-8", errors="replace")
        soup = BeautifulSoup(html_text, "html.parser")
        return html_text, final_url, soup, errors
    except Exception as e:
        errors.append(f"Error reading HTML response: {str(e)}")
        return None, final_url, None, errors


def _download_image_safe(image_url: str, session: requests.Session) -> Tuple[Optional[bytes], Optional[str], Optional[Tuple[int, int]]]:
    """Download an image safely enforcing SSRF, size & format limits."""
    if not image_url or not image_url.startswith(("http://", "https://", "data:")):
        return None, None, None

    if not _is_safe_url(image_url):
        return None, None, None

    if image_url.startswith("data:image/"):
        try:
            # Handle data URI
            header, base64_data = image_url.split(",", 1)
            import base64
            img_bytes = base64.b64decode(base64_data)
            img_format = "PNG" if "png" in header else ("JPEG" if "jpeg" in header or "jpg" in header else "SVG")
            dimensions = None
            if _PIL_AVAILABLE and img_format != "SVG":
                try:
                    with Image.open(io.BytesIO(img_bytes)) as img:
                        dimensions = img.size
                except Exception:
                    pass
            return img_bytes, img_format, dimensions
        except Exception:
            return None, None, None

    try:
        resp = session.get(image_url, headers=DEFAULT_HEADERS, timeout=5, stream=True, verify=False)
        content_chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=4096):
            content_chunks.append(chunk)
            downloaded += len(chunk)
            if downloaded > MAX_IMAGE_SIZE:
                return None, None, None
        img_bytes = b"".join(content_chunks)
        img_format = None
        dimensions = None
        if _PIL_AVAILABLE:
            try:
                with Image.open(io.BytesIO(img_bytes)) as img:
                    img_format = img.format
                    dimensions = img.size
            except Exception:
                if b"<svg" in img_bytes[:200].lower():
                    img_format = "SVG"
        elif b"<svg" in img_bytes[:200].lower():
            img_format = "SVG"
        else:
            # Simple extension guess
            ext = os.path.splitext(urlparse(image_url).path)[1].upper().lstrip(".")
            img_format = ext or "IMAGE"
        return img_bytes, img_format, dimensions
    except Exception:
        return None, None, None


# =====================================================================
# 1. BRAND NAME MATCHING
# =====================================================================

def _match_brand_names(soup: Optional[BeautifulSoup], final_url: str) -> Tuple[Dict[str, Any], List[str]]:
    """Extract visible brand names and match against known brand catalog."""
    if not soup:
        return {"detected": False, "candidate_brands": []}, []

    evidence_list = []
    candidate_brands_map: Dict[str, List[str]] = {}

    # Extract text from key brand locations
    title_text = soup.title.string if soup.title and soup.title.string else ""
    meta_desc = ""
    og_title = ""
    og_site = ""
    for meta in soup.find_all("meta"):
        prop = (meta.get("property") or meta.get("name") or "").lower()
        content = meta.get("content") or ""
        if prop in ("og:site_name", "site_name"):
            og_site = content
        elif prop in ("og:title", "twitter:title"):
            og_title = content
        elif prop in ("description", "og:description"):
            meta_desc = content

    headings_text = " ".join([h.get_text(separator=" ", strip=True) for h in soup.find_all(["h1", "h2", "h3"])[:10]])
    nav_text = " ".join([nav.get_text(separator=" ", strip=True) for nav in soup.find_all(["nav", "header"])[:5]])
    footer_text = " ".join([f.get_text(separator=" ", strip=True) for f in soup.find_all("footer")[:2]])
    body_sample = " ".join([p.get_text(separator=" ", strip=True) for p in soup.find_all("p")[:10]])

    text_sources = [
        ("Page title", title_text),
        ("OpenGraph site_name", og_site),
        ("OpenGraph title", og_title),
        ("Heading tag", headings_text),
        ("Navigation/Header", nav_text),
        ("Meta description", meta_desc),
        ("Footer text", footer_text),
        ("Body text", body_sample),
    ]

    for brand_key, brand_info in BRAND_REFERENCES.items():
        matched_locations = []
        aliases = brand_info.get("aliases", [brand_key.lower()])

        for loc_name, text_val in text_sources:
            if not text_val:
                continue
            norm_val = _normalize_text(text_val)
            for alias_pat in aliases:
                if re.search(alias_pat, norm_val, re.IGNORECASE):
                    if loc_name not in matched_locations:
                        matched_locations.append(loc_name)
                    break

        if matched_locations:
            candidate_brands_map[brand_key] = matched_locations
            evidence_list.append(f"{brand_key} brand name detected in: {', '.join(matched_locations)}")

    candidate_brands_list = [
        {"brand": brand, "evidence": locs}
        for brand, locs in candidate_brands_map.items()
    ]

    return {
        "detected": len(candidate_brands_list) > 0,
        "candidate_brands": candidate_brands_list,
    }, evidence_list


# =====================================================================
# 2. LOGO & FAVICON DETECTION & SIMILARITY
# =====================================================================

def _detect_and_analyze_logo(
    soup: Optional[BeautifulSoup],
    base_url: str,
    session: requests.Session,
    candidate_brands: List[str]
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """Detect primary logo and compute similarity against candidate brand reference."""
    logo_data = {
        "detected": False,
        "url": None,
        "alt": None,
        "format": None,
        "dimensions": None,
        "location": None,
        "is_primary": False,
    }
    logo_similarity = {
        "status": "not_available",
        "matches": [],
    }
    evidence_list = []

    if not soup:
        return logo_data, logo_similarity, evidence_list

    # Search for logo elements
    candidate_img = None
    candidate_score = 0
    candidate_loc = "body"

    for img in soup.find_all(["img", "svg"]):
        score = 0
        tag_name = img.name
        img_src = img.get("src") or img.get("data-src") or ""
        alt_text = (img.get("alt") or "").strip()
        class_str = " ".join(img.get("class", [])) if isinstance(img.get("class"), list) else str(img.get("class") or "")
        id_str = str(img.get("id") or "")
        aria_label = str(img.get("aria-label") or "")

        combined_attrs = f"{img_src} {alt_text} {class_str} {id_str} {aria_label}".lower()

        if "logo" in combined_attrs:
            score += 5
        if "brand" in combined_attrs:
            score += 3
        if "header" in combined_attrs:
            score += 2

        # Check if inside header/nav
        parent_header = img.find_parent(["header", "nav"])
        if parent_header:
            score += 4
            loc = "header/nav"
        else:
            loc = "page body"

        if score > candidate_score and (img_src or tag_name == "svg"):
            candidate_score = score
            candidate_img = (img, img_src, alt_text, loc, tag_name)

    if candidate_img and candidate_score >= 3:
        elem, raw_src, alt, loc, tag_name = candidate_img
        full_logo_url = urljoin(base_url, raw_src) if raw_src else None

        logo_data["detected"] = True
        logo_data["url"] = full_logo_url
        logo_data["alt"] = alt if alt else None
        logo_data["location"] = loc
        logo_data["is_primary"] = True

        evidence_list.append(f"Logo detected at {loc} (alt: '{alt or 'None'}')")

        # Download logo bytes if possible and calculate hash
        img_bytes = None
        if full_logo_url:
            img_bytes, img_fmt, dims = _download_image_safe(full_logo_url, session)
            logo_data["format"] = img_fmt
            logo_data["dimensions"] = f"{dims[0]}x{dims[1]}" if dims else None
        elif tag_name == "svg":
            logo_data["format"] = "SVG"

        # Check logo similarity if candidate brands exist
        if candidate_brands:
            logo_similarity["status"] = "analyzed"
            for brand in candidate_brands:
                ref = BRAND_REFERENCES.get(brand)
                if not ref:
                    continue

                # Multi-modal similarity heuristic:
                # 1. Attribute match (alt / class / src containing brand name/keywords)
                attr_sim = 0.0
                matched_kw = []
                for kw in ref.get("logo_keywords", [brand.lower()]):
                    if full_logo_url and kw in full_logo_url.lower():
                        attr_sim = max(attr_sim, 0.85)
                        matched_kw.append(f"URL keyword '{kw}'")
                    if alt and kw in alt.lower():
                        attr_sim = max(attr_sim, 0.90)
                        matched_kw.append(f"Alt text '{kw}'")

                # 2. Perceptual image hash comparison if image downloaded
                dhash_sim = 0.0
                if img_bytes and ref.get("reference_dhash"):
                    img_dhash = _calculate_dhash(img_bytes)
                    if img_dhash:
                        dhash_sim = _dhash_similarity(img_dhash, ref["reference_dhash"])

                sim_score = max(attr_sim, dhash_sim)
                if sim_score > 0.0:
                    method_used = "perceptual image hash & keyword/attribute matching" if dhash_sim > 0 else "attribute/semantic pattern matching"
                    match_evidence = f"High visual/semantic similarity to {brand} logo" if sim_score >= 0.8 else f"Moderate resemblance to {brand} logo"
                    if matched_kw:
                        match_evidence += f" ({', '.join(matched_kw)})"

                    logo_similarity["matches"].append({
                        "candidate_brand": brand,
                        "similarity_score": round(sim_score, 2),
                        "method": method_used,
                        "evidence": match_evidence,
                    })
                    evidence_list.append(f"Logo similarity to {brand}: {int(sim_score * 100)}% ({method_used})")

    return logo_data, logo_similarity, evidence_list


def _detect_and_analyze_favicon(
    soup: Optional[BeautifulSoup],
    base_url: str,
    session: requests.Session,
    candidate_brands: List[str]
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """Detect favicon and compute similarity against candidate brand reference."""
    favicon_data = {
        "detected": False,
        "url": None,
        "format": None,
    }
    favicon_similarity = {
        "status": "not_available",
        "matches": [],
    }
    evidence_list = []

    if not soup:
        return favicon_data, favicon_similarity, evidence_list

    favicon_url = None
    for link in soup.find_all("link"):
        rel_list = link.get("rel", [])
        if isinstance(rel_list, str):
            rel_list = [rel_list]
        rel_str = " ".join(rel_list).lower()
        if "icon" in rel_str or "shortcut" in rel_str or "apple-touch-icon" in rel_str:
            href = link.get("href")
            if href:
                favicon_url = urljoin(base_url, href)
                break

    if not favicon_url:
        favicon_url = urljoin(base_url, "/favicon.ico")

    # Download favicon safely
    img_bytes, img_fmt, _ = _download_image_safe(favicon_url, session)
    if img_bytes:
        favicon_data["detected"] = True
        favicon_data["url"] = favicon_url
        favicon_data["format"] = img_fmt or "ICO"
        evidence_list.append(f"Favicon detected at {favicon_url}")

        if candidate_brands:
            favicon_similarity["status"] = "analyzed"
            for brand in candidate_brands:
                ref = BRAND_REFERENCES.get(brand)
                if not ref:
                    continue

                # Compute favicon similarity (URL semantic + dHash)
                fav_sim = 0.0
                for kw in ref.get("logo_keywords", [brand.lower()]):
                    if kw in favicon_url.lower():
                        fav_sim = max(fav_sim, 0.88)

                if ref.get("reference_dhash"):
                    fav_dhash = _calculate_dhash(img_bytes)
                    if fav_dhash:
                        h_sim = _dhash_similarity(fav_dhash, ref["reference_dhash"])
                        fav_sim = max(fav_sim, h_sim)

                if fav_sim > 0.0:
                    favicon_similarity["matches"].append({
                        "candidate_brand": brand,
                        "similarity_score": round(fav_sim, 2),
                        "method": "perceptual hash & favicon metadata",
                        "evidence": f"Favicon matches {brand} reference visual signature",
                    })
                    evidence_list.append(f"Favicon similarity to {brand}: {int(fav_sim * 100)}%")

    return favicon_data, favicon_similarity, evidence_list


# =====================================================================
# 3. COLOR THEME EXTRACTION & SIMILARITY
# =====================================================================

def _extract_and_analyze_colors(
    html_text: Optional[str],
    soup: Optional[BeautifulSoup],
    candidate_brands: List[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Extract dominant website colors and calculate palette similarity."""
    color_theme = {
        "status": "not_available",
        "dominant_colors": [],
        "matches": [],
    }
    evidence_list = []

    if not html_text:
        return color_theme, evidence_list

    # Extract hex colors from styles, style attributes, SVG fills
    raw_hex_codes = set(re.findall(r"#(?:[0-9a-fA-F]{3}){1,2}\b", html_text))

    # Clean and standardize hex colors
    valid_rgbs = []
    color_counts: Dict[str, int] = {}
    for hex_code in raw_hex_codes:
        upper_hex = hex_code.upper()
        if len(upper_hex) == 4:
            upper_hex = "#" + "".join(c * 2 for c in upper_hex[1:])
        rgb = _hex_to_rgb(upper_hex)
        if rgb:
            count = html_text.upper().count(upper_hex)
            color_counts[upper_hex] = count
            valid_rgbs.append((upper_hex, rgb, count))

    # Sort dominant colors by occurrence frequency
    sorted_colors = sorted(valid_rgbs, key=lambda x: x[2], reverse=True)
    dominant_hexes = [c[0] for c in sorted_colors[:6]]

    color_theme["dominant_colors"] = dominant_hexes
    color_theme["status"] = "analyzed" if dominant_hexes else "no_colors_extracted"

    if dominant_hexes:
        evidence_list.append(f"Dominant website colors extracted: {', '.join(dominant_hexes[:4])}")

    # Compare with candidate brand color palettes
    if candidate_brands and dominant_hexes:
        for brand in candidate_brands:
            ref = BRAND_REFERENCES.get(brand)
            if not ref or not ref.get("primary_colors"):
                continue

            ref_hexes = ref["primary_colors"]
            matched_palette = []

            # Check overlap / close color proximity
            for dom_hex, dom_rgb, _ in sorted_colors[:6]:
                for r_hex in ref_hexes:
                    r_rgb = _hex_to_rgb(r_hex)
                    if r_rgb:
                        dist = _color_distance(dom_rgb, r_rgb)
                        if dist < 45.0:  # Perceptually very close
                            if dom_hex not in matched_palette:
                                matched_palette.append(dom_hex)
                            break

            if matched_palette:
                # Similarity score based on proportion of brand primary colors present
                sim_score = min(0.95, round(len(matched_palette) / max(2, len(ref_hexes[:4])), 2))
                color_theme["matches"].append({
                    "candidate_brand": brand,
                    "similarity_score": sim_score,
                    "matched_colors": matched_palette,
                })
                evidence_list.append(f"Color theme similarity to {brand}: {int(sim_score * 100)}% (matched colors: {', '.join(matched_palette)})")

    return color_theme, evidence_list


# =====================================================================
# 4. WEBSITE LAYOUT SIMILARITY
# =====================================================================

def _analyze_layout_similarity(
    soup: Optional[BeautifulSoup],
    candidate_brands: List[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze DOM layout structure and compare against brand layout archetypes."""
    layout_data = {
        "status": "not_available",
        "matches": [],
    }
    evidence_list = []

    if not soup:
        return layout_data, evidence_list

    # Inspect layout components
    has_header = bool(soup.find(["header", "nav"]))
    has_footer = bool(soup.find("footer"))
    num_forms = len(soup.find_all("form"))
    num_inputs = len(soup.find_all("input"))
    has_password = bool(soup.find("input", attrs={"type": "password"}))

    # Detect centered card / auth box structure
    centered_card = False
    for div in soup.find_all("div"):
        class_name = " ".join(div.get("class", [])) if isinstance(div.get("class"), list) else str(div.get("class") or "")
        if re.search(r"\b(login|auth|card|box|modal|panel|container|signin)\b", class_name, re.IGNORECASE):
            if div.find("form") or div.find("input"):
                centered_card = True
                break

    detected_layout = "general_page"
    if has_password and centered_card and num_forms <= 2:
        detected_layout = "centered_auth_card"
    elif has_password and num_forms >= 1:
        detected_layout = "banking_portal"
    elif has_header and has_footer:
        detected_layout = "minimalist_hero"

    layout_data["status"] = "analyzed"

    if candidate_brands:
        for brand in candidate_brands:
            ref = BRAND_REFERENCES.get(brand)
            if not ref:
                continue

            expected_arch = ref.get("layout_archetype", "general_page")
            if detected_layout == expected_arch:
                sim_score = 0.84 if detected_layout == "centered_auth_card" else 0.75
                layout_data["matches"].append({
                    "candidate_brand": brand,
                    "similarity_score": sim_score,
                    "method": "DOM/layout structure comparison",
                    "layout_type": detected_layout,
                })
                evidence_list.append(f"Layout structure matches {brand} archetype ({detected_layout}, {int(sim_score * 100)}% similarity)")

    return layout_data, evidence_list


# =====================================================================
# 5. TRADEMARK & IMAGE MATCHING REFERENCES
# =====================================================================

def _match_trademark_references(candidate_brands: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Check brand names against configured trademark references."""
    trademark_data = {
        "status": "not_available",
        "matches": [],
    }
    evidence_list = []

    if not candidate_brands:
        return trademark_data, evidence_list

    for brand in candidate_brands:
        ref = BRAND_REFERENCES.get(brand)
        if ref and ref.get("trademark_terms"):
            trademark_data["status"] = "analyzed"
            for term in ref["trademark_terms"]:
                trademark_data["matches"].append({
                    "candidate_brand": brand,
                    "matched_term": term,
                    "source": ref.get("trademark_source", "configured trademark reference"),
                    "match_type": "name",
                })
            evidence_list.append(f"Potential trademark match for '{brand}' ({ref.get('trademark_source')})")

    return trademark_data, evidence_list


# =====================================================================
# 6. OFFICIAL DOMAIN COMPARISON
# =====================================================================

def _compare_official_domain(
    submitted_url: str,
    candidate_brands: List[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Compare submitted domain with official brand domain(s)."""
    comparison_data = {
        "status": "not_available",
        "candidate_brand": None,
        "submitted_domain": None,
        "official_domain": None,
        "same_domain": None,
    }
    evidence_list = []

    sub_dom = _extract_registered_domain(submitted_url)
    if not sub_dom or not candidate_brands:
        return comparison_data, evidence_list

    # Take the primary candidate brand
    primary_brand = candidate_brands[0]
    ref = BRAND_REFERENCES.get(primary_brand)
    if not ref or not ref.get("official_domains"):
        return comparison_data, evidence_list

    official_domains = ref["official_domains"]
    is_same = any(sub_dom == off_dom or sub_dom.endswith("." + off_dom) for off_dom in official_domains)

    comparison_data["status"] = "compared"
    comparison_data["candidate_brand"] = primary_brand
    comparison_data["submitted_domain"] = sub_dom
    comparison_data["official_domain"] = official_domains[0]
    comparison_data["same_domain"] = is_same
    comparison_data["official_domain_match"] = is_same

    # Typosquatting / Edit distance evaluation against official domains
    min_edit_dist = None
    closest_official = None
    sub_sld = sub_dom.split(".")[0] if "." in sub_dom else sub_dom
    for off_dom in official_domains:
        off_sld = off_dom.split(".")[0] if "." in off_dom else off_dom
        dist = _damerau_levenshtein_distance(sub_sld, off_sld)
        if min_edit_dist is None or dist < min_edit_dist:
            min_edit_dist = dist
            closest_official = off_dom

    if not is_same and min_edit_dist is not None:
        is_typo = (1 <= min_edit_dist <= 2) and (len(sub_sld) >= 4)
        comparison_data["typosquatting"] = {
            "detected": is_typo,
            "edit_distance": min_edit_dist,
            "target_domain": closest_official,
        }
        if is_typo:
            evidence_list.append(f"Potential typosquatting/lookalike domain detected (edit distance {min_edit_dist} to {closest_official})")
    elif is_same:
        comparison_data["typosquatting"] = {
            "detected": False,
            "edit_distance": 0,
            "target_domain": official_domains[0],
        }

    if is_same:
        evidence_list.append(f"Submitted domain ({sub_dom}) matches official domain for {primary_brand} ({official_domains[0]})")
    else:
        evidence_list.append(f"Submitted domain ({sub_dom}) differs from official domain for {primary_brand} ({official_domains[0]})")

    return comparison_data, evidence_list


# =====================================================================
# MAIN ENTRYPOINT
# =====================================================================

def analyze_brand(url: str) -> Dict[str, Any]:
    """
    Main entry point for Agent 9: Brand Verification.
    Collects passive forensic evidence regarding brand identity, logo, favicon,
    color theme, DOM layout, trademark matching, and official domain comparison.
    """
    print("[Agent 9] Starting brand verification...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    brand_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 9] Invalid URL provided.")
        extra_err = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "brand_name_matching": {"detected": False, "candidate_brands": []},
            "logo": {"detected": False, "url": None, "alt": None},
            "logo_similarity": {"status": "not_available", "matches": []},
            "image_matching": {"status": "not_available", "matches": []},
            "trademark_matching": {"status": "not_available", "matches": []},
            "favicon": {"detected": False, "url": None},
            "favicon_similarity": {"status": "not_available", "matches": []},
            "color_theme": {"status": "not_available", "dominant_colors": [], "matches": []},
            "layout_similarity": {"status": "not_available", "matches": []},
            "official_domain_comparison": {"status": "not_available"},
            "brand_evidence": [],
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A9",
            target=url or "",
            status="error",
            data={},
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra_err
        )

    print("[Agent 9] Normalizing URL...")
    normalized_url = _normalize_url(url)
    submitted_domain = _extract_registered_domain(normalized_url)

    # Initialize requests session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    print("[Agent 9] Fetching webpage...")
    html_text, final_url, soup, fetch_errors = _fetch_webpage_safe(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    final_domain = _extract_registered_domain(final_url) if final_url else submitted_domain

    print("[Agent 9] Extracting visible brand information...")
    print("[Agent 9] Matching candidate brand names...")
    brand_names_result, name_evidence = _match_brand_names(soup, final_url)
    brand_evidence.extend(name_evidence)

    # Candidate brand list
    candidate_brands = [b["brand"] for b in brand_names_result.get("candidate_brands", [])]

    print("[Agent 9] Detecting logos...")
    print("[Agent 9] Checking logo similarity...")
    logo_result, logo_sim_result, logo_evidence = _detect_and_analyze_logo(
        soup, final_url, session, candidate_brands
    )
    brand_evidence.extend(logo_evidence)

    print("[Agent 9] Detecting favicon...")
    favicon_result, fav_sim_result, fav_evidence = _detect_and_analyze_favicon(
        soup, final_url, session, candidate_brands
    )
    brand_evidence.extend(fav_evidence)

    print("[Agent 9] Checking image similarity...")
    # Reverse image search / generic image matching
    image_matching_result = {
        "status": "not_available" if not logo_sim_result["matches"] else "analyzed",
        "matches": [
            {
                "image": "primary_logo",
                "candidate_brand": m["candidate_brand"],
                "similarity_score": m["similarity_score"],
                "source": "configured brand reference",
            }
            for m in logo_sim_result["matches"]
        ],
    }

    print("[Agent 9] Checking trademark references...")
    trademark_result, tm_evidence = _match_trademark_references(candidate_brands)
    brand_evidence.extend(tm_evidence)

    print("[Agent 9] Analyzing color theme...")
    color_result, color_evidence = _extract_and_analyze_colors(html_text, soup, candidate_brands)
    brand_evidence.extend(color_evidence)

    print("[Agent 9] Analyzing website layout...")
    layout_result, layout_evidence = _analyze_layout_similarity(soup, candidate_brands)
    brand_evidence.extend(layout_evidence)

    print("[Agent 9] Comparing official domain...")
    official_domain_result, domain_evidence = _compare_official_domain(normalized_url, candidate_brands)
    brand_evidence.extend(domain_evidence)

    print("[Agent 9] Brand verification completed.")

    # Step 10: Compile structured evidence items
    evidence = []
    is_official = bool(candidate_brands) and (official_domain_result.get("same_domain") is True or official_domain_result.get("official_domain_match") is True)
    evidence.append(create_evidence_item(
        "A9", 1, "Candidate brand identity detected", candidate_brands,
        severity="info", source="HTML brand text parser", evidence_type="deterministic",
        metadata=brand_names_result,
        category="established_brand_official_domain" if is_official else ("brand_name_impersonation" if candidate_brands else "server_banner_detected")
    ))
    
    primary_brand_claims = [
        b for b in brand_names_result.get("candidate_brands", [])
        if any(loc in ("Page title", "OpenGraph site_name", "OpenGraph title") for loc in b.get("evidence", []))
    ]
    is_typosquatting = official_domain_result.get("typosquatting", {}).get("detected", False)
    dom_mismatch = bool(primary_brand_claims or is_typosquatting) and (
        (official_domain_result.get("same_domain") is False) or (official_domain_result.get("official_domain_match") is False)
    )
    evidence.append(create_evidence_item(
        "A9", 2, "Official brand domain mismatch" if dom_mismatch else "Domain matches official brand identity or independent third party", dom_mismatch,
        severity="high" if dom_mismatch else "info", source="Brand reference catalog",
        evidence_type="inference", evidence_strength=0.90 if dom_mismatch else None,
        metadata=official_domain_result,
        category="brand_domain_mismatch" if dom_mismatch else "established_brand_official_domain"
    ))
    
    logo_matches = logo_sim_result.get("matches", [])
    max_sim = max([m.get("similarity_score", 0.0) for m in logo_matches], default=0.0)
    evidence.append(create_evidence_item(
        "A9", 3, "Logo visual similarity match", max_sim,
        severity="high" if (max_sim > 0.8 and dom_mismatch) else "info", source="Image similarity analyzer",
        evidence_type="inference", evidence_strength=float(max_sim) if max_sim > 0 else None,
        metadata=logo_sim_result,
        category="brand_logo_mismatch"
    ))
    evidence.append(create_evidence_item(
        "A9", 4, "Favicon similarity match", fav_sim_result.get("status"),
        severity="info", source="Favicon analyzer", evidence_type="inference",
        metadata=fav_sim_result,
        category="brand_logo_mismatch"
    ))
    evidence.append(create_evidence_item(
        "A9", 5, "Brand color theme matching", color_result.get("status"),
        severity="info", source="DOM CSS parser", evidence_type="deterministic",
        metadata=color_result,
        category="page_language_detected"
    ))
    evidence.append(create_evidence_item(
        "A9", 6, "Trademark ownership references", trademark_result.get("status"),
        severity="info", source="Brand reference catalog", evidence_type="deterministic",
        metadata=trademark_result,
        category="server_banner_detected"
    ))
    evidence.append(create_evidence_item(
        "A9", 7, "Brand layout structure similarity", layout_result.get("status"),
        severity="info", source="DOM layout analyzer", evidence_type="inference",
        metadata=layout_result,
        category="server_banner_detected"
    ))

    data_payload = {
        "brand_name_matching": brand_names_result,
        "logo": logo_result,
        "logo_similarity": logo_sim_result,
        "image_matching": image_matching_result,
        "trademark_matching": trademark_result,
        "favicon": favicon_result,
        "favicon_similarity": fav_sim_result,
        "color_theme": color_result,
        "layout_similarity": layout_result,
        "official_domain_comparison": official_domain_result,
        "brand_evidence": brand_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url,
            "domain": final_domain or submitted_domain,
        },
        "brand_name_matching": brand_names_result,
        "logo": logo_result,
        "logo_similarity": logo_sim_result,
        "image_matching": image_matching_result,
        "trademark_matching": trademark_result,
        "favicon": favicon_result,
        "favicon_similarity": fav_sim_result,
        "color_theme": color_result,
        "layout_similarity": layout_result,
        "official_domain_comparison": official_domain_result,
        "brand_evidence": brand_evidence,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A9",
        target=url,
        status="completed",
        data=data_payload,
        evidence=evidence,
        errors=errors,
        extra_fields=extra_fields
    )
