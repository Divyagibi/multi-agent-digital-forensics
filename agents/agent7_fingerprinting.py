"""
Agent 7 — Technical Fingerprinting
===================================
Evidence Collection Agent.

Purpose:
    Inspect the submitted website and passively identify technical technologies,
    web server software, CMS platforms, application frameworks, JavaScript libraries,
    analytics scripts, third-party services, tracking scripts, and check for
    potentially exposed administrative panels and open directory listings.

Features collected (Exactly 9):
    1. Web Server Detection (Server header, version, source)
    2. CMS Detection (WordPress, Joomla, Drupal, Shopify, Magento, Wix, etc.)
    3. Framework Detection (Next.js, React, Vue, Angular, Django, Flask, Laravel, Express, etc.)
    4. JavaScript Libraries (jQuery, Bootstrap, Lodash, Axios, GSAP, D3, Chart.js, etc.)
    5. Analytics Scripts (Google Analytics, GTM, Matomo, Plausible, Adobe, Hotjar, Clarity, etc.)
    6. Third-party Services (Google Fonts, Cloudflare, Stripe, PayPal, reCAPTCHA, CDNs, etc.)
    7. Tracking Scripts (Meta Pixel, TikTok Pixel, LinkedIn Insight Tag, Twitter Pixel, etc.)
    8. Exposed Admin Panels (Safe, limited check of common paths: /admin, /login, /wp-admin, etc.)
    9. Open Directories (Safe, limited check of common paths: /, /uploads/, /files/, /backup/, etc.)

IMPORTANT SAFETY & ARCHITECTURAL RULES:
    - This is strictly an EVIDENCE COLLECTION AGENT.
    - PASSIVE / LOW-IMPACT technical fingerprinting only.
    - Do NOT perform exploitation, login attempts, authentication bypass, or brute-forcing.
    - Do NOT calculate final Trust Scores, Risk Scores, or phishing probabilities.
    - Do NOT classify the website as Safe, Malicious, or Phishing.
    - Never guess or fabricate versions: unidentified versions remain null.
    - Safe timeouts, limited redirect chains, and response size caps.
"""

import re
import sys
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 10        # Seconds for main page fetch
PATH_CHECK_TIMEOUT = 5      # Seconds for secondary path checks
MAX_REDIRECTS = 5           # Max redirect hops
MAX_HTML_SIZE = 2 * 1024 * 1024  # 2MB response truncation limit

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 DigitalForensics-Agent7/1.0"
)

# Limited list of common administrative paths for passive verification
ADMIN_PATHS = [
    "/admin",
    "/login",
    "/wp-admin",
    "/administrator",
    "/cpanel",
    "/user/login"
]

# Limited list of common directory paths for open listing verification
DIRECTORY_PATHS = [
    "/",
    "/uploads/",
    "/files/",
    "/backup/",
    "/assets/",
    "/static/"
]


# ---------------------------------------------------------------------------
# Helpers: Time & Logging
# ---------------------------------------------------------------------------

def _get_utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str):
    """Log Agent 7 actions cleanly to stdout."""
    print(f"[Agent 7] {msg}", flush=True)


# ---------------------------------------------------------------------------
# URL Normalization
# ---------------------------------------------------------------------------

def normalize_url(raw_url: str) -> dict:
    """
    Validate and normalize input URL.
    Returns dictionary with original_url, normalized_url, scheme, hostname, and domain.
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "original_url": "",
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "domain": "",
            "is_valid": False
        }

    trimmed = raw_url.strip()
    if not trimmed.startswith(("http://", "https://")):
        normalized = "https://" + trimmed
    else:
        normalized = trimmed

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").strip().lower()

    domain = hostname
    if _TLDEXTRACT_AVAILABLE and hostname:
        ext = tldextract.extract(normalized)
        if hasattr(ext, "top_domain_under_public_suffix"):
            reg_dom = ext.top_domain_under_public_suffix
            if reg_dom:
                domain = reg_dom.lower()
        else:
            try:
                if ext.domain and ext.suffix:
                    domain = f"{ext.domain}.{ext.suffix}".lower()
            except Exception:
                pass
    elif hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])

    return {
        "original_url": trimmed,
        "normalized_url": normalized,
        "scheme": parsed.scheme.lower() if parsed.scheme else "https",
        "hostname": hostname,
        "domain": domain,
        "is_valid": bool(hostname)
    }


# ---------------------------------------------------------------------------
# Safe Webpage Fetcher
# ---------------------------------------------------------------------------

def fetch_webpage(url: str) -> dict:
    """
    Safely perform an HTTP GET request to the target website.
    Limits response size, follows redirects safely, and records redirect chain.
    """
    redirect_chain = [url]
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS

        resp = session.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            verify=True,
            allow_redirects=True
        )

        # Build redirect history chain
        if resp.history:
            redirect_chain = [r.url for r in resp.history] + [resp.url]
        else:
            redirect_chain = [resp.url]

        # Read content with size cap
        content_bytes = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            content_bytes.extend(chunk)
            if len(content_bytes) >= MAX_HTML_SIZE:
                break

        # Decode content safely
        try:
            encoding = resp.encoding or "utf-8"
            html_text = content_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = content_bytes.decode("utf-8", errors="replace")

        return {
            "status": "success",
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": dict(resp.headers),
            "html": html_text,
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain
        }

    except requests.exceptions.SSLError:
        # Fallback to unverified SSL if certificate verification fails
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                verify=False,
                allow_redirects=True
            )
            content_bytes = bytearray()
            for chunk in resp.iter_content(chunk_size=8192):
                content_bytes.extend(chunk)
                if len(content_bytes) >= MAX_HTML_SIZE:
                    break
            html_text = content_bytes.decode("utf-8", errors="replace")
            return {
                "status": "success",
                "status_code": resp.status_code,
                "final_url": resp.url,
                "headers": dict(resp.headers),
                "html": html_text,
                "redirect_count": len(resp.history),
                "redirect_chain": [r.url for r in resp.history] + [resp.url]
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"SSL/Connection failed: {str(e)}",
                "final_url": url,
                "headers": {},
                "html": "",
                "redirect_count": 0,
                "redirect_chain": [url]
            }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "message": f"Request timed out after {REQUEST_TIMEOUT}s",
            "final_url": url,
            "headers": {},
            "html": "",
            "redirect_count": 0,
            "redirect_chain": [url]
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"HTTP request failed: {str(e)}",
            "final_url": url,
            "headers": {},
            "html": "",
            "redirect_count": 0,
            "redirect_chain": [url]
        }


# ---------------------------------------------------------------------------
# 1. Web Server Detection
# ---------------------------------------------------------------------------

def detect_web_server(headers: dict) -> dict:
    """
    Identify web server software from HTTP response headers without guessing.
    """
    server_header = headers.get("Server") or headers.get("server")
    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")

    if not server_header and not powered_by:
        return {
            "status": "not_detected",
            "name": None,
            "version": None,
            "source": None
        }

    raw_val = server_header if server_header else powered_by
    source_label = "HTTP Server header" if server_header else "HTTP X-Powered-By header"

    # Match server name and version pattern (e.g., "nginx/1.24.0", "Apache/2.4.52 (Ubuntu)")
    match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:/([0-9\.\_\-a-zA-Z]+))?", raw_val.strip())
    if match:
        name = match.group(1)
        version = match.group(2) if match.group(2) else None
    else:
        name = raw_val.strip()
        version = None

    return {
        "status": "detected",
        "name": name,
        "version": version,
        "source": source_label,
        "raw": raw_val
    }


# ---------------------------------------------------------------------------
# 2. CMS Detection
# ---------------------------------------------------------------------------

def detect_cms(soup: BeautifulSoup, html: str, headers: dict) -> dict:
    """
    Identify whether the website uses a known Content Management System (CMS)
    using multiple passive indicators.
    """
    evidence = []
    cms_name = None
    cms_version = None

    html_lower = html.lower()

    # Meta generator checks
    meta_generators = soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    for meta in meta_generators:
        gen_content = meta.get("content", "")
        if "wordpress" in gen_content.lower():
            cms_name = "WordPress"
            evidence.append(f"Meta generator: {gen_content}")
            v_match = re.search(r"wordpress\s+([0-9\.]+)", gen_content, re.I)
            if v_match:
                cms_version = v_match.group(1)
        elif "joomla" in gen_content.lower():
            cms_name = "Joomla"
            evidence.append(f"Meta generator: {gen_content}")
            v_match = re.search(r"joomla!?\s+([0-9\.]+)", gen_content, re.I)
            if v_match:
                cms_version = v_match.group(1)
        elif "drupal" in gen_content.lower():
            cms_name = "Drupal"
            evidence.append(f"Meta generator: {gen_content}")
            v_match = re.search(r"drupal\s+([0-9\.]+)", gen_content, re.I)
            if v_match:
                cms_version = v_match.group(1)
        elif "ghost" in gen_content.lower():
            cms_name = "Ghost"
            evidence.append(f"Meta generator: {gen_content}")
        elif "prestashop" in gen_content.lower():
            cms_name = "PrestaShop"
            evidence.append(f"Meta generator: {gen_content}")
        elif "wix" in gen_content.lower():
            cms_name = "Wix"
            evidence.append(f"Meta generator: {gen_content}")
        elif "shopify" in gen_content.lower():
            cms_name = "Shopify"
            evidence.append(f"Meta generator: {gen_content}")
        elif "squarespace" in gen_content.lower():
            cms_name = "Squarespace"
            evidence.append(f"Meta generator: {gen_content}")

    # Path & asset indicators
    if not cms_name or cms_name == "WordPress":
        wp_hits = []
        if "/wp-content/" in html:
            wp_hits.append("/wp-content/")
        if "/wp-includes/" in html:
            wp_hits.append("/wp-includes/")
        if "wp-json" in html:
            wp_hits.append("wp-json")
        if "wp-block-" in html or "wp-custom-logo" in html:
            wp_hits.append("wp-block classes")

        if len(wp_hits) >= 1:
            cms_name = "WordPress"
            evidence.extend(wp_hits)

    if not cms_name:
        if "cdn.shopify.com" in html or "shopify.theme" in html_lower or "myshopify.com" in html_lower:
            cms_name = "Shopify"
            evidence.append("Shopify CDN & theme assets")

    if not cms_name:
        if "static1.squarespace.com" in html or "squarespace.constants" in html_lower:
            cms_name = "Squarespace"
            evidence.append("Squarespace static assets")

    if not cms_name:
        if "_wix_" in html or "wix-code-" in html or "wix-image" in html:
            cms_name = "Wix"
            evidence.append("Wix structural attributes")

    if not cms_name:
        if "drupal.settings" in html or "sites/default/files" in html or "sites/all/" in html:
            cms_name = "Drupal"
            evidence.append("Drupal settings & site paths")

    if not cms_name:
        if "/components/com_" in html or "/media/jui/" in html:
            cms_name = "Joomla"
            evidence.append("Joomla component paths")

    if not cms_name:
        if "mage.cookies" in html_lower or "/skin/frontend/" in html or "/mage/" in html:
            cms_name = "Magento"
            evidence.append("Magento frontend paths & scripts")

    if cms_name:
        return {
            "status": "detected",
            "name": cms_name,
            "version": cms_version,
            "evidence": sorted(list(set(evidence)))
        }

    return {
        "status": "not_detected",
        "name": None,
        "version": None,
        "evidence": []
    }


# ---------------------------------------------------------------------------
# 3. Framework Detection
# ---------------------------------------------------------------------------

def detect_frameworks(soup: BeautifulSoup, html: str, headers: dict) -> list:
    """
    Detect application frameworks (frontend & backend) using passive DOM,
    headers, and script signatures.
    """
    frameworks = []
    html_lower = html.lower()

    # Next.js
    next_ev = []
    if "__NEXT_DATA__" in html:
        next_ev.append("__NEXT_DATA__ payload")
    if "/_next/" in html:
        next_ev.append("/_next/ static path")
    if soup.find(id="__next"):
        next_ev.append('id="__next" container')
    if next_ev:
        frameworks.append({
            "name": "Next.js",
            "version": None,
            "evidence": next_ev
        })

    # Nuxt.js
    nuxt_ev = []
    if "__NUXT__" in html:
        nuxt_ev.append("__NUXT__ state")
    if "/_nuxt/" in html:
        nuxt_ev.append("/_nuxt/ path")
    if soup.find(id="__nuxt"):
        nuxt_ev.append('id="__nuxt" container')
    if nuxt_ev:
        frameworks.append({
            "name": "Nuxt.js",
            "version": None,
            "evidence": nuxt_ev
        })

    # React
    react_ev = []
    if soup.find(attrs={"data-reactroot": True}) or soup.find(attrs={"data-reactid": True}):
        react_ev.append("data-reactroot / data-reactid attribute")
    if "_reactlistening" in html_lower:
        react_ev.append("_reactListening attribute")
    if "react.production.min.js" in html or "react-dom" in html:
        react_ev.append("React production bundle scripts")
    if react_ev and not any(f["name"] == "Next.js" for f in frameworks):
        frameworks.append({
            "name": "React",
            "version": None,
            "evidence": react_ev
        })

    # Vue.js
    vue_ev = []
    if re.search(r"data-v-[a-zA-Z0-9]+", html):
        vue_ev.append("data-v-* scoped CSS attributes")
    if "__vue__" in html or "vue.global.js" in html or "vue.min.js" in html:
        vue_ev.append("Vue runtime scripts")
    if vue_ev and not any(f["name"] == "Nuxt.js" for f in frameworks):
        frameworks.append({
            "name": "Vue.js",
            "version": None,
            "evidence": vue_ev
        })

    # Angular
    angular_ev = []
    ng_tag = soup.find(attrs={"ng-version": True})
    if ng_tag:
        v = ng_tag.get("ng-version")
        angular_ev.append(f"ng-version attribute ({v})")
        frameworks.append({
            "name": "Angular",
            "version": v,
            "evidence": angular_ev
        })
    elif soup.find(attrs={"ng-app": True}) or soup.find(attrs={"ng-controller": True}) or "angular.min.js" in html:
        angular_ev.append("AngularJS directive / script")
        frameworks.append({
            "name": "AngularJS",
            "version": None,
            "evidence": angular_ev
        })

    # Svelte
    if re.search(r"class=[\"'][^\"']*svelte-[a-zA-Z0-9]+", html):
        frameworks.append({
            "name": "Svelte",
            "version": None,
            "evidence": ["svelte-* scoped classes"]
        })

    # Django
    django_ev = []
    if soup.find("input", attrs={"name": "csrfmiddlewaretoken"}):
        django_ev.append("csrfmiddlewaretoken hidden input")
    if django_ev:
        frameworks.append({
            "name": "Django",
            "version": None,
            "evidence": django_ev
        })

    # Laravel
    laravel_ev = []
    if soup.find("meta", attrs={"name": "csrf-token"}):
        laravel_ev.append("csrf-token meta tag")
    if "laravel_session" in headers.get("Set-Cookie", "") or "XSRF-TOKEN" in headers.get("Set-Cookie", ""):
        laravel_ev.append("Laravel session / XSRF cookie")
    if laravel_ev:
        frameworks.append({
            "name": "Laravel",
            "version": None,
            "evidence": laravel_ev
        })

    # Express / Node.js
    powered_by = headers.get("X-Powered-By", "")
    if "Express" in powered_by:
        frameworks.append({
            "name": "Express",
            "version": None,
            "evidence": ["HTTP header: X-Powered-By: Express"]
        })

    # ASP.NET
    asp_ev = []
    if soup.find("input", attrs={"id": "__VIEWSTATE"}) or soup.find("input", attrs={"id": "__EVENTVALIDATION"}):
        asp_ev.append("__VIEWSTATE / __EVENTVALIDATION form tokens")
    if "ASP.NET" in powered_by:
        asp_ev.append("HTTP header: X-Powered-By: ASP.NET")
    if "ASP.NET_SessionId" in headers.get("Set-Cookie", ""):
        asp_ev.append("ASP.NET_SessionId cookie")
    if asp_ev:
        frameworks.append({
            "name": "ASP.NET",
            "version": None,
            "evidence": asp_ev
        })

    # Ruby on Rails
    if soup.find("meta", attrs={"name": "csrf-param", "content": "authenticity_token"}):
        frameworks.append({
            "name": "Ruby on Rails",
            "version": None,
            "evidence": ["authenticity_token meta tag"]
        })

    return frameworks


# ---------------------------------------------------------------------------
# 4. JavaScript Libraries Detection
# ---------------------------------------------------------------------------

def detect_javascript_libraries(soup: BeautifulSoup, html: str) -> list:
    """
    Identify JavaScript libraries loaded in <script> tags or referenced in the page.
    """
    libraries = []
    seen = set()

    scripts = soup.find_all("script")
    script_sources = [s.get("src") for s in scripts if s.get("src")]

    patterns = [
        ("jQuery", r"jquery(?:-([0-9\.]+))?(?:\.min)?\.js|jquery@([0-9\.]+)", "jQuery"),
        ("Bootstrap", r"bootstrap(?:@|\/|\-)?([0-9\.]+)?(?:\.bundle)?(?:\.min)?\.js", "Bootstrap"),
        ("Lodash", r"lodash(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Lodash"),
        ("Axios", r"axios(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Axios"),
        ("GSAP", r"(?:gsap|tweenmax)(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "GSAP"),
        ("D3.js", r"d3(?:\.v([0-9\.]+))?(?:\.min)?\.js|d3@([0-9\.]+)", "D3.js"),
        ("Moment.js", r"moment(?:-with-locales)?(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Moment.js"),
        ("Chart.js", r"chart(?:@|\/|\-)?([0-9\.]+)?(?:\.bundle)?(?:\.min)?\.js", "Chart.js"),
        ("Swiper", r"swiper(?:-bundle)?(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Swiper"),
        ("Popper.js", r"popper(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Popper.js"),
        ("Font Awesome JS", r"fontawesome(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js|kit\.fontawesome\.com", "Font Awesome"),
        ("Alpine.js", r"alpine(?:js)?(?:@|\/|\-)?([0-9\.]+)?(?:\.min)?\.js", "Alpine.js")
    ]

    for src in script_sources:
        src_clean = src.split("?")[0]
        for lib_name, pattern, display_name in patterns:
            if display_name in seen:
                continue
            match = re.search(pattern, src_clean, re.I)
            if match:
                version = None
                for group in match.groups():
                    if group:
                        version = group
                        break
                libraries.append({
                    "name": display_name,
                    "version": version,
                    "source": src
                })
                seen.add(display_name)

    return libraries


# ---------------------------------------------------------------------------
# 5. Analytics Scripts Detection
# ---------------------------------------------------------------------------

def detect_analytics(soup: BeautifulSoup, html: str) -> list:
    """
    Detect analytics platforms and extract tracking IDs when available.
    """
    analytics = []
    seen = set()

    # Google Analytics / GTM
    if "google-analytics.com" in html or "googletagmanager.com/gtag/js" in html or "gtag(" in html:
        ga_ids = re.findall(r"(G-[A-Z0-9]{6,12}|UA-[0-9]{4,10}-[0-9]{1,4})", html)
        tracking_id = ga_ids[0] if ga_ids else None
        analytics.append({
            "name": "Google Analytics",
            "detected": True,
            "tracking_id": tracking_id
        })
        seen.add("Google Analytics")

    if "googletagmanager.com/gtm.js" in html or "GTM-" in html:
        gtm_ids = re.findall(r"(GTM-[A-Z0-9]{5,10})", html)
        tracking_id = gtm_ids[0] if gtm_ids else None
        if "Google Tag Manager" not in seen:
            analytics.append({
                "name": "Google Tag Manager",
                "detected": True,
                "tracking_id": tracking_id
            })
            seen.add("Google Tag Manager")

    # Matomo / Piwik
    if "matomo.js" in html or "piwik.js" in html or "_paq.push" in html:
        if "Matomo" not in seen:
            analytics.append({
                "name": "Matomo (Piwik)",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Matomo")

    # Plausible
    if "plausible.io" in html:
        if "Plausible" not in seen:
            analytics.append({
                "name": "Plausible Analytics",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Plausible")

    # Adobe Analytics
    if "adobedtm.com" in html or "appmeasurement.js" in html or "s_code.js" in html:
        if "Adobe Analytics" not in seen:
            analytics.append({
                "name": "Adobe Analytics",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Adobe Analytics")

    # Mixpanel
    if "cdn.mxpnl.com" in html or "mixpanel.init" in html:
        if "Mixpanel" not in seen:
            analytics.append({
                "name": "Mixpanel",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Mixpanel")

    # Hotjar
    if "static.hotjar.com" in html or "_hjsettings" in html.lower():
        if "Hotjar" not in seen:
            analytics.append({
                "name": "Hotjar",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Hotjar")

    # Microsoft Clarity
    if "clarity.ms" in html:
        if "Microsoft Clarity" not in seen:
            clarity_id = re.search(r"clarity\.ms\/tag\/([a-zA-Z0-9]+)", html)
            analytics.append({
                "name": "Microsoft Clarity",
                "detected": True,
                "tracking_id": clarity_id.group(1) if clarity_id else None
            })
            seen.add("Microsoft Clarity")

    # Yandex Metrica
    if "mc.yandex.ru/metrika" in html:
        if "Yandex Metrica" not in seen:
            analytics.append({
                "name": "Yandex Metrica",
                "detected": True,
                "tracking_id": None
            })
            seen.add("Yandex Metrica")

    return analytics


# ---------------------------------------------------------------------------
# 6. Third-Party Services Detection
# ---------------------------------------------------------------------------

def detect_third_party_services(soup: BeautifulSoup, html: str, target_domain: str) -> list:
    """
    Identify external services loaded or referenced by the webpage.
    """
    services = []
    seen = set()

    service_definitions = [
        ("Google Fonts", ["fonts.googleapis.com", "fonts.gstatic.com"], "Font / Typography"),
        ("Adobe Fonts", ["use.typekit.net"], "Font / Typography"),
        ("Cloudflare CDN / Security", ["cdnjs.cloudflare.com", "cloudflare.com"], "CDN / Security"),
        ("jsDelivr CDN", ["cdn.jsdelivr.net"], "CDN"),
        ("unpkg CDN", ["unpkg.com"], "CDN"),
        ("Google reCAPTCHA", ["google.com/recaptcha", "gstatic.com/recaptcha"], "Security / Bot Protection"),
        ("hCaptcha", ["hcaptcha.com", "js.hcaptcha.com"], "Security / Bot Protection"),
        ("Cloudflare Turnstile", ["challenges.cloudflare.com"], "Security / Bot Protection"),
        ("Stripe", ["js.stripe.com", "m.stripe.network"], "Payment Gateway"),
        ("PayPal", ["paypal.com/sdk/js", "www.paypalobjects.com"], "Payment Gateway"),
        ("YouTube Video", ["youtube.com/iframe_api", "youtube.com/embed"], "Media / Video"),
        ("Vimeo Video", ["player.vimeo.com"], "Media / Video"),
        ("Intercom", ["widget.intercom.io"], "Customer Support / Chat"),
        ("Zendesk", ["ekr.zdassets.com", "zendesk.com"], "Customer Support / Chat"),
        ("Tawk.to", ["embed.tawk.to"], "Customer Support / Chat"),
        ("Crisp Chat", ["client.crisp.chat"], "Customer Support / Chat"),
        ("Gravatar", ["gravatar.com/avatar"], "User Avatar")
    ]

    for name, domains, category in service_definitions:
        for d in domains:
            if d in html:
                if name not in seen:
                    services.append({
                        "name": name,
                        "domain": d,
                        "category": category
                    })
                    seen.add(name)
                break

    return services


# ---------------------------------------------------------------------------
# 7. Tracking Scripts Detection
# ---------------------------------------------------------------------------

def detect_tracking_scripts(soup: BeautifulSoup, html: str) -> list:
    """
    Detect marketing, advertising, session recording, and behavioral tracking scripts.
    """
    trackers = []
    seen = set()

    tracker_definitions = [
        ("Meta Pixel (Facebook)", r"connect\.facebook\.net\/[a-zA-Z_]+\/fbevents\.js|fbq\(", "fbq() pixel initialization"),
        ("TikTok Pixel", r"analytics\.tiktok\.com\/i18n\/pixel\/|ttq\.load\(", "TikTok analytics script"),
        ("LinkedIn Insight Tag", r"snap\.licdn\.com\/li\.lms-analytics\/insight\.min\.js|_linkedin_partner_id", "LinkedIn partner insight script"),
        ("Twitter / X Pixel", r"static\.ads-twitter\.com\/uwt\.js|twq\(", "Twitter advertising tag"),
        ("Pinterest Tag", r"pintrk\(|assets\.pinterest\.com", "Pinterest tracking tag"),
        ("Microsoft Clarity", r"clarity\.ms", "Clarity session recording script"),
        ("Hotjar Tracking", r"static\.hotjar\.com", "Hotjar heatmap & session script"),
        ("Snapchat Pixel", r"sc-static\.net\/scevent\.min\.js|snaptr\(", "Snapchat pixel event tracker")
    ]

    for name, pattern, evidence_label in tracker_definitions:
        if re.search(pattern, html, re.I):
            if name not in seen:
                trackers.append({
                    "name": name,
                    "detected": True,
                    "evidence": evidence_label
                })
                seen.add(name)

    return trackers


# ---------------------------------------------------------------------------
# 8. Exposed Admin Panels (Safe & Limited)
# ---------------------------------------------------------------------------

def check_admin_panels(base_url: str) -> list:
    """
    Safely check a limited set of common administrative paths.
    Does NOT brute-force, attempt login, or submit credentials.
    """
    results = []

    parsed = urlparse(base_url)
    root_origin = f"{parsed.scheme}://{parsed.netloc}"

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,*/*",
        "Connection": "close"
    }

    def _check_path(path: str):
        target = urljoin(root_origin, path)
        try:
            resp = requests.get(
                target,
                headers=headers,
                timeout=PATH_CHECK_TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            code = resp.status_code
            text_sample = resp.text[:4096].lower() if resp.text else ""

            if code == 200:
                # Check if it looks like an authentication / admin portal
                is_admin_form = (
                    'type="password"' in text_sample or
                    "login" in text_sample or
                    "admin" in text_sample or
                    "sign in" in text_sample or
                    "dashboard" in text_sample
                )
                return {
                    "path": path,
                    "status_code": 200,
                    "detected": is_admin_form,
                    "final_url": resp.url
                }
            elif code in (401, 403):
                return {
                    "path": path,
                    "status_code": code,
                    "detected": "possibly_protected",
                    "final_url": resp.url
                }
            else:
                return {
                    "path": path,
                    "status_code": code,
                    "detected": False,
                    "final_url": resp.url
                }
        except requests.exceptions.Timeout:
            return {
                "path": path,
                "status_code": None,
                "detected": "timeout",
                "final_url": target
            }
        except Exception:
            return {
                "path": path,
                "status_code": None,
                "detected": False,
                "final_url": target
            }

    with ThreadPoolExecutor(max_workers=len(ADMIN_PATHS)) as executor:
        futures = {executor.submit(_check_path, p): p for p in ADMIN_PATHS}
        for future in as_completed(futures):
            results.append(future.result())

    # Sort results by original path order
    order_map = {p: i for i, p in enumerate(ADMIN_PATHS)}
    results.sort(key=lambda r: order_map.get(r["path"], 999))
    return results


# ---------------------------------------------------------------------------
# 9. Open Directories (Safe & Limited)
# ---------------------------------------------------------------------------

def check_open_directories(base_url: str) -> list:
    """
    Safely check a limited set of common directory paths for open directory listings.
    """
    results = []

    parsed = urlparse(base_url)
    root_origin = f"{parsed.scheme}://{parsed.netloc}"

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,*/*",
        "Connection": "close"
    }

    dir_listing_markers = [
        "index of /",
        "<title>index of",
        "[to parent directory]",
        "parent directory</a>",
        "directory listing for",
        "last modified</a>",
        "parent directory/</a>"
    ]

    def _check_dir(path: str):
        target = urljoin(root_origin, path)
        try:
            resp = requests.get(
                target,
                headers=headers,
                timeout=PATH_CHECK_TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            code = resp.status_code
            text_sample = resp.text[:8192].lower() if resp.text else ""

            if code == 200:
                is_open = any(marker in text_sample for marker in dir_listing_markers)
                evidence_text = f"Directory listing marker found on {path}" if is_open else "Standard response (no directory listing)"
                return {
                    "path": path,
                    "status_code": 200,
                    "directory_listing": is_open,
                    "evidence": evidence_text if is_open else None
                }
            elif code in (401, 403):
                return {
                    "path": path,
                    "status_code": code,
                    "directory_listing": "unknown",
                    "evidence": "Access restricted (HTTP 403/401)"
                }
            else:
                return {
                    "path": path,
                    "status_code": code,
                    "directory_listing": False,
                    "evidence": None
                }
        except requests.exceptions.Timeout:
            return {
                "path": path,
                "status_code": None,
                "directory_listing": "timeout",
                "evidence": "Request timed out"
            }
        except Exception:
            return {
                "path": path,
                "status_code": None,
                "directory_listing": False,
                "evidence": None
            }

    with ThreadPoolExecutor(max_workers=len(DIRECTORY_PATHS)) as executor:
        futures = {executor.submit(_check_dir, p): p for p in DIRECTORY_PATHS}
        for future in as_completed(futures):
            results.append(future.result())

    order_map = {p: i for i, p in enumerate(DIRECTORY_PATHS)}
    results.sort(key=lambda r: order_map.get(r["path"], 999))
    return results


# ---------------------------------------------------------------------------
# Main Agent 7 Entrypoint
# ---------------------------------------------------------------------------

def analyze_fingerprint(raw_url: str) -> dict:
    """
    Execute technical fingerprinting across 9 technical feature areas:
    Web Server, CMS, Frameworks, JavaScript Libraries, Analytics,
    Third-party Services, Tracking Scripts, Admin Panels, and Open Directories.

    Strict rules:
    - Evidence collection only.
    - No trust scores or risk scores calculated.
    - No classification verdicts (Safe/Malicious/Phishing).
    - Passive, low-impact inspection.
    """
    _log("Starting technical fingerprinting...")
    _log("Normalizing URL...")

    norm = normalize_url(raw_url)
    if not norm["is_valid"]:
        _log("Invalid URL provided.")
        extra_err = {
            "input": {
                "original_url": raw_url or "",
                "final_url": ""
            },
            "web_server": {"status": "not_detected"},
            "cms": {"status": "not_detected", "name": None, "version": None, "evidence": []},
            "frameworks": [],
            "javascript_libraries": [],
            "analytics": [],
            "third_party_services": [],
            "tracking_scripts": [],
            "admin_panels": [],
            "open_directories": [],
            "redirects": {"count": 0, "chain": []},
            "checked_at": _get_utc_now_iso()
        }
        return build_agent_result(
            agent_identifier="A7",
            target=raw_url or "",
            status="error",
            data={},
            evidence=[],
            errors=["Input URL is empty or invalid."],
            extra_fields=extra_err
        )

    target_url = norm["normalized_url"]
    errors = []

    _log("Fetching webpage...")
    fetch_res = fetch_webpage(target_url)

    if fetch_res["status"] != "success":
        errors.append(fetch_res.get("message", "Webpage could not be fetched"))

    final_url = fetch_res.get("final_url", target_url)
    headers = fetch_res.get("headers", {})
    html_text = fetch_res.get("html", "")
    redirect_count = fetch_res.get("redirect_count", 0)
    redirect_chain = fetch_res.get("redirect_chain", [target_url])

    soup = BeautifulSoup(html_text, "html.parser") if html_text else BeautifulSoup("", "html.parser")

    _log("Inspecting HTTP headers...")
    _log("Detecting web server...")
    web_server_info = detect_web_server(headers)

    _log("Detecting CMS...")
    cms_info = detect_cms(soup, html_text, headers)

    _log("Detecting frameworks...")
    frameworks_info = detect_frameworks(soup, html_text, headers)

    _log("Detecting JavaScript libraries...")
    js_libraries_info = detect_javascript_libraries(soup, html_text)

    _log("Detecting analytics...")
    analytics_info = detect_analytics(soup, html_text)

    _log("Detecting third-party services...")
    third_party_info = detect_third_party_services(soup, html_text, norm["domain"])

    _log("Detecting tracking scripts...")
    tracking_scripts_info = detect_tracking_scripts(soup, html_text)

    _log("Checking limited admin paths...")
    admin_panels_info = check_admin_panels(final_url)

    _log("Checking limited directory paths...")
    open_directories_info = check_open_directories(final_url)

    checked_at = _get_utc_now_iso()

    # Step 10: Compile structured evidence items
    evidence = []
    evidence.append(create_evidence_item("A7", 1, "Web server signature", web_server_info.get("name") if web_server_info.get("status") == "detected" else None, severity="info", source="HTTP headers", evidence_type="deterministic", metadata=web_server_info, category="server_banner_detected"))
    evidence.append(create_evidence_item("A7", 2, "Content management system", cms_info.get("name") if cms_info.get("status") == "detected" else None, severity="info", source="Website HTML / Headers", evidence_type="deterministic", metadata=cms_info, category="framework_detected"))
    evidence.append(create_evidence_item("A7", 3, "Web frameworks detected", [f.get("name") for f in frameworks_info] if frameworks_info else [], severity="info", source="Website HTML", evidence_type="deterministic", metadata={"frameworks": frameworks_info}, category="framework_detected"))
    evidence.append(create_evidence_item("A7", 4, "JavaScript libraries detected", [j.get("name") for j in js_libraries_info] if js_libraries_info else [], severity="info", source="Website HTML", evidence_type="deterministic", metadata={"libraries": js_libraries_info}, category="framework_detected"))
    evidence.append(create_evidence_item("A7", 5, "Analytics services detected", [a.get("name") for a in analytics_info] if analytics_info else [], severity="info", source="Website HTML", evidence_type="deterministic", metadata={"analytics": analytics_info}, category="analytics_tracker_detected"))
    evidence.append(create_evidence_item("A7", 6, "Third-party services integrated", [t.get("name") for t in third_party_info] if third_party_info else [], severity="info", source="Website HTML", evidence_type="deterministic", metadata={"services": third_party_info}, category="analytics_tracker_detected"))
    evidence.append(create_evidence_item("A7", 7, "Tracking and marketing pixels", [s.get("name") for s in tracking_scripts_info] if tracking_scripts_info else [], severity="info", source="Website HTML", evidence_type="deterministic", metadata={"tracking_scripts": tracking_scripts_info}, category="analytics_tracker_detected"))
    
    detected_admin_panels = [p.get("path") for p in admin_panels_info if p.get("detected") is True] if isinstance(admin_panels_info, list) else []
    # Standard login pages and authentication endpoints requiring login are normal web interfaces (neutral info)
    if len(detected_admin_panels) > 0:
        admin_sev = "info"
        admin_cat = "server_banner_detected"
        admin_finding = "Public login and user authentication interface identified"
    else:
        admin_sev = "info"
        admin_cat = "server_banner_detected"
        admin_finding = "No exposed administrative panel paths found"

    evidence.append(create_evidence_item("A7", 8, admin_finding, detected_admin_panels, severity=admin_sev, source="HTTP probe", evidence_type="deterministic", metadata={"admin_panels": admin_panels_info, "detected_paths": detected_admin_panels}, category=admin_cat))
    
    detected_open_dirs = [d.get("path") for d in open_directories_info if d.get("directory_listing") is True] if isinstance(open_directories_info, list) else []
    open_dir_sev = "medium" if len(detected_open_dirs) > 0 else "info"
    open_dir_finding = "Open directory listing paths detected" if len(detected_open_dirs) > 0 else "No open directory listings found"
    evidence.append(create_evidence_item("A7", 9, open_dir_finding, detected_open_dirs, severity=open_dir_sev, source="HTTP probe", evidence_type="deterministic", metadata={"open_directories": open_directories_info, "detected_paths": detected_open_dirs}, category="open_directory_listing" if open_dir_sev == "medium" else "server_banner_detected"))

    data_payload = {
        "web_server": web_server_info,
        "cms": cms_info,
        "frameworks": frameworks_info,
        "javascript_libraries": js_libraries_info,
        "analytics": analytics_info,
        "third_party_services": third_party_info,
        "tracking_scripts": tracking_scripts_info,
        "admin_panels": admin_panels_info,
        "open_directories": open_directories_info,
        "redirects": {
            "count": redirect_count,
            "chain": redirect_chain
        }
    }

    extra_fields = {
        "input": {
            "original_url": norm["original_url"],
            "final_url": final_url
        },
        "web_server": web_server_info,
        "cms": cms_info,
        "frameworks": frameworks_info,
        "javascript_libraries": js_libraries_info,
        "analytics": analytics_info,
        "third_party_services": third_party_info,
        "tracking_scripts": tracking_scripts_info,
        "admin_panels": admin_panels_info,
        "open_directories": open_directories_info,
        "redirects": {
            "count": redirect_count,
            "chain": redirect_chain
        },
        "checked_at": checked_at
    }

    response_payload = build_agent_result(
        agent_identifier="A7",
        target=norm["original_url"],
        status="success",
        data=data_payload,
        evidence=evidence,
        errors=errors,
        extra_fields=extra_fields
    )

    _log("Technical fingerprinting completed.")
    return response_payload


def get_technical_fingerprint(url: str) -> dict:
    """
    Convenience alias for analyze_fingerprint().
    """
    return analyze_fingerprint(url)
