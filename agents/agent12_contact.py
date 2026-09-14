"""
Agent 12 — Contact Verification
Evidence collection module for business identity, email verification,
phone number normalization, physical addresses, Google Maps presence,
social media links, company registration, and GST/VAT tax identifiers.

Strictly passive forensic evidence collection.
DO NOT calculate Trust/Risk score, phishing probability, or final verdict.
"""

import datetime
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import phonenumbers
    from phonenumbers import geocoder, number_type, PhoneNumberType
    _PHONENUMBERS_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for forensic inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable constants & limits
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2MB HTML limit
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

FREE_EMAIL_DOMAINS: Set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "zoho.com", "mail.com",
    "yandex.com", "gmx.com", "fastmail.com", "tutanota.com"
}

SOCIAL_PLATFORMS = {
    "LinkedIn": r"(?:linkedin\.com/(?:company|in)/([^/?#\s]+))",
    "Instagram": r"(?:instagram\.com/([^/?#\s]+))",
    "Facebook": r"(?:facebook\.com/(?:pages/)?([^/?#\s]+))",
    "Twitter / X": r"(?:(?:twitter|x)\.com/([^/?#\s]+))",
    "YouTube": r"(?:youtube\.com/(?:c/|channel/|user/|@)?([^/?#\s]+))",
    "TikTok": r"(?:tiktok\.com/@([^/?#\s]+))",
    "GitHub": r"(?:github\.com/([^/?#\s]+))",
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
# 1. STRUCTURED DATA & BUSINESS IDENTITY
# =====================================================================

def _extract_structured_data(soup: Optional[BeautifulSoup]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Parse Schema.org JSON-LD scripts for Organization and LocalBusiness metadata."""
    structured_summary = {
        "organization_found": False,
        "local_business_found": False,
        "contact_information_found": False,
    }
    extracted_entities = {}

    if not soup:
        return structured_summary, extracted_entities

    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            raw_json = script.string or script.get_text()
            if not raw_json:
                continue
            data = json.loads(raw_json)
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and "@graph" in data:
                items = data["@graph"]
            else:
                items = [data]

            for item in items:
                if not isinstance(item, dict):
                    continue
                schema_type = str(item.get("@type") or "").lower()
                if any(t in schema_type for t in ["organization", "corporation"]):
                    structured_summary["organization_found"] = True
                    extracted_entities["organization"] = item
                if "localbusiness" in schema_type or "store" in schema_type:
                    structured_summary["local_business_found"] = True
                    extracted_entities["local_business"] = item
                if any(k in item for k in ["telephone", "email", "address", "contactPoint"]):
                    structured_summary["contact_information_found"] = True
        except Exception:
            pass

    return structured_summary, extracted_entities


def _detect_business_identity(soup: Optional[BeautifulSoup], structured_entities: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Extract claimed business/company names across title, header, footer, and schema."""
    business_identity = {
        "name": None,
        "sources": [],
    }
    evidence_list = []

    if not soup:
        return business_identity, evidence_list

    names_found: Dict[str, List[str]] = {}

    # 1. Schema.org name
    for entity in structured_entities.values():
        name = entity.get("name") or entity.get("legalName")
        if name and isinstance(name, str) and len(name.strip()) > 2:
            clean_name = name.strip()
            names_found.setdefault(clean_name, []).append("JSON-LD Schema")

    # 2. Page title extraction (split by | or -)
    if soup.title and soup.title.string:
        title_text = soup.title.string.strip()
        parts = re.split(r"[-|•–—]", title_text)
        if len(parts) >= 2:
            candidate = parts[-1].strip() if len(parts[-1].strip()) < len(parts[0].strip()) else parts[0].strip()
            if len(candidate) > 2:
                names_found.setdefault(candidate, []).append("Page Title")

    # 3. Footer copyright line
    footer = soup.find("footer")
    if footer:
        footer_text = footer.get_text(separator=" ", strip=True)
        m = re.search(r"(?:©|copyright|&copy;)\s*(?:\d{4})?\s*([A-Za-z0-9\s.,&-]+?)(?:\.|\s+all\s+rights|\s+inc|\s+ltd|\s+pvt|\s*$)", footer_text, re.IGNORECASE)
        if m:
            clean_footer_name = m.group(1).strip().rstrip(".,")
            if len(clean_footer_name) > 2 and len(clean_footer_name) < 60:
                names_found.setdefault(clean_footer_name, []).append("Footer Copyright")

    # 4. Logo alt text
    for img in soup.find_all("img"):
        alt = (img.get("alt") or "").strip()
        classes = " ".join(img.get("class", [])) if isinstance(img.get("class"), list) else str(img.get("class") or "")
        if "logo" in classes.lower() or "logo" in str(img.get("src") or "").lower():
            if len(alt) > 2 and len(alt) < 40:
                names_found.setdefault(alt, []).append("Logo Alt Text")

    if names_found:
        # Select most prominent name (most source occurrences)
        sorted_names = sorted(names_found.items(), key=lambda x: len(x[1]), reverse=True)
        primary_name, sources = sorted_names[0]
        business_identity["name"] = primary_name
        business_identity["sources"] = sources
        evidence_list.append(f"Business identity detected: '{primary_name}' (Sources: {', '.join(sources)})")

    return business_identity, evidence_list


# =====================================================================
# 2. CONTACT PAGE DISCOVERY
# =====================================================================

def _find_contact_page(soup: Optional[BeautifulSoup], base_url: str) -> Dict[str, Any]:
    """Find dedicated Contact or Support page URL."""
    contact_page_info = {
        "found": False,
        "url": None,
    }
    if not soup:
        return contact_page_info

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = a.get_text(separator=" ", strip=True).lower()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if re.search(r"\b(contact|contact us|get in touch|support|help center)\b", text) or re.search(r"/(contact|contact-us|support|help)$", href, re.IGNORECASE):
            full_contact_url = urljoin(base_url, href)
            contact_page_info["found"] = True
            contact_page_info["url"] = full_contact_url
            break

    return contact_page_info


# =====================================================================
# 3. EMAIL ADDRESS EXTRACTION & VALIDATION
# =====================================================================

def _extract_and_validate_emails(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str],
    site_domain: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Extract email addresses from mailto links and text, performing format validation."""
    emails_list = []
    validations_list = []
    evidence_list = []

    if not soup or not html_text:
        return emails_list, validations_list, evidence_list

    found_emails: Dict[str, Dict[str, Any]] = {}

    # 1. Mailto links
    for a in soup.find_all("a", href=re.compile(r"^mailto:", re.IGNORECASE)):
        raw_href = a["href"].replace("mailto:", "").split("?")[0].strip()
        if raw_href:
            found_emails[raw_href.lower()] = {
                "email": raw_href,
                "source": "mailto: hyperlink",
                "location": "Navigation / Links",
            }

    # 2. Regex from text
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    for match in re.findall(email_pattern, html_text):
        low_m = match.lower()
        # Avoid asset filenames mistakenly matched
        if not low_m.endswith((".png", ".jpg", ".svg", ".webp", ".js", ".css")):
            if low_m not in found_emails:
                found_emails[low_m] = {
                    "email": match,
                    "source": "Webpage visible text",
                    "location": "Page body / Footer",
                }

    for email_key, data in list(found_emails.items())[:10]:
        email_str = data["email"]
        email_domain = email_str.split("@")[-1].lower() if "@" in email_str else ""
        is_free = email_domain in FREE_EMAIL_DOMAINS
        domain_mismatch = bool(site_domain and email_domain and site_domain not in email_domain and email_domain not in site_domain)

        # RFC format check
        valid_format = bool(re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email_str))

        email_entry = {
            "email": email_str,
            "source": data["source"],
            "type": "free_webmail" if is_free else "business",
            "domain_mismatch": domain_mismatch,
            "is_free_provider": is_free,
        }
        emails_list.append(email_entry)

        validations_list.append({
            "email": email_str,
            "valid_format": valid_format,
            "domain": email_domain,
        })

        evidence_msg = f"Email extracted: {email_str} (Source: {data['source']})"
        if is_free:
            evidence_msg += " [Free email provider]"
        if domain_mismatch and not is_free:
            evidence_msg += f" [Domain mismatch with {site_domain}]"
        evidence_list.append(evidence_msg)

    return emails_list, validations_list, evidence_list


# =====================================================================
# 4. PHONE NUMBER EXTRACTION & VALIDATION
# =====================================================================

def _extract_and_validate_phones(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Extract phone numbers and validate/format using phonenumbers."""
    phones_list = []
    validations_list = []
    evidence_list = []

    if not soup or not html_text:
        return phones_list, validations_list, evidence_list

    raw_candidates: Set[Tuple[str, str]] = set()

    # 1. tel: and WhatsApp links
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("tel:"):
            num = href.replace("tel:", "").strip()
            raw_candidates.add((num, "tel: hyperlink"))
        elif "wa.me/" in href or "api.whatsapp.com/send" in href:
            m = re.search(r"(?:wa\.me/|phone=)(\+?[0-9]+)", href)
            if m:
                raw_candidates.add((m.group(1), "WhatsApp contact link"))

    # 2. Text regex for international and standard phone formats
    phone_pattern = r"(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
    for match in re.findall(phone_pattern, html_text):
        clean_cand = match.strip()
        digits = re.sub(r"\D", "", clean_cand)
        if 8 <= len(digits) <= 15 and not clean_cand.startswith(("19", "20")):  # avoid matching dates/years
            raw_candidates.add((clean_cand, "Webpage visible text"))

    for raw_num, src in list(raw_candidates)[:8]:
        normalized = raw_num
        country_code = None
        valid_format = False
        num_type = "unknown"

        if _PHONENUMBERS_AVAILABLE:
            try:
                # Attempt parse as international (+...) or US default
                parsed = phonenumbers.parse(raw_num, None if raw_num.startswith("+") else "US")
                valid_format = phonenumbers.is_valid_number(parsed)
                normalized = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                country_code = geocoder.country_name_for_number(parsed, "en") or phonenumbers.region_code_for_number(parsed)
                t = number_type(parsed)
                if t == PhoneNumberType.MOBILE:
                    num_type = "mobile"
                elif t == PhoneNumberType.FIXED_LINE:
                    num_type = "fixed_line"
                elif t == PhoneNumberType.TOLL_FREE:
                    num_type = "toll_free"
            except Exception:
                valid_format = bool(len(re.sub(r"\D", "", raw_num)) >= 8)
        else:
            valid_format = bool(len(re.sub(r"\D", "", raw_num)) >= 8)

        phone_entry = {
            "number": raw_num,
            "normalized": normalized,
            "source": src,
            "country": country_code,
        }
        phones_list.append(phone_entry)

        validations_list.append({
            "number": raw_num,
            "valid_format": valid_format,
            "country": country_code,
            "type": num_type,
        })

        evidence_list.append(f"Phone number extracted: {raw_num} (Normalized: {normalized}, Country: {country_code or 'Unknown'})")

    return phones_list, validations_list, evidence_list


# =====================================================================
# 5. PHYSICAL ADDRESS & CONSISTENCY
# =====================================================================

def _extract_and_check_addresses(
    soup: Optional[BeautifulSoup],
    html_text: Optional[str],
    structured_entities: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Extract physical postal addresses and evaluate consistency."""
    addresses_list = []
    consistency_data = {"status": "not_available"}
    evidence_list = []

    if not soup or not html_text:
        return addresses_list, consistency_data, evidence_list

    found_addresses: List[Dict[str, Any]] = []

    # 1. Schema.org address
    for entity in structured_entities.values():
        addr = entity.get("address")
        if isinstance(addr, dict):
            parts = [addr.get("streetAddress"), addr.get("addressLocality"), addr.get("addressRegion"), addr.get("postalCode"), addr.get("addressCountry")]
            full_addr = ", ".join([str(p) for p in parts if p])
            if len(full_addr) > 8:
                found_addresses.append({"address": full_addr, "source": "JSON-LD PostalAddress"})
        elif isinstance(addr, str) and len(addr) > 8:
            found_addresses.append({"address": addr, "source": "JSON-LD Address"})

    # 2. HTML address / footer extraction
    address_tags = soup.find_all(["address", "p", "div", "span"])
    for tag in address_tags:
        classes = " ".join(tag.get("class", [])) if isinstance(tag.get("class"), list) else str(tag.get("class") or "")
        tag_id = str(tag.get("id") or "")
        if tag.name == "address" or re.search(r"\b(address|location|headquarters|office)\b", f"{classes} {tag_id}", re.IGNORECASE):
            text = tag.get_text(separator=", ", strip=True)
            if 15 <= len(text) <= 200 and re.search(r"\b(street|road|st|rd|ave|avenue|suite|floor|building|bldg|nagar|city|zip|pin|postal)\b", text, re.IGNORECASE):
                if not any(text == a["address"] for a in found_addresses):
                    found_addresses.append({"address": text, "source": "Webpage address block"})

    addresses_list = found_addresses[:5]

    if addresses_list:
        if len(addresses_list) == 1:
            consistency_data = {
                "status": "single_address_identified",
                "consistent": True,
                "addresses_found": [a["address"] for a in addresses_list]
            }
        else:
            # Check overlap / consistency
            first_addr = addresses_list[0]["address"].lower()
            second_addr = addresses_list[1]["address"].lower()
            overlap = any(word in second_addr for word in first_addr.split(",") if len(word.strip()) > 3)
            consistency_data = {
                "status": "consistent" if overlap else "inconsistent_or_multiple_locations",
                "consistent": overlap,
                "addresses_found": [a["address"] for a in addresses_list]
            }
        for a in addresses_list:
            evidence_list.append(f"Physical address extracted: '{a['address']}' (Source: {a['source']})")

    return addresses_list, consistency_data, evidence_list


# =====================================================================
# 6. GOOGLE MAPS PRESENCE
# =====================================================================

def _detect_google_maps(soup: Optional[BeautifulSoup]) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """Detect Google Maps iframe embeds and place links."""
    maps_data = {
        "detected": False,
        "links": [],
        "business_name": None,
        "location": None,
    }
    verification_data = {
        "status": "not_available"
    }
    evidence_list = []

    if not soup:
        return maps_data, verification_data, evidence_list

    found_links = []

    # Check iframes
    for iframe in soup.find_all("iframe", src=True):
        src = iframe["src"]
        if "google.com/maps" in src or "maps.google.com" in src:
            found_links.append(src)
            # Try extracting place query
            m = re.search(r"[?&]q=([^&]+)", src)
            if m:
                maps_data["location"] = requests.utils.unquote(m.group(1).replace("+", " "))

    # Check anchor links
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "google.com/maps" in href or "maps.google.com" in href or "goo.gl/maps" in href or "maps.app.goo.gl" in href:
            found_links.append(href)
            link_text = a.get_text(separator=" ", strip=True)
            if link_text and len(link_text) > 3 and not maps_data["business_name"]:
                maps_data["business_name"] = link_text

    if found_links:
        maps_data["detected"] = True
        maps_data["links"] = found_links[:5]
        evidence_list.append(f"Google Maps presence detected ({len(found_links)} map link(s)/iframe(s))")

    return maps_data, verification_data, evidence_list


# =====================================================================
# 7. SOCIAL MEDIA LINKS & CONSISTENCY
# =====================================================================

def _extract_social_media(
    soup: Optional[BeautifulSoup],
    company_name: Optional[str]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Extract official social media profile links and check handle alignment."""
    social_list = []
    consistency_data = {"status": "not_available"}
    evidence_list = []

    if not soup:
        return social_list, consistency_data, evidence_list

    found_handles: Dict[str, Dict[str, Any]] = {}

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        for platform, pat in SOCIAL_PLATFORMS.items():
            m = re.search(pat, href, re.IGNORECASE)
            if m:
                handle = m.group(1).rstrip("/")
                if handle.lower() not in ("share", "intent", "sharer", "home", "search", "p"):
                    if platform not in found_handles:
                        found_handles[platform] = {
                            "platform": platform,
                            "url": href,
                            "handle": handle,
                            "source": "Webpage links / Footer",
                        }

    social_list = list(found_handles.values())

    if social_list:
        matched_count = 0
        if company_name:
            norm_comp = re.sub(r"[^a-zA-Z0-9]", "", company_name.lower())
            for s in social_list:
                norm_handle = re.sub(r"[^a-zA-Z0-9]", "", s["handle"].lower())
                if norm_comp in norm_handle or norm_handle in norm_comp:
                    matched_count += 1

        consistency_data = {
            "status": "consistent" if (company_name and matched_count > 0) else "profiles_detected",
            "platforms_found": [s["platform"] for s in social_list],
        }
        for s in social_list:
            evidence_list.append(f"Social media profile: {s['platform']} (@{s['handle']})")

    return social_list, consistency_data, evidence_list


# =====================================================================
# 8. BUSINESS, COMPANY & TAX (GST/VAT) REGISTRATION
# =====================================================================

def _extract_registration_and_tax(
    html_text: Optional[str],
    company_name: Optional[str]
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Extract corporate registration (CIN/CRN) and tax numbers (GSTIN/VAT).
    Returns (business_registration, business_reg_verification, tax_registration, company_registration, evidence_list).
    """
    business_reg = {
        "found_on_website": False,
        "company_name": company_name,
        "registration_number": None,
        "source": None,
    }
    business_reg_verification = {"status": "not_available"}
    tax_list = []
    company_reg = {
        "found": False,
        "number": None,
        "company_name": company_name,
        "source": None,
    }
    evidence_list = []

    if not html_text:
        return business_reg, business_reg_verification, tax_list, company_reg, evidence_list

    # 1. Indian CIN (Corporate Identity Number: 21 alphanumeric chars)
    cin_match = re.search(r"\b([LUu][0-9]{5}[A-Za-z]{2}[0-9]{4}[A-Za-z]{3}[0-9]{6})\b", html_text)
    if cin_match:
        cin_num = cin_match.group(1).upper()
        business_reg["found_on_website"] = True
        business_reg["registration_number"] = cin_num
        business_reg["source"] = "Corporate Disclosures / CIN"
        company_reg["found"] = True
        company_reg["number"] = cin_num
        company_reg["source"] = "Corporate Identity Number (CIN)"
        evidence_list.append(f"Corporate registration number extracted: CIN {cin_num}")

    # 2. General Company Registration / CRN
    if not company_reg["found"]:
        crn_match = re.search(r"\b(?:company\s+number|registration\s+(?:number|no|#)|incorporation\s+no|reg\s+no\.?)\s*[:#-]?\s*([A-Za-z0-9-]{6,14})\b", html_text, re.IGNORECASE)
        if crn_match:
            crn_num = crn_match.group(1).strip()
            business_reg["found_on_website"] = True
            business_reg["registration_number"] = crn_num
            business_reg["source"] = "Company Registration Section"
            company_reg["found"] = True
            company_reg["number"] = crn_num
            company_reg["source"] = "Company Registration Number"
            evidence_list.append(f"Company registration number extracted: {crn_num}")

    # 3. Indian GSTIN (15 characters)
    gstin_match = re.search(r"\b([0-9]{2}[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}[1-9A-Za-z]{1}[Zz][0-9A-Za-z]{1})\b", html_text)
    if gstin_match:
        gstin_num = gstin_match.group(1).upper()
        tax_list.append({
            "type": "GSTIN",
            "number": gstin_num,
            "format_valid": True,
            "source": "Footer / Tax Disclosures",
            "official_verification": "not_available",
        })
        evidence_list.append(f"GSTIN tax identifier extracted: {gstin_num} (Valid Indian GSTIN format)")

    # 4. European / UK VAT Number
    vat_match = re.search(r"\b(?:VAT|TVA|USt-IdNr|IVA)(?:\s+(?:number|no|reg|registration|id|tax|identification)\b)*\s*[:#-]?\s*([A-Za-z]{2}[0-9A-Za-z]{6,12})\b", html_text, re.IGNORECASE)
    if vat_match:
        vat_num = vat_match.group(1).strip().upper()
        if any(c.isdigit() for c in vat_num) and not any(t["number"] == vat_num for t in tax_list):
            tax_list.append({
                "type": "VAT",
                "number": vat_num,
                "format_valid": True,
                "source": "Tax / VAT Disclosures",
                "official_verification": "not_available",
            })
            evidence_list.append(f"VAT registration number extracted: {vat_num}")

    return business_reg, business_reg_verification, tax_list, company_reg, evidence_list


# =====================================================================
# 9. IDENTITY CROSS-CHECK
# =====================================================================

def _perform_identity_cross_check(
    business_name: Optional[str],
    emails: List[Dict[str, Any]],
    phones: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    socials: List[Dict[str, Any]],
    taxes: List[Dict[str, Any]],
    company_reg: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    """Cross-reference collected identity signals to evaluate identity consistency."""
    identity_consistency = {
        "status": "not_available",
        "conflicts": [],
    }
    evidence_list = []

    if not business_name and not emails and not addresses and not socials:
        return identity_consistency, evidence_list

    conflicts = []

    # Check for domain/email conflicts
    for em in emails:
        if em.get("domain_mismatch") and not em.get("is_free_provider"):
            conflicts.append({
                "source1": "business_identity",
                "value1": business_name or "Website Domain",
                "source2": "email_domain",
                "value2": em["email"],
                "note": "Email domain differs from website business identity",
            })

    if conflicts:
        identity_consistency["status"] = "inconsistent"
        identity_consistency["conflicts"] = conflicts
        evidence_list.append(f"Identity cross-check observed {len(conflicts)} point(s) of divergence across contact sources")
    elif business_name and (emails or phones or addresses or socials or company_reg.get("found")):
        identity_consistency["status"] = "consistent"
        evidence_list.append("Identity cross-check: Business identity shows consistent alignment across contact signals")
    else:
        identity_consistency["status"] = "partial"

    return identity_consistency, evidence_list


# =====================================================================
# MAIN ENTRYPOINT
# =====================================================================

def analyze_contact(url: str) -> Dict[str, Any]:
    """
    Main entry point for Agent 12: Contact Verification.
    Collects passive forensic evidence regarding business identity, email validity,
    phone normalization, physical addresses, maps presence, social links,
    corporate registration, and tax identifiers.
    """
    print("[Agent 12] Starting contact verification...")
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []
    forensic_evidence: List[str] = []

    if not url or not isinstance(url, str) or not url.strip():
        print("[Agent 12] Invalid URL provided.")
        extra = {
            "input": {
                "original_url": url,
                "final_url": None,
                "domain": None,
            },
            "business_identity": {"name": None, "source": "none", "confidence": "none"},
            "contact_page": {"found": False, "url": None},
            "email_addresses": [],
            "email_validation": [],
            "phone_numbers": [],
            "phone_validation": [],
            "physical_addresses": [],
            "address_consistency": {"status": "not_available", "consistent": False},
            "google_maps": {"detected": False, "links": [], "embeds": []},
            "google_maps_verification": {"status": "not_available"},
            "social_media": [],
            "social_media_consistency": {"status": "not_available"},
            "business_registration": {"found_on_website": False, "registration_number": None},
            "business_registration_verification": {"status": "not_available"},
            "tax_registration": [],
            "company_registration": {"found": False, "number": None},
            "identity_consistency": {"status": "not_available", "conflicts": []},
            "contact_availability": {
                "email": False, "phone": False, "physical_address": False,
                "google_maps": False, "social_media": False, "business_registration": False,
                "tax_registration": False
            },
            "structured_data": {"organization_found": False, "local_business_found": False, "contact_information_found": False},
            "checked_at": checked_at,
        }
        return build_agent_result(
            agent_identifier="A12",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=["URL is required and cannot be empty"],
            extra_fields=extra,
        )

    print("[Agent 12] Normalizing URL...")
    normalized_url = _normalize_url(url)
    submitted_domain = _extract_registered_domain(normalized_url)

    # Initialize session
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    print("[Agent 12] Fetching webpage...")
    html_text, final_url, soup, fetch_errors = _fetch_webpage_safe(normalized_url, session)
    if fetch_errors:
        errors.extend(fetch_errors)

    final_domain = _extract_registered_domain(final_url) if final_url else submitted_domain

    # Structured data parsing
    structured_summary, structured_entities = _extract_structured_data(soup)

    print("[Agent 12] Detecting business identity...")
    business_identity, biz_ev = _detect_business_identity(soup, structured_entities)
    forensic_evidence.extend(biz_ev)

    # Contact page discovery
    contact_page_info = _find_contact_page(soup, final_url or normalized_url)
    if contact_page_info["found"]:
        forensic_evidence.append(f"Dedicated contact/support page found at {contact_page_info['url']}")

    print("[Agent 12] Extracting email addresses...")
    emails_list, email_val_list, email_ev = _extract_and_validate_emails(soup, html_text, final_domain)
    forensic_evidence.extend(email_ev)

    print("[Agent 12] Extracting phone numbers...")
    phones_list, phone_val_list, phone_ev = _extract_and_validate_phones(soup, html_text)
    forensic_evidence.extend(phone_ev)

    print("[Agent 12] Extracting physical addresses...")
    addresses_list, addr_consistency, addr_ev = _extract_and_check_addresses(soup, html_text, structured_entities)
    forensic_evidence.extend(addr_ev)

    print("[Agent 12] Detecting Google Maps...")
    maps_data, maps_verification, maps_ev = _detect_google_maps(soup)
    forensic_evidence.extend(maps_ev)

    print("[Agent 12] Detecting social media...")
    social_list, social_consistency, social_ev = _extract_social_media(soup, business_identity.get("name"))
    forensic_evidence.extend(social_ev)

    print("[Agent 12] Searching registration information...")
    print("[Agent 12] Searching tax registration information...")
    business_reg, business_reg_verif, tax_list, company_reg, reg_ev = _extract_registration_and_tax(
        html_text, business_identity.get("name")
    )
    forensic_evidence.extend(reg_ev)

    print("[Agent 12] Performing identity consistency analysis...")
    identity_consistency, id_ev = _perform_identity_cross_check(
        business_identity.get("name"), emails_list, phones_list, addresses_list, social_list, tax_list, company_reg
    )
    forensic_evidence.extend(id_ev)

    # Contact availability matrix
    contact_availability = {
        "email": len(emails_list) > 0,
        "phone": len(phones_list) > 0,
        "physical_address": len(addresses_list) > 0,
        "google_maps": maps_data["detected"],
        "social_media": len(social_list) > 0,
        "business_registration": business_reg["found_on_website"],
        "tax_registration": len(tax_list) > 0,
    }

    print("[Agent 12] Generating evidence...")
    # Build structured evidence items
    structured_evidence = []

    # E12-01: Business Identity
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=1,
        finding="Declared business, company, or organizational entity identification",
        value=business_identity.get("name"),
        severity="info",
        source="DOM / JSON-LD Schema",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=business_identity
    ))

    # E12-02: Email Addresses
    has_free_email = any(e.get("is_free_provider") for e in emails_list)
    has_mismatch_email = any(e.get("domain_mismatch") for e in emails_list)
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=2,
        finding="Contact email addresses and domain alignment analysis",
        value=[e.get("email") for e in emails_list],
        severity="medium" if (has_free_email or has_mismatch_email) else "info",
        source="HTML Mailto / Regex",
        evidence_type="deterministic",
        evidence_strength=0.6 if (has_free_email or has_mismatch_email) else 0.1,
        metadata={"emails": emails_list, "validation": email_val_list}
    ))

    # E12-03: Phone Numbers
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=3,
        finding="Telephone contact channels and international number normalization",
        value=[p.get("number") for p in phones_list],
        severity="info",
        source="HTML Tel / Phonenumbers Parser",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata={"phones": phones_list, "validation": phone_val_list}
    ))

    # E12-04: Physical Address
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=4,
        finding="Physical corporate address extraction and location consistency",
        value=[a.get("address") for a in addresses_list],
        severity="info",
        source="Postal Address DOM Parser",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata={"addresses": addresses_list, "consistency": addr_consistency}
    ))

    # E12-05: Google Maps
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=5,
        finding="Embedded map and geographic business reference verification",
        value=maps_data.get("detected", False),
        severity="info",
        source="Iframe / Map Anchor Analysis",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata=maps_data
    ))

    # E12-06: Social Media Channels
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=6,
        finding="Official organizational social media channels and handle consistency",
        value=[s.get("platform") for s in social_list],
        severity="info",
        source="Social Profile Link Analysis",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata={"social_profiles": social_list, "consistency": social_consistency}
    ))

    # E12-07: Business Registration (CIN/CRN)
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=7,
        finding="Corporate registration identifiers (CIN / CRN / Company Number)",
        value=company_reg.get("number") if company_reg.get("found") else None,
        severity="info",
        source="Corporate Registry Disclosures",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata={"business_reg": business_reg, "company_reg": company_reg}
    ))

    # E12-08: Tax Registration (GSTIN/VAT)
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=8,
        finding="Fiscal and tax registration numbers (GSTIN / VAT)",
        value=[t.get("number") for t in tax_list],
        severity="info",
        source="Fiscal Authority Disclosure",
        evidence_type="external_source",
        evidence_strength=0.1,
        metadata={"taxes": tax_list}
    ))

    # E12-09: Cross-Check Consistency
    is_inconsistent = identity_consistency.get("status") == "inconsistent"
    structured_evidence.append(create_evidence_item(
        agent_id="A12",
        index=9,
        finding="Multi-source cross-channel business identity consistency and conflict analysis",
        value=identity_consistency.get("status", "unknown"),
        severity="high" if is_inconsistent else "info",
        source="Cross-Channel Corroboration Engine",
        evidence_type="inference",
        evidence_strength=0.8 if is_inconsistent else 0.1,
        metadata=identity_consistency
    ))

    print("[Agent 12] Contact verification completed.")

    data_payload = {
        "business_identity": business_identity,
        "contact_page": contact_page_info,
        "email_addresses": emails_list,
        "email_validation": email_val_list,
        "phone_numbers": phones_list,
        "phone_validation": phone_val_list,
        "physical_addresses": addresses_list,
        "address_consistency": addr_consistency,
        "google_maps": maps_data,
        "google_maps_verification": maps_verification,
        "social_media": social_list,
        "social_media_consistency": social_consistency,
        "business_registration": business_reg,
        "business_registration_verification": business_reg_verif,
        "tax_registration": tax_list,
        "company_registration": company_reg,
        "identity_consistency": identity_consistency,
        "contact_availability": contact_availability,
        "structured_data": structured_summary,
        "evidence": forensic_evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "final_url": final_url or normalized_url,
            "domain": final_domain or submitted_domain,
        },
        "business_identity": business_identity,
        "contact_page": contact_page_info,
        "email_addresses": emails_list,
        "email_validation": email_val_list,
        "phone_numbers": phones_list,
        "phone_validation": phone_val_list,
        "physical_addresses": addresses_list,
        "address_consistency": addr_consistency,
        "google_maps": maps_data,
        "google_maps_verification": maps_verification,
        "social_media": social_list,
        "social_media_consistency": social_consistency,
        "business_registration": business_reg,
        "business_registration_verification": business_reg_verif,
        "tax_registration": tax_list,
        "company_registration": company_reg,
        "identity_consistency": identity_consistency,
        "contact_availability": contact_availability,
        "structured_data": structured_summary,
        "evidence": forensic_evidence,
        "checked_at": checked_at,
    }

    return build_agent_result(
        agent_identifier="A12",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
