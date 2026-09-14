"""
Agent 15 — User Trust Signals Agent
Multi-Agent Digital Forensics System

Strictly an EVIDENCE COLLECTION module for gathering, organizing, and
corroborating publicly available user-generated trust, review, complaint,
community discussion, and official website testimonial evidence.

DO NOT calculate final Trust Score.
DO NOT decide 'Website is a scam' or 'Website is legitimate'.
DO NOT fabricate unavailable information.
"""

import datetime
import html
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse
import urllib3
import requests
from bs4 import BeautifulSoup

from services.evidence_schema import create_evidence_item, build_agent_result

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Suppress insecure request warnings for passive inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Network & Search Limits
MAX_HTML_SIZE = 2 * 1024 * 1024        # 2MB
REQUEST_TIMEOUT = 10                    # 10s general timeout
SEARCH_TIMEOUT = 8                      # 8s OSINT query timeout

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Standardized Complaint Categories
STANDARD_COMPLAINT_CATEGORIES = [
    "payment_issue",
    "refund_issue",
    "delivery_issue",
    "product_quality",
    "customer_support",
    "account_issue",
    "subscription_issue",
    "unauthorized_charge",
    "phishing_claim",
    "fake_product_claim",
    "non_delivery",
    "misleading_advertising",
    "privacy_concern",
    "security_concern",
    "other"
]

# Keywords mapped to standardized complaint categories
CATEGORY_KEYWORDS = {
    "non_delivery": [
        r"\b(?:never\s+arrived|not\s+delivered|did\s+not\s+receive|non[\s-]?delivery|package\s+lost|never\s+received|missing\s+order)\b"
    ],
    "refund_issue": [
        r"\b(?:refund|chargeback|money\s+back|refused\s+refund|return\s+policy|reimbursement|refund\s+denied|no\s+refund)\b"
    ],
    "payment_issue": [
        r"\b(?:payment|double\s+billed|charged\s+twice|billing\s+error|checkout\s+error|transaction\s+failed)\b"
    ],
    "unauthorized_charge": [
        r"\b(?:unauthorized\s+charge|stole\s+my\s+card|hidden\s+fee|unwanted\s+charge|unauthorized\s+transaction)\b"
    ],
    "subscription_issue": [
        r"\b(?:recurring\s+charge|cannot\s+cancel|subscription|auto[\s-]?renew|cancellation\s+problem)\b"
    ],
    "delivery_issue": [
        r"\b(?:late\s+delivery|shipping\s+delay|delayed\s+order|slow\s+shipping|transit\s+delay|damaged\s+in\s+shipping)\b"
    ],
    "product_quality": [
        r"\b(?:broken|defective|poor\s+quality|cheap\s+material|doesn't\s+work|junk|flawed|damaged\s+goods)\b"
    ],
    "fake_product_claim": [
        r"\b(?:fake\s+product|counterfeit|knock[\s-]?off|replica|bootleg|not\s+genuine|fraudulent\s+item)\b"
    ],
    "customer_support": [
        r"\b(?:customer\s+service|support|staff|service)\b.*?\b(?:unresponsive|ignored|ignore|no\s+reply|rude|ghosted|unhelpful|terrible|bad)\b",
        r"\b(?:ignore[ds]?\s+emails?|ignored|unresponsive|ghosted|rude\s+staff|never\s+answered)\b",
        r"\b(?:customer\s+support|customer\s+service)\b"
    ],
    "account_issue": [
        r"\b(?:account\s+locked|suspended\s+account|banned|cannot\s+login|login\s+failed|password\s+reset)\b"
    ],
    "phishing_claim": [
        r"\b(?:phishing|credential\s+theft|fake\s+login|stole\s+credentials|impersonator|mimic\s+site)\b"
    ],
    "misleading_advertising": [
        r"\b(?:misleading|false\s+advertising|bait\s+and\s+switch|deceptive|not\s+as\s+advertised|hidden\s+terms)\b"
    ],
    "privacy_concern": [
        r"\b(?:data\s+leak|privacy\s+violation|sold\s+my\s+email|spam\s+emails|tracking|personal\s+data)\b"
    ],
    "security_concern": [
        r"\b(?:malware|virus|trojan|insecure|hacked|breach|vulnerability)\b"
    ]
}

# General Sentiment Classification Keywords
SENTIMENT_PATTERNS = {
    "positive": [
        r"\b(?:great|excellent|amazing|loved|fantastic|reliable|fast\s+shipping|helpful|superb|awesome|recommend|smooth|trustworthy|legit|honest|5\s+stars?|five\s+stars?)\b"
    ],
    "negative": [
        r"\b(?:scam|fraud|fake|terrible|horrible|awful|rip[\s-]?off|thieves|stole|worst|avoid|garbage|useless|warning|nightmare|never\s+buy|cheat|beware|1\s+star|one\s+star)\b"
    ]
}


# =====================================================================
# 1. URL NORMALIZATION & IDENTITY EXTRACTION
# =====================================================================

def _normalize_url(url: str) -> str:
    """Normalize input URL with http/https scheme."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def _extract_domain_info(url: str) -> Dict[str, str]:
    """Extract registered domain, hostname, and brand candidate."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {"domain": "", "hostname": "", "brand": ""}
        
        domain = hostname
        brand = ""
        if _TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(hostname)
            reg_dom = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', '')
            if reg_dom:
                domain = reg_dom.lower()
            if ext.domain:
                brand = ext.domain.replace("-", " ").capitalize()
        else:
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                brand = parts[-2].replace("-", " ").capitalize()
            else:
                domain = hostname
                brand = hostname.capitalize()
                
        return {
            "domain": domain,
            "hostname": hostname,
            "brand": brand
        }
    except Exception:
        return {"domain": "", "hostname": "", "brand": ""}


def _generate_search_identities(domain: str, company_name: str, brand: str) -> List[str]:
    """Generate comprehensive search query variations."""
    queries = []
    seen = set()

    def add_q(q: str):
        q_clean = q.strip()
        if q_clean and q_clean.lower() not in seen:
            seen.add(q_clean.lower())
            queries.append(q_clean)

    if domain:
        add_q(domain)
        add_q(f"{domain} reviews")
        add_q(f"{domain} scam")
        add_q(f"{domain} complaints")
        add_q(f"{domain} fraud")
        add_q(f"{domain} experience")

    if company_name and company_name.lower() != domain.lower():
        add_q(f'"{company_name}" reviews')
        add_q(f'"{company_name}" scam')
        add_q(f'"{company_name}" complaints')
        add_q(f'"{company_name}" experience')

    if brand and brand.lower() not in (domain.lower(), company_name.lower()):
        add_q(f'"{brand}" reviews')
        add_q(f'"{brand}" scam')
        add_q(f'"{brand}" complaints')

    return queries


# =====================================================================
# 2. SENTIMENT & COMPLAINT CATEGORIZATION ENGINE
# =====================================================================

def classify_sentiment(text: str) -> str:
    """Classify sentiment as positive, negative, neutral, mixed, or unknown."""
    if not text or not isinstance(text, str):
        return "unknown"
    
    txt_lower = text.lower()

    # Check if text is a community question / neutral inquiry first
    if re.search(r"\b(?:does\s+anyone\s+know|is\s+(?:it|this|the)\s+(?:reliable|legit|safe|good|real|trustworthy)|has\s+anyone\s+tried|thoughts\s+on|can\s+anyone\s+confirm)\b", txt_lower):
        return "neutral"
    
    pos_matches = 0
    neg_matches = 0
    
    for pat in SENTIMENT_PATTERNS["positive"]:
        pos_matches += len(re.findall(pat, txt_lower))
        
    for pat in SENTIMENT_PATTERNS["negative"]:
        neg_matches += len(re.findall(pat, txt_lower))
        
    if pos_matches > 0 and neg_matches > 0:
        return "mixed"
    elif pos_matches > 0 and neg_matches == 0:
        return "positive"
    elif neg_matches > 0 and pos_matches == 0:
        return "negative"
    elif re.search(r"\b(?:does\s+anyone\s+know|is\s+it\s+legit|how\s+is|what\s+about|question)\b", txt_lower) or txt_lower.endswith("?"):
        return "neutral"
    return "neutral"


def classify_complaint_category(text: str) -> str:
    """Map text to a standardized complaint category."""
    if not text or not isinstance(text, str):
        return "other"
    
    txt_lower = text.lower()
    
    for category, patterns in CATEGORY_KEYWORDS.items():
        for pat in patterns:
            if re.search(pat, txt_lower):
                return category
                
    if re.search(r"\b(?:scam|fraud|fake|cheat|rip[\s-]?off|stole)\b", txt_lower):
        return "other"
        
    return "other"


# =====================================================================
# 3. TESTIMONIALS EXTRACTOR (FROM OFFICIAL WEBSITE HTML)
# =====================================================================

def extract_website_testimonials(html_text: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extract customer testimonials displayed directly on the target website.
    Marks them as SELF-PUBLISHED claims and verifies author presence.
    """
    if not html_text:
        return []
    
    testimonials: List[Dict[str, Any]] = []
    try:
        soup = BeautifulSoup(html_text[:MAX_HTML_SIZE], "html.parser")
        
        # Testimonial item candidate selectors (avoid matching outer lists directly)
        selectors = [
            ".testimonial", ".review-card", ".client-review",
            ".quote-card", "[data-testimonial]", ".swiper-slide blockquote",
            ".feedback-item", ".customer-story", ".endorsement"
        ]
        
        containers = []
        for sel in selectors:
            found = soup.select(sel)
            if found:
                containers.extend(found[:6])
                
        # Also look for blockquote tags if no dedicated containers found
        if not containers:
            containers = soup.find_all("blockquote")[:6]
            
        seen_texts = set()
        for c in containers:
            text = c.get_text(strip=True, separator=" ")
            if not text or len(text) < 15 or len(text) > 600:
                continue
            
            clean_snippet = text[:250].strip()
            if clean_snippet in seen_texts:
                continue
            seen_texts.add(clean_snippet)
            
            # Find name / author
            name_el = c.find(["strong", "h4", "h5", "cite", "span", "p"], class_=re.compile(r"name|author|client|user", re.I))
            name = name_el.get_text(strip=True) if name_el else None
            if not name:
                # Regex heuristic for author signature e.g. "- John Doe, CEO"
                sig_match = re.search(r"[-—–]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?:,\s*([^.]+))?", text)
                if sig_match:
                    name = sig_match.group(1)
                    
            # Find company / role
            company_el = c.find(["span", "small", "p"], class_=re.compile(r"role|company|title|position", re.I))
            company = company_el.get_text(strip=True) if company_el else None
            
            # Verification status assessment
            # Check if there is an external link (LinkedIn, external company)
            links = [a.get("href", "") for a in c.find_all("a", href=True)]
            has_linkedin = any("linkedin.com" in h.lower() for h in links)
            has_external_link = any(re.match(r"^https?://", h) and base_url not in h for h in links)
            
            if has_linkedin:
                verification = "verified"
            elif has_external_link:
                verification = "partially_verified"
            elif name:
                verification = "not_verified"
            else:
                verification = "not_available"
                
            testimonials.append({
                "testimonial": clean_snippet,
                "name": name or "Anonymous Customer",
                "company": company,
                "source": "Official website (Self-Published Claim)",
                "verification": verification,
                "source_url": base_url
            })
            
            if len(testimonials) >= 8:
                break
                
    except Exception:
        pass
    
    return testimonials


# =====================================================================
# 4. TRUSTPILOT EVIDENCE COLLECTOR
# =====================================================================

def check_trustpilot(domain: str) -> Dict[str, Any]:
    """
    Inspect public Trustpilot page for domain.
    Extract rating out of 5, review count, rating distribution, recent review summaries.
    """
    result = {
        "available": False,
        "profile_url": None,
        "company_name": None,
        "rating": None,
        "review_count": None,
        "rating_distribution": {},
        "recent_reviews": [],
        "positive_patterns": [],
        "negative_patterns": [],
        "reviews": []
    }
    
    if not domain:
        return result
        
    profile_url = f"https://www.trustpilot.com/review/{domain}"
    
    try:
        resp = requests.get(
            profile_url,
            headers=DEFAULT_HEADERS,
            timeout=SEARCH_TIMEOUT,
            verify=False
        )
        
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text[:MAX_HTML_SIZE], "html.parser")
            
            # Check if domain not found or 404
            if "Page not found" in soup.text or "not found on Trustpilot" in soup.text:
                return result
                
            result["available"] = True
            result["profile_url"] = profile_url
            
            # Company Name
            name_el = soup.find(["span", "h1"], class_=re.compile(r"title|business-unit-name|header", re.I))
            if name_el:
                result["company_name"] = name_el.get_text(strip=True)
                
            # TrustScore / Rating
            # Look for JSON-LD data or rating score elements
            scripts = soup.find_all("script", type="application/ld+json")
            for sc in scripts:
                try:
                    data = json.loads(sc.string or "")
                    if isinstance(data, dict):
                        agg = data.get("aggregateRating")
                        if agg:
                            result["rating"] = float(agg.get("ratingValue", 0))
                            result["review_count"] = int(agg.get("reviewCount", 0))
                            break
                except Exception:
                    pass
                    
            if result["rating"] is None:
                rating_el = soup.find(["span", "p"], class_=re.compile(r"trustscore|score|rating", re.I))
                if rating_el:
                    m = re.search(r"(\d+(?:\.\d+)?)", rating_el.get_text(strip=True))
                    if m:
                        try:
                            result["rating"] = float(m.group(1))
                        except Exception:
                            pass
                            
            if result["review_count"] is None:
                rc_el = soup.find(["span", "p"], class_=re.compile(r"review-count|count|total", re.I))
                if rc_el:
                    m = re.search(r"([\d,]+)", rc_el.get_text(strip=True))
                    if m:
                        try:
                            result["review_count"] = int(m.group(1).replace(",", ""))
                        except Exception:
                            pass
                            
            # Parse individual review cards
            review_cards = soup.find_all(["div", "article"], class_=re.compile(r"review-card|reviewArticle|styles_reviewCard", re.I))
            for card in review_cards[:10]:
                reviewer_el = card.find(["span", "aside", "a"], class_=re.compile(r"consumer-name|displayName|consumerName", re.I))
                reviewer_name = reviewer_el.get_text(strip=True) if reviewer_el else "Trustpilot User"
                
                title_el = card.find(["h2", "h3", "a"], class_=re.compile(r"review-title|typography|heading", re.I))
                review_title = title_el.get_text(strip=True) if title_el else ""
                
                body_el = card.find(["p", "div"], class_=re.compile(r"review-content|content__text|reviewText", re.I))
                review_text = body_el.get_text(strip=True) if body_el else ""
                
                # Rating image or attribute
                star_rating = None
                star_el = card.find(["img", "div"], alt=re.compile(r"Rated (\d) out of 5", re.I))
                if star_el and star_el.get("alt"):
                    m_star = re.search(r"Rated (\d) out of 5", star_el["alt"], re.I)
                    if m_star:
                        star_rating = int(m_star.group(1))
                elif card.find("div", attrs={"data-service-review-rating": True}):
                    try:
                        star_rating = int(card["data-service-review-rating"])
                    except Exception:
                        pass
                        
                date_el = card.find(["time", "span"], class_=re.compile(r"date|time", re.I))
                review_date = date_el.get_text(strip=True) if date_el else None
                if date_el and date_el.get("datetime"):
                    review_date = date_el["datetime"][:10]
                    
                combined_text = f"{review_title} {review_text}".strip()
                if not combined_text:
                    continue
                    
                sent = "positive" if (star_rating and star_rating >= 4) else ("negative" if (star_rating and star_rating <= 2) else classify_sentiment(combined_text))
                cat = classify_complaint_category(combined_text)
                
                review_entry = {
                    "source": "Trustpilot",
                    "reviewer_name": reviewer_name,
                    "date": review_date or "recent",
                    "rating": star_rating,
                    "title": review_title or "Trustpilot Review",
                    "text": review_text[:280],
                    "sentiment": sent,
                    "category": cat,
                    "source_url": profile_url,
                    "confidence": "medium"
                }
                
                result["reviews"].append(review_entry)
                result["recent_reviews"].append(review_entry)
                
                if sent == "positive":
                    result["positive_patterns"].append(review_title or review_text[:80])
                elif sent == "negative":
                    result["negative_patterns"].append(review_title or review_text[:80])
                    
    except Exception:
        pass
        
    return result


# =====================================================================
# 5. GOOGLE BUSINESS & REVIEWS COLLECTOR
# =====================================================================

def check_google_reviews(domain: str, company_name: str) -> Dict[str, Any]:
    """
    Search for publicly accessible Google Business / Google Reviews profiles.
    Verifies entity match to prevent merging similarly named entities.
    """
    result = {
        "available": False,
        "business_name": None,
        "rating": None,
        "review_count": None,
        "location": None,
        "profile_url": None,
        "entity_match": "uncertain",
        "positive_themes": [],
        "negative_themes": [],
        "reviews": []
    }
    
    if not domain and not company_name:
        return result
        
    # Search Google business index via passive public engine query
    query = f'"{domain}" OR "{company_name}" site:google.com/maps OR site:business.google.com'
    search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
    
    try:
        resp = requests.get(
            search_url,
            headers=DEFAULT_HEADERS,
            timeout=SEARCH_TIMEOUT,
            verify=False
        )
        
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text[:MAX_HTML_SIZE], "html.parser")
            results = soup.find_all("div", class_="result")
            
            for res in results[:5]:
                snippet_el = res.find("a", class_="result__snippet")
                snippet = snippet_el.get_text(strip=True) if snippet_el else ""
                title_el = res.find("a", class_="result__title")
                title = title_el.get_text(strip=True) if title_el else ""
                url_el = res.find("a", class_="result__url")
                g_url = url_el.get("href", "").strip() if url_el else ""
                
                if "google.com" in g_url or "Rating:" in snippet or "reviews" in snippet.lower():
                    # Rating extraction e.g. "Rating: 4.2 · ‎540 reviews"
                    m_rating = re.search(r"Rating:\s*(\d+(?:\.\d+)?)", snippet, re.I)
                    m_count = re.search(r"([\d,]+)\s+reviews", snippet, re.I)
                    
                    if m_rating or m_count:
                        result["available"] = True
                        result["profile_url"] = g_url or f"https://www.google.com/maps/search/{quote(company_name or domain)}"
                        result["business_name"] = company_name or domain
                        
                        if m_rating:
                            result["rating"] = float(m_rating.group(1))
                        if m_count:
                            result["review_count"] = int(m_count.group(1).replace(",", ""))
                            
                        # Extract location heuristic
                        loc_match = re.search(r"(?:in|at|located in)\s+([A-Z][a-zA-Z\s,]+)", snippet)
                        if loc_match:
                            result["location"] = loc_match.group(1).strip()
                            
                        # Entity match check
                        if domain.lower() in snippet.lower() or domain.lower() in title.lower():
                            result["entity_match"] = "confirmed"
                        elif company_name and company_name.lower() in snippet.lower():
                            result["entity_match"] = "probable"
                        else:
                            result["entity_match"] = "uncertain"
                            
                        # Themes
                        if result["rating"] and result["rating"] >= 4.0:
                            result["positive_themes"].append("High average customer satisfaction on Google profile")
                        elif result["rating"] and result["rating"] <= 2.5:
                            result["negative_themes"].append("Substantially low Google rating with customer grievances")
                            
                        break
                        
    except Exception:
        pass
        
    return result


# =====================================================================
# 6. REDDIT DISCUSSIONS COLLECTOR
# =====================================================================

def search_reddit_discussions(domain: str, company_name: str) -> Dict[str, Any]:
    """
    Search publicly accessible Reddit discussions regarding domain/company experiences.
    Formats observations as user reports without asserting them as absolute facts.
    """
    result = {
        "available": False,
        "discussions_found": 0,
        "discussions": [],
        "positive_count": 0,
        "negative_count": 0,
        "neutral_count": 0
    }
    
    if not domain and not company_name:
        return result
        
    search_terms = [domain]
    if company_name and company_name.lower() != domain.lower():
        search_terms.append(company_name)
        
    for term in search_terms[:2]:
        reddit_api_url = f"https://www.reddit.com/search.json?q={quote(term)}&limit=15&sort=relevance"
        try:
            resp = requests.get(
                reddit_api_url,
                headers={"User-Agent": "AntigravityForensicsBot/1.0 (Passive Research)"},
                timeout=SEARCH_TIMEOUT
            )
            
            if resp.status_code == 200:
                data = resp.json()
                children = data.get("data", {}).get("children", [])
                
                for item in children:
                    post = item.get("data", {})
                    title = post.get("title", "")
                    selftext = post.get("selftext", "")
                    subreddit = f"r/{post.get('subreddit', 'unknown')}"
                    permalink = f"https://www.reddit.com{post.get('permalink', '')}"
                    created_utc = post.get("created_utc", 0)
                    
                    post_date = "unknown"
                    if created_utc:
                        try:
                            post_date = datetime.datetime.fromtimestamp(created_utc, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
                        except Exception:
                            pass
                            
                    full_content = f"{title} {selftext}"
                    sentiment = classify_sentiment(full_content)
                    category = classify_complaint_category(full_content)
                    
                    themes = []
                    if category != "other":
                        themes.append(category.replace("_", " "))
                    if sentiment == "negative":
                        themes.append("user reported negative experience")
                    elif sentiment == "positive":
                        themes.append("user reported positive experience")
                    else:
                        themes.append("community inquiry/discussion")
                        
                    discussion_entry = {
                        "subreddit": subreddit,
                        "date": post_date,
                        "title": title[:180],
                        "sentiment": sentiment,
                        "category": category,
                        "themes": themes,
                        "url": permalink,
                        "confidence": "medium",
                        "claim": f"User in {subreddit} reported: '{title[:120]}'"
                    }
                    
                    # Avoid duplicates
                    if not any(d["url"] == permalink for d in result["discussions"]):
                        result["discussions"].append(discussion_entry)
                        result["available"] = True
                        if sentiment == "positive":
                            result["positive_count"] += 1
                        elif sentiment == "negative":
                            result["negative_count"] += 1
                        else:
                            result["neutral_count"] += 1
                            
                    if len(result["discussions"]) >= 15:
                        break
        except Exception:
            pass
            
    result["discussions_found"] = len(result["discussions"])
    return result


# =====================================================================
# 7. SCAM COMPLAINTS & PUBLIC COMPLAINT FORUMS
# =====================================================================

def search_scam_complaints_and_forums(domain: str, company_name: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Search public search engines and consumer complaint forums for scam grievances,
    categorized issues, and community complaint threads.
    """
    scam_complaints: List[Dict[str, Any]] = []
    complaint_forums: List[Dict[str, Any]] = []
    
    if not domain and not company_name:
        return scam_complaints, complaint_forums
        
    queries = [
        f"{domain} scam complaints",
        f"{domain} fraud refund",
        f'"{company_name}" scam complaint' if company_name else f"{domain} consumer complaints"
    ]
    
    seen_urls = set()
    
    for q in queries[:2]:
        search_url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
        try:
            resp = requests.get(
                search_url,
                headers=DEFAULT_HEADERS,
                timeout=SEARCH_TIMEOUT,
                verify=False
            )
            
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text[:MAX_HTML_SIZE], "html.parser")
                results = soup.find_all("div", class_="result")
                
                for res in results[:6]:
                    link_el = res.find("a", class_="result__url")
                    title_el = res.find("a", class_="result__title")
                    snippet_el = res.find("a", class_="result__snippet")
                    
                    url_str = link_el.get("href", "").strip() if link_el else ""
                    if not url_str or url_str in seen_urls:
                        continue
                    seen_urls.add(url_str)
                    
                    title = title_el.get_text(strip=True) if title_el else ""
                    snippet = snippet_el.get_text(strip=True) if snippet_el else ""
                    full_txt = f"{title} {snippet}"
                    
                    # Determine platform
                    parsed_link = urlparse(url_str)
                    netloc = (parsed_link.netloc or "").lower()
                    
                    category = classify_complaint_category(full_txt)
                    sentiment = classify_sentiment(full_txt)
                    
                    is_complaint_site = any(kw in netloc for kw in [
                        "complaint", "scam", "pissedconsumer", "ripoffreport",
                        "trustpilot", "sitejabber", "bbb.org", "complaintsboard"
                    ])
                    
                    is_scam_allegation = bool(re.search(r"\b(?:scam|fraud|fake|rip[\s-]?off|stole|complaint)\b", full_txt, re.I))
                    
                    entry = {
                        "source": netloc or "Public Search Index",
                        "platform": netloc or "Web Forum",
                        "title": title[:160],
                        "date": "recent",
                        "complaint_summary": f"Public page contains claim: '{snippet[:200]}'",
                        "summary": snippet[:220],
                        "category": category,
                        "sentiment": sentiment,
                        "url": url_str,
                        "confidence": "medium" if is_complaint_site else "low"
                    }
                    
                    if is_complaint_site:
                        complaint_forums.append(entry)
                    if is_scam_allegation:
                        scam_complaints.append(entry)
                        
                    if len(scam_complaints) >= 10 and len(complaint_forums) >= 10:
                        break
                        
        except Exception:
            pass
            
    return scam_complaints, complaint_forums


# =====================================================================
# 8. PATTERN CORROBORATION & RECURRING COMPLAINT DETECTION
# =====================================================================

def detect_recurring_patterns(all_evidence: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Identify recurring complaint categories and cross-source corroboration patterns.
    """
    category_sources: Dict[str, Set[str]] = {}
    category_counts: Dict[str, int] = {}
    
    for ev in all_evidence:
        cat = ev.get("category")
        src = ev.get("source") or "unknown"
        sentiment = ev.get("sentiment")
        
        if cat and cat != "other" and sentiment in ("negative", "mixed"):
            category_counts[cat] = category_counts.get(cat, 0) + 1
            if cat not in category_sources:
                category_sources[cat] = set()
            category_sources[cat].add(src)
            
    recurring_complaints = []
    cross_source_patterns = []
    
    for cat, count in category_counts.items():
        sources_list = sorted(list(category_sources.get(cat, set())))
        unique_src_count = len(sources_list)
        is_corroborated = unique_src_count > 1
        
        pattern_data = {
            "pattern": cat,
            "occurrences": count,
            "sources": sources_list,
            "unique_sources": unique_src_count,
            "total_reports": count,
            "cross_source_corroboration": is_corroborated,
            "confidence": "high" if (is_corroborated and count >= 3) else ("medium" if count >= 2 else "low")
        }
        
        if count >= 2:
            recurring_complaints.append(pattern_data)
            
        if is_corroborated:
            cross_source_patterns.append(pattern_data)
            
    return recurring_complaints, cross_source_patterns


# =====================================================================
# 9. REVIEW ANOMALIES & AUTHENTICITY DETECTION
# =====================================================================

def detect_review_anomalies(reviews: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect duplicated wording, identical review snippets, or burst patterns.
    Marks findings as 'possible_review_anomaly' rather than definitive fraud.
    """
    anomalies = []
    if not reviews or len(reviews) < 3:
        return anomalies
        
    seen_texts: Dict[str, int] = {}
    for r in reviews:
        txt = (r.get("text") or r.get("title") or "").strip().lower()
        if len(txt) > 20:
            # Normalize whitespace
            norm = re.sub(r"\s+", " ", txt)
            seen_texts[norm] = seen_texts.get(norm, 0) + 1
            
    for norm_txt, cnt in seen_texts.items():
        if cnt >= 2:
            anomalies.append({
                "type": "possible_review_anomaly",
                "observation": f"Identical or highly similar review wording was detected across {cnt} review submissions.",
                "snippet": norm_txt[:120],
                "confidence": "medium"
            })
            
    return anomalies


# =====================================================================
# 10. TIMELINE & RECENCY BUILDER
# =====================================================================

def build_evidence_timeline(all_evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build chronological timeline of user feedback and reputation events.
    """
    period_buckets: Dict[str, List[Dict[str, Any]]] = {}
    
    for ev in all_evidence:
        dt_str = ev.get("date") or "undated"
        year_match = re.search(r"\b(20[12]\d)\b", dt_str)
        period = year_match.group(1) if year_match else "recent"
        
        if period not in period_buckets:
            period_buckets[period] = []
        period_buckets[period].append(ev)
        
    timeline = []
    for period in sorted(period_buckets.keys(), reverse=True):
        items = period_buckets[period]
        pos = sum(1 for i in items if i.get("sentiment") == "positive")
        neg = sum(1 for i in items if i.get("sentiment") == "negative")
        
        if pos > neg and neg == 0:
            summary = f"Predominantly positive user reports ({pos} positive items recorded)"
        elif neg > pos:
            summary = f"Complaints and grievances recorded ({neg} negative user reports)"
        elif pos > 0 and neg > 0:
            summary = f"Mixed user feedback ({pos} positive, {neg} negative reports)"
        else:
            summary = f"{len(items)} public discussions / community mentions recorded"
            
        timeline.append({
            "period": period,
            "summary": summary,
            "total_items": len(items),
            "positive_count": pos,
            "negative_count": neg
        })
        
    return timeline


# =====================================================================
# 11. MAIN ENTRYPOINT: analyze_user_trust(url)
# =====================================================================

def analyze_user_trust(url: str) -> Dict[str, Any]:
    """
    Main forensic entrypoint for Agent 15: User Trust Signals Agent.
    Collects user reviews, Trustpilot profiles, Google reviews, Reddit discussions,
    scam complaints, complaint forums, official website testimonials, and recurring patterns.
    """
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[Dict[str, str]] = []
    
    # 1. Normalize Input
    norm_url = _normalize_url(url)
    if not norm_url:
        extra = {
            "input": {"original_url": url, "domain": "", "company_name": ""},
            "trustpilot": {"available": False, "profile_url": None, "rating": None, "review_count": None, "rating_distribution": {}, "reviews": []},
            "google_reviews": {"available": False, "business_name": None, "rating": None, "review_count": None, "location": None, "reviews": []},
            "reddit": {"available": False, "discussions": []},
            "user_reviews": [],
            "scam_complaints": [],
            "customer_testimonials": [],
            "complaint_forums": [],
            "review_summary": {"total": 0, "positive": 0, "negative": 0, "neutral": 0, "mixed": 0, "unknown": 0},
            "recurring_complaints": [],
            "positive_signals": [],
            "negative_signals": [],
            "cross_source_patterns": [],
            "review_anomalies": [],
            "timeline": [],
            "error": "URL is required and must be a valid string.",
            "checked_at": checked_at
        }
        return build_agent_result(
            agent_identifier="A15",
            target=url or "",
            status="error",
            data=extra,
            evidence=[],
            errors=[{"source": "Input", "error": "Invalid URL provided."}],
            extra_fields=extra,
        )
        
    dom_info = _extract_domain_info(norm_url)
    domain = dom_info["domain"]
    hostname = dom_info["hostname"]
    company_name = dom_info["brand"]
    
    # 2. Fetch target website HTML to extract company name, title, and customer testimonials
    html_content = ""
    try:
        resp = requests.get(
            norm_url,
            headers=DEFAULT_HEADERS,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        if resp.status_code == 200:
            html_content = resp.text
            soup = BeautifulSoup(html_content[:MAX_HTML_SIZE], "html.parser")
            if soup.title and soup.title.string:
                title_clean = soup.title.string.strip()
                # If title contains brand like "Brand: Subtitle", extract brand
                if " - " in title_clean:
                    candidate = title_clean.split(" - ")[0].strip()
                    if candidate and len(candidate) < 40:
                        company_name = candidate
                elif " | " in title_clean:
                    candidate = title_clean.split(" | ")[0].strip()
                    if candidate and len(candidate) < 40:
                        company_name = candidate
    except Exception as e:
        errors.append({"source": "Target Website", "error": f"Could not fetch target page HTML: {str(e)}"})
        
    # 3. Collect Customer Testimonials on Official Website
    customer_testimonials = extract_website_testimonials(html_content, norm_url)
    
    # 4. Collect Trustpilot Profile & Reviews
    trustpilot_data = {"available": False, "profile_url": None, "rating": None, "review_count": None, "rating_distribution": {}, "reviews": []}
    try:
        trustpilot_data = check_trustpilot(domain)
    except Exception as e:
        errors.append({"source": "Trustpilot", "error": f"Trustpilot inspection failed: {str(e)}"})
        
    # 5. Collect Google Reviews / Business Data
    google_data = {"available": False, "business_name": None, "rating": None, "review_count": None, "location": None, "reviews": []}
    try:
        google_data = check_google_reviews(domain, company_name)
    except Exception as e:
        errors.append({"source": "Google Reviews", "error": f"Google review inspection failed: {str(e)}"})
        
    # 6. Collect Reddit Discussions
    reddit_data = {"available": False, "discussions": []}
    try:
        reddit_data = search_reddit_discussions(domain, company_name)
    except Exception as e:
        errors.append({"source": "Reddit", "error": f"Reddit discussion search failed: {str(e)}"})
        
    # 7. Collect Scam Complaints and Complaint Forums
    scam_complaints = []
    complaint_forums = []
    try:
        scam_complaints, complaint_forums = search_scam_complaints_and_forums(domain, company_name)
    except Exception as e:
        errors.append({"source": "Complaint Forums", "error": f"Forum search failed: {str(e)}"})
        
    # 8. Aggregate All User Reviews
    user_reviews: List[Dict[str, Any]] = []
    if trustpilot_data.get("reviews"):
        user_reviews.extend(trustpilot_data["reviews"])
    if google_data.get("reviews"):
        user_reviews.extend(google_data["reviews"])
        
    # 9. Build Standardized Evidence Observations List
    evidence: List[Dict[str, Any]] = []
    
    # Trustpilot Evidence
    if trustpilot_data.get("available"):
        evidence.append({
            "evidence_type": "trustpilot_profile",
            "source": "Trustpilot",
            "date": "current",
            "observation": f"Public Trustpilot profile found with rating {trustpilot_data.get('rating')}/5 across {trustpilot_data.get('review_count')} reviews.",
            "category": "reputation_profile",
            "sentiment": "positive" if (trustpilot_data.get("rating") and trustpilot_data["rating"] >= 3.5) else "negative",
            "entity_match": "confirmed",
            "confidence": "high",
            "source_url": trustpilot_data.get("profile_url")
        })
        
    for r in trustpilot_data.get("reviews", []):
        evidence.append({
            "evidence_type": "user_review",
            "source": "Trustpilot",
            "date": r.get("date", "recent"),
            "observation": f"Trustpilot review: '{r.get('title')}' - {r.get('text')[:120]}",
            "category": r.get("category", "other"),
            "sentiment": r.get("sentiment", "neutral"),
            "entity_match": "confirmed",
            "confidence": r.get("confidence", "medium"),
            "source_url": r.get("source_url")
        })
        
    # Google Reviews Evidence
    if google_data.get("available"):
        evidence.append({
            "evidence_type": "google_business_profile",
            "source": "Google Business",
            "date": "current",
            "observation": f"Google profile found for '{google_data.get('business_name')}' with rating {google_data.get('rating')}/5 ({google_data.get('review_count')} reviews).",
            "category": "reputation_profile",
            "sentiment": "positive" if (google_data.get("rating") and google_data["rating"] >= 3.5) else "negative",
            "entity_match": google_data.get("entity_match", "uncertain"),
            "confidence": "high" if google_data.get("entity_match") == "confirmed" else "medium",
            "source_url": google_data.get("profile_url")
        })
        
    # Reddit Evidence
    for rd in reddit_data.get("discussions", []):
        evidence.append({
            "evidence_type": "community_discussion",
            "source": "Reddit",
            "date": rd.get("date", "recent"),
            "observation": rd.get("claim", f"User discussed: {rd.get('title')}"),
            "category": rd.get("category", "other"),
            "sentiment": rd.get("sentiment", "neutral"),
            "entity_match": "probable",
            "confidence": rd.get("confidence", "medium"),
            "source_url": rd.get("url")
        })
        
    # Scam Complaints Evidence
    for sc in scam_complaints:
        evidence.append({
            "evidence_type": "user_complaint",
            "source": sc.get("source", "Public Index"),
            "date": sc.get("date", "recent"),
            "observation": sc.get("complaint_summary", sc.get("title", "")),
            "category": sc.get("category", "other"),
            "sentiment": sc.get("sentiment", "negative"),
            "entity_match": "probable",
            "confidence": sc.get("confidence", "low"),
            "source_url": sc.get("url")
        })
        
    # Complaint Forums Evidence
    for cf in complaint_forums:
        evidence.append({
            "evidence_type": "forum_complaint",
            "source": cf.get("platform", "Complaint Forum"),
            "date": cf.get("date", "recent"),
            "observation": f"Public complaint forum entry: '{cf.get('title')}'",
            "category": cf.get("category", "other"),
            "sentiment": cf.get("sentiment", "negative"),
            "entity_match": "probable",
            "confidence": cf.get("confidence", "medium"),
            "source_url": cf.get("url")
        })
        
    # Customer Testimonials (Self-published)
    for ct in customer_testimonials:
        evidence.append({
            "evidence_type": "self_published_testimonial",
            "source": "Official Website Testimonial",
            "date": "current",
            "observation": f"Self-published quote by '{ct.get('name')}': '{ct.get('testimonial')[:120]}'",
            "category": "product_quality",
            "sentiment": "positive",
            "entity_match": "confirmed",
            "confidence": "medium" if ct.get("verification") == "verified" else "low",
            "source_url": ct.get("source_url")
        })
        
    # 10. Volume Summary Calculation
    total_ev = len(evidence)
    pos_count = sum(1 for e in evidence if e.get("sentiment") == "positive")
    neg_count = sum(1 for e in evidence if e.get("sentiment") == "negative")
    neu_count = sum(1 for e in evidence if e.get("sentiment") == "neutral")
    mix_count = sum(1 for e in evidence if e.get("sentiment") == "mixed")
    unk_count = total_ev - (pos_count + neg_count + neu_count + mix_count)
    
    review_summary = {
        "total": total_ev,
        "positive": pos_count,
        "negative": neg_count,
        "neutral": neu_count,
        "mixed": mix_count,
        "unknown": unk_count
    }
    
    # 11. Positive & Negative Signal Summaries
    positive_signals = []
    tp_rating = trustpilot_data.get("rating")
    if trustpilot_data.get("available") and tp_rating is not None and tp_rating >= 4.0:
        positive_signals.append(f"Trustpilot rating is positive at {tp_rating}/5 with {trustpilot_data.get('review_count')} reviews.")
    gr_rating = google_data.get("rating")
    if google_data.get("available") and gr_rating is not None and gr_rating >= 4.0:
        positive_signals.append(f"Google Business profile reflects a positive rating of {gr_rating}/5.")
    if pos_count > 0:
        positive_signals.append(f"Found {pos_count} positive user/community reports across public sources.")
    if customer_testimonials:
        positive_signals.append(f"Target website displays {len(customer_testimonials)} customer testimonials.")
        
    negative_signals = []
    if trustpilot_data.get("available") and tp_rating is not None and tp_rating <= 2.5:
        negative_signals.append(f"Trustpilot rating is unfavorable at {tp_rating}/5.")
    if google_data.get("available") and gr_rating is not None and gr_rating <= 2.5:
        negative_signals.append(f"Google profile shows low average review rating of {gr_rating}/5.")
    if neg_count > 0:
        negative_signals.append(f"Found {neg_count} public negative reviews, complaints, or grievance reports.")
    if scam_complaints:
        negative_signals.append(f"Detected {len(scam_complaints)} public pages or posts containing scam/fraud allegations.")
        
    # 12. Recurring Complaints & Cross-Source Corroboration
    recurring_complaints, cross_source_patterns = detect_recurring_patterns(evidence)
    
    # 13. Review Anomalies Detection
    review_anomalies = detect_review_anomalies(user_reviews)
    
    # 14. Timeline Construction
    timeline = build_evidence_timeline(evidence)

    # 15. Structured Evidence Items for Common Schema
    structured_evidence = []

    # E15-01: Trustpilot Profile
    tp_avail = trustpilot_data.get("available", False)
    tp_bad = tp_avail and tp_rating is not None and tp_rating <= 2.5
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=1,
        finding="Trustpilot merchant rating profile",
        value=f"{tp_rating}/5 ({trustpilot_data.get('review_count', 0)} reviews)" if tp_avail else "Not Available",
        severity="high" if tp_bad else "info",
        source="Trustpilot Public Profile",
        evidence_type="external_source",
        evidence_strength=0.8 if tp_bad else 0.1,
        metadata=trustpilot_data
    ))

    # E15-02: Google Reviews
    gr_avail = google_data.get("available", False)
    gr_bad = gr_avail and gr_rating is not None and gr_rating <= 2.5
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=2,
        finding="Google Business rating and customer reviews",
        value=f"{gr_rating}/5 ({google_data.get('review_count', 0)} reviews)" if gr_avail else "Not Available",
        severity="high" if gr_bad else "info",
        source="Google Business Reviews",
        evidence_type="external_source",
        evidence_strength=0.8 if gr_bad else 0.1,
        metadata=google_data
    ))

    # E15-03: Reddit Community Feedback
    rd_discs = reddit_data.get("discussions", [])
    rd_bad = any(d.get("sentiment") == "negative" for d in rd_discs)
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=3,
        finding="Reddit user discussions and community threads",
        value=len(rd_discs),
        severity="medium" if rd_bad else "info",
        source="Reddit Search",
        evidence_type="external_source",
        evidence_strength=0.6 if rd_bad else 0.1,
        metadata=reddit_data
    ))

    # E15-04: User Reviews Aggregation
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=4,
        finding="Public review aggregation and sentiment distribution",
        value=review_summary,
        severity="high" if neg_count > pos_count else "info",
        source="Aggregated Consumer Reviews",
        evidence_type="external_source",
        evidence_strength=0.75 if neg_count > pos_count else 0.1,
        metadata={"summary": review_summary, "anomalies": review_anomalies}
    ))

    # E15-05: Scam Complaints
    has_scam_c = len(scam_complaints) > 0
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=5,
        finding="Public scam and consumer fraud complaint records",
        value=len(scam_complaints),
        severity="critical" if has_scam_c else "info",
        source="Consumer Protection / Complaint Sites",
        evidence_type="threat_intelligence",
        evidence_strength=0.9 if has_scam_c else 0.05,
        metadata={"complaints": scam_complaints}
    ))

    # E15-06: Customer Testimonials
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=6,
        finding="Official website customer testimonials and verification",
        value=len(customer_testimonials),
        severity="info",
        source="Target Website Testimonial Inspection",
        evidence_type="deterministic",
        evidence_strength=0.1,
        metadata={"testimonials": customer_testimonials}
    ))

    # E15-07: Public Grievance Forums
    has_forums = len(complaint_forums) > 0
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=7,
        finding="Consumer forum grievance and dispute reports",
        value=len(complaint_forums),
        severity="high" if has_forums else "info",
        source="Public Dispute Forums",
        evidence_type="external_source",
        evidence_strength=0.75 if has_forums else 0.05,
        metadata={"forums": complaint_forums}
    ))

    # E15-08: Cross-Source Corroborated Patterns
    has_cross = len(cross_source_patterns) > 0
    structured_evidence.append(create_evidence_item(
        agent_id="A15",
        index=8,
        finding="Cross-source corroborated complaint patterns",
        value=[p.get("pattern") for p in cross_source_patterns],
        severity="critical" if has_cross else "info",
        source="Multi-Source Corroboration Engine",
        evidence_type="inference",
        evidence_strength=0.9 if has_cross else 0.1,
        metadata={"cross_source_patterns": cross_source_patterns, "recurring": recurring_complaints}
    ))

    data_payload = {
        "trustpilot": trustpilot_data,
        "google_reviews": google_data,
        "reddit": reddit_data,
        "user_reviews": user_reviews,
        "scam_complaints": scam_complaints,
        "customer_testimonials": customer_testimonials,
        "complaint_forums": complaint_forums,
        "review_summary": review_summary,
        "recurring_complaints": recurring_complaints,
        "positive_signals": positive_signals,
        "negative_signals": negative_signals,
        "cross_source_patterns": cross_source_patterns,
        "review_anomalies": review_anomalies,
        "timeline": timeline,
        "evidence": evidence,
    }

    extra_fields = {
        "input": {
            "original_url": url,
            "domain": domain,
            "hostname": hostname,
            "company_name": company_name
        },
        **data_payload,
        "checked_at": checked_at
    }
    
    return build_agent_result(
        agent_identifier="A15",
        target=url,
        status="completed",
        data=data_payload,
        evidence=structured_evidence,
        errors=errors,
        extra_fields=extra_fields,
    )
