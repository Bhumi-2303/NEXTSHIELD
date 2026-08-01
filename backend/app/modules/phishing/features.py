"""Phishing feature extraction pipeline.

Extracts three categories of features from raw email data:
  1. Text features  — urgency language, spelling anomalies, generic greetings
  2. Sender features — domain age (WHOIS), SPF/DKIM/DMARC from headers
  3. URL features    — shortened URLs, suspicious TLDs, homograph/lookalike detection

All features are returned as a flat dict suitable for model input.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Brand list for lookalike / homograph detection
# ---------------------------------------------------------------------------
TOP_BRAND_DOMAINS: list[str] = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "netflix.com", "linkedin.com", "instagram.com",
    "twitter.com", "dropbox.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "dhl.com", "fedex.com", "ups.com",
    "usps.com", "yahoo.com", "outlook.com", "icloud.com", "adobe.com",
    "spotify.com", "zoom.us", "slack.com", "github.com", "stripe.com",
    "square.com", "coinbase.com",
]

# TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
    ".club", ".work", ".click", ".link", ".info", ".icu", ".cam",
    ".rest", ".monster", ".surf",
}

# URL shortener domains
SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
}

# Urgency / pressure keywords (weighted)
URGENCY_KEYWORDS: list[tuple[str, float]] = [
    (r"\burgent\b", 0.15),
    (r"\bimmediately\b", 0.15),
    (r"\bsuspend", 0.12),
    (r"\bverif(?:y|ication)\b", 0.10),
    (r"\bexpir(?:e|ed|es|ing)\b", 0.10),
    (r"\bunauthori[sz]ed\b", 0.12),
    (r"\bact\s+now\b", 0.15),
    (r"\blimited\s+time\b", 0.10),
    (r"\bfinal\s+warning\b", 0.15),
    (r"\baccount.*(?:clos|lock|block)", 0.12),
    (r"\bconfirm\s+(?:your\s+)?identity\b", 0.10),
    (r"\bcredit\s*card\b", 0.08),
    (r"\bpassword\b", 0.08),
    (r"\bsocial\s*security\b", 0.12),
    (r"\bclick\s+(?:here|below|the\s+link)\b", 0.08),
    (r"\bwithin\s+\d+\s+hours?\b", 0.10),
]

GENERIC_GREETINGS: list[str] = [
    r"\bdear\s+(?:customer|user|member|client|sir|madam|account\s*holder)\b",
    r"\bhello\s+(?:customer|user|member)\b",
    r"\bvalued\s+(?:customer|client|member)\b",
    r"\bto\s+whom\s+it\s+may\s+concern\b",
    r"\bdear\s+(?:sir|madam)\b",
]

# Common misspelling patterns seen in phishing
SPELLING_NOISE_PATTERNS: list[str] = [
    r"\b[a-z]+[0-9]+[a-z]+\b",          # l3tter substitutions
    r"\b\w*([a-z])\1{3,}\w*\b",          # excessive repeated chars
    r"[^\x00-\x7F]",                      # non-ASCII chars (homoglyphs)
]


# ============================================================================
# Text features
# ============================================================================

def compute_urgency_score(text: str) -> float:
    """Score 0-1 based on urgency/pressure keyword density."""
    text_lower = text.lower()
    score = 0.0
    for pattern, weight in URGENCY_KEYWORDS:
        if re.search(pattern, text_lower):
            score += weight
    return min(score, 1.0)


def detect_generic_greeting(text: str) -> bool:
    """Return True if the email uses a generic / impersonal greeting."""
    text_lower = text.lower()
    return any(re.search(pat, text_lower) for pat in GENERIC_GREETINGS)


def compute_spelling_anomaly_score(text: str) -> float:
    """Heuristic spelling anomaly score 0-1.

    Counts suspicious patterns (homoglyphs, leet-speak, excess repeats)
    normalised by text length.
    """
    if not text:
        return 0.0
    hits = sum(len(re.findall(pat, text)) for pat in SPELLING_NOISE_PATTERNS)
    word_count = max(len(text.split()), 1)
    return min(hits / word_count, 1.0)


def extract_text_features(subject: str, body: str) -> dict[str, Any]:
    """Extract NLP-based features from email subject + body."""
    combined = f"{subject} {body}"
    return {
        "urgency_score": compute_urgency_score(combined),
        "spelling_anomaly_score": compute_spelling_anomaly_score(combined),
        "generic_greeting": detect_generic_greeting(combined),
        "body_length": len(body),
        "subject_length": len(subject),
        "exclamation_count": combined.count("!"),
        "has_html_content": bool(re.search(r"<[a-zA-Z][^>]*>", body)),
    }


# ============================================================================
# Sender features
# ============================================================================

def mock_whois_domain_age(domain: str) -> int | None:
    """Return a synthetic domain age in days for the given domain.

    TODO: Replace with a real WHOIS API lookup (e.g. python-whois,
    whoisxmlapi.com, or SecurityTrails API) once an API key is available.
    Current implementation returns deterministic but plausible synthetic
    values seeded by the domain name for reproducibility.
    """
    # Well-known domains get realistic ages
    well_known_ages: dict[str, int] = {
        "google.com": 9500, "microsoft.com": 11000, "apple.com": 10500,
        "amazon.com": 10000, "paypal.com": 8500, "facebook.com": 7300,
        "netflix.com": 9000, "linkedin.com": 8000, "yahoo.com": 10500,
    }
    if domain.lower() in well_known_ages:
        return well_known_ages[domain.lower()]

    # Deterministic synthetic age based on domain hash
    h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    # Bias: most legit domains are old, phishing domains are young
    # Use the hash to pick from a skewed distribution
    bucket = h % 100
    if bucket < 30:
        return (h % 30) + 1       # 1-30 days (suspicious)
    elif bucket < 60:
        return (h % 365) + 30     # 30-395 days
    else:
        return (h % 3650) + 365   # 1-10 years


def parse_auth_results(headers: dict[str, str]) -> dict[str, bool]:
    """Parse SPF, DKIM, DMARC pass/fail from email headers.

    Looks at the ``Authentication-Results`` header (RFC 8601).
    Falls back to individual ``Received-SPF`` etc. headers.
    """
    spf_pass = False
    dkim_pass = False
    dmarc_pass = False

    auth_results = headers.get("Authentication-Results", "").lower()
    received_spf = headers.get("Received-SPF", "").lower()

    # SPF
    if "spf=pass" in auth_results or received_spf.startswith("pass"):
        spf_pass = True

    # DKIM
    if "dkim=pass" in auth_results:
        dkim_pass = True

    # DMARC
    if "dmarc=pass" in auth_results:
        dmarc_pass = True

    return {
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
    }


def extract_sender_features(
    sender_email: str, headers: dict[str, str]
) -> dict[str, Any]:
    """Extract sender-related features."""
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else sender_email.lower()
    domain_age = mock_whois_domain_age(domain)
    auth = parse_auth_results(headers)

    return {
        "sender_domain": domain,
        "domain_age_days": domain_age,
        "spf_pass": auth["spf_pass"],
        "dkim_pass": auth["dkim_pass"],
        "dmarc_pass": auth["dmarc_pass"],
        "is_freemail": domain in {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "protonmail.com", "mail.com", "yandex.com",
        },
    }


# ============================================================================
# URL features
# ============================================================================

def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


def _extract_registrable_domain(url: str) -> str:
    """Best-effort extraction of the registrable domain from a URL."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = url.lower()
    # Strip common prefixes
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def detect_lookalike_domain(domain: str) -> tuple[bool, str | None, int | None]:
    """Check if *domain* is a lookalike of a top brand domain.

    Returns (is_lookalike, closest_brand, edit_distance).
    A domain is flagged if its Levenshtein distance to any brand domain
    is ≤ 3 **and** it is not an exact match.
    """
    domain_clean = domain.lower()
    if domain_clean.startswith("www."):
        domain_clean = domain_clean[4:]

    best_brand: str | None = None
    best_dist: int = 999

    for brand in TOP_BRAND_DOMAINS:
        dist = _levenshtein(domain_clean, brand)
        if dist < best_dist:
            best_dist = dist
            best_brand = brand

    if 0 < best_dist <= 3:
        return True, best_brand, best_dist
    return False, best_brand, best_dist


def extract_url_features(urls: list[str]) -> dict[str, Any]:
    """Extract aggregate URL features from all URLs in the email."""
    if not urls:
        return {
            "url_count": 0,
            "has_shortened_url": False,
            "suspicious_tld_count": 0,
            "lookalike_domain_detected": False,
            "lookalike_closest_brand": None,
            "lookalike_min_distance": None,
            "url_reputation_flags": [],
        }

    flags: list[str] = []
    has_shortened = False
    suspicious_tld_count = 0
    lookalike_detected = False
    lookalike_brand: str | None = None
    lookalike_dist: int | None = None

    for url in urls:
        domain = _extract_registrable_domain(url)

        # Shortened URL check
        if domain in SHORTENER_DOMAINS:
            has_shortened = True
            flags.append("shortened_url")

        # Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_tld_count += 1
                flags.append(f"suspicious_tld:{tld}")
                break

        # Lookalike / homograph check
        is_look, brand, dist = detect_lookalike_domain(domain)
        if is_look:
            lookalike_detected = True
            lookalike_brand = brand
            lookalike_dist = dist
            flags.append(f"lookalike:{brand}")

        # IP-based URL (e.g. http://192.168.1.1/phish)
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            host = parsed.hostname or ""
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                flags.append("ip_based_url")
        except Exception:
            pass

    return {
        "url_count": len(urls),
        "has_shortened_url": has_shortened,
        "suspicious_tld_count": suspicious_tld_count,
        "lookalike_domain_detected": lookalike_detected,
        "lookalike_closest_brand": lookalike_brand,
        "lookalike_min_distance": lookalike_dist,
        "url_reputation_flags": list(set(flags)),
    }


# ============================================================================
# Extract URLs from text
# ============================================================================

_URL_REGEX = re.compile(
    r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> list[str]:
    """Pull all URLs out of email body text."""
    return _URL_REGEX.findall(text)


# ============================================================================
# Master extraction function
# ============================================================================

# Ordered list of feature names used by the model — MUST match training order
FEATURE_NAMES: list[str] = [
    "urgency_score",
    "spelling_anomaly_score",
    "generic_greeting",
    "body_length",
    "subject_length",
    "exclamation_count",
    "has_html_content",
    "domain_age_days",
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "is_freemail",
    "url_count",
    "has_shortened_url",
    "suspicious_tld_count",
    "lookalike_domain_detected",
]

def extract_all_features(
    sender: str,
    subject: str,
    body: str,
    headers: dict[str, str],
    urls: list[str] | None = None,
) -> dict[str, Any]:
    """Run the full feature extraction pipeline.

    Parameters
    ----------
    sender : str
        Full sender email address, e.g. ``"spoofed@evil.xyz"``.
    subject : str
        Email subject line.
    body : str
        Plain-text or HTML email body.
    headers : dict
        Raw email headers as key-value pairs.
    urls : list[str] | None
        Pre-extracted URLs.  If ``None``, URLs are extracted from the body.

    Returns
    -------
    dict[str, Any]
        Flat feature dictionary.  Includes all fields needed for model
        inference *and* extra metadata fields for ``PhishingScanResult``.
    """
    if urls is None:
        urls = extract_urls_from_text(body)

    text_feats = extract_text_features(subject, body)
    sender_feats = extract_sender_features(sender, headers)
    url_feats = extract_url_features(urls)

    # Merge into a single dict
    all_features: dict[str, Any] = {}
    all_features.update(text_feats)
    all_features.update(sender_feats)
    all_features.update(url_feats)

    return all_features


def features_to_model_input(features: dict[str, Any]) -> list[float]:
    """Convert feature dict to an ordered numeric vector for the model.

    Booleans become 1.0/0.0.  ``None`` values become -1.0 (sentinel).
    """
    vec: list[float] = []
    for name in FEATURE_NAMES:
        val = features.get(name)
        if val is None:
            vec.append(-1.0)
        elif isinstance(val, bool):
            vec.append(1.0 if val else 0.0)
        else:
            vec.append(float(val))
    return vec
