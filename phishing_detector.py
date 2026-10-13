"""Deterministic URL-text analysis. No DNS or network operations."""

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

MAX_URL_LENGTH = 4096
LIMITATION = (
    "Heuristic URL-text analysis cannot guarantee that a website is safe or malicious. "
    "No website was visited, and no reputation, DNS, certificate, or page-content checks were performed."
)
KEYWORDS = ("login", "verify", "secure", "account", "update", "password", "bank", "wallet", "gift", "free")
BRANDS = {"paypal", "google", "microsoft", "apple", "amazon", "facebook"}
CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u04cf": "l", "\u03bf": "o", "\u03c1": "p",
})


def validate_url(value):
    if not isinstance(value, str):
        raise ValueError("The URL must be a string.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URLs must be at most {MAX_URL_LENGTH} characters.")
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if any(c.isspace() or unicodedata.category(c).startswith("C") for c in value) or "\\" in value:
        raise ValueError("URLs cannot contain spaces, control characters, or backslashes.")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Percent encoding must contain two hexadecimal digits, such as %20.")
    has_scheme = re.match(r"^[a-z][a-z\d+.-]*:", value, re.I)
    host_port = re.match(r"^[^/:?#]+:\d+(?:[/?#]|$)", value)
    candidate = "https:" + value if value.startswith("//") else value
    if not value.startswith("//") and (not has_scheme or host_port):
        candidate = "https://" + value
    if not re.match(r"^https?://[^/?#]", candidate, re.I):
        raise ValueError("Enter an HTTP or HTTPS website URL, such as https://example.com.")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        raise ValueError("Enter a valid domain, IP address, and optional port (1-65535).") from None
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Embedded URL credentials are not allowed.")
    try:
        hostname = parsed.hostname
        port = parsed.port
        if not hostname or port == 0 or parsed.netloc.endswith(":"):
            raise ValueError()
        authority_host = parsed.netloc.rsplit("@", 1)[-1]
        if authority_host.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", authority_host):
            raise ValueError()
        if authority_host.startswith("[") and ":" not in hostname:
            raise ValueError()
        if hostname.endswith(".."):
            raise ValueError()
        hostname = hostname.removesuffix(".")
        try:
            ip = ipaddress.ip_address(hostname)
            if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
                raise ValueError()
            ascii_host = str(ip)
            unicode_host = hostname
        except ValueError:
            ip = None
            ascii_host = hostname.encode("idna").decode("ascii").lower()
            labels = ascii_host.split(".")
            if (len(ascii_host) > 253 or (len(labels) < 2 and ascii_host != "localhost")
                    or labels[-1].isdigit()
                    or not all(re.fullmatch(r"[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?", label) for label in labels)):
                raise ValueError()
            unicode_host = ascii_host.encode("ascii").decode("idna")
    except (ValueError, UnicodeError):
        raise ValueError("Enter a valid domain, IP address, and optional port (1-65535).") from None
    return candidate, parsed, ascii_host, unicode_host, ip


def classify_score(score):
    return "High" if score >= 60 else "Medium" if score >= 30 else "Low"


def analyze_url(value):
    url, parsed, hostname, unicode_host, ip = validate_url(value)
    reasons = []

    def add(rule, points, explanation):
        reasons.append({"rule": rule, "points": points, "explanation": explanation})

    if ip is not None:
        add("ip_address", 25, "The host is an IP address instead of a recognizable domain name.")
    if len(url) > 200:
        add("url_length", 20, f"URL length is {len(url)} characters, exceeding the 200-character threshold.")
    elif len(url) > 100:
        add("url_length", 10, f"URL length is {len(url)} characters, exceeding the 100-character threshold.")
    # Approximation only: no public suffix list is consulted.
    subdomains = max(0, len(hostname.split(".")) - 2) if ip is None else 0
    if subdomains > 3:
        add("excessive_subdomains", 15, f"Host has approximately {subdomains} subdomains (more than 3); multi-part public suffixes can affect this estimate.")
    decoded = unquote(url).lower()
    matched = [keyword for keyword in KEYWORDS if keyword in decoded]
    if matched:
        add("suspicious_keywords", min(20, len(matched) * 5), "Attention-worthy keywords: " + ", ".join(matched) + ". Legitimate URLs can also contain these words.")
    escapes = re.findall(r"%[0-9a-f]{2}", url, re.I)
    if len(escapes) >= 5 or re.search(r"%(?:25[0-9a-f]{2}|2f|40|3a|5c|00|0a|0d)", url, re.I):
        add("unusual_encoding", 20, "URL contains encoded delimiters/control characters, nested percent encoding, or at least five encoded bytes; encoding can obscure readable text.")
    if any(label.startswith("xn--") for label in hostname.split(".")):
        add("punycode", 15, "Host uses an internationalized (punycode) label. Internationalized domains are legitimate, but can conceal visual similarities.")
    scripts = {script for character in unicode_host for script in ("LATIN", "CYRILLIC", "GREEK") if script in unicodedata.name(character, "")}
    lookalikes = []
    for label in unicode_host.lower().split("."):
        skeleton = unicodedata.normalize("NFKC", label).translate(CONFUSABLES)
        if skeleton in BRANDS and skeleton != label:
            lookalikes.append(label)
    if len(scripts) > 1 or lookalikes:
        add("lookalike_domain", 20, "Host mixes Latin/Cyrillic/Greek scripts or resembles a name in the limited brand list using substituted characters. This is an indicator, not proof of impersonation.")
    if parsed.scheme.lower() == "http":
        add("http_scheme", 10, "URL specifies HTTP rather than HTTPS. This text check does not verify transport security or certificates.")
    raw_score = sum(reason["points"] for reason in reasons)
    score = min(100, raw_score)
    return {
        "url": url, "hostname": hostname, "risk_score": score,
        "risk_level": classify_score(score), "reasons": reasons,
        "raw_score": raw_score, "score_cap": 100,
        "analysis_type": "URL-text heuristics", "limitation": LIMITATION,
    }
