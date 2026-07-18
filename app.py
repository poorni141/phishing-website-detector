"""
AI Phishing Website Detector — Flask backend
------------------------------------------------
This performs REAL analysis on the submitted URL:
  1. Structural URL checks   (length, IP address, '@', hyphens, subdomains,
                               suspicious keywords, TLD, punycode, HTTPS)
  2. Live DNS resolution     (socket.gethostbyname)
  3. Live HTTP reachability  (requests.get with redirects + timeout)
  4. TLS/SSL certificate validity (via requests' certificate verification)

These are combined into a weighted score (a transparent, rule-based stand-in
for a trained ML classifier) to produce a final verdict + confidence.
"""

import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "bank",
    "confirm", "signin", "password", "wallet", "billing", "authenticate", "unlock"
]
SUSPICIOUS_TLDS = ["xyz", "top", "zip", "country", "gq", "tk", "ml", "work", "click", "info", "loan", "men"]

KNOWN_BRANDS = {
    "google":        ["google.com", "google.co.in"],
    "gmail":         ["gmail.com", "google.com"],
    "paypal":        ["paypal.com"],
    "amazon":        ["amazon.com", "amazon.in"],
    "apple":         ["apple.com", "icloud.com"],
    "microsoft":     ["microsoft.com", "live.com", "outlook.com"],
    "facebook":      ["facebook.com", "fb.com"],
    "instagram":     ["instagram.com"],
    "whatsapp":      ["whatsapp.com"],
    "netflix":       ["netflix.com"],
    "linkedin":      ["linkedin.com"],
    "twitter":       ["twitter.com", "x.com"],
    "ebay":          ["ebay.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase":         ["chase.com"],
    "wellsfargo":    ["wellsfargo.com"],
    "hdfcbank":      ["hdfcbank.com"],
    "icicibank":     ["icicibank.com"],
    "sbi":           ["onlinesbi.sbi", "sbi.co.in"],
    "flipkart":      ["flipkart.com"],
    "irctc":         ["irctc.co.in"],
    "yahoo":         ["yahoo.com"],
    "dropbox":       ["dropbox.com"],
    "adobe":         ["adobe.com"],
}

FEATURE_WEIGHTS = {
    "HTTPS Enabled": 4,
    "No IP Address in Domain": 22,
    "Safe URL Length": 6,
    "No '@' Redirect Trick": 18,
    "Safe Hyphen Usage": 8,
    "Normal Subdomain Count": 6,
    "Trusted Domain Extension": 12,
    "No Suspicious Keywords in URL": 12,
    "No Punycode / Homograph Trick": 28,
    "No Brand Impersonation (Typosquatting)": 38,
    "No Brand Name Misuse (Combosquatting)": 32,
    "Valid DNS Resolution": 8,
    "Domain is Reachable": 4,
    "Valid SSL Certificate": 4,
}
CRITICAL_FEATURES = {
    "No Brand Impersonation (Typosquatting)",
    "No Brand Name Misuse (Combosquatting)",
    "No Punycode / Homograph Trick",
    "No IP Address in Domain",
}

SCAN_HISTORY = []
STATS = {"total": 0, "legit": 0, "phish": 0}


def normalize_url(raw_url: str) -> str:
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        return "http://" + raw_url
    return raw_url


DOMAIN_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$"
)


def looks_like_domain(hostname: str) -> bool:
    if not hostname:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        return True
    return bool(DOMAIN_REGEX.match(hostname))


def registrable_label(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return hostname


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def is_official_domain(hostname: str, official_domains) -> bool:
    hostname = hostname.lower()
    return any(hostname == d or hostname.endswith("." + d) for d in official_domains)


def detect_brand_impersonation(hostname: str, full_url: str):
    hostname_l = hostname.lower()
    url_l = full_url.lower()
    label = registrable_label(hostname_l)

    for brand, domains in KNOWN_BRANDS.items():
        if is_official_domain(hostname_l, domains):
            return False, False, None

    typosquat_hit = False
    combosquat_hit = False
    matched_brand = None

    tokens = set(re.split(r"[-_]", label))
    tokens.add(label)

    for brand, domains in KNOWN_BRANDS.items():
        if brand in hostname_l or brand in url_l:
            combosquat_hit = True
            matched_brand = brand
            break

        for token in tokens:
            if len(token) < 4:
                continue
            max_dist = 1 if len(brand) <= 5 else 2
            dist = levenshtein(token, brand)
            if 0 < dist <= max_dist:
                typosquat_hit = True
                matched_brand = brand
                break
        if typosquat_hit:
            break

    return typosquat_hit, combosquat_hit, matched_brand


def extract_features(raw_url: str):
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = []

    is_https = raw_url.lower().startswith("https://")
    features.append({"name": "HTTPS Enabled", "safe": is_https})

    has_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))
    features.append({"name": "No IP Address in Domain", "safe": not has_ip})

    features.append({"name": "Safe URL Length", "safe": len(raw_url) <= 75})

    features.append({"name": "No '@' Redirect Trick", "safe": "@" not in raw_url})

    dash_count = hostname.count("-")
    features.append({"name": "Safe Hyphen Usage", "safe": dash_count <= 2})

    subdomain_count = hostname.count(".")
    features.append({"name": "Normal Subdomain Count", "safe": subdomain_count <= 3})

    tld = hostname.split(".")[-1].lower() if "." in hostname else ""
    features.append({"name": "Trusted Domain Extension", "safe": tld not in SUSPICIOUS_TLDS})

    kw_hit = any(k in url.lower() for k in SUSPICIOUS_KEYWORDS)
    features.append({"name": "No Suspicious Keywords in URL", "safe": not kw_hit})

    is_punycode = hostname.lower().startswith("xn--") or ".xn--" in hostname.lower()
    features.append({"name": "No Punycode / Homograph Trick", "safe": not is_punycode})

    typosquat_hit, combosquat_hit, matched_brand = detect_brand_impersonation(hostname, url)
    features.append({"name": "No Brand Impersonation (Typosquatting)", "safe": not typosquat_hit})
    features.append({"name": "No Brand Name Misuse (Combosquatting)", "safe": not combosquat_hit})

    dns_ok = False
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(hostname)
        dns_ok = True
    except Exception:
        dns_ok = False
    features.append({"name": "Valid DNS Resolution", "safe": dns_ok})

    reachable = False
    ssl_valid = True
    if dns_ok:
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True, verify=True,
                                 headers={"User-Agent": "Mozilla/5.0 (PhishingDetector/1.0)"})
            reachable = True
            _ = resp.status_code
        except requests.exceptions.SSLError:
            reachable = True
            ssl_valid = False
        except Exception:
            reachable = False

    features.append({"name": "Domain is Reachable", "safe": reachable})
    features.append({"name": "Valid SSL Certificate", "safe": ssl_valid if is_https else True})

    return features, dns_ok, reachable, matched_brand


def score_features(features):
    risk_score = 0
    max_score = sum(FEATURE_WEIGHTS.values())
    critical_hit = False

    for f in features:
        if not f["safe"]:
            risk_score += FEATURE_WEIGHTS.get(f["name"], 5)
            if f["name"] in CRITICAL_FEATURES:
                critical_hit = True

    risk_pct = min(100, round((risk_score / max_score) * 100))
    is_phishing = critical_hit or risk_pct >= 18

    if is_phishing:
        confidence = min(98, 62 + risk_pct)
        risk = "High" if critical_hit or risk_pct >= 40 else "Medium"
    else:
        confidence = min(99, 99 - risk_pct)
        risk = "Low"

    return is_phishing, max(confidence, 51), risk


@app.route("/")
def index():
    return render_template("index.html", history=SCAN_HISTORY[:10], stats=STATS)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True) or {}
    raw_url = (data.get("url") or "").strip()

    if not raw_url:
        return jsonify({"error": "A URL is required."}), 400

    hostname = urlparse(normalize_url(raw_url)).hostname or ""
    if not looks_like_domain(hostname):
        return jsonify({
            "error": "That doesn't look like a valid website URL. "
                     "Please enter something like https://example.com"
        }), 400

    features, dns_ok, reachable, matched_brand = extract_features(raw_url)
    is_phishing, confidence, risk = score_features(features)

    result = {
        "url": raw_url,
        "label": "phishing" if is_phishing else "legitimate",
        "confidence": confidence,
        "status": "Unsafe" if is_phishing else "Safe",
        "risk_level": risk,
        "scan_time": datetime.now().strftime("%H:%M:%S"),
        "timestamp": datetime.now().strftime("%d %b %Y, %H:%M"),
        "features": features,
        "dns_resolved": dns_ok,
        "reachable": reachable,
        "matched_brand": matched_brand,
    }

    SCAN_HISTORY.insert(0, result)
    del SCAN_HISTORY[50:]
    STATS["total"] += 1
    STATS["legit" if not is_phishing else "phish"] += 1

    return jsonify({"result": result, "stats": STATS})


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, port=5050)
