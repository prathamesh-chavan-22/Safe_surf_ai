import re
import math
import socket
from urllib.parse import urlparse
from datetime import datetime
import whois

# ---------- Utility Functions ----------

def resolve_domain_to_ip(domain):
    """Resolves a domain name to its IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def print_feature_summary(features):
    """Nicely formats and prints feature dictionary."""
    print("Features:")
    for k, v in features.items():
        print(f" - {k}: {v}")

def classify_score(score):
    """Returns classification label based on score."""
    if score <= 30:
        return "Safe"
    elif score <= 60:
        return "Suspicious"
    else:
        return "Likely Malicious"

# ---------- Feature Extraction ----------

def shannon_entropy(s):
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = -sum([p * math.log2(p) for p in probabilities])
    return entropy

def is_ip(domain):
    return re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) is not None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        updated_date = w.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]

        domain_age_days = (datetime.now() - creation_date).days if creation_date else -1
        days_until_expiry = (expiration_date - datetime.now()).days if expiration_date else -1
        last_updated_days_ago = (datetime.now() - updated_date).days if updated_date else -1

        return {
            "domain_age_days": domain_age_days,
            "domain_creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "Unavailable",
            "domain_expiration_days": days_until_expiry,
            "domain_last_updated_days": last_updated_days_ago,
            "registrar": str(w.registrar) if w.registrar else "Unavailable",
            "country": str(w.country) if w.country else "Unavailable",
            "whois_success": True
        }

    except Exception:
        return {
            "domain_age_days": -1,
            "domain_creation_date": "Unavailable",
            "domain_expiration_days": -1,
            "domain_last_updated_days": -1,
            "registrar": "Unavailable",
            "country": "Unavailable",
            "whois_success": False
        }

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    path = parsed.path or ""
    full = url

    suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "cn", "biz"}
    tld = domain.split(".")[-1] if "." in domain else ""

    whois_info = get_whois_info(domain) if domain else {}

    features = {
        "url_length": len(full),
        "hostname_length": len(domain),
        "path_length": len(path),
        "count_dots": full.count("."),
        "count_hyphens": full.count("-"),
        "count_at": full.count("@"),
        "count_question_marks": full.count("?"),
        "count_equals": full.count("="),
        "count_underscores": full.count("_"),
        "count_ampersands": full.count("&"),
        "count_exclamations": full.count("!"),
        "count_spaces": full.count(" "),
        "count_digits": sum(c.isdigit() for c in full),
        "count_letters": sum(c.isalpha() for c in full),
        "entropy": round(shannon_entropy(full), 2),
        "has_ip": is_ip(domain),
        "is_https": parsed.scheme == "https",
        "has_port_in_url": ":" in domain,
        "is_encoded": "%" in full,
        "suspicious_tld": tld in suspicious_tlds,
        "resolved_ip": resolve_domain_to_ip(domain)
    }

    features.update(whois_info)
    return features

# ---------- Scoring ----------

def score_url(features):
    score = 0

    if features["url_length"] > 75:
        score += 5
    if features["count_at"] > 0 or features["count_equals"] > 2 or features["count_ampersands"] > 3:
        score += 10
    if features["has_ip"]:
        score += 20
    if features["suspicious_tld"]:
        score += 15
    if features["entropy"] > 4.2:
        score += 10
    if not features["is_https"]:
        score += 5
    if features["has_port_in_url"]:
        score += 5
    if features["is_encoded"]:
        score += 5

    domain_age = features.get("domain_age_days", -1)
    if domain_age == -1:
        score += 5
    elif domain_age < 180:
        score += 10

    expiry_days = features.get("domain_expiration_days", -1)
    if expiry_days != -1 and expiry_days < 30:
        score += 5

    last_updated = features.get("domain_last_updated_days", -1)
    if 0 <= last_updated < 30:
        score += 3

    registrar = features.get("registrar", "").lower()
    risky_registrars = {"tencent cloud", "namecheap", "freenom", "bizcn"}
    if any(r in registrar for r in risky_registrars):
        score += 5

    country = features.get("country", "").upper()
    high_risk_countries = {"RU", "CN", "IR", "KP", "SY"}
    if country in high_risk_countries:
        score += 5

    if not features.get("whois_success", False):
        score += 5

    return score

# ---------- Main Classification ----------

def classify_url(url):
    print("\n" + "=" * 60)
    print(f"🔗 Analyzing URL: {url}")

    features = extract_features(url)
    score = score_url(features)
    classification = classify_score(score)

    print_feature_summary(features)
    print(f"\n📊 Risk Score: {score}")
    print(f"🔒 Classification: {classification}")
    print("=" * 60)

    return {
        "features": features,
        "score": score,
        "classification": classification
    }

# ---------- Optional CLI Entry ----------

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        urls = sys.argv[1:]
        for url in urls:
            classify_url(url)
    else:
        print("🔍 Enter URLs to analyze (type 'exit' to quit):")
        while True:
            try:
                url = input("> ").strip()
                if url.lower() == "exit":
                    break
                if url:
                    classify_url(url)
            except KeyboardInterrupt:
                print("\nExiting.")
                break

# # Example usage:
# from Lexical_analysis import classify_url

# # Test URL
# url = "http://example.tk/login?user=test@site.com"

# # Run lexical analysis
# result = classify_url(url)

# # Extract results
# features = result["features"]
# score = result["score"]
# classification = result["classification"]

# # Display summary
# print("\n🔍 Final Result")
# print(f"🧠 Score: {score}")
# print(f"🔒 Classification: {classification}")
# print("📌 Top Features:")
# for key in ["url_length", "entropy", "suspicious_tld", "has_ip", "domain_age_days"]:
#     print(f" - {key}: {features.get(key)}")
