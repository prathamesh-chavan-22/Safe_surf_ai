import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score, log_loss
import joblib
import asyncio

# Suspicious words
SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'account', 'update', 'verify',
    'banking', 'password', 'signin', 'confirm', 'security',
    'ebay', 'paypal', 'webscr', 'amazon', 'appleid', 'support',
    'billing', 'submit', 'alert', 'authentication', 'recovery',
    'admin', 'service', 'webmail', 'dropbox', 'office365',
    'verifyaccount', 'transaction', 'credentials', 'connect',
    'verifyidentity', 'restricted', 'warning', 'risk', 'malware',
    'suspend', 'unlock', 'recover', 'violation', 'win', 'gift',
    'claim', 'updateinfo', 'urgent', 'unusual', 'important'
]

print("📥 Loading phishing detection model...")
model = joblib.load("./api/modules/phishing_model.pkl")
print("✅ Model loaded.\n")

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""

    return {
        "url_length": len(url),
        "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "num_dots": url.count("."),
        "has_at_symbol": 1 if "@" in url else 0,
        "has_hyphen": 1 if "-" in ext.domain else 0,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "num_subdomains": ext.subdomain.count(".") + 1 if ext.subdomain else 0,
        "has_suspicious_keyword": 1 if any(k in url.lower() for k in SUSPICIOUS_KEYWORDS) else 0,
        "num_query_params": len(parsed.query.split("&")) if parsed.query else 0,
        "path_length": len(parsed.path),
        "count_https": url.lower().count("https"),
        "count_www": url.lower().count("www"),
        "has_long_path": 1 if len(parsed.path) > 40 else 0,
        "dns_resolves": -1  # Placeholder
    }

# ✅ Async version of predict_url
async def async_predict_url(url):
    await asyncio.sleep(0)  # simulate async behavior
    features = extract_features(url)
    X = pd.DataFrame([features])
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    return {
        "url": url,
        "predicted_label": int(prediction),
        "phishing_probability": float(probability)
    }

# Example usage
if __name__ == "__main__":
    test_url = "https://example.com/login"

    async def main():
        result = await async_predict_url(test_url)
        print(f"\n🔍 Prediction for '{test_url}':")
        print(f"Predicted Label: {'Phishing' if result['predicted_label'] else 'Legitimate'}")
        print(f"Phishing Probability: {result['phishing_probability']:.4f}")

    asyncio.run(main())
