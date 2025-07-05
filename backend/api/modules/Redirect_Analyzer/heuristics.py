# heuristics.py

import re
import tldextract
from typing import List, Dict

# Known cloaking/monetization domains
KNOWN_CLOAKERS = set(domain.lower() for domain in [
    "adf.ly", "bit.do", "linkbucks.com", "sh.st", "shortest.st", "ouo.io",
    "bc.vc", "adfoc.us", "lnk.co", "ity.im", "soo.gd", "clk.im",
    "urlcash.net", "zpag.es", "cur.lv", "linkshrink.net", "moourl.com",
    "yourls.org", "robo.to", "v.gd", "q.gs", "1shortlink.com", "short.am",
    "linkzip.net", "gestyy.com", "clk.sh", "megaurl.in", "linksly.co",
    "shrinkearn.com", "cpmlink.net", "tmearn.com", "shortzon.com",
    "shrinke.me", "boost.ink", "link-target.net", "srt.am", "tny.im",
    "viralurl.com", "tny.cz", "budurl.com", "tinyurl.com", "cutt.ly",
    "is.gd", "bit.ly", "t.co", "rb.gy", "rebrand.ly", "x.co", "cli.gs",
    "ouo.press", "adfly.link", "linktr.ee", "bio.link", "bio.site"
])

# Trusted final destination domains (add more as needed)
TRUSTED_FINAL_DOMAINS = {
    # Tech Giants
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", "whatsapp.com",
    "amazon.com", "alibaba.com", "baidu.com", "yahoo.com", "bing.com",

    # Developer & Code Hosting
    "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
    "sourceforge.net", "stackblitz.com", "codesandbox.io",

    # Cloud & DevOps
    "cloudflare.com", "vercel.com", "netlify.app", "aws.amazon.com",
    "azure.microsoft.com", "gcp.google.com", "digitalocean.com",
    "heroku.com", "render.com", "railway.app",

    # Docs & Collaboration
    "docs.google.com", "drive.google.com", "dropbox.com", "box.com",
    "notion.so", "slack.com", "asana.com", "trello.com", "monday.com",
    "figma.com", "miro.com", "zoom.us", "skype.com", "teams.microsoft.com",

    # Finance & Payments
    "paypal.com", "stripe.com", "visa.com", "mastercard.com", "squareup.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "intuit.com", "mint.com",

    # Education & Research
    "edx.org", "coursera.org", "udemy.com", "khanacademy.org", "pluralsight.com",
    "harvard.edu", "mit.edu", "stanford.edu", "cam.ac.uk", "ox.ac.uk",

    # Messaging & Social Media
    "twitter.com", "x.com", "linkedin.com", "discord.com", "reddit.com",
    "snapchat.com", "tiktok.com", "pinterest.com", "tumblr.com", "medium.com",

    # Shopping & Services
    "shopify.com", "etsy.com", "ebay.com", "walmart.com", "target.com",
    "bestbuy.com", "costco.com", "ubereats.com", "doordash.com", "grubhub.com",

    # Crypto & Web3
    "coinbase.com", "binance.com", "opensea.io", "etherscan.io", "metamask.io",

    # Healthcare & Government (U.S.-centric)
    "cdc.gov", "nih.gov", "whitehouse.gov", "usa.gov", "irs.gov",
    "healthcare.gov", "nasa.gov", "fda.gov",

}

def is_low_entropy_domain(domain: str) -> bool:
    """Heuristic for junk or random-letter domains"""
    score = sum(1 for c in domain if c in 'aeiou') / max(len(domain), 1)
    return score < 0.2 and len(domain) >= 8

def is_suspicious_path(url: str) -> bool:
    """Flag long query strings or excessive path depth"""
    path = url.split('?', 1)[0]
    segments = path.split('/')
    return len(segments) > 6 or any(len(s) > 30 for s in segments)

def evaluate_chain(chain: List[str]) -> Dict:
    issues = []
    seen_urls = set()
    tlds = set()
    seen_domains = set()
    proxy_detected = False
    recaptcha_detected = False
    intermediate_blank = False
    suspicious_entropy_domains = []
    suspicious_paths = []
    shortener_deep_links = []

    proxy_keywords = ["proxy.html", "proxy.php"]
    captcha_keywords = ["recaptcha/api2", "captcha"]
    obfuscation_flags = ["base64", "%3D", "%2F"]
    internal_protocols = ("about:", "data:")
    image_extensions = [".gif", ".jpg", ".jpeg", ".png", ".svg", ".webp"]
    javascript_endpoints = [".js", "/gtag/js", "analytics.js"]

    if not chain:
        return {
            "chain": [],
            "status": "error",
            "reason": ["Empty redirection chain"]
        }

    for i, url in enumerate(chain):
        lower_url = url.lower()

        # Rule: Duplicates = loop
        if url in seen_urls:
            issues.append("Redirect loop detected (repeating URLs)")
        seen_urls.add(url)

        # Rule: Obfuscation
        if any(flag in lower_url for flag in obfuscation_flags):
            issues.append("Obfuscated URL parameters detected")

        # Proxy/Captcha Detection
        if any(proxy in lower_url for proxy in proxy_keywords):
            proxy_detected = True

        if any(captcha in lower_url for captcha in captcha_keywords):
            recaptcha_detected = True

        if lower_url.startswith("about:") and i != len(chain) - 1:
            intermediate_blank = True

        # Extract domain
        if not lower_url.startswith(internal_protocols):
            parts = tldextract.extract(url)
            if parts.suffix:
                tlds.add(parts.suffix)
            domain = parts.registered_domain.lower()
            seen_domains.add(domain)

            if domain in KNOWN_CLOAKERS:
                issues.append(f"Known cloaking service detected: {domain}")

            # Low-entropy junk domain (e.g., xyzkfwq.com)
            if is_low_entropy_domain(parts.domain):
                suspicious_entropy_domains.append(domain)

            # Suspicious paths
            if is_suspicious_path(url):
                suspicious_paths.append(url)

            # Shortener with a deep path
            if domain in KNOWN_CLOAKERS and '/' in url.partition(domain)[2]:
                shortener_deep_links.append(url)

            # Static content that shouldn't be a redirect
            if any(url.endswith(ext) for ext in image_extensions + javascript_endpoints):
                issues.append(f"Static content endpoint in chain: {url}")

    # Mixed protocols
    for i in range(len(chain) - 1):
        if chain[i].startswith("http://") and chain[i+1].startswith("https://"):
            issues.append("Mixed protocols (HTTP ➝ HTTPS)")
        elif chain[i].startswith("https://") and chain[i+1].startswith("http://"):
            issues.append("Mixed protocols (HTTPS ➝ HTTP)")

    if len(tlds) > 1:
        issues.append("Cross-TLD redirection: " + ", ".join(sorted(tlds)))

    if proxy_detected:
        issues.append("Proxy-based redirection detected")

    if recaptcha_detected:
        issues.append("CAPTCHA barrier detected mid-redirection")

    if intermediate_blank:
        issues.append("Unexpected about:blank mid-chain")

    if suspicious_entropy_domains:
        issues.append("Low-entropy/random-looking domains: " + ", ".join(suspicious_entropy_domains))

    if suspicious_paths:
        issues.append("Suspiciously long or deep paths in chain")

    if shortener_deep_links:
        issues.append("Shortlink with deep tracking paths")

    if len(chain) > 6:
        issues.append("Unusually long redirect chain (>6 hops)")

    # Final domain trust
    final_domain = tldextract.extract(chain[-1]).registered_domain.lower()
    if final_domain in TRUSTED_FINAL_DOMAINS and not any("cloaking" in i.lower() for i in issues):
        return {
            "chain": chain,
            "status": "safe",
            "reason": ["Final destination is a trusted domain"]
        }

    status = "suspicious" if issues else "safe"
    return {
        "chain": len(chain),
        "status": status,
        "reason": issues
    }
