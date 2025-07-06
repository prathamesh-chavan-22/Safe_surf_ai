# domain_checker.py

import re
import tldextract
import dns.resolver

def extract_domain(url):
    """
    Extracts the subdomain, domain, and suffix from the given URL.
    """
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix


def is_suspicious_domain(domain, subdomain):
    """
    Checks if a domain or subdomain is suspicious based on keyword patterns
    and DNS resolution.
    Returns: (Boolean, Reason string)
    """
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify']

    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in subdomain.lower() or keyword in domain.lower():
            return True, f"Contains suspicious keyword: '{keyword}'"

    # DNS resolution check
    try:
        dns.resolver.resolve(f"{domain}.com", 'A')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return True, "Domain does not resolve to any IP"

    return False, "Looks clean"


def check_url(url):
    """
    Full pipeline: extract domain parts, check suspiciousness, and return result.
    """
    subdomain, domain, suffix = extract_domain(url)
    is_suspicious, reason = is_suspicious_domain(domain, subdomain)

    return {
        "URL": url,
        "Domain": domain,
        "Subdomain": subdomain,
        "Suffix": suffix,
        "Is Suspicious": is_suspicious,
        "Reason": reason
    }


# Example run (uncomment to test directly)
if __name__ == "__main__":
    url_input = input("Enter URL: ")
    result = check_url(url_input)
    for key, value in result.items():
        print(f"{key}: {value}")
