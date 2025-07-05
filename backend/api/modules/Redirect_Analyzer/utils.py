# utils.py

import tldextract
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode


def extract_domain(url: str) -> str:
    """
    Extracts the registered domain from a URL.

    Args:
        url (str): Input URL

    Returns:
        str: Registered domain (e.g., "example.com")
    """
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else url


def is_same_domain(url1: str, url2: str) -> bool:
    """
    Checks whether two URLs belong to the same registered domain.

    Args:
        url1 (str): First URL
        url2 (str): Second URL

    Returns:
        bool: True if domains match, else False
    """
    return extract_domain(url1) == extract_domain(url2)


def get_scheme(url: str) -> str:
    """
    Returns the scheme (http or https) of the given URL.

    Args:
        url (str): Input URL

    Returns:
        str: 'http' or 'https'
    """
    return urlparse(url).scheme


def get_netloc(url: str) -> str:
    """
    Returns the network location (host:port) of a URL.

    Args:
        url (str): Input URL

    Returns:
        str: Netloc portion
    """
    return urlparse(url).netloc


def is_trusted_domain(url: str, trusted_domains: list) -> bool:
    """
    Checks if a URL belongs to a list of trusted domains.

    Args:
        url (str): Input URL
        trusted_domains (list): List of trusted domains like ['google.com', 'microsoft.com']

    Returns:
        bool: True if domain is trusted
    """
    domain = extract_domain(url)
    return any(domain.endswith(td) for td in trusted_domains)


def clean_url(url: str) -> str:
    """
    Normalizes the URL by removing tracking parameters like `utm_*`.

    Args:
        url (str): Input URL

    Returns:
        str: Cleaned URL
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    filtered_query = {k: v for k, v in query.items() if not k.startswith('utm_')}
    clean_query = urlencode(filtered_query, doseq=True)
    return urlunparse(parsed._replace(query=clean_query))


def get_path_depth(url: str) -> int:
    """
    Calculates how deep the URL path is.

    Args:
        url (str): Input URL

    Returns:
        int: Path depth
    """
    path = urlparse(url).path
    return len([p for p in path.split('/') if p])
