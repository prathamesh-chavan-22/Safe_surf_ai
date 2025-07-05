import http.client
import urllib.parse
import requests

def is_shortened_url(url):
    """
    Expands a shortened URL using low-level HTTP redirect tracing.

    Args:
        url (str): The shortened URL.

    Returns:
        tuple:
            - is_shortened (bool)
            - expanded_url (str)
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        conn = http.client.HTTPSConnection(parsed_url.netloc, timeout=10)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query

        conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
        response = conn.getresponse()

        # Handle redirect chain manually
        if 300 <= response.status < 400 and "Location" in response.headers:
            expanded = response.headers["Location"]
            if expanded.startswith("/"):
                expanded = f"https://{parsed_url.netloc}{expanded}"
            return True, expanded

        # Fallback: try requests if not redirected
        resp = requests.get(url, allow_redirects=True, timeout=10)
        return url != resp.url, resp.url

    except Exception as e:
        print(f"Error expanding URL: {e}")
        return False, url
