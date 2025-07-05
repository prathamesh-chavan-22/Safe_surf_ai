import os
import sys
import json
import browser_driver
from browser_driver import trace_redirection


def sanitize_url(url: str) -> str:
    """Ensure the URL has a valid scheme."""
    url = url.strip()
    if not url:
        raise ValueError("Empty URL provided.")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url




def run_browser_mode(url: str):
    """Run using Selenium-based ChromeDriver."""
    result = trace_redirection(url)
    print(json.dumps(result, indent=2))


def main():
    try:
        url = sanitize_url("https://en.wikipedia.org/wiki/Talk:English_Wikipedia")


        
        run_browser_mode(url)
        
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
