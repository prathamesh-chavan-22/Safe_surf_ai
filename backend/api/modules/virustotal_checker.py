import os
import sys
import time
import base64
import hashlib
import asyncio
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    print("[!] Error: VT_API_KEY not found in .env file")
    sys.exit(1)


def get_url_id(url: str) -> str:
    """Generate VirusTotal-compatible ID for a URL using SHA256 hash base64 encoding."""
    url_bytes = url.encode("utf-8")
    sha256_hash = hashlib.sha256(url_bytes).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode().rstrip("=")


async def scan_url(url: str) -> dict:
    """
    Asynchronously scan a URL using VirusTotal API with hash lookup fallback.

    Args:
        url (str): The URL to scan.

    Returns:
        dict: Scan results (malicious/suspicious/etc.)
    """
    try:
        headers = {
            "x-apikey": VT_API_KEY,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Try fetching cached scan result using hashed URL ID
            url_id = get_url_id(url)
            cached_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            cached_resp = await client.get(cached_url, headers=headers)

            if cached_resp.status_code == 200:
                stats = cached_resp.json()["data"]["attributes"]["last_analysis_stats"]
                print("[✔] Used cached VirusTotal scan result")
                return stats

            print("[⏳] No cache found. Submitting URL for new scan...")

            # Step 2: Submit new scan
            post_headers = headers | {"Content-Type": "application/x-www-form-urlencoded"}
            scan_resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                data=f"url={url}",
                headers=post_headers
            )

            analysis_id = scan_resp.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            for _ in range(15):  # ~30 seconds max
                result = await client.get(analysis_url, headers=headers)
                status = result.json()["data"]["attributes"]["status"]
                if status == "completed":
                    stats = result.json()["data"]["attributes"]["stats"]
                    break
                await asyncio.sleep(2)
            else:
                print("[!] Timeout waiting for analysis.")
                return {"malicious": 0, "suspicious": 0}

            print("\n--- VirusTotal Scan Result ---")
            print(f"URL:         {url}")
            print(f"Malicious:   {stats['malicious']}")
            print(f"Suspicious:  {stats['suspicious']}")
            print(f"Harmless:    {stats['harmless']}")
            print(f"Undetected:  {stats['undetected']}")

            return stats

    except Exception as e:
        print("❌ Error during VirusTotal scan:", e)
        return {"malicious": 0, "suspicious": 0}
