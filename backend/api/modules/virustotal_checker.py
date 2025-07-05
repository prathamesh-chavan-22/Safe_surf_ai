import requests
from virustotal_python import Virustotal
import time
from dotenv import load_dotenv
import os
import sys
import base64

# Load environment variables
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    print("[!] Error: VT_API_KEY not found in .env file")
    sys.exit(1)

# Initialize VirusTotal client
vtotal = Virustotal(API_KEY=VT_API_KEY)

def scan_url(url: str):
    """    Scans a URL using VirusTotal and returns the scan results.   
    Args:
        url (str): The URL to scan.
    Returns:
        dict: A dictionary containing the scan results.
    """
    try:
        # Submit URL to VirusTotal
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        analysis_id = resp.data["id"]  # ✅ use .data instead of subscript

        # Check scan status
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {"x-apikey": VT_API_KEY}

        while True:
            result = requests.get(analysis_url, headers=headers).json()
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                break
            print("[*] Waiting for analysis to complete...")
            time.sleep(2)

        stats = result["data"]["attributes"]["stats"]

        # Encode the URL into base64 (VT's GUI format)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        print("\n--- URL Scan Result ---")
        print(f"URL:         {url}")
        print(f"Malicious:   {stats['malicious']}")
        print(f"Suspicious:  {stats['suspicious']}")
        print(f"Harmless:    {stats['harmless']}")
        print(f"Undetected:  {stats['undetected']}")
        # print(f"Full Report: https://www.virustotal.com/gui/url/{url_id}")

        return stats

    except Exception as e:
        print("Error during URL scan:", e)


