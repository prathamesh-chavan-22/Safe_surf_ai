import asyncio
import ssl
from urllib.parse import urlparse
from datetime import datetime


def is_https(url):
    """
    Checks if the given URL uses HTTPS.
    Returns: True if HTTPS, else False
    """
    parsed_url = urlparse(url)
    return parsed_url.scheme.lower() == 'https'


async def get_certificate_expiry_date_async(hostname):
    """
    Asynchronously fetches the SSL certificate expiry date for the given hostname.
    Returns: expiry date as a string or 'Invalid Certificate'
    """
    context = ssl.create_default_context()

    try:
        reader, writer = await asyncio.open_connection(hostname, 443, ssl=context, server_hostname=hostname)
        ssl_object = writer.get_extra_info('ssl_object')
        cert = ssl_object.getpeercert()
        writer.close()
        await writer.wait_closed()

        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        return expiry_date.strftime("%Y-%m-%d")
    except Exception as e:
        return "Invalid Certificate"


async def check_https_and_certificate_async(url):
    """
    Asynchronous version of HTTPS and certificate checker.
    Returns: dict with is_https flag and certificate expiry date.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    https_flag = is_https(url)
    cert_expiry = await get_certificate_expiry_date_async(hostname) if https_flag else "Not HTTPS"

    return {
        "URL": url,
        "Is HTTPS": https_flag,
        "Certificate Expiry Date": cert_expiry
    }


# # Example Usage
# async def main():
#     result = await check_https_and_certificate_async("https://www.google.com")
#     for key, value in result.items():
#         print(f"{key}: {value}")

# if __name__ == "__main__":
#     asyncio.run(main())
