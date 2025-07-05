# modules/detect_and_expand.py
import httpx

async def is_shortened_url(url):
    """
    Asynchronously expands a shortened URL by following redirects.

    Args:
        url (str): The input URL (possibly shortened).

    Returns:
        tuple: (is_shortened: bool, expanded_url: str)
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
            response = await client.get(url)
            expanded = str(response.url)
            return url != expanded, expanded

    except httpx.RequestError as e:
        print(f"HTTPX Error: {e}")
        return False, url

    except Exception as e:
        print(f"Error: {e}")
        return False, url