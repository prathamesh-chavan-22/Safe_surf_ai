from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time
from utils import clean_url


def trace_redirection(url: str, verbose: bool = False):
    """
    Launches a headless Chrome browser to trace redirections.

    Args:
        url (str): The URL to trace.
        verbose (bool): Whether to print debug output.

    Returns:
        list[str]: List of visited URLs in redirection chain.
    """
    options = Options()
    options.add_argument("--headless=new")  # Use new headless mode (Chrome 109+)
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")

    driver = webdriver.Chrome(options=options)

    visited = []
    seen = set()

    try:
        if verbose:
            print(f"[Start] Navigating to {url}")

        driver.get(url)
        time.sleep(5)  # Give time for meta/JS-based redirects

        current_url = clean_url(driver.current_url)
        if verbose:
            print(f"[Landed] {current_url}")

        if current_url not in seen:
            visited.append(current_url)
            seen.add(current_url)

    except Exception as e:
        if verbose:
            print("[Error]", str(e))
        visited.append(url)

    finally:
        driver.quit()

    return visited
