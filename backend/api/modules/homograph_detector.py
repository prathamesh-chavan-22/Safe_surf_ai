# Define scripts considered suspicious for URLs (non-Latin)
SUSPICIOUS_SCRIPTS = ["CYRILLIC", "GREEK", "ARMENIAN", "GEORGIAN", "CHEROKEE"]
import unicodedata

def extract_unicode_info(char):
    """
    Get the Unicode name of a character.
    """
    try:
        return unicodedata.name(char)
    except ValueError:
        return "UNKNOWN CHARACTER"

def is_homograph(text):
    """
    Detects if the given text contains non-Latin lookalike Unicode characters.
    Returns True if such characters are found.
    """
    suspicious_chars = []

    for ch in text:
        name = extract_unicode_info(ch)
        if any(script in name for script in SUSPICIOUS_SCRIPTS):
            suspicious_chars.append((ch, name))

    return len(suspicious_chars) > 0, suspicious_chars
