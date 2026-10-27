"""Turns a link into a list of 14 numbers (features) that the AI model can learn from."""
import re
from urllib.parse import urlparse

BAIT_WORDS = ["login", "verify", "secure", "account", "update", "bank",
              "confirm", "password", "signin", "wallet", "billing"]
RISKY_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "country"]


def extract_features(url):
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)  # split the link into parts
    host = parsed.netloc.split("@")[-1].lower()
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    host_only = host.split(":")[0]
    parts = host_only.split(".")
    tld = parts[-1] if parts else ""  # domain ending, like com or xyz
    low = url.lower()

    digits = sum(c.isdigit() for c in url)
    return [
        len(url),                                                    # 1 total length
        len(host_only),                                              # 2 domain length
        len(path),                                                   # 3 path length
        url.count("."),                                              # 4 number of dots
        host_only.count("-"),                                        # 5 hyphens in the domain
        digits / max(len(url), 1),                                   # 6 share of digits
        max(len(parts) - 2, 0),                                      # 7 number of subdomains
        1 if "@" in url else 0,                                      # 8 contains @
        1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_only) else 0,  # 9 IP address as domain
        1 if url.lower().startswith("https://") else 0,              # 10 uses HTTPS
        1 if ":" in host else 0,                                     # 11 custom port
        sum(url.count(c) for c in "?=&%_~"),                         # 12 special characters
        sum(1 for w in BAIT_WORDS if w in low),                      # 13 bait words
        1 if tld in RISKY_TLDS else 0,                               # 14 risky domain ending
    ]
