"""Conservative URL normalization for consistent feature extraction and CTI lookup."""
from urllib.parse import urlparse, urlunparse


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    normalized = parsed._replace(
        scheme=scheme,
        netloc=netloc,
    )
    return urlunparse(normalized)
