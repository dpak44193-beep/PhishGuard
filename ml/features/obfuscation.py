"""Decode and normalize common URL obfuscation techniques."""
import re
import urllib.parse


def decode_url(url: str) -> str:
    """Best-effort canonical form of an obfuscated URL."""
    url = _decode_percent_encoding(url)
    url = _decode_hex_ip(url)
    url = _decode_octal_ip(url)
    return url


def detect_obfuscation_signals(url: str) -> list[str]:
    signals = []
    if "%" in url:
        signals.append("percent_encoding")
    if re.search(r"0x[0-9a-fA-F]+", url):
        signals.append("hex_ip")
    if re.search(r"\b0\d+\.0\d+\.0\d+\.0\d+\b", url):
        signals.append("octal_ip")
    if "xn--" in url.lower():
        signals.append("punycode_idn")
    if url.count("//") > 1:
        signals.append("double_slash_redirect")
    if "@" in url:
        signals.append("at_sign_misdirect")
    return signals


def _decode_percent_encoding(url: str) -> str:
    try:
        return urllib.parse.unquote(url)
    except Exception:
        return url


def _decode_hex_ip(url: str) -> str:
    def _replace(m: re.Match) -> str:
        try:
            return str(int(m.group(0), 16))
        except ValueError:
            return m.group(0)
    return re.sub(r"0x[0-9a-fA-F]+", _replace, url)


def _decode_octal_ip(url: str) -> str:
    pattern = re.compile(r"\b0\d+\.0\d+\.0\d+\.0\d+\b")
    def _replace(m: re.Match) -> str:
        try:
            return ".".join(str(int(p, 8)) for p in m.group(0).split("."))
        except ValueError:
            return m.group(0)
    return pattern.sub(_replace, url)
