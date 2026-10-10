"""
Download real-world phishing + legitimate URL datasets and save as
ml/data/raw/labeled_urls.csv (columns: url, label — 1=phishing, 0=legit).

Sources:
  Phishing : PhishTank verified feed  (no key needed for community access)
             + Mitchell K phishing DB (GitHub, no key needed)
  Legitimate: Tranco top-1M list      (no key needed)

Usage (from repo root):
    python ml/data/download_dataset.py
    python ml/data/download_dataset.py --phish 5000 --legit 5000
"""
import argparse
import csv
import io
import logging
import random
import sys
import zipfile
from pathlib import Path

import httpx

# Suffix pool for legit URL augmentation.
# Weights toward "" so ~30 % stay as bare-domain roots; the rest get a path.
_LEGIT_PATH_SUFFIXES = [
    "", "", "", "", "",
    "/about", "/products", "/services", "/blog", "/news",
    "/help", "/support", "/contact", "/docs", "/search",
    "/careers", "/terms", "/privacy", "/faq", "/press",
    "/about/team", "/products/overview", "/blog/latest",
    "/help/faq", "/docs/overview", "/docs/getting-started",
]

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

OUT_PATH = Path(__file__).parent / "raw" / "labeled_urls.csv"

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
MITCHELLK_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database"
    "/master/phishing-links-ACTIVE.txt"
)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def fetch_phishtank(limit: int, client: httpx.Client) -> list[str]:
    log.info("Fetching PhishTank feed…")
    try:
        resp = client.get(PHISHTANK_URL, timeout=60, follow_redirects=True)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        urls = []
        for row in reader:
            url = row.get("url", "").strip()
            if url.startswith("http"):
                urls.append(url)
            if len(urls) >= limit:
                break
        log.info(f"PhishTank: {len(urls)} URLs")
        return urls
    except Exception as exc:
        log.warning(f"PhishTank failed ({exc}) — trying fallback source…")
        return []


def fetch_mitchellk(limit: int, client: httpx.Client) -> list[str]:
    log.info("Fetching Mitchell K phishing DB…")
    try:
        resp = client.get(MITCHELLK_URL, timeout=60, follow_redirects=True)
        resp.raise_for_status()
        urls = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.append(line)
            if len(urls) >= limit:
                break
        log.info(f"Mitchell K DB: {len(urls)} URLs")
        return urls
    except Exception as exc:
        log.warning(f"Mitchell K DB failed ({exc})")
        return []


def fetch_tranco(limit: int, client: httpx.Client) -> list[str]:
    log.info("Fetching Tranco top-1M list…")
    rng = random.Random(42)
    try:
        resp = client.get(TRANCO_URL, timeout=120, follow_redirects=True)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            name = zf.namelist()[0]
            with zf.open(name) as f:
                reader = csv.reader(io.TextIOWrapper(f))
                urls = []
                for row in reader:
                    if len(row) >= 2:
                        domain = row[1].strip()
                        # Augment ~70 % of entries with a path suffix so the model
                        # sees legitimate URLs at various path depths, not just root.
                        suffix = rng.choice(_LEGIT_PATH_SUFFIXES)
                        urls.append(f"https://{domain}{suffix}")
                    if len(urls) >= limit:
                        break
        log.info(f"Tranco: {len(urls)} URLs")
        return urls
    except Exception as exc:
        log.warning(f"Tranco failed ({exc})")
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Download phishing + legit URL dataset")
    parser.add_argument("--phish", type=int, default=5000, help="Phishing URLs to collect")
    parser.add_argument("--legit", type=int, default=5000, help="Legitimate URLs to collect")
    args = parser.parse_args()

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with httpx.Client(headers={"User-Agent": "PhishGuard-DataCollector/1.0"}) as client:
        phish_urls = fetch_phishtank(args.phish, client)
        if len(phish_urls) < args.phish:
            extra = fetch_mitchellk(args.phish - len(phish_urls), client)
            phish_urls.extend(extra)

        legit_urls = fetch_tranco(args.legit, client)

    if not phish_urls:
        log.error("No phishing URLs collected — aborting.")
        sys.exit(1)
    if not legit_urls:
        log.error("No legitimate URLs collected — aborting.")
        sys.exit(1)

    phish_urls = list(dict.fromkeys(phish_urls))[:args.phish]
    legit_urls = list(dict.fromkeys(legit_urls))[:args.legit]

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url in phish_urls:
            writer.writerow([url, 1])
        for url in legit_urls:
            writer.writerow([url, 0])

    total = len(phish_urls) + len(legit_urls)
    log.info(f"Saved {total} rows → {OUT_PATH}")
    log.info(f"  Phishing : {len(phish_urls)}")
    log.info(f"  Legitimate: {len(legit_urls)}")
    log.info("Now run:  python ml/train.py")


if __name__ == "__main__":
    main()
