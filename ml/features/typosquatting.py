"""Typosquatting detection via Levenshtein distance against top brand domains."""

TOP_BRANDS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "ebay.com", "wellsfargo.com", "chase.com", "bankofamerica.com", "citibank.com",
    "dropbox.com", "adobe.com", "salesforce.com", "github.com", "stackoverflow.com",
    "yahoo.com", "gmail.com", "outlook.com", "live.com", "hotmail.com",
]


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def check_typosquatting(domain: str) -> dict:
    """
    Returns closest brand and edit distance.
    is_typosquatting = distance ≤ 2 and domain is not the brand itself.
    """
    domain = domain.lower().replace("www.", "")
    best_brand, best_dist = "", float("inf")
    for brand in TOP_BRANDS:
        d = levenshtein(domain, brand)
        if d < best_dist:
            best_dist = d
            best_brand = brand

    return {
        "closest_brand": best_brand,
        "edit_distance": int(best_dist),
        "is_typosquatting": best_dist <= 2 and domain != best_brand,
    }
