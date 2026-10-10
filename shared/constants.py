RISK_THRESHOLDS = {"safe": 0.30, "suspicious": 0.65}

RISK_WEIGHTS = {"ml": 0.40, "virustotal": 0.30, "urlhaus": 0.20, "whois": 0.10}

# Must match URLFeatureExtractor.FEATURE_ORDER exactly
FEATURE_ORDER = [
    "url_length", "domain_length", "subdomain_count", "has_ip",
    "uses_https", "dot_count", "hyphen_count", "at_sign_count",
    "special_char_count", "digit_ratio", "entropy", "suspicious_keywords",
    "is_url_shortener", "tld_risk", "path_depth", "query_param_count",
    "has_encoded_chars", "double_slash_in_path", "has_port", "is_punycode",
    "tilde_in_path", "hex_in_domain", "redirect_double_slash",
    "domain_digit_count", "url_shortener_flag", "brand_count",
    "num_dots_in_path", "query_length", "fragment_present", "multi_subdomain",
]

HIGH_RISK_TLDS = frozenset([
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".club", ".work", ".click", ".link", ".party", ".download",
    # Commonly abused new gTLDs
    ".shop", ".store", ".online", ".site", ".icu", ".vip",
    ".buzz", ".cam", ".cyou", ".fun", ".monster", ".uno",
])

SUSPICIOUS_KEYWORDS = frozenset([
    "login", "signin", "secure", "verify", "account", "update",
    "banking", "password", "credential", "authenticate", "confirm", "wallet",
    "suspended", "unusual", "alert", "notification",
])
