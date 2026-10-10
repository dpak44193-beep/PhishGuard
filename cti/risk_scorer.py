"""Map a calibrated score to a risk level and build human-readable explanations."""
from typing import Iterable

from cti.base import CTIResponse


DEFAULT_THRESHOLDS = {"safe": 0.25, "suspicious": 0.60}


def compute_risk_score(
    calibrated_score: float,
    cti_results: Iterable[CTIResponse],
    thresholds: dict[str, float] | None = None,
    ml_probability: float | None = None,
) -> tuple[float, str, list[str]]:
    """Returns (score 0-1, level string, explanation bullets)."""
    thresholds = thresholds or DEFAULT_THRESHOLDS
    score = round(min(max(float(calibrated_score), 0.0), 1.0), 4)

    safe_threshold = thresholds.get("safe", DEFAULT_THRESHOLDS["safe"])
    suspicious_threshold = thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"])

    by_source = {r.source: r for r in cti_results}
    has_cti_hit = any(r.hit for r in by_source.values())

    if score < safe_threshold:
        level = "safe"
    elif score < suspicious_threshold:
        level = "suspicious"
    elif has_cti_hit or score >= 0.985:
        level = "malicious"
    else:
        level = "suspicious"

    explanation: list[str] = []

    if ml_probability is not None and ml_probability > 0.5:
        explanation.append(f"ML classifier: {ml_probability:.1%} phishing probability")

    vt = by_source.get("virustotal")
    if vt and vt.hit:
        cnt = vt.details.get("malicious_count", "?")
        total = vt.details.get("total_engines", "?")
        explanation.append(f"VirusTotal: {cnt}/{total} engines flagged as malicious")

    uh = by_source.get("urlhaus")
    if uh and uh.hit:
        explanation.append("URL matches URLhaus malware/phishing database (abuse.ch)")

    ws = by_source.get("whois")
    if ws and ws.hit:
        age = ws.details.get("domain_age_days", ws.details.get("age_days", "?"))
        explanation.append(f"Domain is only {age} days old — newly registered domains carry elevated risk")

    if level == "suspicious" and score >= suspicious_threshold and not has_cti_hit:
        explanation.append("High model confidence without independent CTI corroboration")

    return score, level, explanation
