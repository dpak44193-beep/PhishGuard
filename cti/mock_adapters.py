"""Mock CTI adapters used when API keys are absent (CTI_MOCK=true)."""
import hashlib
import random

from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus


_TOTAL_ENGINES = 72


def _seed(url: str, source: str) -> int:
    digest = hashlib.sha256(f"{source}:{url}".encode("utf-8")).hexdigest()
    return int(digest[:16], 16)


def _rng(url: str, source: str) -> random.Random:
    return random.Random(_seed(url, source))


def _score(url: str, source: str, low: float, high: float) -> float:
    rng = _rng(url, source)
    return round(rng.uniform(low, high), 4)


def _skewed_low_score(url: str, source: str, alpha: float = 1.2, beta: float = 18.0) -> float:
    rng = _rng(url, source)
    return round(rng.betavariate(alpha, beta), 4)


class MockVirusTotalAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        score = _skewed_low_score(url, "virustotal", 1.4, 22.0)
        malicious = int(round(score * _TOTAL_ENGINES))
        hit = score >= 0.70
        return CTIResponse(
            source="virustotal",
            status=CTIStatus.MOCK,
            hit=hit,
            score=score,
            details={
                "stats": {"malicious": malicious, "harmless": _TOTAL_ENGINES - malicious, "suspicious": 0},
                "malicious_count": malicious,
                "total_engines": _TOTAL_ENGINES,
                "mock": True,
            },
        )


class MockURLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        score = _skewed_low_score(url, "urlhaus", 1.1, 28.0)
        hit = score >= 0.80
        return CTIResponse(
            source="urlhaus",
            status=CTIStatus.MOCK,
            hit=hit,
            score=score,
            details={"query_status": "is_db" if hit else "no_results", "mock": True},
        )


class MockWHOISAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        rng = _rng(url, "whois")
        age = int(rng.uniform(90, 5000))
        score = round(max(0.0, min(1.0, 1.0 - (age / 5000.0))), 4)
        hit = score >= 0.85
        return CTIResponse(
            source="whois",
            status=CTIStatus.MOCK,
            hit=hit,
            score=score,
            details={
                "domain_age_days": age,
                "registrar": "Mock Registrar LLC",
                "creation_date": "2022-01-01 00:00:00+00:00",
                "country": "US",
                "mock": True,
            },
        )
