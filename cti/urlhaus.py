"""URLhaus (abuse.ch) adapter — no API key required."""
import httpx
import time
from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

# Threat type → risk score (abuse.ch threat taxonomy)
_THREAT_SCORES: dict[str, float] = {
    "malware_download": 1.0,
    "phishing": 1.0,
    "botnet_cc": 0.9,
    "ransomware": 1.0,
    "exploit": 0.9,
    "coinminer": 0.7,
}


class URLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.post(URLHAUS_API, data={"url": url})
            data = resp.json()
            in_db = data.get("query_status") == "is_db"
            threat = data.get("threat") or ""
            score = _THREAT_SCORES.get(threat.lower(), 0.8) if in_db else 0.0
            return CTIResponse(
                source="urlhaus",
                status=CTIStatus.LIVE,
                hit=in_db,
                score=score,
                details={
                    "query_status": data.get("query_status"),
                    "threat": threat or None,
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                    "url_status": data.get("url_status"),
                } if in_db else {"query_status": data.get("query_status")},
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except httpx.TimeoutException:
            return CTIResponse(
                source="urlhaus",
                status=CTIStatus.TIMEOUT,
                hit=None,
                score=None,
                details={},
                error="URLhaus lookup timed out",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return CTIResponse(
                source="urlhaus",
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
