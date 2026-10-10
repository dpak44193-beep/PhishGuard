"""VirusTotal v3 URL reputation adapter."""
import asyncio
import base64
import time
import httpx
from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus

VT_BASE = "https://www.virustotal.com/api/v3"
_VT_MIN_GAP = 15.1   # free tier: 4 req/min → 1 per ~15 s
_vt_lock = asyncio.Lock()
_vt_last_call: float = 0.0


class VirusTotalAdapter(BaseCTIAdapter):
    def __init__(self, api_key: str):
        self._headers = {"x-apikey": api_key}

    async def lookup(self, url: str) -> CTIResponse:
        global _vt_last_call
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        started = time.perf_counter()
        try:
            async with _vt_lock:
                gap = time.monotonic() - _vt_last_call
                if gap < _VT_MIN_GAP:
                    await asyncio.sleep(_VT_MIN_GAP - gap)
                _vt_last_call = time.monotonic()

            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=self._headers)

                if resp.status_code == 429:
                    # Rate limit hit — back off and return neutral
                    await asyncio.sleep(60)
                    return CTIResponse(
                        source="virustotal",
                        status=CTIStatus.ERROR,
                        hit=None,
                        score=None,
                        details={"status": "rate_limited"},
                        error="VirusTotal rate limit exceeded",
                        latency_ms=int((time.perf_counter() - started) * 1000),
                    )

                if resp.status_code == 404:
                    await client.post(f"{VT_BASE}/urls", data={"url": url}, headers=self._headers)
                    return CTIResponse(
                        source="virustotal",
                        status=CTIStatus.LIVE,
                        hit=False,
                        score=0.0,
                        details={"status": "submitted_for_analysis"},
                        latency_ms=int((time.perf_counter() - started) * 1000),
                    )

                data = resp.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                # Weight suspicious hits at 0.5 so partial signals aren't lost
                score = (malicious + 0.5 * suspicious) / total

                return CTIResponse(
                    source="virustotal",
                    status=CTIStatus.LIVE,
                    hit=malicious > 0 or suspicious > 1,
                    score=round(score, 4),
                    details={
                        "stats": stats,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_engines": total,
                    },
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
        except httpx.TimeoutException:
            return CTIResponse(
                source="virustotal",
                status=CTIStatus.TIMEOUT,
                hit=None,
                score=None,
                details={},
                error="VirusTotal lookup timed out",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return CTIResponse(
                source="virustotal",
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
