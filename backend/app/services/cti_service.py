import sys
from pathlib import Path
import asyncio
from typing import List

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.config import settings
from cti.base import CTIResponse, CTIStatus  # noqa: E402

_PROVIDER_ORDER = ("virustotal", "urlhaus", "whois")


def _build_provider_plan():
    if settings.cti_mock:
        from cti.mock_adapters import MockVirusTotalAdapter, MockURLhausAdapter, MockWHOISAdapter

        return {
            "virustotal": MockVirusTotalAdapter(),
            "urlhaus": MockURLhausAdapter(),
            "whois": MockWHOISAdapter(),
        }

    from cti.urlhaus import URLhausAdapter
    from cti.whois_lookup import WHOISAdapter

    plan = {
        "urlhaus": URLhausAdapter(),
        "whois": WHOISAdapter(),
    }

    if settings.virustotal_api_key:
        from cti.virustotal import VirusTotalAdapter

        plan["virustotal"] = VirusTotalAdapter(settings.virustotal_api_key)
    else:
        plan["virustotal"] = None

    return plan


async def enrich(url: str) -> List[CTIResponse]:
    plan = _build_provider_plan()
    tasks: list[tuple[str, asyncio.Future]] = []
    responses: dict[str, CTIResponse] = {}

    for provider in _PROVIDER_ORDER:
        adapter = plan.get(provider)
        if adapter is None:
            responses[provider] = CTIResponse(
                source=provider,
                status=CTIStatus.UNKNOWN,
                hit=None,
                score=None,
                details={},
                error="Provider not configured",
            )
            continue
        tasks.append((provider, asyncio.ensure_future(adapter.lookup(url))))

    if tasks:
        results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
        for (provider, _), result in zip(tasks, results):
            if isinstance(result, CTIResponse):
                responses[provider] = result
            else:
                responses[provider] = CTIResponse(
                    source=provider,
                    status=CTIStatus.ERROR,
                    hit=None,
                    score=None,
                    details={},
                    error=str(result),
                )

    return [responses[provider] for provider in _PROVIDER_ORDER]
