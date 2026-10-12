"""Non-network CTI placeholders used when CTI_MOCK=true."""
from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus


class _UnavailableMockAdapter(BaseCTIAdapter):
    source: str

    async def lookup(self, url: str) -> CTIResponse:
        return CTIResponse(
            source=self.source,
            status=CTIStatus.MOCK,
            hit=None,
            score=None,
            details={
                "mock": True,
                "provider_request_performed": False,
            },
        )


class MockVirusTotalAdapter(_UnavailableMockAdapter):
    source = "virustotal"


class MockURLhausAdapter(_UnavailableMockAdapter):
    source = "urlhaus"


class MockWHOISAdapter(_UnavailableMockAdapter):
    source = "whois"
