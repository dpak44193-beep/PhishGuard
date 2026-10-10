from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CTIStatus(str, Enum):
    LIVE = "live"
    MOCK = "mock"
    UNKNOWN = "unknown"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class CTIResponse:
    source: str
    status: CTIStatus
    hit: Optional[bool]
    score: Optional[float]  # 0.0 – 1.0; higher = more malicious
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: Optional[int] = None

    @property
    def available(self) -> bool:
        return self.status in {CTIStatus.LIVE, CTIStatus.MOCK}


class BaseCTIAdapter(ABC):
    @abstractmethod
    async def lookup(self, url: str) -> CTIResponse: ...
