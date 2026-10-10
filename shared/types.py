from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    type: str
    severity: str
    description: str
    source: str
    value: Optional[str] = None


@dataclass
class RiskScore:
    score: float
    level: RiskLevel
    ml_probability: float
    indicators: list[ThreatIndicator] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
