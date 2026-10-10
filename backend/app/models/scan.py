from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from app.models.threat import RiskLevel, ThreatIndicator


class ScanRequest(BaseModel):
    url: str
    source: str = "api"   # "api" | "extension" | "dashboard"


class ProviderStatus(str, Enum):
    LIVE = "live"
    MOCK = "mock"
    UNKNOWN = "unknown"
    ERROR = "error"
    TIMEOUT = "timeout"


class ScanMode(str, Enum):
    FULL = "full"
    DEGRADED = "degraded"
    ML_ONLY = "ml_only"
    FAILED = "failed"


class URLFeatures(BaseModel):
    url_length: int
    domain_length: int
    subdomain_count: int
    has_ip: bool
    uses_https: bool
    dot_count: int
    hyphen_count: int
    at_sign_count: int
    special_char_count: int
    digit_ratio: float
    entropy: float
    suspicious_keywords: int
    is_url_shortener: bool
    tld_risk: float
    path_depth: int
    query_param_count: int
    has_encoded_chars: bool
    double_slash_in_path: bool
    has_port: bool
    is_punycode: bool
    tilde_in_path: bool
    hex_in_domain: bool
    redirect_double_slash: bool
    domain_digit_count: int
    url_shortener_flag: int
    brand_count: int
    num_dots_in_path: int
    query_length: int
    fragment_present: bool
    multi_subdomain: int


class ProviderEvidence(BaseModel):
    provider: str
    status: ProviderStatus
    hit: Optional[bool] = None
    score: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: Optional[int] = None


class CTIResult(BaseModel):
    virustotal: Optional[ProviderEvidence] = None
    urlhaus: Optional[ProviderEvidence] = None
    whois: Optional[ProviderEvidence] = None
    enriched: bool = False


class MLEvidence(BaseModel):
    score: float
    model_version: Optional[str] = None
    thresholds: Dict[str, float] = Field(default_factory=dict)


class ScanEvidence(BaseModel):
    ml: MLEvidence
    cti: CTIResult


class ScanResult(BaseModel):
    id: Optional[str] = None
    url: str
    score: float
    risk_score: float
    level: RiskLevel
    verdict: RiskLevel
    scan_mode: ScanMode
    ml_probability: float
    features: Optional[URLFeatures] = None
    cti: Optional[CTIResult] = None
    evidence: Optional[ScanEvidence] = None
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    explanation: List[str] = Field(default_factory=list)
    scanned_at: Optional[datetime] = None
    source: str = "api"

    model_config = {"from_attributes": True}
