"""Shared event dataclass used by all detectors."""

from dataclasses import dataclass, field


@dataclass
class DetectorEvent:
    detector: str
    threat: str
    source_ip: str | None
    pid: int | None
    confidence: str
    evidence: dict = field(default_factory=dict)
    notes: str = ""
