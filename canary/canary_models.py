"""
RansomGuard - Canary Data Models (canary/canary_models.py)

Data structures for registered canary files and normalized canary events.
"""

import time
import uuid
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class CanaryRecord:
    canary_id: str
    device_id: str
    file_path: str
    filename: str
    file_type: str
    created_at: float = field(default_factory=time.time)
    baseline_hash: str = ""
    baseline_size: int = 0
    baseline_entropy: float = 0.0
    enabled: bool = True
    last_verified_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanaryRecord":
        return cls(**data)


@dataclass
class CanaryEvent:
    canary_id: str
    device_id: str
    timestamp: float = field(default_factory=time.time)
    event_type: str = "MODIFIED"  # MODIFIED, RENAMED, DELETED, EXTENSION_CHANGED
    event_id: str = field(default_factory=lambda: f"cev-{uuid.uuid4().hex[:12]}")
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    process_context: Optional[Dict[str, Any]] = None
    attribution_confidence: str = "UNKNOWN"
    current_threat_probability: float = 0.0
    current_threat_score: float = 0.0
    current_rule_score: int = 0
    current_severity: str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanaryEvent":
        return cls(**data)
