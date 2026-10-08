from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class FeatureWindow(BaseModel):
    """
    Behavioral features produced by RansomGuard telemetry.
    """

    files_created: int = Field(ge=0)
    files_modified: int = Field(ge=0)
    files_deleted: int = Field(ge=0)
    files_renamed: int = Field(ge=0)

    writes_per_second: float = Field(ge=0)

    unique_extensions: int = Field(ge=0)
    unique_directories: int = Field(ge=0)

    extension_change_count: int = Field(ge=0)

    rename_ratio: float = Field(ge=0, le=1)

    mean_entropy: float = Field(ge=0)

    entropy_change: float

    # Optional metadata fields for live prediction logging and scenario tracking
    scenario_id: Optional[str] = "live"
    window_start: Optional[str] = None
    window_end: Optional[str] = None


class AgentRegistration(BaseModel):
    device_id: str
    hostname: str
    os: str
    agent_version: str = "3.0-dev"
    model_version: str = "rf_v2"
    feature_schema_version: str = "v1"
    started_at: float


class AgentHeartbeat(BaseModel):
    device_id: str
    timestamp: float
    status: str = "ONLINE"
    current_severity: str = "LOW"
    current_threat_score: float = Field(ge=0.0, le=100.0, default=0.0)
    last_prediction: str = "BENIGN"
    model_version: str = "rf_v2"


def sanitize_process_payload(proc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not proc or not isinstance(proc, dict):
        return None
    res = dict(proc)
    pid = res.get("pid")
    if pid is not None:
        try:
            res["pid"] = int(pid)
        except (ValueError, TypeError):
            res["pid"] = None

    parent_pid = res.get("parent_pid")
    if parent_pid is not None:
        try:
            res["parent_pid"] = int(parent_pid)
        except (ValueError, TypeError):
            res["parent_pid"] = None

    conf = res.get("attribution_confidence", "UNKNOWN")
    if conf not in ("DIRECT", "CORRELATED_HIGH", "CORRELATED_LOW", "UNKNOWN"):
        res["attribution_confidence"] = "UNKNOWN"

    return res


class AgentTelemetry(BaseModel):
    device_id: str
    timestamp: float
    prediction: str
    threat_probability: float = Field(ge=0.0, le=1.0, default=0.0)
    benign_probability: float = Field(ge=0.0, le=1.0, default=1.0)
    rule_score: int = Field(ge=0, default=0)
    threat_score: float = Field(ge=0.0, le=100.0, default=0.0)
    severity: str = "LOW"
    confirmed_alert: bool = False
    triggered_rules: List[str] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)
    dominant_process: Optional[Dict[str, Any]] = None
    processes: Optional[List[Dict[str, Any]]] = None
    model_version: str = "rf_v2"
    feature_schema_version: str = "v1"

    def model_post_init(self, __context):
        if self.dominant_process:
            self.dominant_process = sanitize_process_payload(self.dominant_process)
        if self.processes:
            self.processes = [p for p in (sanitize_process_payload(pr) for pr in self.processes) if p]


class AgentAlert(BaseModel):
    alert_id: str
    device_id: str
    timestamp: float
    severity: str = "HIGH"
    prediction: str = "THREAT"
    threat_score: float = Field(ge=0.0, le=100.0, default=75.0)
    threat_probability: float = Field(ge=0.0, le=1.0, default=1.0)
    triggered_rules: List[str] = Field(default_factory=list)
    confirmed: bool = True
    containment_status: str = "NONE"
    primary_process: Optional[Dict[str, Any]] = None
    process_attribution_confidence: Optional[str] = "UNKNOWN"
    process_summary: Optional[List[Dict[str, Any]]] = None
    canary_triggered: bool = False
    canary_id: Optional[str] = None
    canary_event_type: Optional[str] = None
    early_confirmation: bool = False
    confirmation_source: str = "STANDARD_DEBOUNCE"

    def model_post_init(self, __context):
        if self.primary_process:
            self.primary_process = sanitize_process_payload(self.primary_process)
            if self.primary_process:
                self.process_attribution_confidence = self.primary_process.get("attribution_confidence", "UNKNOWN")
        if self.process_summary:
            self.process_summary = [p for p in (sanitize_process_payload(pr) for pr in self.process_summary) if p]