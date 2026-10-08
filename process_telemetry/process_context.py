"""
RansomGuard - Process Context Schema (process_telemetry/process_context.py)

Defines normalized ProcessContext representation for process telemetry layer.
Enforces type safety: pid and parent_pid must strictly be integer or None.
Separates process identity from simulation/run identity.
"""
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


def _clean_pid(val: Any) -> Optional[int]:
    """Ensures PID is an integer or None. Converts valid numeric strings safely."""
    if val is None:
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, float):
        return int(val) if val >= 0 else None
    if isinstance(val, str):
        try:
            cleaned = val.strip()
            return int(cleaned)
        except (ValueError, TypeError):
            return None
    return None


@dataclass
class ProcessContext:
    """
    Metadata representation of an OS process responsible for or associated with file activity.
    """
    # Process Identity
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    username: Optional[str] = None
    command_line_optional: Optional[str] = None
    process_start_time: Optional[float] = None
    attribution_confidence: str = "UNKNOWN"  # DIRECT, CORRELATED_HIGH, CORRELATED_LOW, UNKNOWN

    # Separate Simulation / Run Identity (Optional)
    simulator_type: Optional[str] = None     # "attack", "benign", "normal", None
    run_id: Optional[str] = None             # e.g. "attack_seed_42"

    def __post_init__(self):
        self.pid = _clean_pid(self.pid)
        self.parent_pid = _clean_pid(self.parent_pid)
        valid_conf = ("DIRECT", "CORRELATED_HIGH", "CORRELATED_LOW", "UNKNOWN")
        if self.attribution_confidence not in valid_conf:
            self.attribution_confidence = "UNKNOWN"

    def to_dict(self, include_cmdline: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if not include_cmdline:
            data.pop("command_line_optional", None)
        return data

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ProcessContext":
        if not data:
            return cls()
        return cls(
            pid=_clean_pid(data.get("pid")),
            process_name=data.get("process_name"),
            executable_path=data.get("executable_path"),
            parent_pid=_clean_pid(data.get("parent_pid")),
            parent_process_name=data.get("parent_process_name"),
            username=data.get("username"),
            command_line_optional=data.get("command_line_optional"),
            process_start_time=data.get("process_start_time"),
            attribution_confidence=data.get("attribution_confidence", "UNKNOWN"),
            simulator_type=data.get("simulator_type"),
            run_id=data.get("run_id"),
        )
