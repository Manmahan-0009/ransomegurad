"""
RansomGuard - Event Schema Module (monitoring/event_schema.py)

Defines the structured, normalized event representation for filesystem actions.
Converts raw Watchdog event objects into standardized Python dictionary / dataclass instances.
Includes optional persisted entropy fields to ensure offline replay parity.
"""

import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Any


@dataclass
class StructuredEvent:
    """
    Standardized event record representing a filesystem change inside sandbox/demo_folder.
    """
    event_time: float                     # Epoch timestamp when event occurred
    arrival_time: float                   # Epoch timestamp when event was received by watcher
    event_type: str                       # 'created', 'modified', 'moved', 'deleted'
    src_path: str                         # Relative path from sandbox/demo_folder
    dest_path: Optional[str]              # Relative destination path (for move events)
    extension: str                        # Source file extension (e.g. '.txt' or '')
    dest_extension: Optional[str]         # Destination file extension (for move events)
    file_size: int                        # File size in bytes (0 if unavailable or deleted)
    entropy: Optional[float] = None       # Persisted Shannon entropy reading (if calculated)
    entropy_delta: Optional[float] = None # Persisted entropy delta reading (if calculated)
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    username: Optional[str] = None
    process_path: Optional[str] = None
    attribution_confidence: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Converts structured event instance into a standard dictionary."""
        return asdict(self)


def get_file_extension(path_str: str) -> str:
    """Helper to extract lowercase file extension from a path string."""
    if not path_str:
        return ""
    ext = os.path.splitext(path_str)[1]
    return ext.lower() if ext else ""


def create_structured_event(
    event_type: str,
    src_rel_path: str,
    dest_rel_path: Optional[str] = None,
    abs_file_path: Optional[Path] = None,
    event_time: Optional[float] = None,
    entropy: Optional[float] = None,
    entropy_delta: Optional[float] = None,
    process_id: Optional[int] = None,
    process_name: Optional[str] = None,
    parent_process_id: Optional[int] = None,
    parent_process_name: Optional[str] = None,
    username: Optional[str] = None,
    process_path: Optional[str] = None,
    attribution_confidence: str = "UNKNOWN",
) -> StructuredEvent:
    """
    Factory function to construct a StructuredEvent from raw watcher parameters.
    """
    now = time.time()
    evt_time = event_time if event_time is not None else now
    
    src_ext = get_file_extension(src_rel_path)
    dest_ext = get_file_extension(dest_rel_path) if dest_rel_path else None
    
    file_size = 0
    if abs_file_path and abs_file_path.exists() and abs_file_path.is_file():
        try:
            file_size = abs_file_path.stat().st_size
        except Exception:
            file_size = 0

    return StructuredEvent(
        event_time=evt_time,
        arrival_time=now,
        event_type=event_type.lower(),
        src_path=src_rel_path,
        dest_path=dest_rel_path,
        extension=src_ext,
        dest_extension=dest_ext,
        file_size=file_size,
        entropy=entropy,
        entropy_delta=entropy_delta,
        process_id=process_id,
        process_name=process_name,
        parent_process_id=parent_process_id,
        parent_process_name=parent_process_name,
        username=username,
        process_path=process_path,
        attribution_confidence=attribution_confidence,
    )

