"""
RansomGuard - Run Recorder Module (training/run_recorder.py)

Manages saving and loading of run metadata, raw event JSONL logs,
and ground-truth attack operation records.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from utils.sandbox_manager import get_project_root
from monitoring.event_schema import StructuredEvent, get_file_extension


def get_data_dir() -> Path:
    """Returns absolute path to the data directory."""
    data_dir = get_project_root() / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_raw_events_dir() -> Path:
    d = get_data_dir() / "raw_events"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_run_metadata_dir() -> Path:
    d = get_data_dir() / "run_metadata"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_datasets_dir() -> Path:
    d = get_data_dir() / "datasets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_splits_dir() -> Path:
    d = get_data_dir() / "splits"
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_run_id(cls_name: str, index: int = 1) -> str:
    """
    Generates a deterministic, readable run ID.
    Example: 'normal_20261002_001'
    """
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{cls_name.lower()}_{ts_str}_{index:03d}"


def save_run_metadata(metadata: Dict[str, Any]) -> Path:
    """
    Saves run metadata dictionary to data/run_metadata/<run_id>.json.
    """
    run_id = metadata["run_id"]
    filepath = get_run_metadata_dir() / f"{run_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    return filepath


def load_run_metadata(run_id: str) -> Dict[str, Any]:
    """
    Loads metadata JSON for a given run_id.
    """
    filepath = get_run_metadata_dir() / f"{run_id}.json"
    if not filepath.exists():
        raise FileNotFoundError(f"Run metadata file not found: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_ground_truth_ops(run_id: str, ops: List[Dict[str, Any]]) -> Path:
    """
    Saves ground-truth attack operation records to data/run_metadata/<run_id>_attack_ops.jsonl.
    """
    filepath = get_run_metadata_dir() / f"{run_id}_attack_ops.jsonl"
    with open(filepath, "w", encoding="utf-8") as f:
        for op in ops:
            f.write(json.dumps(op) + "\n")
    return filepath


def load_ground_truth_ops(run_id: str) -> List[Dict[str, Any]]:
    """
    Loads ground-truth attack operations JSONL for a given run_id.
    Returns empty list if file does not exist (e.g. for normal/benign runs).
    """
    filepath = get_run_metadata_dir() / f"{run_id}_attack_ops.jsonl"
    if not filepath.exists():
        return []
    ops = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ops.append(json.loads(line.strip()))
    return ops


def save_raw_events(run_id: str, events: List[StructuredEvent]) -> Path:
    """
    Saves structured raw events for a run to data/raw_events/<run_id>.jsonl.
    """
    filepath = get_raw_events_dir() / f"{run_id}.jsonl"
    with open(filepath, "w", encoding="utf-8") as f:
        for evt in events:
            row_dict = evt.to_dict()
            row_dict["run_id"] = run_id
            f.write(json.dumps(row_dict) + "\n")
    return filepath


def load_raw_events(run_id: str) -> List[StructuredEvent]:
    """
    Replays raw events from data/raw_events/<run_id>.jsonl into StructuredEvent objects.
    """
    filepath = get_raw_events_dir() / f"{run_id}.jsonl"
    if not filepath.exists():
        raise FileNotFoundError(f"Raw event file not found: {filepath}")

    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line.strip())
            evt = StructuredEvent(
                event_time=data["event_time"],
                arrival_time=data["arrival_time"],
                event_type=data["event_type"],
                src_path=data["src_path"],
                dest_path=data.get("dest_path"),
                extension=data.get("extension", get_file_extension(data["src_path"])),
                dest_extension=data.get("dest_extension"),
                file_size=data.get("file_size", 0),
                entropy=data.get("entropy"),
                entropy_delta=data.get("entropy_delta"),
            )
            events.append(evt)
    return events
