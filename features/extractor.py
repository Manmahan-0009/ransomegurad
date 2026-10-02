"""
RansomGuard - Feature Extractor Module (features/extractor.py)

Unified feature extraction engine for RansomGuard.
Calculates clean behavioral feature vectors from a window of structured filesystem events.
Used identically across live monitoring, dataset generation, model training, and replay.
"""

import os
from pathlib import Path
from typing import List, Dict, Any
from monitoring.event_schema import StructuredEvent
from utils.sandbox_manager import get_demo_dir
from features.entropy import calculate_file_entropy, get_entropy_tracker


def extract_features(
    events: List[StructuredEvent],
    window_seconds: float = 5.0
) -> Dict[str, Any]:
    """
    Extracts an 11-dimensional behavioral feature vector from a list of structured events.

    Args:
        events: List of StructuredEvent objects occurring within the current window.
        window_seconds: Duration of the sliding window in seconds (default: 5.0).

    Returns:
        Dict[str, Any]: Dictionary containing consistent feature keys and ordering.
    """
    if not events or window_seconds <= 0:
        return {
            "files_created": 0,
            "files_modified": 0,
            "files_deleted": 0,
            "files_renamed": 0,
            "writes_per_second": 0.0,
            "unique_extensions": 0,
            "unique_directories": 0,
            "extension_change_count": 0,
            "rename_ratio": 0.0,
            "mean_entropy": 0.0,
            "entropy_change": 0.0,
        }

    demo_dir = get_demo_dir()
    tracker = get_entropy_tracker()

    files_created = 0
    files_modified = 0
    files_deleted = 0
    files_renamed = 0
    extension_change_count = 0

    extensions_set = set()
    directories_set = set()

    entropy_readings: List[float] = []
    entropy_deltas: List[float] = []

    total_events = len(events)

    for evt in events:
        evt_type = evt.event_type.lower()
        src_rel = evt.src_path

        # Track directory
        if src_rel:
            parent_dir = os.path.dirname(src_rel)
            directories_set.add(parent_dir if parent_dir else ".")

        # Track extension
        if evt.extension:
            extensions_set.add(evt.extension.lower())

        if evt_type == "created":
            files_created += 1
        elif evt_type == "modified":
            files_modified += 1
        elif evt_type == "deleted":
            files_deleted += 1
        elif evt_type == "moved":
            files_renamed += 1

            if evt.dest_extension:
                extensions_set.add(evt.dest_extension.lower())

            # Count extension changes (e.g. .txt -> .locked)
            src_ext = (evt.extension or "").lower()
            dest_ext = (evt.dest_extension or "").lower()
            if dest_ext and src_ext != dest_ext:
                extension_change_count += 1

        # Entropy measurement for created or modified files
        if evt_type in ["created", "modified"] and src_rel:
            if evt.entropy is not None:
                entropy_readings.append(evt.entropy)
                if evt.entropy_delta is not None:
                    entropy_deltas.append(evt.entropy_delta)
            else:
                abs_path = demo_dir / src_rel
                ent = calculate_file_entropy(abs_path)
                if ent is not None:
                    entropy_readings.append(ent)
                    delta = tracker.update_entropy(src_rel, ent)
                    if delta is not None:
                        entropy_deltas.append(delta)

    # Derived aggregations
    writes_per_second = round((files_created + files_modified) / window_seconds, 4)
    rename_ratio = round(files_renamed / total_events, 4) if total_events > 0 else 0.0

    mean_entropy = (
        round(sum(entropy_readings) / len(entropy_readings), 4)
        if entropy_readings else 0.0
    )

    entropy_change = (
        round(sum(entropy_deltas) / len(entropy_deltas), 4)
        if entropy_deltas else 0.0
    )

    return {
        "files_created": files_created,
        "files_modified": files_modified,
        "files_deleted": files_deleted,
        "files_renamed": files_renamed,
        "writes_per_second": writes_per_second,
        "unique_extensions": len(extensions_set),
        "unique_directories": len(directories_set),
        "extension_change_count": extension_change_count,
        "rename_ratio": rename_ratio,
        "mean_entropy": mean_entropy,
        "entropy_change": entropy_change,
    }
