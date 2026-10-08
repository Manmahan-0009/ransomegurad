"""
RansomGuard - Unit Test for Directory Identity & Replay Parity (training/test_unique_directories.py)

Tests unique_directories parity across synthetic filesystem events:
1. Root file modification ("report.txt") -> directory "."
2. Nested directory file modification ("Documents/file.txt") -> directory "Documents"
3. Rename in same directory ("Documents/a.txt" -> "Documents/a.locked") -> directory "Documents"
4. Rename across directories ("Documents/b.txt" -> "Archive/b.locked") -> directories "Documents" and "Archive"

Verifies identical unique_directories count in live-like extraction and serialized+deserialized replay.
"""

import sys
import json
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from monitoring.event_schema import StructuredEvent
from features.extractor import extract_features, normalize_event_directory
from training.run_recorder import save_raw_events, load_raw_events


def test_unique_directories_semantics_and_replay_parity():
    # 1. Test normalize_event_directory helper explicitly
    assert normalize_event_directory("report.txt") == "."
    assert normalize_event_directory("Documents/file.txt") == "Documents"
    assert normalize_event_directory("Documents\\HR\\file.csv") == "Documents/HR"
    assert normalize_event_directory("C:/path/sandbox/demo_folder/Documents/HR/file.csv", Path("C:/path/sandbox/demo_folder")) == "Documents/HR"

    # 2. Construct synthetic event sequence
    events = [
        StructuredEvent(
            event_time=100.0,
            arrival_time=100.0,
            event_type="modified",
            src_path="report.txt",
            dest_path=None,
            extension=".txt",
            dest_extension=None,
            file_size=100,
        ),
        StructuredEvent(
            event_time=101.0,
            arrival_time=101.0,
            event_type="modified",
            src_path="Documents/file.txt",
            dest_path=None,
            extension=".txt",
            dest_extension=None,
            file_size=200,
        ),
        StructuredEvent(
            event_time=102.0,
            arrival_time=102.0,
            event_type="moved",
            src_path="Documents/a.txt",
            dest_path="Documents/a.locked",
            extension=".txt",
            dest_extension=".locked",
            file_size=200,
        ),
        StructuredEvent(
            event_time=103.0,
            arrival_time=103.0,
            event_type="moved",
            src_path="Documents/b.txt",
            dest_path="Archive/b.locked",
            extension=".txt",
            dest_extension=".locked",
            file_size=300,
        ),
    ]

    # Live-like extraction
    live_features = extract_features(events)
    # Expected directories: ".", "Documents", "Archive" => 3 unique directories
    assert live_features["unique_directories"] == 3, f"Expected 3 unique directories live, got {live_features['unique_directories']}"

    # 3. Test serialization & deserialization replay
    run_id = "test_synth_replay_001"
    save_raw_events(run_id, events)
    reloaded_events = load_raw_events(run_id)

    # Replay extraction
    replay_features = extract_features(reloaded_events)
    assert replay_features["unique_directories"] == live_features["unique_directories"], (
        f"Replay parity mismatch: live={live_features['unique_directories']} vs replay={replay_features['unique_directories']}"
    )
    print("  [OK] Unit test passed: unique_directories semantics and replay parity verified.")


if __name__ == "__main__":
    test_unique_directories_semantics_and_replay_parity()
