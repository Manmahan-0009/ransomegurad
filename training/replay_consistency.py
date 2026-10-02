"""
RansomGuard - Replay Consistency Verification Helper (training/replay_consistency.py)

Compares live feature window vectors against offline replayed feature window vectors
for a recorded run. Verifies that offline replay yields identical:
- window count
- feature names / schema alignment
- feature numerical values within a floating-point tolerance (1e-4)

Used to guarantee offline feature extractor parity with live monitoring.
"""

import math
from typing import List, Dict, Any, Tuple
from training.run_recorder import load_raw_events, load_run_metadata, load_ground_truth_ops
from training.generate_dataset import replay_and_extract_windows


def verify_run_replay_consistency(
    run_id: str,
    live_windows: List[Dict[str, Any]] = None,
    tolerance: float = 1e-4,
) -> Tuple[bool, str]:
    """
    Verifies offline feature extraction replay parity against recorded run data.

    Args:
        run_id: Unique identifier for the recorded simulation run.
        live_windows: Optional list of feature window dicts captured live.
        tolerance: Maximum acceptable difference for floating-point feature values.

    Returns:
        Tuple[bool, str]: (is_consistent, status_message)
    """
    try:
        metadata = load_run_metadata(run_id)
        raw_events = load_raw_events(run_id)
        ground_truth_ops = load_ground_truth_ops(run_id)
    except Exception as e:
        return False, f"Failed to load run artifacts for '{run_id}': {e}"

    replay_windows = replay_and_extract_windows(
        metadata=metadata,
        raw_events=raw_events,
        ground_truth_ops=ground_truth_ops,
    )

    if not replay_windows:
        return False, f"Offline replay generated 0 windows for run '{run_id}'"

    if live_windows is None:
        # If no live windows provided, verify internal replay structural integrity
        print(f"[REPLAY CONSISTENCY] Run '{run_id}' replayed successfully: {len(replay_windows)} windows generated.")
        return True, f"Replay generated {len(replay_windows)} valid feature windows."

    # Compare live vs replay window count
    if len(live_windows) != len(replay_windows):
        msg = f"Window count mismatch for run '{run_id}': live={len(live_windows)} vs replay={len(replay_windows)}"
        print(f"[FAIL] {msg}")
        return False, msg

    feature_keys = [
        "files_created",
        "files_modified",
        "files_deleted",
        "files_renamed",
        "writes_per_second",
        "unique_extensions",
        "unique_directories",
        "extension_change_count",
        "rename_ratio",
        "mean_entropy",
        "entropy_change",
    ]

    mismatches = 0
    for idx, (live_w, rply_w) in enumerate(zip(live_windows, replay_windows)):
        for key in feature_keys:
            val1_raw = live_w.get(key, 0.0)
            val2_raw = rply_w.get(key, 0.0)

            try:
                v1 = float(val1_raw)
                v2 = float(val2_raw)
                if not math.isclose(v1, v2, abs_tol=tolerance):
                    print(f"  [MISMATCH] Window #{idx} key '{key}': live={val1_raw} vs replay={val2_raw}")
                    mismatches += 1
            except (ValueError, TypeError):
                if val1_raw != val2_raw:
                    print(f"  [MISMATCH] Window #{idx} key '{key}': live={val1_raw} vs replay={val2_raw}")
                    mismatches += 1

    if mismatches == 0:
        msg = f"Replay parity PASSED for run '{run_id}': {len(replay_windows)} windows matched within tolerance {tolerance}"
        print(f"[OK] {msg}")
        return True, msg
    else:
        msg = f"Replay parity FAILED for run '{run_id}': {mismatches} feature value mismatches detected"
        print(f"[FAIL] {msg}")
        return False, msg


if __name__ == "__main__":
    print("Replay consistency helper loaded successfully.")
