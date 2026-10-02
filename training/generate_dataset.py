"""
RansomGuard - Dataset Generator Module (training/generate_dataset.py)

Automates end-to-end dataset generation:
1. Resets sandbox environment.
2. Runs simulator (normal, benign, attack) while recording Watchdog events over a controlled observation lifecycle.
3. Saves raw events (JSONL), ground-truth attack operations, and run metadata.
4. Replays raw events through the EXACT Stage 2 pipeline:
   - EventDeduplicator (200ms)
   - SlidingWindowBuffer (5s window, 1s stride)
   - extract_features()
5. Computes ground-truth labels [window_start, window_end).
6. Exports feature rows to data/datasets/dataset_v1.csv.
"""

import csv
import sys
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from utils.sandbox_manager import reset_sandbox, get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from simulator.normal_simulator import run_normal_simulation
from simulator.benign_simulator import run_benign_simulation
from simulator.attack_simulator import run_attack_simulation

from training.run_recorder import (
    generate_run_id,
    save_run_metadata,
    save_raw_events,
    save_ground_truth_ops,
    get_datasets_dir,
    get_splits_dir,
    get_raw_events_dir,
    get_run_metadata_dir,
)
from training.label_windows import compute_window_label

PRE_OBSERVATION_SECONDS: float = 3.0
POST_OBSERVATION_SECONDS: float = 5.0

CSV_FIELDNAMES = [
    "run_id",
    "class",
    "window_start",
    "window_end",
    "label",
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


def clear_previous_dataset_artifacts() -> None:
    """
    Safely removes generated dataset artifacts when --fresh is specified.
    Never touches source code or sandbox/templates.
    """
    csv_path = get_datasets_dir() / "dataset_v1.csv"
    if csv_path.exists():
        csv_path.unlink()

    splits_dir = get_splits_dir()
    for fname in ["train.csv", "validation.csv", "test.csv", "split_manifest.json"]:
        f = splits_dir / fname
        if f.exists():
            f.unlink()

    raw_dir = get_raw_events_dir()
    for f in raw_dir.glob("*.jsonl"):
        f.unlink()

    meta_dir = get_run_metadata_dir()
    for f in meta_dir.glob("*.json"):
        f.unlink()
    for f in meta_dir.glob("*.jsonl"):
        f.unlink()

    print("[DATASET] Cleared previous dataset artifacts (--fresh mode active).")


def generate_single_run(
    cls_name: str,
    run_index: int = 1,
    duration: float = 15.0,
    speed: str = "medium",
    seed: Optional[int] = None,
    pre_observation_seconds: float = PRE_OBSERVATION_SECONDS,
    post_observation_seconds: float = POST_OBSERVATION_SECONDS,
) -> Dict[str, Any]:
    """
    Executes a single simulation run and records raw events & metadata.
    Decouples observation duration from simulator duration.
    """
    cls_lower = cls_name.lower()
    cls_upper = cls_lower.upper()
    run_id = generate_run_id(cls_lower, run_index)
    demo_dir = get_demo_dir()

    print(f"\n==================================================")
    print(f" [GENERATE RUN] ID: {run_id} | Class: {cls_upper}")
    print(f"==================================================")

    # 1. Reset sandbox
    reset_sandbox()

    # 2. Setup Event Queue & Watchdog Observer in background
    eq = EventQueue()
    start_ts = time.time()

    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    attack_start_time = None
    ground_truth_ops = []

    try:
        # Pre-observation baseline monitoring (default: 3.0s)
        time.sleep(pre_observation_seconds)

        # 3. Execute Simulator
        if cls_lower == "normal":
            run_normal_simulation(duration=duration, delay=2.0, seed=seed)
        elif cls_lower == "benign":
            run_benign_simulation(duration=duration, speed=speed, seed=seed)
        elif cls_lower == "attack":
            res = run_attack_simulation(speed=speed, max_files=20, seed=seed, run_id=run_id)
            attack_start_time = res.get("attack_start_time")
            ground_truth_ops = res.get("ground_truth_ops", [])
        else:
            raise ValueError(f"Unknown simulation class: {cls_name}")
    finally:
        # Post-observation grace period (default: 5.0s)
        time.sleep(post_observation_seconds)
        observer.stop()
        observer.join()

    end_ts = time.time()
    total_observation_duration = end_ts - start_ts

    # 4. Flush all raw events from queue
    raw_events = eq.flush()

    # 5. Save Raw Events & Metadata
    save_raw_events(run_id, raw_events)
    if ground_truth_ops:
        save_ground_truth_ops(run_id, ground_truth_ops)

    file_count = len([f for f in demo_dir.rglob("*") if f.is_file()])

    metadata = {
        "run_id": run_id,
        "class": cls_lower,
        "seed": seed,
        "speed": speed,
        "duration": duration,
        "pre_observation_seconds": pre_observation_seconds,
        "post_observation_seconds": post_observation_seconds,
        "total_observation_duration": total_observation_duration,
        "file_count": file_count,
        "simulator_version": "v1",
        "feature_schema_version": "v1",
        "window_seconds": 5.0,
        "stride_seconds": 1.0,
        "dedupe_ms": 200.0,
        "start_time": start_ts,
        "end_time": end_ts,
        "attack_start_time": attack_start_time,
        "raw_event_count": len(raw_events),
    }

    save_run_metadata(metadata)

    return {
        "metadata": metadata,
        "raw_events": raw_events,
        "ground_truth_ops": ground_truth_ops,
    }


def replay_and_extract_windows(
    metadata: Dict[str, Any],
    raw_events: List[Any],
    ground_truth_ops: List[Dict[str, Any]],
    window_seconds: float = 5.0,
    stride_seconds: float = 1.0,
    dedupe_ms: float = 200.0,
) -> List[Dict[str, Any]]:
    """
    Replays raw events through the Stage 2 pipeline to generate windowed feature rows.
    """
    run_id = metadata["run_id"]
    cls_name = metadata["class"]
    start_time = metadata["start_time"]
    end_time = metadata["end_time"]

    deduplicator = EventDeduplicator(dedupe_ms=dedupe_ms)
    window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)

    # Sort events chronologically by arrival_time
    sorted_events = sorted(raw_events, key=lambda e: e.arrival_time) if raw_events else []

    rows = []

    # Slide window across total recorded observation interval [start_time, end_time]
    current_time = start_time + window_seconds
    event_idx = 0

    while current_time <= end_time + stride_seconds:
        # Feed events that arrived up to current_time
        while event_idx < len(sorted_events) and sorted_events[event_idx].arrival_time <= current_time:
            evt = sorted_events[event_idx]
            event_idx += 1
            if deduplicator.should_keep(evt):
                window_buffer.add_event(evt)

        window_start = current_time - window_seconds
        window_end = current_time

        active_events = window_buffer.get_current_events(current_time=current_time)
        features = extract_features(active_events, window_seconds=window_seconds)

        # Ground-truth label for [window_start, window_end)
        label = compute_window_label(window_start, window_end, cls_name, ground_truth_ops)

        row = {
            "run_id": run_id,
            "class": cls_name,
            "window_start": round(window_start, 4),
            "window_end": round(window_end, 4),
            "label": label,
            **features,
        }
        rows.append(row)

        current_time += stride_seconds

    return rows


def append_rows_to_dataset(rows: List[Dict[str, Any]], csv_path: Path) -> None:
    """
    Appends feature rows to data/datasets/dataset_v1.csv, writing headers if file is new.
    """
    file_exists = csv_path.exists() and csv_path.stat().st_size > 0

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def run_dataset_generation(
    target_class: str = "all",
    runs_per_class: int = 3,
    duration: float = 15.0,
    seed: Optional[int] = 42,
    fresh: bool = False,
) -> Path:
    """
    Generates dataset by running simulations, collecting raw events, replaying features, and writing CSV.
    """
    dataset_csv = get_datasets_dir() / "dataset_v1.csv"

    if fresh:
        clear_previous_dataset_artifacts()
    elif dataset_csv.exists() and dataset_csv.stat().st_size > 0:
        print(f"[ERROR] Existing dataset found at: {dataset_csv}")
        print("Please use --fresh flag to clear previous generated dataset artifacts before regenerating.")
        raise RuntimeError("Dataset CSV already exists. Use --fresh to clear previous generated dataset artifacts.")

    classes_to_run = (
        ["normal", "benign", "attack"]
        if target_class.lower() == "all"
        else [target_class.lower()]
    )

    class_run_counts = {"normal": 0, "benign": 0, "attack": 0}
    class_row_counts = {"normal": 0, "benign": 0, "attack": 0}
    positive_labels = 0
    negative_labels = 0
    zero_row_runs: List[str] = []

    for cls in classes_to_run:
        for idx in range(1, runs_per_class + 1):
            run_seed = (seed + idx) if seed is not None else None
            speed = "medium" if cls == "attack" else "medium"

            run_data = generate_single_run(
                cls_name=cls,
                run_index=idx,
                duration=duration,
                speed=speed,
                seed=run_seed,
            )

            rows = replay_and_extract_windows(
                metadata=run_data["metadata"],
                raw_events=run_data["raw_events"],
                ground_truth_ops=run_data["ground_truth_ops"],
            )

            run_id = run_data["metadata"]["run_id"]

            if not rows:
                zero_row_runs.append(run_id)
                print(f"[ERROR] Run '{run_id}' generated 0 window rows!")
            else:
                append_rows_to_dataset(rows, dataset_csv)
                class_run_counts[cls] += 1
                class_row_counts[cls] += len(rows)
                for r in rows:
                    if r["label"] == 1:
                        positive_labels += 1
                    else:
                        negative_labels += 1
                print(f"[DATASET] Extracted & appended {len(rows)} window rows for run '{run_id}'")

    total_runs = sum(class_run_counts.values())
    total_rows = sum(class_row_counts.values())

    print("\n==================================================")
    print("           DATASET GENERATION COMPLETE            ")
    print("==================================================")
    print(f"Normal Runs       : {class_run_counts['normal']}")
    print(f"Benign Runs       : {class_run_counts['benign']}")
    print(f"Attack Runs       : {class_run_counts['attack']}")
    print(f"Normal Rows       : {class_row_counts['normal']}")
    print(f"Benign Rows       : {class_row_counts['benign']}")
    print(f"Attack Rows       : {class_row_counts['attack']}")
    print(f"Positive Labels   : {positive_labels}")
    print(f"Negative Labels   : {negative_labels}")
    print(f"Runs With 0 Rows  : {len(zero_row_runs)}")
    print(f"Total Runs        : {total_runs}")
    print(f"Total Rows        : {total_rows}")
    print(f"Dataset Path      : {dataset_csv}")
    print("==================================================")

    if zero_row_runs:
        raise RuntimeError(f"Dataset generation FAILED: {len(zero_row_runs)} run(s) generated 0 rows: {zero_row_runs}")

    return dataset_csv


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Dataset Generator")
    parser.add_argument(
        "--class",
        dest="target_class",
        choices=["normal", "benign", "attack", "all"],
        default="all",
        help="Class to generate: normal | benign | attack | all (default: all)",
    )
    parser.add_argument("--all", action="store_true", help="Generate runs for all classes")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs (default: 3)")
    parser.add_argument("--runs-per-class", type=int, default=3, help="Runs per class if class=all (default: 3)")
    parser.add_argument("--duration", type=float, default=15.0, help="Run duration in seconds (default: 15)")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed (default: 42)")
    parser.add_argument("--fresh", action="store_true", help="Clear previous generated dataset artifacts before running")
    args = parser.parse_args()

    target_cls = "all" if args.all else args.target_class
    runs_cnt = args.runs if (target_cls != "all" and not args.all) else args.runs_per_class

    run_dataset_generation(
        target_class=target_cls,
        runs_per_class=runs_cnt,
        duration=args.duration,
        seed=args.seed,
        fresh=args.fresh,
    )


if __name__ == "__main__":
    main()
