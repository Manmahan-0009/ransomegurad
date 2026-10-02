"""
RansomGuard - Ransomware-like Behavior Simulator (simulator/attack_simulator.py)

Safely simulates high-frequency, benign ransomware-like filesystem bursts:
- Rapid file modifications
- Pseudo-random byte overwrites (simulating high-entropy content)
- File extension changes (.locked)

STRICT SAFETY RESTRICTIONS:
- Benign simulation only. No real encryption algorithms or key generation.
- No network connections, OS configuration modifications, persistence, or privilege escalation.
- Operates strictly inside sandbox/demo_folder.
"""

import argparse
import random
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List
from utils.sandbox_manager import get_demo_dir
from simulator.simulator_utils import (
    list_demo_files,
    safe_write_bytes,
    safe_rename,
    generate_random_bytes,
)


SPEED_DELAYS = {
    "slow": 0.4,
    "medium": 0.1,
    "fast": 0.02,
}


def run_attack_simulation(
    speed: str = "medium",
    max_files: int = 20,
    seed: Optional[int] = None,
    run_id: Optional[str] = None,
    op_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Runs a safe ransomware-like burst simulation on files inside sandbox/demo_folder.
    Records ground-truth operation timestamps for Stage 3 dataset labeling.

    Returns:
        Dict[str, Any]: {
            'attack_start_time': Optional[float],
            'ground_truth_ops': List[Dict[str, Any]]
        }
    """
    demo_dir = get_demo_dir()

    if not demo_dir.exists():
        print(f"[ATTACK-LIKE ERROR] Demo folder '{demo_dir}' does not exist! Please run reset first.")
        return {"attack_start_time": None, "ground_truth_ops": []}

    delay = SPEED_DELAYS.get(speed.lower(), 0.1)
    rng = random.Random(seed) if seed is not None else random

    print("==================================================")
    print("   RANSOMWARE-LIKE BEHAVIOR SIMULATOR STARTED     ")
    print(f" Target Folder : {demo_dir}")
    print(f" Speed Mode    : {speed.upper()} ({delay}s delay/file)")
    print(f" Max Files     : {max_files}")
    if seed is not None:
        print(f" Seed          : {seed}")
    print(" SAFETY STATUS : Strictly contained in demo_folder")
    print("==================================================")

    # Get candidate files that haven't been locked yet
    files = [f for f in list_demo_files() if not f.name.endswith(".locked")]

    if not files:
        print("[ATTACK-LIKE] No unencrypted files found. Run reset to restore original files.")
        return {"attack_start_time": None, "ground_truth_ops": []}

    # Shuffle or limit target count
    rng.shuffle(files)
    target_files = files[:max_files]

    ground_truth_ops: List[Dict[str, Any]] = []
    attack_start_time: Optional[float] = None

    # Record attack start time immediately prior to first operation
    attack_start_time = time.time()

    for file_path in target_files:
        if not file_path.exists():
            continue

        rel_path = file_path.relative_to(demo_dir)

        # Record Ground-Truth Operation 1: RANDOM-WRITE
        op1_time = time.time()
        op1_rec = {
            "run_id": run_id or "local_attack_run",
            "operation_time": op1_time,
            "operation_type": "RANDOM_WRITE",
            "relative_path": str(rel_path),
        }
        ground_truth_ops.append(op1_rec)
        if op_callback:
            op_callback(op1_rec)

        # Action 1: Modify file with random bytes (simulating high entropy)
        print(f"[ATTACK-LIKE] RANDOM-WRITE {rel_path}")
        file_size = file_path.stat().st_size if file_path.exists() else 512
        encrypted_bytes = generate_random_bytes(file_size, rng)
        safe_write_bytes(file_path, encrypted_bytes)

        time.sleep(delay / 2)

        # Record Ground-Truth Operation 2: EXTENSION-CHANGE
        locked_name = file_path.name + ".locked"
        locked_rel_path = (file_path.parent / locked_name).relative_to(demo_dir)

        op2_time = time.time()
        op2_rec = {
            "run_id": run_id or "local_attack_run",
            "operation_time": op2_time,
            "operation_type": "EXTENSION_CHANGE",
            "relative_path": str(locked_rel_path),
        }
        ground_truth_ops.append(op2_rec)
        if op_callback:
            op_callback(op2_rec)

        # Action 2: Change extension to .locked
        print(f"[ATTACK-LIKE] EXTENSION-CHANGE {rel_path} -> {locked_rel_path}")
        safe_rename(file_path, locked_name)

        time.sleep(delay / 2)

    print("\n[ATTACK-LIKE] Simulation complete")
    return {
        "attack_start_time": attack_start_time,
        "ground_truth_ops": ground_truth_ops,
    }


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Safe Ransomware-like Behavior Simulator")
    parser.add_argument(
        "--speed",
        choices=["slow", "medium", "fast"],
        default="medium",
        help="Burst speed mode: slow (0.4s), medium (0.1s), fast (0.02s) (default: medium)",
    )
    parser.add_argument("--max-files", type=int, default=20, help="Maximum number of files to affect (default: 20)")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducibility")
    args = parser.parse_args()

    run_attack_simulation(speed=args.speed, max_files=args.max_files, seed=args.seed)


if __name__ == "__main__":
    main()
