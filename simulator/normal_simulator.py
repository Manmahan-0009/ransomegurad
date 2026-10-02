"""
RansomGuard - Normal Activity Simulator (simulator/normal_simulator.py)

Simulates ordinary, slow, harmless user file activity inside sandbox/demo_folder.
Used to demonstrate baseline filesystem event behavior.
"""

import argparse
import random
import time
from pathlib import Path
from utils.sandbox_manager import get_demo_dir
from simulator.simulator_utils import (
    list_demo_files,
    choose_random_file,
    safe_write_text,
    safe_rename,
    safe_create_file,
    safe_delete,
    generate_text_content,
)


def run_normal_simulation(duration: float = 15.0, delay: float = 2.0, seed: int = None) -> None:
    """
    Runs normal user file simulation for the specified duration (in seconds).
    
    Actions (low frequency, spread out over time):
    - Modify an existing text file
    - Create a new document/note file
    - Rename an existing file
    - Delete a temporary file created during simulation
    """
    demo_dir = get_demo_dir()

    if not demo_dir.exists():
        print(f"[NORMAL ERROR] Demo folder '{demo_dir}' does not exist! Please run reset first.")
        return

    rng = random.Random(seed) if seed is not None else random

    print("==================================================")
    print("      NORMAL USER ACTIVITY SIMULATOR STARTED      ")
    print(f" Target Folder : {demo_dir}")
    print(f" Duration      : {duration}s")
    print(f" Action Delay  : {delay}s")
    if seed is not None:
        print(f" Seed          : {seed}")
    print("==================================================")

    start_time = time.time()
    action_step = 0
    created_temp_files = []

    while time.time() - start_time < duration:
        action_step += 1
        action_type = rng.choice(["modify", "create", "rename", "delete_temp"])
        files = list_demo_files()

        if action_type == "modify" and files:
            target = choose_random_file(files, rng)
            if target and target.suffix in [".txt", ".log", ".csv", ".md"]:
                rel_path = target.relative_to(demo_dir)
                print(f"[NORMAL] MODIFY {rel_path}")
                current_text = target.read_text(encoding="utf-8", errors="ignore") if target.exists() else ""
                new_text = current_text + generate_text_content(rng)
                safe_write_text(target, new_text)

        elif action_type == "create":
            new_filename = f"user_note_{action_step}_{rng.randint(100, 999)}.txt"
            print(f"[NORMAL] CREATE {new_filename}")
            new_file_path = safe_create_file(new_filename, generate_text_content(rng))
            created_temp_files.append(new_file_path)

        elif action_type == "rename" and files:
            target = choose_random_file(files, rng)
            if target and not target.name.endswith("_renamed.txt"):
                rel_path = target.relative_to(demo_dir)
                new_name = f"{target.stem}_renamed{target.suffix}"
                new_rel_path = (target.parent / new_name).relative_to(demo_dir)
                print(f"[NORMAL] RENAME {rel_path} -> {new_rel_path}")
                safe_rename(target, new_name)

        elif action_type == "delete_temp" and created_temp_files:
            target_temp = created_temp_files.pop(0)
            if target_temp.exists():
                rel_path = target_temp.relative_to(demo_dir)
                print(f"[NORMAL] DELETE {rel_path}")
                safe_delete(target_temp)

        time.sleep(delay)

    print("\n[NORMAL] Simulation complete")


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Normal User Activity Simulator")
    parser.add_argument("--duration", type=float, default=15.0, help="Simulation duration in seconds (default: 15.0)")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between actions in seconds (default: 2.0)")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducibility")
    args = parser.parse_args()

    run_normal_simulation(duration=args.duration, delay=args.delay, seed=args.seed)


if __name__ == "__main__":
    main()
