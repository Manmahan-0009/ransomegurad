"""
RansomGuard - Benign High-Activity Simulator (simulator/benign_simulator.py)

Simulates harmless but busy/high-frequency filesystem activity inside sandbox/demo_folder.
Examples:
- Bulk copying text/csv files
- Backup-style repeated writes
- Mass file creation (simulating archive extractions)
- File renaming keeping normal extensions

PURPOSE:
Prevents future machine learning models from learning the naive heuristic:
"many file operations = ransomware".

STRICT SAFETY RESTRICTIONS:
- No encryption or pseudo-random byte overwrites.
- No .locked or ransomware-style extension changes.
- No network, OS changes, persistence, or privilege escalation.
- Restricted strictly to sandbox/demo_folder.
"""

import argparse
import random
import shutil
import time
from pathlib import Path
from utils.sandbox_manager import get_demo_dir, assert_safe_path
from simulator.simulator_utils import (
    list_demo_files,
    choose_random_file,
    safe_write_text,
    safe_rename,
    safe_create_file,
    generate_text_content,
)

SPEED_DELAYS = {
    "slow": 0.4,
    "medium": 0.1,
    "fast": 0.02,
}


def run_benign_simulation(
    duration: float = 15.0,
    delay: float = 0.2,
    speed: str = "medium",
    max_files: int = 30,
    seed: int = None,
) -> None:
    """
    Runs a harmless, high-activity file simulation inside sandbox/demo_folder.
    """
    demo_dir = get_demo_dir().resolve()

    import os
    from process_telemetry.process_resolver import process_resolver
    process_resolver.register_simulator_process(
        process_name="python.exe" if os.name == "nt" else "python3",
    )


    if not demo_dir.exists():
        print(f"[BENIGN ERROR] Demo folder '{demo_dir}' does not exist! Run reset first.")
        return

    eff_delay = SPEED_DELAYS.get(speed.lower(), delay)
    rng = random.Random(seed) if seed is not None else random

    print("==================================================")
    print("     BENIGN HIGH-ACTIVITY SIMULATOR STARTED      ")
    print(f" Target Folder : {demo_dir}")
    print(f" Duration      : {duration}s")
    print(f" Speed Mode    : {speed.upper()} ({eff_delay}s delay)")
    if seed is not None:
        print(f" Seed          : {seed}")
    print("==================================================")

    start_time = time.time()
    step_count = 0

    while time.time() - start_time < duration:
        step_count += 1
        action = rng.choice(["create_mass", "copy_bulk", "modify_rapid", "rename_normal"])
        files = list_demo_files()

        if action == "create_mass":
            # Simulate archive extraction or build output creation
            new_name = f"extracted_doc_{step_count}_{rng.randint(1000, 9999)}.txt"
            print(f"[BENIGN] CREATE {new_name}")
            safe_create_file(new_name, generate_text_content(rng))

        elif action == "copy_bulk" and files:
            # Simulate backup copy of an existing document
            src_file = choose_random_file(files, rng)
            if src_file:
                rel_src = src_file.relative_to(demo_dir)
                dest_name = f"{src_file.stem}_backup_{step_count}{src_file.suffix}"
                dest_path = src_file.parent / dest_name
                print(f"[BENIGN] COPY {rel_src} -> {dest_path.relative_to(demo_dir)}")
                assert_safe_path(dest_path)
                shutil.copy2(src_file, dest_path)

        elif action == "modify_rapid" and files:
            # Simulate active document saving / log writing
            target = choose_random_file(files, rng)
            if target and target.suffix in [".txt", ".log", ".csv", ".json", ".md"]:
                rel_path = target.relative_to(demo_dir)
                print(f"[BENIGN] MODIFY {rel_path}")
                content = generate_text_content(rng)
                existing = target.read_text(encoding="utf-8", errors="ignore") if target.exists() else ""
                safe_write_text(target, existing + content)

        elif action == "rename_normal" and files:
            # Simulate normal document reorganization (keeping legitimate extensions)
            target = choose_random_file(files, rng)
            if target and not target.name.endswith("_archived" + target.suffix):
                rel_src = target.relative_to(demo_dir)
                new_name = f"{target.stem}_archived{target.suffix}"
                rel_dest = (target.parent / new_name).relative_to(demo_dir)
                print(f"[BENIGN] RENAME {rel_src} -> {rel_dest}")
                safe_rename(target, new_name)

        time.sleep(eff_delay)

    print("\n[BENIGN] Simulation complete")


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Benign High-Activity Simulator")
    parser.add_argument("--duration", type=float, default=15.0, help="Simulation duration in seconds (default: 15.0)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between actions in seconds (default: 0.2)")
    parser.add_argument("--speed", choices=["slow", "medium", "fast"], default="medium", help="Speed mode (default: medium)")
    parser.add_argument("--max-files", type=int, default=30, help="Max files limit (default: 30)")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducibility")
    args = parser.parse_args()

    run_benign_simulation(
        duration=args.duration,
        delay=args.delay,
        speed=args.speed,
        max_files=args.max_files,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
