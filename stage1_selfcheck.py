"""
RansomGuard - Stage 1 Self-Check Script (stage1_selfcheck.py)

Static diagnostic validation tool for Stage 1 setup.
Verifies project structure, path safety definitions, and package integrity.

SAFETY GUARANTEE: Does NOT modify any files or execute shell operations.
"""

import sys
from pathlib import Path


def run_stage1_selfcheck() -> bool:
    print("==================================================")
    print("       RANSOMGUARD STAGE 1 STATIC SELF-CHECK      ")
    print("==================================================")

    project_root = Path(__file__).resolve().parent
    print(f"[*] Project Root: {project_root}")

    all_passed = True

    # 1. Verify Directories
    required_dirs = [
        project_root / "monitoring",
        project_root / "simulator",
        project_root / "utils",
        project_root / "sandbox" / "templates",
        project_root / "sandbox" / "demo_folder",
    ]

    for d in required_dirs:
        if d.exists() and d.is_dir():
            print(f"  [OK] Directory found: {d.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing directory: {d.relative_to(project_root)}")
            all_passed = False

    # 2. Verify Files
    required_files = [
        project_root / "main.py",
        project_root / "reset_sandbox.py",
        project_root / "requirements.txt",
        project_root / "README.md",
        project_root / ".gitignore",
        project_root / "utils" / "sandbox_manager.py",
        project_root / "simulator" / "simulator_utils.py",
        project_root / "simulator" / "normal_simulator.py",
        project_root / "simulator" / "attack_simulator.py",
        project_root / "monitoring" / "watcher.py",
    ]

    for f in required_files:
        if f.exists() and f.is_file():
            print(f"  [OK] File found: {f.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing file: {f.relative_to(project_root)}")
            all_passed = False

    # 3. Path Topology Check (demo_folder must be sibling of templates, not child)
    template_dir = project_root / "sandbox" / "templates"
    demo_dir = project_root / "sandbox" / "demo_folder"

    if template_dir in demo_dir.parents or demo_dir in template_dir.parents:
        print("  [FAIL] Invalid Topology: demo_folder and templates must be siblings under sandbox/")
        all_passed = False
    else:
        print("  [OK] Sandbox Topology: demo_folder and templates are proper siblings.")

    # 4. Check requirements.txt contents
    req_file = project_root / "requirements.txt"
    if req_file.exists():
        content = req_file.read_text(encoding="utf-8")
        if "watchdog" in content:
            print("  [OK] requirements.txt contains 'watchdog'")
        else:
            print("  [FAIL] requirements.txt is missing 'watchdog'")
            all_passed = False

    # 5. Import Verification
    sys.path.insert(0, str(project_root))
    try:
        from utils.sandbox_manager import is_safe_path, assert_safe_path, reset_sandbox
        print("  [OK] Import succeeded: utils.sandbox_manager")
    except Exception as e:
        print(f"  [FAIL] Import error utils.sandbox_manager: {e}")
        all_passed = False

    try:
        from simulator.simulator_utils import list_demo_files, safe_write_text
        print("  [OK] Import succeeded: simulator.simulator_utils")
    except Exception as e:
        print(f"  [FAIL] Import error simulator.simulator_utils: {e}")
        all_passed = False

    print("==================================================")
    if all_passed:
        print(" [RESULT] Stage 1 Self-Check PASSED. Ready for manual testing.")
    else:
        print(" [RESULT] Stage 1 Self-Check FAILED. Fix highlighted errors.")
    print("==================================================")

    return all_passed


if __name__ == "__main__":
    run_stage1_selfcheck()
