"""
RansomGuard - Sandbox Manager (utils/sandbox_manager.py)

Single source of truth for all sandbox paths, path safety checks, and sandbox reset operations.
Ensures ALL file operations strictly remain inside sandbox/demo_folder.
"""

import os
import shutil
from pathlib import Path


def get_project_root() -> Path:
    """Returns the absolute Path of the RansomGuard project root directory."""
    return Path(__file__).resolve().parent.parent


def get_sandbox_root() -> Path:
    """Returns the absolute Path of the sandbox directory."""
    return get_project_root() / "sandbox"


def get_template_dir() -> Path:
    """Returns the absolute Path of the template directory containing reference files."""
    return get_sandbox_root() / "templates"


def get_demo_dir() -> Path:
    """Returns the absolute Path of the active demo directory where simulations occur."""
    return get_sandbox_root() / "demo_folder"


def is_safe_path(target_path: Path) -> bool:
    """
    Strict Path Safety Check.
    Verifies that target_path resolves strictly INSIDE get_demo_dir().

    Returns:
        bool: True if safe, False otherwise.
    """
    try:
        demo_dir = get_demo_dir().resolve()
        
        # Resolve target path (handles symlinks, relative components like '..')
        if target_path.exists():
            resolved_target = target_path.resolve()
        else:
            resolved_target = (target_path.parent.resolve() / target_path.name)

        # Ensure target_path is inside demo_dir or is demo_dir itself
        return demo_dir in resolved_target.parents or resolved_target == demo_dir
    except Exception:
        return False


def assert_safe_path(target_path: Path) -> None:
    """
    Enforces strict path safety. Raises RuntimeError if target_path is outside demo_folder.
    """
    if not is_safe_path(target_path):
        raise RuntimeError(
            f"[FATAL PATH SAFETY ERROR] Attempted operation outside sandbox! Path: '{target_path}'"
        )


def reset_sandbox() -> None:
    """
    Cleans sandbox/demo_folder and populates it with fresh copies of template files.
    
    Safety Rules:
    - Operates ONLY inside sandbox/demo_folder.
    - Never deletes or modifies sandbox/templates.
    - Recreates demo_folder if missing.
    - Preserves nested folder structure during recursive copy.
    - Validates every destination path using assert_safe_path().
    """
    print("[SANDBOX] Reset started")
    
    template_dir = get_template_dir().resolve()
    demo_dir = get_demo_dir().resolve()

    # Ensure template and demo directories exist
    template_dir.mkdir(parents=True, exist_ok=True)
    demo_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Safely clear demo_folder contents ONLY
    for item in demo_dir.iterdir():
        assert_safe_path(item)
        if item.is_file() or item.is_symlink():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)

    # Re-create .gitkeep to maintain directory tracking
    gitkeep = demo_dir / ".gitkeep"
    if is_safe_path(gitkeep):
        gitkeep.touch(exist_ok=True)

    # Step 2: Recursively copy all files from templates to demo_folder
    copied_count = 0
    for template_item in template_dir.rglob("*"):
        if template_item.name == ".gitkeep":
            continue

        rel_path = template_item.relative_to(template_dir)
        dest_path = demo_dir / rel_path

        # Verify destination path safety
        assert_safe_path(dest_path)

        if template_item.is_dir():
            dest_path.mkdir(parents=True, exist_ok=True)
        elif template_item.is_file():
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(template_item, dest_path)
            copied_count += 1

    print(f"[SANDBOX] Copied {copied_count} template files")
    print("[SANDBOX] Ready")


if __name__ == "__main__":
    reset_sandbox()
