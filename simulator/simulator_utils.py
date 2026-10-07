"""
RansomGuard - Simulator Utilities (simulator/simulator_utils.py)

Reusable, path-safe helper functions for filesystem simulations.
Every write, rename, create, and delete operation is strictly validated
by assert_safe_path() before execution.
Includes retry mechanism for transient Windows file-lock (WinError 32) race conditions.
"""

import os
import time
import random
from pathlib import Path
from typing import List, Optional
from utils.sandbox_manager import get_demo_dir, assert_safe_path


def list_demo_files() -> List[Path]:
    """
    Returns a list of all existing files inside sandbox/demo_folder recursively,
    excluding hidden files like .gitkeep.
    """
    demo_dir = get_demo_dir()
    if not demo_dir.exists():
        return []
    return [
        p for p in demo_dir.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    ]


def choose_random_file(files: List[Path], rng: Optional[random.Random] = None) -> Optional[Path]:
    """
    Selects a random file from a list of Path objects using an optional seeded Random instance.
    """
    if not files:
        return None
    picker = rng if rng is not None else random
    return picker.choice(files)


def safe_write_text(path: Path, text: str) -> None:
    """
    Safely writes text content to path, validating that path is strictly inside demo_folder.
    """
    assert_safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(5):
        try:
            path.write_text(text, encoding="utf-8", errors="ignore")
            return
        except PermissionError:
            time.sleep(0.05)
    path.write_text(text, encoding="utf-8", errors="ignore")


def safe_write_bytes(path: Path, data: bytes) -> None:
    """
    Safely writes binary content to path, validating that path is strictly inside demo_folder.
    """
    assert_safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(5):
        try:
            path.write_bytes(data)
            return
        except PermissionError:
            time.sleep(0.05)
    path.write_bytes(data)


def safe_rename(src_path: Path, new_name_or_rel_path: str) -> Path:
    """
    Safely renames src_path to a new filename or relative destination within demo_folder.
    Returns the new destination Path. Retries on transient Windows file lock.
    """
    assert_safe_path(src_path)
    dest_path = src_path.parent / new_name_or_rel_path
    assert_safe_path(dest_path)

    for attempt in range(5):
        try:
            src_path.rename(dest_path)
            return dest_path
        except PermissionError:
            time.sleep(0.05)
    src_path.rename(dest_path)
    return dest_path


def safe_create_file(rel_filename: str, content: str = "") -> Path:
    """
    Safely creates a new file inside demo_folder at relative path rel_filename.
    """
    target_path = get_demo_dir() / rel_filename
    assert_safe_path(target_path)
    safe_write_text(target_path, content)
    return target_path


def safe_delete(path: Path) -> None:
    """
    Safely deletes a file inside demo_folder.
    """
    assert_safe_path(path)
    if path.exists() and path.is_file():
        for attempt in range(5):
            try:
                path.unlink()
                return
            except PermissionError:
                time.sleep(0.05)
        if path.exists():
            path.unlink()


def generate_random_bytes(size: int = 512, rng: Optional[random.Random] = None) -> bytes:
    """
    Generates pseudo-random bytes to simulate high-entropy encrypted data.
    """
    header = b"MOCK_HIGH_ENTROPY_HEADER_AES256\n"
    picker = rng if rng is not None else random
    random_payload = bytes(picker.getrandbits(8) for _ in range(max(64, size)))
    return header + random_payload


def generate_text_content(rng: Optional[random.Random] = None) -> str:
    """
    Generates harmless text content simulating standard user edits.
    """
    picker = rng if rng is not None else random
    samples = [
        "Updated meeting notes with client feedback.",
        "Added Q3 financial projection estimates.",
        "Verified database backup completion log.",
        "Updated security compliance checklist items.",
        "Refactored internal documentation layout."
    ]
    return f"User Edit: {picker.choice(samples)}\nTimestamp: {picker.randint(1000, 9999)}\n"
