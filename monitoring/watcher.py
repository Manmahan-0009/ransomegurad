"""
RansomGuard - Real-Time Filesystem Event Watcher (monitoring/watcher.py)

Uses Python's watchdog library to observe sandbox/demo_folder.
Logs file operations (CREATE, MODIFY, MOVE, DELETE) with timestamps.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Graceful import check for watchdog package
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("\n==================================================")
    print(" [ERROR] The 'watchdog' package is not installed.")
    print(" Please install it by running:")
    print("     pip install watchdog")
    print("==================================================\n")
    sys.exit(1)

from utils.sandbox_manager import get_demo_dir


class RansomGuardHandler(FileSystemEventHandler):
    """
    Custom Watchdog Event Handler.
    Translates OS filesystem notifications into clean, timestamped RansomGuard logs.
    """

    def __init__(self, watch_dir: Path):
        super().__init__()
        self.watch_dir = watch_dir.resolve()
        self.watch_str = str(self.watch_dir)

    def _format_rel_path(self, path_str: str) -> str:
        """Converts an absolute event path into a clean relative string from demo_folder across OSes."""
        if not path_str:
            return ""
        try:
            p = Path(path_str).resolve()
            try:
                return str(p.relative_to(self.watch_dir))
            except ValueError:
                # Handle Windows drive casing or path prefix variations cross-platform
                p_str = str(p)
                w_str = self.watch_str
                if p_str.lower().startswith(w_str.lower()):
                    rel = p_str[len(w_str):].lstrip(os.sep).lstrip("/")
                    return rel if rel else p.name
                return p.name
        except Exception:
            return os.path.basename(path_str)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def on_created(self, event):
        if getattr(event, 'is_directory', False):
            return
        rel = self._format_rel_path(event.src_path)
        if rel and rel != ".gitkeep":
            print(f"[{self._timestamp()}] [WATCHER] CREATE  {rel}")
            sys.stdout.flush()

    def on_modified(self, event):
        if getattr(event, 'is_directory', False):
            return
        rel = self._format_rel_path(event.src_path)
        if rel and rel != ".gitkeep":
            print(f"[{self._timestamp()}] [WATCHER] MODIFY  {rel}")
            sys.stdout.flush()

    def on_moved(self, event):
        if getattr(event, 'is_directory', False):
            return
        src_rel = self._format_rel_path(event.src_path)
        dest_rel = self._format_rel_path(getattr(event, 'dest_path', event.src_path))
        if src_rel and dest_rel and src_rel != ".gitkeep":
            print(f"[{self._timestamp()}] [WATCHER] MOVE    {src_rel} -> {dest_rel}")
            sys.stdout.flush()

    def on_deleted(self, event):
        if getattr(event, 'is_directory', False):
            return
        rel = self._format_rel_path(event.src_path)
        if rel and rel != ".gitkeep":
            print(f"[{self._timestamp()}] [WATCHER] DELETE  {rel}")
            sys.stdout.flush()


def start_monitoring(target_dir: Path = None) -> None:
    """
    Initializes and starts the Watchdog Observer on sandbox/demo_folder.
    """
    if target_dir is None:
        target_dir = get_demo_dir()

    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir.resolve()

    print("==================================================")
    print("      RANSOMGUARD WATCHDOG MONITOR ACTIVE        ")
    print(f" Target Directory: {target_path}")
    print(" Press Ctrl+C to terminate monitor.")
    print("==================================================")

    event_handler = RansomGuardHandler(watch_dir=target_path)
    observer = Observer()
    observer.schedule(event_handler, path=str(target_path), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[WATCHER] Stopping Watchdog Observer...")
        observer.stop()
    except Exception as e:
        print(f"\n[WATCHER ERROR] Unexpected observer error: {e}")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_monitoring()
