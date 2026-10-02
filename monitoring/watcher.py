"""
RansomGuard - Real-Time Filesystem Event Watcher (monitoring/watcher.py)

Uses Python's watchdog library to observe sandbox/demo_folder.
Logs file operations (CREATE, MODIFY, MOVE, DELETE) and converts them
into StructuredEvent objects pushed to the EventQueue.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

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
from monitoring.event_schema import create_structured_event, StructuredEvent


class RansomGuardHandler(FileSystemEventHandler):
    """
    Custom Watchdog Event Handler.
    Translates OS filesystem notifications into:
    1. Human-readable timestamped console output (Stage 1 compatibility).
    2. Normalized StructuredEvent instances dispatched to queue_callback (Stage 2).
    """

    def __init__(
        self,
        watch_dir: Path,
        queue_callback: Optional[Callable[[StructuredEvent], None]] = None,
        print_events: bool = True,
    ):
        super().__init__()
        self.watch_dir = watch_dir.resolve()
        self.watch_str = str(self.watch_dir)
        self.queue_callback = queue_callback
        self.print_events = print_events

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

    def _process_event(
        self,
        event_type: str,
        src_path_str: str,
        dest_path_str: Optional[str] = None,
    ):
        src_rel = self._format_rel_path(src_path_str)
        if not src_rel or src_rel == ".gitkeep":
            return

        dest_rel = self._format_rel_path(dest_path_str) if dest_path_str else None
        abs_file = Path(src_path_str)

        # Build structured event
        struct_evt = create_structured_event(
            event_type=event_type,
            src_rel_path=src_rel,
            dest_rel_path=dest_rel,
            abs_file_path=abs_file,
        )

        # Stage 1 Console Print Output
        if self.print_events:
            ts = self._timestamp()
            if event_type == "created":
                print(f"[{ts}] [WATCHER] CREATE  {src_rel}")
            elif event_type == "modified":
                print(f"[{ts}] [WATCHER] MODIFY  {src_rel}")
            elif event_type == "moved":
                print(f"[{ts}] [WATCHER] MOVE    {src_rel} -> {dest_rel}")
            elif event_type == "deleted":
                print(f"[{ts}] [WATCHER] DELETE  {src_rel}")
            sys.stdout.flush()

        # Stage 2 Queue Dispatch
        if self.queue_callback:
            try:
                self.queue_callback(struct_evt)
            except Exception:
                pass

    def on_created(self, event):
        if getattr(event, 'is_directory', False):
            return
        self._process_event("created", event.src_path)

    def on_modified(self, event):
        if getattr(event, 'is_directory', False):
            return
        self._process_event("modified", event.src_path)

    def on_moved(self, event):
        if getattr(event, 'is_directory', False):
            return
        dest_p = getattr(event, 'dest_path', event.src_path)
        self._process_event("moved", event.src_path, dest_p)

    def on_deleted(self, event):
        if getattr(event, 'is_directory', False):
            return
        self._process_event("deleted", event.src_path)


def start_monitoring(
    target_dir: Path = None,
    queue_callback: Optional[Callable[[StructuredEvent], None]] = None,
    print_events: bool = True,
    block: bool = True,
) -> Observer:
    """
    Initializes and starts the Watchdog Observer on sandbox/demo_folder.
    """
    if target_dir is None:
        target_dir = get_demo_dir()

    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir.resolve()

    if print_events and block:
        print("==================================================")
        print("      RANSOMGUARD WATCHDOG MONITOR ACTIVE        ")
        print(f" Target Directory: {target_path}")
        print(" Press Ctrl+C to terminate monitor.")
        print("==================================================")

    event_handler = RansomGuardHandler(
        watch_dir=target_path,
        queue_callback=queue_callback,
        print_events=print_events,
    )
    observer = Observer()
    observer.schedule(event_handler, path=str(target_path), recursive=True)
    observer.start()

    if not block:
        return observer

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        if print_events:
            print("\n[WATCHER] Stopping Watchdog Observer...")
        observer.stop()
    except Exception as e:
        if print_events:
            print(f"\n[WATCHER ERROR] Unexpected observer error: {e}")
        observer.stop()
    observer.join()
    return observer


if __name__ == "__main__":
    start_monitoring()
