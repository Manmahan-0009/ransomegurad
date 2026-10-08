"""
RansomGuard - Process Activity Cache (process_telemetry/process_cache.py)

Maintains a lightweight, rate-controlled process table to avoid high CPU overhead.
"""
import os
import time
from typing import Dict, Any, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

from process_telemetry.process_context import ProcessContext


class ProcessCache:
    def __init__(self, refresh_interval: float = 1.5):
        self.refresh_interval = refresh_interval
        self.last_refresh_time: float = 0.0
        self._cache: Dict[int, ProcessContext] = {}

    def refresh(self, force: bool = False) -> None:
        """Refreshes process table if refresh_interval has elapsed."""
        now = time.time()
        if not force and (now - self.last_refresh_time < self.refresh_interval):
            return

        self.last_refresh_time = now
        if not psutil:
            return

        new_cache: Dict[int, ProcessContext] = {}
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "create_time"]):
                try:
                    info = proc.info
                    pid = info["pid"]
                    parent_name = None
                    ppid = info.get("ppid")
                    if ppid and ppid in new_cache:
                        parent_name = new_cache[ppid].process_name

                    ctx = ProcessContext(
                        pid=pid,
                        process_name=info.get("name") or "unknown",
                        executable_path=info.get("exe") or "",
                        parent_pid=ppid,
                        parent_process_name=parent_name,
                        username=info.get("username") or "",
                        process_start_time=info.get("create_time"),
                        attribution_confidence="CORRELATED_HIGH",
                    )
                    new_cache[pid] = ctx
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

        self._cache = new_cache

    def get_process_context(self, pid: int) -> Optional[ProcessContext]:
        self.refresh(force=False)
        return self._cache.get(pid)

    def get_all_cached(self) -> Dict[int, ProcessContext]:
        self.refresh(force=False)
        return dict(self._cache)


process_cache = ProcessCache()
