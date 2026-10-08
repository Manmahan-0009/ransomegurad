"""
RansomGuard - Process Resolver (process_telemetry/process_resolver.py)

Resolves process identity for filesystem events and sliding window behavior summaries.
Supports deterministic simulator attribution (DIRECT confidence) and best-effort correlation.
"""
import os
import sys
import getpass
import time
from typing import Dict, Any, List, Optional
from process_telemetry.process_context import ProcessContext
from process_telemetry.process_cache import process_cache


class ProcessResolver:
    """
    Maps filesystem activity to process context cleanly and safely.
    """

    def __init__(self):
        self._registered_simulators: Dict[int, ProcessContext] = {}

    def register_simulator_process(
        self,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        executable_path: Optional[str] = None,
        parent_process_name: Optional[str] = None,
    ) -> ProcessContext:
        """
        Registers controlled simulator process context for deterministic DIRECT attribution.
        """
        target_pid = pid or os.getpid()
        p_name = process_name or (os.path.basename(sys.executable) if sys.executable else "python.exe")
        p_exe = executable_path or sys.executable
        user = "UNKNOWN"
        try:
            user = getpass.getuser()
        except Exception:
            pass

        parent_pid = getattr(os, "getppid", lambda: None)()
        parent_name = parent_process_name or ("powershell.exe" if os.name == "nt" else "bash")

        ctx = ProcessContext(
            pid=target_pid,
            process_name=p_name,
            executable_path=p_exe,
            parent_pid=parent_pid,
            parent_process_name=parent_name,
            username=user,
            process_start_time=time.time(),
            attribution_confidence="DIRECT",
        )
        self._registered_simulators[target_pid] = ctx
        return ctx

    def resolve_event_process(
        self,
        event_dict: Optional[Dict[str, Any]] = None,
        known_pid: Optional[int] = None,
    ) -> ProcessContext:
        """
        Resolves ProcessContext for an event.
        Returns DIRECT attribution if known_pid or registered simulator,
        CORRELATED_HIGH/CORRELATED_LOW if matched in cache, or UNKNOWN.
        """
        # 1. Check known / registered simulator PID
        target_pid = known_pid or (event_dict.get("process_id") if event_dict else None)
        if target_pid and target_pid in self._registered_simulators:
            return self._registered_simulators[target_pid]

        current_pid = os.getpid()
        if target_pid == current_pid or (event_dict and event_dict.get("process_id") == current_pid):
            if current_pid in self._registered_simulators:
                return self._registered_simulators[current_pid]

        # 2. Check if event_dict has process info attached
        if event_dict and event_dict.get("process_name"):
            return ProcessContext(
                pid=event_dict.get("process_id"),
                process_name=event_dict.get("process_name"),
                executable_path=event_dict.get("process_path"),
                parent_pid=event_dict.get("parent_process_id"),
                parent_process_name=event_dict.get("parent_process_name"),
                username=event_dict.get("username"),
                attribution_confidence=event_dict.get("attribution_confidence", "DIRECT"),
            )

        # 3. Best effort fallback: if registered simulator exists, use active simulator context
        if self._registered_simulators:
            for sim_pid, sim_ctx in self._registered_simulators.items():
                return sim_ctx

        # 4. Process cache lookup if PID present
        if target_pid:
            cached = process_cache.get_process_context(target_pid)
            if cached:
                return cached

        # 5. Default UNKNOWN
        return ProcessContext(
            pid=target_pid,
            process_name="unknown",
            attribution_confidence="UNKNOWN",
        )

    def aggregate_process_summary(
        self,
        events: List[Dict[str, Any]],
        dominant_pid: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Summarizes process-level metrics across a sliding window without altering 11 filesystem features.
        """
        if not events:
            dom_ctx = self.resolve_event_process(known_pid=dominant_pid)
            return {
                "dominant_process": dom_ctx.to_dict(),
                "processes": [dom_ctx.to_dict()],
            }

        # Tally files touched per process
        process_stats: Dict[int, Dict[str, Any]] = {}
        for evt in events:
            ctx = self.resolve_event_process(evt, known_pid=dominant_pid)
            pid_key = ctx.pid or 0
            if pid_key not in process_stats:
                process_stats[pid_key] = {
                    "context": ctx,
                    "files_touched": 0,
                    "files_modified": 0,
                    "files_renamed": 0,
                    "extension_changes": 0,
                }
            stats = process_stats[pid_key]
            stats["files_touched"] += 1
            e_type = evt.get("event_type", "").lower()
            if e_type == "modified":
                stats["files_modified"] += 1
            elif e_type == "moved":
                stats["files_renamed"] += 1
                if evt.get("extension") != evt.get("dest_extension"):
                    stats["extension_changes"] += 1

        # Select top processes (top 3-5)
        sorted_procs = sorted(
            process_stats.values(),
            key=lambda x: x["files_touched"],
            reverse=True,
        )

        top_list = []
        for item in sorted_procs[:5]:
            c_dict = item["context"].to_dict()
            c_dict["files_touched"] = item["files_touched"]
            c_dict["files_modified"] = item["files_modified"]
            c_dict["files_renamed"] = item["files_renamed"]
            c_dict["extension_changes"] = item["extension_changes"]
            top_list.append(c_dict)

        dominant = top_list[0] if top_list else self.resolve_event_process(known_pid=dominant_pid).to_dict()

        return {
            "dominant_process": dominant,
            "processes": top_list,
        }


process_resolver = ProcessResolver()
