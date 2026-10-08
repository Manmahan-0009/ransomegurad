"""
RansomGuard - Linux Process Resolver Platform Helper (process_telemetry/platform/linux.py)
"""
import os
import sys
import getpass
from typing import Dict, Any

try:
    import psutil
except ImportError:
    psutil = None


def get_current_process_info_linux() -> Dict[str, Any]:
    """Retrieves process metadata for current process safely on Linux."""
    pid = os.getpid()
    ppid = getattr(os, "getppid", lambda: None)()
    p_name = "python3"
    p_path = sys.executable
    parent_name = None
    user = None

    try:
        user = getpass.getuser()
    except Exception:
        user = "UNKNOWN"

    if psutil:
        try:
            proc = psutil.Process(pid)
            p_name = proc.name()
            p_path = proc.exe()
            user = proc.username()
            if proc.parent():
                parent_name = proc.parent().name()
                ppid = proc.parent().pid
        except Exception:
            pass

    return {
        "pid": pid,
        "process_name": p_name,
        "executable_path": p_path,
        "parent_pid": ppid,
        "parent_process_name": parent_name or "bash",
        "username": user,
    }
