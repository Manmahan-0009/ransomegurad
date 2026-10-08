"""
RansomGuard - Test Server Manager Helper (utils/test_server_manager.py)

Provides robust, reusable test server lifecycle management for test suites:
- Port collision detection & cleanup
- Reliable server startup with bounded readiness polling (/health endpoint)
- Clean server shutdown handling
"""

import os
import sys
import time
import socket
import threading
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

import uvicorn
import requests
import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class UvicornTestServer(threading.Thread):
    """Daemon thread runner for Uvicorn server instance in test suites."""

    def __init__(self, app_import: str, host: str, port: int):
        super().__init__(daemon=True)
        self.app_import = app_import
        self.host = host
        self.port = port
        self.server_config = uvicorn.Config(app=app_import, host=host, port=port, log_level="warning")
        self.server = uvicorn.Server(config=self.server_config)

    def run(self):
        try:
            self.server.run()
        except Exception as e:
            print(f"[TEST SERVER ERROR] Server execution error on port {self.port}: {e}")

    def stop(self):
        self.server.should_exit = True


def kill_process_on_port(port: int) -> None:
    """Terminates any existing process listening on specified port."""
    current_pid = os.getpid()
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.pid == current_pid:
            continue
        try:
            connections = proc.net_connections(kind="inet")
            for conn in connections:
                if conn.laddr and conn.laddr.port == port:
                    print(f"[TEST SERVER] Terminating process {proc.pid} ({proc.name()}) listening on port {port}")
                    proc.terminate()
                    proc.wait(timeout=3.0)
        except Exception:
            pass


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a local TCP port is currently in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def wait_for_server_health(
    server_url: str,
    timeout_seconds: float = 15.0,
    poll_interval: float = 0.3,
    server_thread: Optional[UvicornTestServer] = None,
) -> bool:
    """
    Polls server_url/health until 200 OK or timeout.
    Returns True if healthy, False if timed out.
    """
    health_url = f"{server_url.rstrip('/')}/health"
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        if server_thread and not server_thread.is_alive() and time.time() - start_time > 1.0:
            print(f"[TEST SERVER FAIL] Server thread died unexpectedly while waiting for health at {health_url}")
            return False

        try:
            res = requests.get(health_url, timeout=1.0)
            if res.status_code == 200:
                return True
        except Exception:
            pass

        time.sleep(poll_interval)

    return False


def start_test_server(
    app_import: str = "backend.app.main:app",
    host: str = "127.0.0.1",
    port: int = 8999,
    env_vars: Optional[Dict[str, str]] = None,
    timeout_seconds: float = 15.0,
) -> Tuple[UvicornTestServer, str]:
    """
    Starts a test server on host:port, ensuring port cleanup, env settings, and readiness polling.
    Returns (server_thread, server_url).
    """
    os.environ["RANSOMGUARD_ENV"] = "test"

    if env_vars:
        for k, v in env_vars.items():
            os.environ[k] = v

    if "RANSOMGUARD_DB_PATH" not in os.environ:
        test_db_dir = PROJECT_ROOT / "data" / "test_runtime"
        test_db_dir.mkdir(parents=True, exist_ok=True)
        temp_db_file = test_db_dir / f"ransomguard_test_{os.getpid()}_{int(time.time() * 1000)}.db"
        os.environ["RANSOMGUARD_DB_PATH"] = str(temp_db_file)

    # Cleanup leftover process on target port
    kill_process_on_port(port)
    time.sleep(0.2)

    server_url = f"http://{host}:{port}"
    server_thread = UvicornTestServer(app_import=app_import, host=host, port=port)
    server_thread.start()

    healthy = wait_for_server_health(
        server_url=server_url,
        timeout_seconds=timeout_seconds,
        poll_interval=0.3,
        server_thread=server_thread,
    )

    if not healthy:
        stop_test_server(server_thread, port=port)
        raise RuntimeError(
            f"Central Test Server on {server_url} failed to respond on /health within {timeout_seconds}s"
        )

    return server_thread, server_url


def stop_test_server(server_thread: Optional[UvicornTestServer] = None, port: Optional[int] = None) -> None:
    """Cleanly terminates test server thread and cleans up port bindings."""
    if server_thread:
        try:
            server_thread.stop()
            server_thread.join(timeout=3.0)
        except Exception:
            pass

    if port:
        kill_process_on_port(port)

    # Clean up temporary test DB if path is in test_runtime directory
    test_db_path_str = os.environ.get("RANSOMGUARD_DB_PATH")
    if test_db_path_str and "test_runtime" in test_db_path_str:
        try:
            p = Path(test_db_path_str)
            if p.exists():
                p.unlink()
        except Exception:
            pass
