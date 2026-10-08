"""
RansomGuard - Agent Configuration (agent/agent_config.py)

Manages agent settings, server URLs, heartbeat intervals, and authentication tokens.
Supports environment variable overrides.
"""

import os
from dataclasses import dataclass


RANSOMGUARD_ENV = os.getenv("RANSOMGUARD_ENV", "production").lower()
_env_token = os.getenv("RANSOMGUARD_AGENT_TOKEN")
if not _env_token:
    if RANSOMGUARD_ENV in ("development", "dev", "test"):
        _env_token = "rg-dev-secret-token-2026"
    else:
        _env_token = ""


@dataclass
class AgentConfig:
    server_url: str = os.getenv("RANSOMGUARD_SERVER_URL", "http://127.0.0.1:8000")
    heartbeat_interval: float = float(os.getenv("RANSOMGUARD_HEARTBEAT_INTERVAL", "10.0"))
    agent_version: str = "3.1"
    telemetry_enabled: bool = os.getenv("RANSOMGUARD_TELEMETRY_ENABLED", "True").lower() in ("true", "1", "yes")
    process_telemetry_enabled: bool = os.getenv("PROCESS_TELEMETRY_ENABLED", "True").lower() in ("true", "1", "yes")
    process_cache_refresh_seconds: float = float(os.getenv("PROCESS_CACHE_REFRESH_SECONDS", "1.5"))
    process_top_n: int = int(os.getenv("PROCESS_TOP_N", "5"))
    process_command_line_enabled: bool = os.getenv("PROCESS_COMMAND_LINE_ENABLED", "False").lower() in ("true", "1", "yes")

    @property
    def agent_token(self) -> str:
        env_token = os.getenv("RANSOMGUARD_AGENT_TOKEN")
        if env_token:
            return env_token
        mode = os.getenv("RANSOMGUARD_ENV", "production").lower()
        if mode in ("development", "dev", "test"):
            return "rg-dev-secret-token-2026"
        return ""


agent_config = AgentConfig()


