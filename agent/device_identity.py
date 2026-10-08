"""
RansomGuard - Device Identity Generator & Persister (agent/device_identity.py)

Generates and persists stable device identity metadata (device_id, hostname, os, versions).
"""

import json
import os
import platform
import uuid
from pathlib import Path
from typing import Dict, Any

IDENTITY_FILE = Path(__file__).resolve().parent / "device_identity.json"


def get_or_create_device_identity(custom_hostname: str = None) -> Dict[str, Any]:
    """
    Retrieves or generates a persistent device identity object.
    When custom_hostname is provided, generates a stable, unique device_id for that hostname.
    In real mode (custom_hostname is None), preserves persistent device_id across restarts
    and uses the actual host machine identity (hostname, OS, versions).
    """
    import socket

    if custom_hostname:
        device_id = f"rg-{uuid.uuid5(uuid.NAMESPACE_DNS, custom_hostname).hex[:12]}"
        return {
            "device_id": device_id,
            "hostname": custom_hostname,
            "os": platform.system(),
            "os_version": platform.version(),
            "agent_version": "3.1",
            "model_version": "rf_v2",
            "feature_schema_version": "v1",
        }

    actual_hostname = platform.node() or socket.gethostname() or "UNKNOWN-NODE"
    os_name = platform.system()
    os_ver = platform.version()

    if IDENTITY_FILE.exists():
        try:
            with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # Preserve existing device_id across restarts (Item 3)
            device_id = data.get("device_id")
            if not device_id:
                raw_mac = uuid.getnode()
                unique_seed = f"{actual_hostname}-{raw_mac}"
                device_id = f"rg-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_seed).hex[:12]}"

            identity = {
                "device_id": device_id,
                "hostname": actual_hostname,
                "os": os_name,
                "os_version": os_ver,
                "agent_version": "3.1",
                "model_version": "rf_v2",
                "feature_schema_version": "v1",
            }
            # Update persisted identity file with actual host details
            with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
                json.dump(identity, f, indent=2)
            return identity
        except Exception:
            pass

    # Generate stable new device identity for local host
    raw_mac = uuid.getnode()
    unique_seed = f"{actual_hostname}-{raw_mac}"
    device_id = f"rg-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_seed).hex[:12]}"

    identity = {
        "device_id": device_id,
        "hostname": actual_hostname,
        "os": os_name,
        "os_version": os_ver,
        "agent_version": "3.1",
        "model_version": "rf_v2",
        "feature_schema_version": "v1",
    }

    try:
        with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
            json.dump(identity, f, indent=2)
    except Exception as err:
        print(f"[IDENTITY WARNING] Failed to persist device identity: {err}")

    return identity


get_device_identity = get_or_create_device_identity

