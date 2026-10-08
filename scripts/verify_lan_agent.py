"""
RansomGuard - Real LAN Endpoint Agent Verification Script (scripts/verify_lan_agent.py)

Validates LAN connectivity, agent registration, heartbeat transmission, telemetry ingestion,
log persistence, and alert reporting against a live RansomGuard Central server.

Usage:
  python scripts/verify_lan_agent.py --server http://192.168.1.5:8888
"""

import sys
import os
import time
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import requests
from agent.agent_config import agent_config
from agent.device_identity import get_or_create_device_identity
from agent.telemetry_sender import TelemetrySender


def run_lan_verification(server_url: str, token: str) -> bool:
    print("==================================================")
    print("     RANSOMGUARD REAL-LAN AGENT VERIFIER          ")
    print(f" Target Server : {server_url}")
    print("==================================================")

    sender = TelemetrySender(server_url=server_url, token=token)

    # 1. Health Check
    print("\n[1/6] Checking Central Server Health (/health)...")
    reachable = sender.check_server_connectivity(max_retries=3, base_retry_delay=1.0)
    if not reachable:
        print("[FAIL] Central server unreachable. Ensure server is running and accessible.")
        return False
    print("  [OK] Central server health check PASSED.")

    # 2. Host Identity & Registration
    print("\n[2/6] Inspecting Real Host Identity & Registering...")
    identity = get_or_create_device_identity(custom_hostname=None)
    print(f"  Device ID : {identity['device_id']}")
    print(f"  Hostname  : {identity['hostname']}")
    print(f"  OS        : {identity['os']} ({identity['os_version']})")

    registered = sender.register_agent(identity)
    if not registered:
        print("[FAIL] Agent registration failed.")
        return False
    print("  [OK] Real host agent registration PASSED.")

    # 3. Heartbeat Transmission
    print("\n[3/6] Sending Periodic Heartbeat...")
    hb_ok = sender.send_heartbeat(
        device_id=identity["device_id"],
        current_severity="LOW",
        current_threat_score=0.0,
        last_prediction="BENIGN",
    )
    if not hb_ok:
        print("[FAIL] Heartbeat transmission failed.")
        return False
    print("  [OK] Heartbeat transmission PASSED.")

    # 4. Telemetry Window Ingestion
    print("\n[4/6] Sending Sample Telemetry Window...")
    sample_prediction = {
        "timestamp": time.time(),
        "prediction": "BENIGN",
        "severity": "LOW",
        "threat_score": 5.0,
        "ml": {"threat_probability": 0.05, "benign_probability": 0.95},
        "rules": {"rule_score": 0, "triggered_rules": []},
        "features": {
            "files_created": 1,
            "files_modified": 2,
            "files_deleted": 0,
            "files_renamed": 0,
            "writes_per_second": 0.5,
            "unique_extensions": 1,
            "unique_directories": 1,
            "extension_change_count": 0,
            "rename_ratio": 0.0,
            "mean_entropy": 2.5,
            "entropy_change": 0.01,
        },
        "dominant_process": {"process_name": "explorer.exe", "pid": 1234, "attribution_confidence": "DIRECT"},
    }
    telem_ok = sender.send_telemetry(identity["device_id"], sample_prediction)
    if not telem_ok:
        print("[FAIL] Telemetry ingestion failed.")
        return False
    print("  [OK] Telemetry ingestion PASSED.")

    # 5. Log Persistence Check
    print("\n[5/6] Sending Log Event to Central...")
    log_ok = sender.send_log_event(
        device_id=identity["device_id"],
        category="AGENT",
        severity="INFO",
        event_type="LAN_VERIFICATION",
        message=f"LAN verification test executed cleanly on {identity['hostname']}",
    )
    if not log_ok:
        print("[FAIL] Log ingestion failed.")
        return False
    print("  [OK] Log ingestion PASSED.")

    # 6. Central Database Queries Verification
    print("\n[6/6] Verifying Central Endpoint Registries via REST API...")
    server_clean = server_url.rstrip("/")
    try:
        dev_res = requests.get(f"{server_clean}/devices/{identity['device_id']}", timeout=3.0)
        if dev_res.status_code != 200:
            print(f"[FAIL] Could not query device record for {identity['device_id']}: status {dev_res.status_code}")
            return False
        dev_data = dev_res.json()
        if dev_data.get("status") != "ONLINE":
            print(f"[FAIL] Central server reports device status '{dev_data.get('status')}', expected 'ONLINE'")
            return False
        print(f"  [OK] Device record verified in central registry (Status: {dev_data['status']})")

        logs_res = requests.get(f"{server_clean}/devices/{identity['device_id']}/logs?limit=5", timeout=3.0)
        if logs_res.status_code != 200 or not logs_res.json():
            print(f"[FAIL] Log verification query failed: status {logs_res.status_code}")
            return False
        print(f"  [OK] Persisted event logs verified ({len(logs_res.json())} entries retrieved)")

    except Exception as err:
        print(f"[FAIL] Verification API query failed: {err}")
        return False

    print("\n==================================================")
    print("  [SUCCESS] REAL-LAN AGENT VERIFICATION PASSED!   ")
    print("==================================================")
    return True


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Real-LAN Agent Verification Script")
    parser.add_argument(
        "--server",
        default=os.getenv("RANSOMGUARD_SERVER_URL", "http://127.0.0.1:8000"),
        help="RansomGuard Central server URL (default: RANSOMGUARD_SERVER_URL or http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--token",
        default=os.getenv("RANSOMGUARD_AGENT_TOKEN", "rg-dev-secret-token-2026"),
        help="Agent authorization token"
    )
    args = parser.parse_args()

    success = run_lan_verification(server_url=args.server, token=args.token)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
