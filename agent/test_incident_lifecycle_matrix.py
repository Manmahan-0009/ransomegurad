"""
RansomGuard - Unit Test for Incident Lifecycle State Matrix (agent/test_incident_lifecycle_matrix.py)

Tests authoritative incident lifecycle transitions:
1. HIGH -> LOW => ACTIVE (low_streak=1)
2. HIGH -> LOW -> LOW => ACTIVE (low_streak=2)
3. HIGH -> LOW -> LOW -> LOW => CLOSED (low_streak=3)
4. HIGH -> LOW -> HIGH => ACTIVE (low_streak reset to 0)
5. HIGH -> LOW -> MEDIUM -> LOW => ACTIVE (MEDIUM resets streak to 0, count=1 LOW after MEDIUM)
6. HIGH -> LOW -> LOW -> CRITICAL => ACTIVE (CRITICAL resets streak to 0)
7. Second Episode after CLOSED creates a NEW incident ID (no reopening closed incident).
"""

import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Mandate TEST mode and isolated temporary database path before importing DB modules
os.environ["RANSOMGUARD_ENV"] = "test"
test_db_dir = PROJECT_ROOT / "data" / "test_runtime"
test_db_dir.mkdir(parents=True, exist_ok=True)
TEMP_TEST_DB = test_db_dir / f"test_matrix_{os.getpid()}_{int(time.time() * 1000)}.db"
os.environ["RANSOMGUARD_DB_PATH"] = str(TEMP_TEST_DB)

from backend.app.db import get_db_connection, CentralDatabase
from backend.app.device_registry import device_registry


def reset_test_db(device_id: str):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM alerts WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM telemetry WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        conn.commit()


def make_alert_payload(device_id: str, severity: str = "HIGH", threat_score: float = 75.0) -> dict:
    return {
        "device_id": device_id,
        "timestamp": time.time(),
        "severity": severity,
        "threat_score": threat_score,
        "triggered_rules": ["RULE_MASS_MODIFY"],
    }


def test_incident_lifecycle_matrix():
    device_id = "test-matrix-dev-01"
    reset_test_db(device_id)

    # 1. HIGH -> LOW => ACTIVE
    inc1 = device_registry.record_alert(make_alert_payload(device_id))
    assert inc1["current_status"] in ("OPEN", "UPDATED")

    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    active1 = CentralDatabase.get_active_alert(device_id)
    assert active1 is not None
    assert active1["current_status"] in ("OPEN", "UPDATED")
    assert active1["low_streak"] == 1
    print("  [OK] Transition HIGH -> LOW => ACTIVE (streak=1)")

    # 2. HIGH -> LOW -> LOW => ACTIVE
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    active2 = CentralDatabase.get_active_alert(device_id)
    assert active2 is not None
    assert active2["current_status"] in ("OPEN", "UPDATED")
    assert active2["low_streak"] == 2
    print("  [OK] Transition HIGH -> LOW -> LOW => ACTIVE (streak=2)")

    # 3. HIGH -> LOW -> LOW -> LOW => CLOSED
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    active3 = CentralDatabase.get_active_alert(device_id)
    assert active3 is None, "Incident should be CLOSED and no active alert should remain!"

    with get_db_connection() as conn:
        closed1 = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (inc1["alert_id"],)).fetchone()
        assert closed1["current_status"] == "CLOSED"
        assert closed1["closed_at"] is not None
    print("  [OK] Transition HIGH -> LOW -> LOW -> LOW => CLOSED")

    # 4. HIGH -> LOW -> HIGH => ACTIVE (streak reset)
    reset_test_db(device_id)
    inc2 = device_registry.record_alert(make_alert_payload(device_id))
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    assert CentralDatabase.get_active_alert(device_id)["low_streak"] == 1

    device_registry.record_alert(make_alert_payload(device_id, threat_score=85.0))
    active_high = CentralDatabase.get_active_alert(device_id)
    assert active_high["low_streak"] == 0
    assert active_high["current_status"] in ("OPEN", "UPDATED")
    print("  [OK] Transition HIGH -> LOW -> HIGH => ACTIVE (streak reset to 0)")

    # 5. HIGH -> LOW -> MEDIUM -> LOW => ACTIVE (MEDIUM resets streak)
    reset_test_db(device_id)
    inc3 = device_registry.record_alert(make_alert_payload(device_id))
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    assert CentralDatabase.get_active_alert(device_id)["low_streak"] == 1

    device_registry.record_telemetry({"device_id": device_id, "severity": "MEDIUM", "timestamp": time.time()})
    assert CentralDatabase.get_active_alert(device_id)["low_streak"] == 0

    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    active_med_low = CentralDatabase.get_active_alert(device_id)
    assert active_med_low["low_streak"] == 1
    assert active_med_low["current_status"] in ("OPEN", "UPDATED")
    print("  [OK] Transition HIGH -> LOW -> MEDIUM -> LOW => ACTIVE (streak reset on MEDIUM)")

    # 6. HIGH -> LOW -> LOW -> CRITICAL => ACTIVE (CRITICAL resets streak)
    reset_test_db(device_id)
    inc4 = device_registry.record_alert(make_alert_payload(device_id))
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})
    assert CentralDatabase.get_active_alert(device_id)["low_streak"] == 2

    device_registry.record_telemetry({"device_id": device_id, "severity": "CRITICAL", "timestamp": time.time()})
    active_crit = CentralDatabase.get_active_alert(device_id)
    assert active_crit["low_streak"] == 0
    assert active_crit["current_status"] in ("OPEN", "UPDATED")
    print("  [OK] Transition HIGH -> LOW -> LOW -> CRITICAL => ACTIVE (streak reset on CRITICAL)")

    # 7. Episode 2 test: New HIGH after CLOSED creates a NEW incident ID
    reset_test_db(device_id)
    inc_ep1 = device_registry.record_alert(make_alert_payload(device_id))
    for _ in range(3):
        device_registry.record_telemetry({"device_id": device_id, "severity": "LOW", "timestamp": time.time()})

    active_ep1 = CentralDatabase.get_active_alert(device_id)
    assert active_ep1 is None, "Episode 1 incident should be CLOSED"

    inc_ep2 = device_registry.record_alert(make_alert_payload(device_id) | {"timestamp": time.time() + 10.0})
    assert inc_ep2["alert_id"] != inc_ep1["alert_id"], "Episode 2 created a new incident ID!"
    assert inc_ep2["current_status"] == "OPEN"
    print("  [OK] Episode 2 test passed: New HIGH after CLOSED creates independent Incident ID.")


if __name__ == "__main__":
    try:
        test_incident_lifecycle_matrix()
    finally:
        if TEMP_TEST_DB.exists():
            try:
                TEMP_TEST_DB.unlink()
            except Exception:
                pass
