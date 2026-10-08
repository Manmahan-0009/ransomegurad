"""
RansomGuard - Device Registry Service (backend/app/device_registry.py)

Central service managing endpoint registration, heartbeats, online/offline calculation,
telemetry sampling, and alert persistence using CentralDatabase.
"""

import time
from typing import Dict, Any, List, Optional
from backend.app.db import CentralDatabase

OFFLINE_THRESHOLD_SECONDS = 30.0


class DeviceRegistry:
    """
    Device Registry Service for central server.
    """

    def __init__(self, offline_threshold: float = OFFLINE_THRESHOLD_SECONDS):
        self.offline_threshold = offline_threshold
        # In-memory tracking for rate-controlled telemetry sampling count per device
        self._telemetry_counter: Dict[str, int] = {}
        self._low_telemetry_streak: Dict[str, int] = {}

    def register_device(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Registers a new agent or updates an existing device record."""
        data["registered_at"] = data.get("started_at", time.time())
        data["last_seen"] = time.time()
        data["status"] = "ONLINE"
        device = CentralDatabase.upsert_device(data)
        print(f"[REGISTRY] Registered device {device['hostname']} ({device['device_id']})")
        return device

    def update_heartbeat(
        self,
        device_id: str,
        timestamp: float,
        current_severity: str,
        current_threat_score: float,
        last_prediction: str,
    ) -> bool:
        """Processes agent heartbeat."""
        device = CentralDatabase.get_device(device_id)
        if not device:
            # Auto-register stub if heartbeat received before registration endpoint
            stub_identity = {
                "device_id": device_id,
                "hostname": f"DEVICE-{device_id[:6]}",
                "os": "Unknown",
                "agent_version": "3.1",
                "model_version": "rf_v2",
                "feature_schema_version": "v1",
                "started_at": timestamp,
            }
            CentralDatabase.upsert_device(stub_identity)

        success = CentralDatabase.update_heartbeat(
            device_id=device_id,
            timestamp=timestamp,
            current_severity=current_severity,
            current_threat_score=current_threat_score,
            last_prediction=last_prediction,
        )
        return success

    def record_telemetry(self, data: Dict[str, Any]) -> bool:
        """
        Records windowed telemetry.
        Applies storage rate control (Phase 8.26):
        - HIGH/CRITICAL telemetry is stored every window.
        - LOW/MEDIUM telemetry is stored 1 out of every 5 windows per device.
        """
        device_id = data["device_id"]
        severity = data.get("severity", "LOW")

        # Track LOW telemetry streak to auto-close active incident after 3 LOW windows
        CentralDatabase.process_telemetry_streak(device_id, severity, data.get("timestamp"))

        # Rate control sampling
        count = self._telemetry_counter.get(device_id, 0) + 1
        self._telemetry_counter[device_id] = count

        should_store = (severity in ("HIGH", "CRITICAL")) or (count % 5 == 1)
        if should_store:
            CentralDatabase.insert_telemetry(data)
        return should_store

    def record_alert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Records or updates an incident alert episode for device (Part 1 Fix 2)."""
        device_id = data["device_id"]
        device = CentralDatabase.get_device(device_id)
        if not device:
            stub_identity = {
                "device_id": device_id,
                "hostname": f"DEVICE-{device_id[:6]}",
                "os": "Unknown",
                "agent_version": "3.1",
                "model_version": "rf_v2",
                "feature_schema_version": "v1",
                "started_at": data.get("timestamp", time.time()),
            }
            CentralDatabase.upsert_device(stub_identity)

        incident = CentralDatabase.record_incident_alert(data)
        print(f"[REGISTRY] Incident {incident.get('alert_id')} [{incident.get('current_status')}] for device {device_id}")
        return incident


    def get_devices(self) -> List[Dict[str, Any]]:
        """Returns all registered devices with dynamically computed ONLINE/OFFLINE status."""
        now = time.time()
        devices = CentralDatabase.get_devices()

        for dev in devices:
            last_seen = dev.get("last_seen", 0)
            if now - last_seen <= self.offline_threshold:
                computed_status = "ONLINE"
            else:
                computed_status = "OFFLINE"
            dev["status"] = computed_status

            # Active incident override for device visual state (Item 11)
            active_alert = CentralDatabase.get_active_alert(dev["device_id"])
            if active_alert:
                dev["active_incident"] = active_alert
                dev["effective_severity"] = active_alert.get("peak_severity") or active_alert.get("severity") or "HIGH"
            else:
                dev["active_incident"] = None
                dev["effective_severity"] = dev.get("current_severity", "LOW")

        return devices

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        devices = self.get_devices()
        for d in devices:
            if d["device_id"] == device_id:
                return d
        return None

    def get_telemetry(self, device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return CentralDatabase.get_telemetry(device_id, limit=limit)

    def get_alerts(self, device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return CentralDatabase.get_alerts(device_id, limit=limit)

    def check_offline_transitions(self) -> List[Dict[str, Any]]:
        """Returns list of devices that recently transitioned to OFFLINE."""
        devices = self.get_devices()
        offline_devs = [d for d in devices if d["status"] == "OFFLINE"]
        return offline_devs


device_registry = DeviceRegistry()
