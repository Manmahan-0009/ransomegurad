"""
RansomGuard - Telemetry & Alert HTTP Sender (agent/telemetry_sender.py)

Sends device registration, periodic heartbeats, windowed telemetry, and alerts
to the central FastAPI server. Handles network unavailability gracefully without blocking local detection.
"""

import time
import requests
from typing import Dict, Any, Optional
from agent.agent_config import agent_config


class TelemetrySender:
    """
    HTTP Client for reporting agent status, telemetry, and alerts to central server.
    """

    def __init__(self, server_url: Optional[str] = None, token: Optional[str] = None):
        self.server_url = (server_url or agent_config.server_url).rstrip("/")
        self._custom_token = token

    @property
    def token(self) -> str:
        return self._custom_token or agent_config.agent_token

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

    def check_server_connectivity(self, max_retries: int = 4, base_retry_delay: float = 1.0) -> bool:
        """
        Checks connectivity to RansomGuard Central server via GET /health with bounded exponential backoff.
        """
        health_url = f"{self.server_url}/health"
        clean_server = self.server_url.replace("http://", "").replace("https://", "")
        for attempt in range(1, max_retries + 1):
            try:
                res = requests.get(health_url, timeout=3.0)
                if res.status_code == 200:
                    print(f"[CONNECTED] RansomGuard Central\nServer: {clean_server}")
                    return True
                else:
                    print(f"[CONNECTIVITY WARNING] Attempt {attempt}/{max_retries}: Central server returned status {res.status_code}")
            except Exception as err:
                print(f"[CONNECTIVITY WARNING] Attempt {attempt}/{max_retries}: Cannot reach RansomGuard Central at {self.server_url} ({err})")
            
            if attempt < max_retries:
                backoff = base_retry_delay * (2 ** (attempt - 1))
                time.sleep(backoff)

        print(f"[CONNECTIVITY ERROR] Could not verify health of RansomGuard Central at {self.server_url} after {max_retries} attempts.")
        return False

    def send_log_event(self, device_id: str, log_payload: Optional[Dict[str, Any]] = None, **kwargs) -> bool:
        """Sends POST /agents/logs."""
        url = f"{self.server_url}/agents/logs"
        if isinstance(log_payload, dict):
            payload = dict(log_payload)
        else:
            payload = {}
        payload.update(kwargs)
        payload["device_id"] = device_id
        if "timestamp" not in payload:
            payload["timestamp"] = time.time()
        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=2.0)
            return res.status_code == 200
        except Exception:
            return False

    def register_agent(self, identity: Dict[str, Any]) -> bool:
        """Sends POST /agents/register."""
        url = f"{self.server_url}/agents/register"
        payload = dict(identity)
        payload["started_at"] = time.time()

        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=3.0)
            if res.status_code == 200:
                print(f"[AGENT] Registered successfully with server: {self.server_url}")
                return True
            else:
                print(f"[AGENT WARNING] Registration returned status {res.status_code}: {res.text}")
                return False
        except Exception as err:
            print(f"[AGENT] Server unavailable for registration ({err}). Local detection active.")
            return False

    register = register_agent

    def send_heartbeat(
        self,
        device_id: str,
        current_severity: str = "LOW",
        current_threat_score: float = 0.0,
        last_prediction: str = "BENIGN",
    ) -> bool:
        """Sends POST /agents/heartbeat."""
        url = f"{self.server_url}/agents/heartbeat"
        payload = {
            "device_id": device_id,
            "timestamp": time.time(),
            "status": "ONLINE",
            "current_severity": current_severity,
            "current_threat_score": current_threat_score,
            "last_prediction": last_prediction,
            "model_version": "rf_v2",
        }

        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=2.0)
            return res.status_code == 200
        except Exception as err:
            # Silent fallback when server offline
            return False

    def send_telemetry(self, device_id: str, prediction_data: Dict[str, Any]) -> bool:
        """Sends POST /agents/telemetry."""
        url = f"{self.server_url}/agents/telemetry"
        payload = {
            "device_id": device_id,
            "timestamp": prediction_data.get("timestamp", time.time()),
            "prediction": prediction_data.get("prediction", "BENIGN"),
            "threat_probability": prediction_data.get("ml", {}).get("threat_probability", 0.0),
            "benign_probability": prediction_data.get("ml", {}).get("benign_probability", 1.0),
            "rule_score": prediction_data.get("rules", {}).get("rule_score", 0),
            "threat_score": prediction_data.get("threat_score", 0.0),
            "severity": prediction_data.get("severity", "LOW"),
            "confirmed_alert": bool(prediction_data.get("debounce", {}).get("debounced_alert", False)),
            "triggered_rules": [r.get("rule") for r in prediction_data.get("rules", {}).get("triggered_rules", [])],
            "features": prediction_data.get("features", {}),
            "dominant_process": prediction_data.get("dominant_process"),
            "processes": prediction_data.get("processes", []),
            "model_version": prediction_data.get("version_info", {}).get("model_version", "rf_v2"),
            "feature_schema_version": prediction_data.get("version_info", {}).get("feature_schema_version", "v1"),
        }

        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=2.0)
            return res.status_code == 200
        except Exception:
            return False

    def send_alert(self, device_id: str, alert_data: Dict[str, Any]) -> bool:
        """Sends POST /agents/alerts."""
        url = f"{self.server_url}/agents/alerts"
        payload = {
            "alert_id": f"alert-{device_id}-{int(time.time())}",
            "device_id": device_id,
            "timestamp": alert_data.get("timestamp", time.time()),
            "severity": alert_data.get("severity", "HIGH"),
            "prediction": alert_data.get("prediction", "THREAT"),
            "threat_score": alert_data.get("threat_score", 0.0),
            "threat_probability": alert_data.get("ml", {}).get("threat_probability", 1.0),
            "triggered_rules": [r.get("rule") for r in alert_data.get("rules", {}).get("triggered_rules", [])],
            "confirmed": True,
            "containment_status": alert_data.get("containment", {}).get("state", "NONE"),
            "primary_process": alert_data.get("primary_process"),
            "process_attribution_confidence": alert_data.get("process_attribution_confidence", "UNKNOWN"),
            "process_summary": alert_data.get("process_summary", []),
            "canary_triggered": bool(alert_data.get("canary_triggered", False)),
            "canary_id": alert_data.get("canary_id"),
            "canary_event_type": alert_data.get("canary_event_type"),
            "early_confirmation": bool(alert_data.get("early_confirmation", False)),
            "confirmation_source": alert_data.get("confirmation_source", "STANDARD_DEBOUNCE"),
        }

        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=3.0)
            if res.status_code == 200:
                print(f"[AGENT] Sent alert {payload['alert_id']} to central server.")
                return True
            return False
        except Exception as err:
            print(f"[AGENT WARNING] Failed to send alert to central server: {err}")
            return False

    def send_canary_registration(self, device_id: str, canary_data: Dict[str, Any]) -> bool:
        """Sends POST /agents/canaries."""
        url = f"{self.server_url}/agents/canaries"
        payload = dict(canary_data)
        payload["device_id"] = device_id
        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=2.0)
            return res.status_code == 200
        except Exception:
            return False

    def send_canary_event(self, device_id: str, event_data: Dict[str, Any]) -> bool:
        """Sends POST /agents/canary-events."""
        url = f"{self.server_url}/agents/canary-events"
        payload = dict(event_data)
        payload["device_id"] = device_id
        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=2.0)
            return res.status_code == 200
        except Exception:
            return False

