"""
RansomGuard - Agent Heartbeat Thread (agent/heartbeat.py)

Periodically sends heartbeats to the central FastAPI server in a background thread.
Handles server disconnects gracefully and re-attempts registration if needed.
"""

import time
import threading
from typing import Callable, Dict, Any, Optional
from agent.telemetry_sender import TelemetrySender
from agent.agent_config import agent_config


class HeartbeatThread(threading.Thread):
    """
    Background thread for sending periodic 10s agent heartbeats.
    """

    def __init__(
        self,
        telemetry_sender: TelemetrySender,
        identity: Dict[str, Any],
        status_provider: Callable[[], Dict[str, Any]],
        interval: Optional[float] = None,
    ):
        super().__init__(daemon=True)
        self.sender = telemetry_sender
        self.identity = identity
        self.device_id = identity["device_id"]
        self.status_provider = status_provider
        self.interval = interval or agent_config.heartbeat_interval
        self._stop_event = threading.Event()
        self.is_registered = False

    def stop(self):
        """Stops the heartbeat thread cleanly."""
        self._stop_event.set()

    def run(self):
        print(f"[HEARTBEAT] Started heartbeat thread for device {self.device_id} (interval={self.interval}s)")

        while not self._stop_event.is_set():
            # Try to register if not yet registered
            if not self.is_registered:
                self.is_registered = self.sender.register_agent(self.identity)

            # Gather current status from agent service
            status = self.status_provider()
            severity = status.get("current_severity", "LOW")
            score = status.get("current_threat_score", 0.0)
            prediction = status.get("last_prediction", "BENIGN")

            # Send heartbeat
            success = self.sender.send_heartbeat(
                device_id=self.device_id,
                current_severity=severity,
                current_threat_score=score,
                last_prediction=prediction,
            )

            if not success and self.is_registered:
                # If heartbeat failed, server might have restarted or gone offline
                # Reset registration flag to force re-registration attempt next cycle
                self.is_registered = False

            # Wait for interval or stop signal
            self._stop_event.wait(self.interval)

        print(f"[HEARTBEAT] Stopped heartbeat thread for device {self.device_id}")
