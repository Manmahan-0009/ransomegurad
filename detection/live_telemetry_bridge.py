"""
RansomGuard - Live Telemetry Bridge (detection/live_telemetry_bridge.py)

Connects verified Stage 2 live telemetry pipeline directly to FastAPI backend:
sandbox/demo_folder
    ↓
Watchdog (Observer)
    ↓
StructuredEvent
    ↓
EventQueue
    ↓
EventDeduplicator (200ms)
    ↓
SlidingWindowBuffer (5s window, 1s stride)
    ↓
11-Feature Extractor
    ↓
HTTP POST to FastAPI /predict endpoint (http://127.0.0.1:8000/predict)
    ↓
ML Model + Rule Engine + Threat Score Engine -> WebSocket Broadcast -> Dashboard

Provides explicit pipeline reset capability between test runs to prevent cross-contamination.
"""

import sys
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from features.entropy import get_entropy_tracker


class LiveTelemetryBridge:
    """
    Manages live monitoring bridge state with clean reset support.
    """

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:8000/predict",
        reset_url: str = "http://127.0.0.1:8000/reset-pipeline",
        window_seconds: float = 5.0,
        stride_seconds: float = 1.0,
        dedupe_ms: float = 200.0,
    ):
        self.api_url = api_url
        self.reset_url = reset_url
        self.window_seconds = window_seconds
        self.stride_seconds = stride_seconds
        self.dedupe_ms = dedupe_ms

        self.eq = EventQueue()
        self.deduplicator = EventDeduplicator(dedupe_ms=dedupe_ms)
        self.window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)
        self.observer = None

    def reset_state(self, notify_backend: bool = True) -> None:
        """
        Clears pending queues, deduplication cache, sliding window buffer, and entropy tracker.
        Optionally notifies backend to reset debounce counters.
        """
        self.eq.clear()
        self.deduplicator.clear()
        self.window_buffer.clear()
        get_entropy_tracker().clear()

        if notify_backend:
            try:
                requests.post(self.reset_url, timeout=1.5)
            except Exception:
                pass
        print("[BRIDGE] Live pipeline state cleared.")

    def start(self, scenario_id: Optional[str] = None) -> None:
        demo_dir = get_demo_dir().resolve()

        print("==================================================")
        print("      RANSOMGUARD LIVE TELEMETRY BRIDGE ACTIVE     ")
        print(f" Target Directory: {demo_dir}")
        print(f" Backend Endpoint: {self.api_url}")
        print(f" Window: {self.window_seconds}s | Stride: {self.stride_seconds}s | Dedupe: {self.dedupe_ms}ms")
        print(" Press Ctrl+C to terminate live bridge.")
        print("==================================================")

        self.observer = start_monitoring(
            target_dir=demo_dir,
            queue_callback=self.eq.push,
            print_events=False,
            block=False,
        )

        try:
            while True:
                time.sleep(self.stride_seconds)
                raw_events = self.eq.flush()
                kept_events = self.deduplicator.deduplicate_list(raw_events)
                self.window_buffer.add_events(kept_events)
                current_window_events = self.window_buffer.get_current_events()

                # Extract exact 11 features
                features = extract_features(current_window_events, window_seconds=self.window_seconds)
                if scenario_id:
                    features["scenario_id"] = scenario_id

                ts = datetime.now().strftime("%H:%M:%S")

                # Post feature window to FastAPI backend
                try:
                    response = requests.post(self.api_url, json=features, timeout=2.0)
                    if response.status_code == 200:
                        data = response.json()
                        pred = data.get("prediction", "UNKNOWN")
                        score = data.get("threat_score", 0.0)
                        severity = data.get("severity", "LOW")
                        debounced = data.get("debounce", {}).get("debounced_severity", severity)

                        if score > 0 or features["files_modified"] > 0 or features["files_created"] > 0:
                            print(f"[{ts}] [BRIDGE -> API] Score: {score:<5} | Raw Sev: {severity:<8} | Debounced: {debounced:<8} | Pred: {pred}")
                    else:
                        print(f"[{ts}] [BRIDGE] API Error {response.status_code}: {response.text}")

                except requests.exceptions.RequestException:
                    print(f"[{ts}] [BRIDGE WARNING] Backend unavailable at {self.api_url}. Monitoring continues...")

                sys.stdout.flush()

        except KeyboardInterrupt:
            print("\n[BRIDGE] Stopping Live Telemetry Bridge...")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()


def start_live_telemetry_bridge(
    api_url: str = "http://127.0.0.1:8000/predict",
    window_seconds: float = 5.0,
    stride_seconds: float = 1.0,
    dedupe_ms: float = 200.0,
) -> None:
    bridge = LiveTelemetryBridge(
        api_url=api_url,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
        dedupe_ms=dedupe_ms,
    )
    bridge.start()


if __name__ == "__main__":
    start_live_telemetry_bridge()
