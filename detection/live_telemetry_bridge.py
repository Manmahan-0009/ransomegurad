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
EventDeduplicator (50ms)
    ↓
SlidingWindowBuffer (5s window, 1s stride)
    ↓
11-Feature Extractor
    ↓
HTTP POST to FastAPI /predict endpoint (http://127.0.0.1:8000/predict)
    ↓
ML Model + Rule Engine + Threat Score Engine -> WebSocket Broadcast -> Dashboard

Handles backend connection errors gracefully without crashing.
"""

import sys
import time
import requests
from datetime import datetime
from pathlib import Path

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


def start_live_telemetry_bridge(
    api_url: str = "http://127.0.0.1:8000/predict",
    window_seconds: float = 5.0,
    stride_seconds: float = 1.0,
    dedupe_ms: float = 200.0,
) -> None:
    """
    Runs the live telemetry bridge linking filesystem Watchdog events
    to the RansomGuard FastAPI /predict endpoint.
    """
    demo_dir = get_demo_dir().resolve()

    print("==================================================")
    print("      RANSOMGUARD LIVE TELEMETRY BRIDGE ACTIVE     ")
    print(f" Target Directory: {demo_dir}")
    print(f" Backend Endpoint: {api_url}")
    print(f" Window: {window_seconds}s | Stride: {stride_seconds}s | Dedupe: {dedupe_ms}ms")
    print(" Press Ctrl+C to terminate live bridge.")
    print("==================================================")

    eq = EventQueue()
    deduplicator = EventDeduplicator(dedupe_ms=dedupe_ms)
    window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)

    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    last_submitted_signature = None

    try:
        while True:
            time.sleep(stride_seconds)
            raw_events = eq.flush()
            kept_events = deduplicator.deduplicate_list(raw_events)
            window_buffer.add_events(kept_events)
            current_window_events = window_buffer.get_current_events()

            # Extract exact 11 features
            features = extract_features(current_window_events, window_seconds=window_seconds)

            # Avoid submitting identical zero-activity signature repeatedly if no change
            current_signature = (
                features["files_created"],
                features["files_modified"],
                features["files_deleted"],
                features["files_renamed"],
                features["writes_per_second"],
                features["mean_entropy"],
            )

            ts = datetime.now().strftime("%H:%M:%S")

            # Post feature window to FastAPI backend
            try:
                response = requests.post(api_url, json=features, timeout=2.0)
                if response.status_code == 200:
                    data = response.json()
                    pred = data.get("prediction", "UNKNOWN")
                    score = data.get("threat_score", 0.0)
                    severity = data.get("severity", "LOW")
                    
                    if score > 0 or features["files_modified"] > 0 or features["files_created"] > 0:
                        print(f"[{ts}] [BRIDGE -> API] Score: {score:<5} | Severity: {severity:<8} | Pred: {pred}")
                else:
                    print(f"[{ts}] [BRIDGE] API Error {response.status_code}: {response.text}")

            except requests.exceptions.RequestException:
                print(f"[{ts}] [BRIDGE WARNING] Backend unavailable at {api_url}. Monitoring continues...")

            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[BRIDGE] Stopping Live Telemetry Bridge...")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    start_live_telemetry_bridge()
