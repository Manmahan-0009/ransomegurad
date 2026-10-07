"""
RansomGuard - Safe Containment Demo Runner (containment/run_containment_demo.py)

Runs a complete, reproducible live containment demonstration:
1. Resets sandbox cleanly
2. Starts Watchdog monitoring & live feature window extractor
3. Starts controlled attack simulator under SimulatorController
4. Evaluates predictions & debounced alerts
5. Fires safe simulated containment upon confirmed threat alert
6. Hides no behavior, outputs full latency (TTD, TTC) and protected file metrics
"""

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import reset_sandbox, get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from features.entropy import get_entropy_tracker

from simulator.simulator_controller import simulator_controller
from backend.app.config import config
from backend.app.model_service import ModelService
from backend.app.rule_engine import RuleEngine
from backend.app.threat_score import ThreatScoreEngine
from backend.app.debounce import DebounceEngine
from containment.stopper import containment_manager


def run_safe_containment_demo(
    speed: str = "medium",
    max_files: int = 20,
    seed: Optional[int] = 42,
    window_seconds: float = 5.0,
    stride_seconds: float = 1.0,
    auto_contain: bool = True,
) -> dict:
    """
    Executes an automated, safe containment demonstration run.
    """
    print("==================================================")
    print("  RANSOMGUARD SAFE SIMULATED CONTAINMENT DEMO     ")
    print("==================================================")
    print(" SAFE SIMULATED CONTAINMENT ENABLED")
    print(f" Mode          : {speed.upper()}")
    print(f" Max Files     : {max_files}")
    print(f" Seed          : {seed}")
    print(" Auto Contain  : TRUE (Controls ONLY RansomGuard attack simulator)")
    print("==================================================")

    # 1. Reset sandbox
    reset_sandbox()
    eq = EventQueue()
    deduplicator = EventDeduplicator(dedupe_ms=200.0)
    window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)
    get_entropy_tracker().clear()

    model_service = ModelService()
    rule_engine = RuleEngine()
    threat_score_engine = ThreatScoreEngine()
    debounce_engine = DebounceEngine()

    containment_manager.auto_containment_enabled = auto_contain
    containment_manager.reset()

    demo_dir = get_demo_dir().resolve()
    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    run_id = f"contain_demo_{speed}_{int(time.time())}"
    running = True

    def monitor_loop():
        while running:
            time.sleep(stride_seconds)
            raw_events = eq.flush()
            if raw_events:
                kept_events = deduplicator.deduplicate_list(raw_events)
                window_buffer.add_events(kept_events)

            current_window_events = window_buffer.get_current_events()
            if not current_window_events:
                continue

            feature_vector = extract_features(current_window_events, window_seconds=window_seconds)
            ml_res = model_service.predict(feature_vector)
            rule_res = rule_engine.evaluate(feature_vector)
            score_res = threat_score_engine.calculate(
                threat_probability=ml_res["threat_probability"],
                rule_score=rule_res["rule_score"],
            )
            debounce_res = debounce_engine.evaluate(
                threat_score=score_res["threat_score"],
                raw_severity=score_res["severity"],
            )

            pred_record = {
                "prediction": ml_res["prediction"],
                "severity": score_res["severity"],
                "threat_score": score_res["threat_score"],
                "debounce": debounce_res,
                "ml": ml_res,
                "rules": rule_res,
                "features": feature_vector,
            }

            # Process prediction and check containment
            containment_manager.process_prediction_window(
                pred_record,
                attack_ops_provider=simulator_controller.get_ground_truth_ops,
            )

    import threading
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()

    try:
        # 2. Launch controlled attack simulator
        print(f"\n[DEMO] Starting attack simulator under SimulatorController...")
        simulator_controller.start_attack(
            speed=speed,
            max_files=max_files,
            seed=seed,
            run_id=run_id,
        )

        containment_manager.record_attack_start(
            run_id=run_id,
            start_time=time.time(),
        )

        # Wait for attack simulator to finish or be contained
        while simulator_controller.is_active():
            time.sleep(0.2)

        # Allow buffer to drain final events
        time.sleep(2.0)
        running = False
        monitor_thread.join(timeout=2.0)

    finally:
        observer.stop()
        observer.join()

    res = containment_manager.last_metrics or {}
    print("\n==================================================")
    print("    CONTAINMENT DEMO COMPLETED SUCCESSFULLY       ")
    print("==================================================")
    return res


if __name__ == "__main__":
    speed_arg = sys.argv[1] if len(sys.argv) > 1 else "medium"
    run_safe_containment_demo(speed=speed_arg)
