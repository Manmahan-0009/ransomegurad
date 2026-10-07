"""
RansomGuard - Live Detection Baseline Validation Runner (run_live_validation.py)

Runs controlled, reproducible baseline live-detection evaluations for:
1. NORMAL
2. BENIGN
3. ATTACK

Executes feature extraction, ML inference, rule evaluation, threat scoring, debounce,
and structured logging for each scenario. Saves results to results/live_validation_v1.json.
"""

import sys
import json
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.sandbox_manager import reset_sandbox, get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from features.entropy import get_entropy_tracker

from simulator.normal_simulator import run_normal_simulation
from simulator.benign_simulator import run_benign_simulation
from simulator.attack_simulator import run_attack_simulation

from backend.app.config import config
from backend.app.model_service import ModelService
from backend.app.rule_engine import RuleEngine
from backend.app.threat_score import ThreatScoreEngine
from backend.app.debounce import DebounceEngine
from backend.app.logger import LivePredictionLogger


def run_scenario_evaluation(scenario_name: str, sim_func, window_seconds: float = 5.0, stride_seconds: float = 1.0) -> dict:
    print(f"\n==================================================")
    print(f"      RUNNING LIVE VALIDATION: {scenario_name.upper()}      ")
    print(f"==================================================")

    # 1. Reset sandbox & pipeline
    reset_sandbox()
    eq = EventQueue()
    deduplicator = EventDeduplicator(dedupe_ms=200.0)
    window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)
    get_entropy_tracker().clear()

    model_service = ModelService()
    rule_engine = RuleEngine()
    threat_score_engine = ThreatScoreEngine()
    debounce_engine = DebounceEngine()
    prediction_logger = LivePredictionLogger()

    demo_dir = get_demo_dir().resolve()
    observer = start_monitoring(
        target_dir=demo_dir,
        queue_callback=eq.push,
        print_events=False,
        block=False,
    )

    windows_results = []
    all_triggered_rules = set()

    max_rf_prob = 0.0
    max_rule_score = 0
    max_final_score = 0.0
    max_severity = "LOW"
    max_debounced_severity = "LOW"

    feature_peaks = {
        "files_created": 0,
        "files_modified": 0,
        "files_deleted": 0,
        "files_renamed": 0,
        "writes_per_second": 0.0,
        "unique_extensions": 0,
        "unique_directories": 0,
        "extension_change_count": 0,
        "rename_ratio": 0.0,
        "mean_entropy": 0.0,
        "entropy_change": 0.0,
    }

    running = True

    def eval_loop():
        nonlocal max_rf_prob, max_rule_score, max_final_score, max_severity, max_debounced_severity
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
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

            res_record = {
                "timestamp": datetime.now().isoformat(),
                "scenario_id": scenario_name,
                "prediction": ml_res["prediction"],
                "severity": score_res["severity"],
                "threat_score": score_res["threat_score"],
                "debounce": debounce_res,
                "ml": ml_res,
                "rules": rule_res,
                "features": feature_vector,
                "version_info": {
                    "model_version": config.model_version,
                    "feature_schema_version": config.feature_schema_version,
                    "rf_threshold": config.rf_threshold,
                    "ml_weight": config.ml_weight,
                    "rule_weight": config.rule_weight,
                },
            }

            prediction_logger.log(res_record)
            windows_results.append(res_record)

            max_rf_prob = max(max_rf_prob, ml_res["threat_probability"])
            max_rule_score = max(max_rule_score, rule_res["rule_score"])
            max_final_score = max(max_final_score, score_res["threat_score"])

            for r in rule_res["triggered_rules"]:
                all_triggered_rules.add(r["rule"])

            for k, v in feature_vector.items():
                if k in feature_peaks:
                    feature_peaks[k] = max(feature_peaks[k], v)

            if sev_rank.get(score_res["severity"], 0) > sev_rank.get(max_severity, 0):
                max_severity = score_res["severity"]

            d_sev = debounce_res["debounced_severity"]
            if sev_rank.get(d_sev, 0) > sev_rank.get(max_debounced_severity, 0):
                max_debounced_severity = d_sev

    import threading
    eval_thread = threading.Thread(target=eval_loop, daemon=True)
    eval_thread.start()

    try:
        # Run simulation in main thread
        sim_start = time.time()
        sim_func()
        sim_duration = time.time() - sim_start

        # Allow final events to arrive and be processed by loop
        time.sleep(3.0)
        running = False
        eval_thread.join(timeout=2.0)

    finally:
        observer.stop()
        observer.join()
        observer.join()

    print(f"[{scenario_name.upper()} RESULTS]")
    print(f"  Max RF Probability     : {max_rf_prob:.4f}")
    print(f"  Max Rule Score         : {max_rule_score}")
    print(f"  Max Final Threat Score : {max_final_score:.2f}")
    print(f"  Max Raw Severity       : {max_severity}")
    print(f"  Max Debounced Severity : {max_debounced_severity}")
    print(f"  Triggered Rules        : {list(all_triggered_rules)}")

    return {
        "scenario": scenario_name,
        "max_rf_probability": round(max_rf_prob, 4),
        "max_rule_score": max_rule_score,
        "max_final_score": round(max_final_score, 2),
        "max_raw_severity": max_severity,
        "max_debounced_severity": max_debounced_severity,
        "triggered_rules": sorted(list(all_triggered_rules)),
        "feature_peaks": feature_peaks,
        "timestamp": datetime.now().isoformat(),
        "config": {
            "model_version": config.model_version,
            "feature_schema_version": config.feature_schema_version,
            "rf_threshold": config.rf_threshold,
            "ml_weight": config.ml_weight,
            "rule_weight": config.rule_weight,
            "min_rename_count": config.min_rename_count,
            "consecutive_windows_required": config.consecutive_windows_required,
        },
    }


def main():
    results = {}

    # 1. Normal
    normal_res = run_scenario_evaluation(
        "normal",
        lambda: run_normal_simulation(duration=15.0, delay=1.5, seed=42)
    )
    results["normal"] = normal_res

    # 2. Benign
    benign_res = run_scenario_evaluation(
        "benign",
        lambda: run_benign_simulation(duration=15.0, speed="fast", max_files=25, seed=42)
    )
    results["benign"] = benign_res

    # 3. Attack
    attack_res = run_scenario_evaluation(
        "attack",
        lambda: run_attack_simulation(speed="fast", max_files=20, seed=42)
    )
    results["attack"] = attack_res

    out_dir = PROJECT_ROOT / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_filename = sys.argv[1] if len(sys.argv) > 1 else "live_validation_v2.json"
    out_file = out_dir / out_filename

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n==================================================")
    print(f" [SUCCESS] Saved live validation artifact to:")
    print(f" {out_file}")
    print(f"==================================================")


if __name__ == "__main__":
    main()
