"""
RansomGuard - Safe Containment Manager (containment/stopper.py)

Orchestrates safe simulated containment when a confirmed threat alert fires.
Ensures containment only stops the RansomGuard controlled attack simulator.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from simulator.simulator_controller import simulator_controller
from containment.containment_metrics import compute_containment_metrics

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_CONTAINMENT_DIR = PROJECT_ROOT / "results" / "containment"
RESULTS_CONTAINMENT_DIR.mkdir(parents=True, exist_ok=True)


class ContainmentManager:
    """
    Manages safe simulated containment state and logs response metrics.
    """

    def __init__(self, auto_containment_enabled: bool = True):
        self.auto_containment_enabled = auto_containment_enabled
        self.state = "IDLE"
        self.current_run_id: Optional[str] = None
        self.attack_start_time: Optional[float] = None
        self.raw_detection_time: Optional[float] = None
        self.confirmed_alert_time: Optional[float] = None
        self.containment_request_time: Optional[float] = None
        self.containment_complete_time: Optional[float] = None
        self.last_metrics: Optional[Dict[str, Any]] = None

    def reset(self):
        """Resets state machine for a new monitoring session."""
        self.state = "IDLE"
        self.current_run_id = None
        self.attack_start_time = None
        self.raw_detection_time = None
        self.confirmed_alert_time = None
        self.containment_request_time = None
        self.containment_complete_time = None
        self.last_metrics = None

    def record_attack_start(self, run_id: str, start_time: Optional[float] = None):
        """Marks attack start timestamp."""
        self.reset()
        self.state = "ATTACK_ACTIVE"
        self.current_run_id = run_id
        self.attack_start_time = start_time or time.time()

    def record_raw_detection(self, timestamp: Optional[float] = None):
        """Records timestamp of first qualifying raw detection window (HIGH/CRITICAL)."""
        if self.raw_detection_time is None:
            self.raw_detection_time = timestamp or time.time()
            if self.state in ["IDLE", "ATTACK_ACTIVE"]:
                self.state = "ALERT_PENDING"

    def process_prediction_window(
        self,
        prediction_result: Dict[str, Any],
        attack_ops_provider: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates prediction result. If debounced confirmed alert is present, triggers containment.
        """
        raw_sev = prediction_result.get("severity", "LOW")
        debounce = prediction_result.get("debounce", {})
        is_debounced_alert = Boolean(debounce.get("debounced_alert", False))

        now_ts = time.time()

        if raw_sev in ["HIGH", "CRITICAL"]:
            self.record_raw_detection(now_ts)

        if is_debounced_alert and self.state in ["IDLE", "ATTACK_ACTIVE", "ALERT_PENDING"]:
            self.confirmed_alert_time = now_ts
            self.state = "ALERT_CONFIRMED"

            if self.auto_containment_enabled:
                return self.execute_containment(attack_ops_provider=attack_ops_provider)

        return {
            "state": self.state,
            "auto_containment": self.auto_containment_enabled,
            "containment_executed": False,
        }

    def execute_containment(self, attack_ops_provider: Optional[callable] = None) -> Dict[str, Any]:
        """
        Executes safe simulated containment by signaling ONLY the controlled simulator.
        Idempotent: will not re-trigger if already requested or contained.
        """
        if self.state in ["CONTAINMENT_REQUESTED", "CONTAINED"]:
            return {
                "state": self.state,
                "status": "already_executed",
                "containment_executed": True,
                "metrics": self.last_metrics,
            }

        self.state = "CONTAINMENT_REQUESTED"
        req_ts = time.time()
        self.containment_request_time = req_ts

        print("\n==================================================")
        print("  [ALERT] SAFE SIMULATED CONTAINMENT SIGNAL FIRED ")
        print(" Signaling controlled RansomGuard attack simulator...")
        print("==================================================")

        # Stop ONLY controlled simulator
        stop_res = simulator_controller.stop_attack()
        comp_ts = stop_res.get("containment_complete_time", time.time())
        self.containment_complete_time = comp_ts
        self.state = "CONTAINED"

        # Obtain ground truth operations from controller or provider
        gt_ops = []
        target_files_count = 20
        if attack_ops_provider:
            gt_ops = attack_ops_provider()
        elif simulator_controller.get_result():
            res = simulator_controller.get_result()
            gt_ops = res.get("ground_truth_ops", [])
            target_files_count = res.get("total_target_files", 20)
        else:
            gt_ops = simulator_controller.get_ground_truth_ops()

        if not self.attack_start_time and gt_ops:
            self.attack_start_time = gt_ops[0].get("operation_time", req_ts - 2.0)

        # Calculate metrics
        metrics = compute_containment_metrics(
            attack_start_time=self.attack_start_time,
            raw_detection_time=self.raw_detection_time,
            confirmed_alert_time=self.confirmed_alert_time,
            containment_request_time=self.containment_request_time,
            containment_complete_time=self.containment_complete_time,
            ground_truth_ops=gt_ops,
            total_files_targeted=target_files_count,
        )

        run_id = self.current_run_id or simulator_controller.get_run_id() or f"attack_{int(time.time())}"
        self.last_metrics = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "containment_status": stop_res.get("status", "stopped_successfully"),
            "state": self.state,
            "timestamps": {
                "attack_start_time": self.attack_start_time,
                "raw_detection_time": self.raw_detection_time,
                "confirmed_alert_time": self.confirmed_alert_time,
                "containment_request_time": self.containment_request_time,
                "containment_complete_time": self.containment_complete_time,
            },
            "metrics": metrics,
        }

        # Save artifact JSON
        save_path = RESULTS_CONTAINMENT_DIR / f"containment_run_{run_id}.json"
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(self.last_metrics, f, indent=2)
            print(f"[CONTAINMENT] Saved run metrics to: {save_path}")
        except Exception as err:
            print(f"[CONTAINMENT WARNING] Failed to save containment log: {err}")

        print("\n[SAFE CONTAINMENT RESULTS]")
        print(f"  Status                  : {stop_res.get('status')}")
        print(f"  TTD (Raw)               : {metrics['TTD_raw']}s")
        print(f"  TTD (Confirmed)         : {metrics['TTD_confirmed']}s")
        print(f"  TTC (Containment Duration): {metrics['TTC']}s")
        print(f"  Files Affected (Raw)    : {metrics['files_affected_before_raw_detection']}")
        print(f"  Files Affected (Confirm): {metrics['files_affected_before_confirmed_alert']}")
        print(f"  Files Affected (Contain): {metrics['files_affected_before_containment']}")
        print(f"  Files Protected         : {metrics['files_protected']} / {metrics['total_target_files']} ({metrics['percentage_files_protected']}%)")
        print("==================================================\n")

        return {
            "state": self.state,
            "status": stop_res.get("status"),
            "containment_executed": True,
            "metrics": self.last_metrics,
        }


# Helper boolean parser
def Boolean(val) -> bool:
    return bool(val)


# Global containment manager singleton
containment_manager = ContainmentManager(auto_containment_enabled=True)
