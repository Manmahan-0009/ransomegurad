"""
RansomGuard - Endpoint Agent Service (agent/agent_service.py)

Main orchestrator for endpoint agent mode:
- Runs local filesystem monitoring (Watchdog)
- Extracts canonical 11 features locally
- Evaluates local Random Forest model + rule engine + threat score + debounce
- Reports heartbeats, windowed telemetry, and confirmed alerts to central FastAPI server
- Reconnects gracefully if central server goes offline without interrupting local detection
"""

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent_config import agent_config
from agent.device_identity import get_or_create_device_identity
from agent.telemetry_sender import TelemetrySender
from agent.heartbeat import HeartbeatThread

from utils.sandbox_manager import get_demo_dir
from monitoring.watcher import start_monitoring
from monitoring.event_queue import EventQueue
from monitoring.deduplicator import EventDeduplicator
from windowing.sliding_window import SlidingWindowBuffer
from features.extractor import extract_features
from features.entropy import get_entropy_tracker

from backend.app.model_service import ModelService
from backend.app.rule_engine import RuleEngine
from backend.app.threat_score import ThreatScoreEngine
from backend.app.debounce import DebounceEngine

from process_telemetry.process_resolver import process_resolver
from canary.canary_config import canary_config
from canary.canary_manager import canary_manager
from canary.canary_monitor import canary_monitor
from canary.canary_policy import canary_policy_engine



class RansomGuardAgent:
    """
    Independent RansomGuard Endpoint Agent.
    Runs local detection and communicates with Central Server.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        custom_hostname: Optional[str] = None,
        watch_dir: Optional[Path] = None,
        window_seconds: float = 5.0,
        stride_seconds: float = 1.0,
        dedupe_ms: float = 200.0,
    ):
        self.server_url = server_url or agent_config.server_url
        self.identity = get_or_create_device_identity(custom_hostname=custom_hostname)
        self.device_id = self.identity["device_id"]
        self.watch_dir = watch_dir or get_demo_dir()
        self.window_seconds = window_seconds
        self.stride_seconds = stride_seconds
        self.dedupe_ms = dedupe_ms

        self.telemetry_sender = TelemetrySender(server_url=self.server_url)

        # Local ML & Rule Detection Pipeline
        self.model_service = ModelService()
        self.rule_engine = RuleEngine()
        self.threat_score_engine = ThreatScoreEngine()
        self.debounce_engine = DebounceEngine()

        # Monitoring components
        self.eq = EventQueue()
        self.deduplicator = EventDeduplicator(dedupe_ms=dedupe_ms)
        self.window_buffer = SlidingWindowBuffer(window_seconds=window_seconds, stride_seconds=stride_seconds)
        self.observer = None
        self.heartbeat_thread: Optional[HeartbeatThread] = None

        # Canary Evidence Layer Components (Phase 10)
        self.canary_manager = canary_manager
        self.canary_monitor = canary_monitor
        self.canary_policy_engine = canary_policy_engine

        # Agent state tracking
        self.current_severity = "LOW"
        self.current_threat_score = 0.0
        self.last_prediction = "BENIGN"

    def get_status(self) -> Dict[str, Any]:
        """Provides current agent status for heartbeats."""
        return {
            "current_severity": self.current_severity,
            "current_threat_score": self.current_threat_score,
            "last_prediction": self.last_prediction,
        }

    def start(self, block: bool = True) -> None:
        self.watch_dir = self.watch_dir.resolve()
        self.watch_dir.mkdir(parents=True, exist_ok=True)

        print("==================================================")
        print("          RANSOMGUARD ENDPOINT AGENT              ")
        print(f" Device ID:   {self.device_id}")
        print(f" Hostname:    {self.identity['hostname']}")
        print(f" OS:          {self.identity['os']}")
        print(f" Central:     {self.server_url}")
        print(f" Target Dir:  {self.watch_dir}")
        print("==================================================")

        # 1. LAN Connectivity Check & Registration
        self.telemetry_sender.check_server_connectivity(max_retries=3, base_retry_delay=1.0)
        registered = self.telemetry_sender.register_agent(self.identity)
        if registered:
            self.telemetry_sender.send_log_event(
                self.device_id,
                category="AGENT",
                severity="INFO",
                event_type="AGENT_STARTED",
                message=f"Agent started on {self.identity['hostname']} ({self.identity['os']})",
            )
        else:
            print("[AGENT WARNING] Central server offline or rejected registration. Continuing local detection...")

        # Initialize local canary files & register with central DB (Phase 10)
        if canary_config.enabled:
            canary_dir = self.watch_dir / canary_config.relative_canary_dir
            records = self.canary_manager.setup_canaries(
                device_id=self.device_id,
                target_dir=canary_dir,
                count=canary_config.canary_count,
            )
            for r in records:
                self.telemetry_sender.send_canary_registration(self.device_id, r.to_dict())

        # 2. Start heartbeat thread
        self.heartbeat_thread = HeartbeatThread(
            telemetry_sender=self.telemetry_sender,
            identity=self.identity,
            status_provider=self.get_status,
        )
        self.heartbeat_thread.start()

        # 3. Start local filesystem watcher
        self.observer = start_monitoring(
            target_dir=self.watch_dir,
            queue_callback=self.eq.push,
            print_events=False,
            block=False,
        )

        if block:
            try:
                self._run_detection_loop()
            except KeyboardInterrupt:
                print("\n[AGENT] Stopping RansomGuard Agent...")
            finally:
                self.stop()

    def _run_detection_loop(self) -> None:
        """Main local detection loop."""
        while True:
            time.sleep(self.stride_seconds)
            self.step_detection()

    def step_detection(self) -> Dict[str, Any]:
        """Runs a single detection step (used by loop and testing)."""
        raw_events = self.eq.flush()
        kept_events = self.deduplicator.deduplicate_list(raw_events)
        self.window_buffer.add_events(kept_events)
        current_window_events = self.window_buffer.get_current_events()

        # Extract local 11 features
        features = extract_features(current_window_events, window_seconds=self.window_seconds)

        # Local ML inference
        ml_result = self.model_service.predict(features)

        # Local Rule Engine evaluation
        rule_result = self.rule_engine.evaluate(features)

        # Local Hybrid Threat Score calculation
        score_result = self.threat_score_engine.calculate(
            threat_probability=ml_result["threat_probability"],
            rule_score=rule_result["rule_score"],
        )

        # Local Debounce logic
        debounce_result = self.debounce_engine.evaluate(
            threat_score=score_result["threat_score"],
            raw_severity=score_result["severity"],
        )

        # Canary Evidence Layer Evaluation (Phase 10)
        canary_events = []
        canary_eval = {"early_confirmation": False, "policy_mode": "DISABLED"}
        if canary_config.enabled:
            event_dicts = [e.to_dict() for e in current_window_events]
            canary_events = self.canary_monitor.inspect_events_batch(
                events=event_dicts,
                device_id=self.device_id,
                ml_prob=ml_result["threat_probability"],
                threat_score=score_result["threat_score"],
                rule_score=rule_result["rule_score"],
                severity=score_result["severity"],
            )
            if canary_events:
                for ce in canary_events:
                    self.telemetry_sender.send_canary_event(self.device_id, ce.to_dict())
                canary_eval = self.canary_policy_engine.evaluate(
                    canary_events=canary_events,
                    ml_result=ml_result,
                    rule_result=rule_result,
                    features=features,
                )
                if canary_eval.get("early_confirmation"):
                    debounce_result["debounced_alert"] = True
                    debounce_result["early_confirmation"] = True
                    debounce_result["confirmation_source"] = canary_eval.get("confirmation_source", "CANARY_ML_ASSISTED")
                    debounce_result["debounced_severity"] = "HIGH"
                    score_result["severity"] = "HIGH"
                elif canary_eval.get("policy_mode") == "CANARY_ONLY":
                    if debounce_result.get("debounced_severity") == "LOW":
                        debounce_result["debounced_severity"] = "MEDIUM"

        # Update current agent state
        self.current_threat_score = score_result["threat_score"]
        self.current_severity = debounce_result.get("debounced_severity", score_result["severity"])
        self.last_prediction = ml_result["prediction"]

        # Process telemetry aggregation (Phase 9)
        process_summary = {"dominant_process": None, "processes": []}
        if agent_config.process_telemetry_enabled:
            event_dicts = [e.to_dict() for e in current_window_events]
            process_summary = process_resolver.aggregate_process_summary(event_dicts)

        # Build prediction payload
        prediction_data = {
            "timestamp": time.time(),
            "prediction": ml_result["prediction"],
            "severity": self.current_severity,
            "threat_score": score_result["threat_score"],
            "debounce": debounce_result,
            "ml": ml_result,
            "rules": rule_result,
            "features": features,
            "dominant_process": process_summary.get("dominant_process"),
            "processes": process_summary.get("processes", []),
            "canary_eval": canary_eval,
            "version_info": {
                "model_version": "rf_v2",
                "feature_schema_version": "v1",
            },
        }

        # Send window telemetry if enabled
        if agent_config.telemetry_enabled:
            self.telemetry_sender.send_telemetry(self.device_id, prediction_data)

        # If debounced alert is confirmed, send POST /agents/alerts
        if debounce_result.get("debounced_alert"):
            dom_proc = process_summary.get("dominant_process") or {}
            primary_ce = canary_eval.get("primary_canary_event")
            alert_data = {
                "timestamp": prediction_data["timestamp"],
                "severity": self.current_severity,
                "prediction": ml_result["prediction"],
                "threat_score": score_result["threat_score"],
                "ml": ml_result,
                "rules": rule_result,
                "containment": {"state": "NONE"},
                "primary_process": dom_proc,
                "process_attribution_confidence": dom_proc.get("attribution_confidence", "UNKNOWN"),
                "process_summary": process_summary.get("processes", []),
                "canary_triggered": bool(canary_events),
                "canary_id": primary_ce.canary_id if primary_ce else None,
                "canary_event_type": primary_ce.event_type if primary_ce else None,
                "early_confirmation": bool(debounce_result.get("early_confirmation", False)),
                "confirmation_source": debounce_result.get("confirmation_source", "STANDARD_DEBOUNCE"),
            }
            self.telemetry_sender.send_alert(self.device_id, alert_data)


        ts = datetime.now().strftime("%H:%M:%S")
        if self.current_threat_score > 0 or features["files_modified"] > 0 or features["files_created"] > 0:
            print(
                f"[{ts}] [{self.identity['hostname']}] Score: {self.current_threat_score:<5} | "
                f"Sev: {self.current_severity:<8} | Pred: {self.last_prediction}"
            )

        return prediction_data

    def stop(self) -> None:
        """Stops agent thread and watcher cleanly."""
        if self.heartbeat_thread:
            self.heartbeat_thread.stop()
        if self.observer:
            self.observer.stop()
            self.observer.join()
        print(f"[AGENT] Agent stopped cleanly for device {self.device_id}")


def run_agent(
    server_url: str = "http://127.0.0.1:8000",
    device_name: Optional[str] = None,
    watch_dir: Optional[str] = None,
) -> None:
    target_path = Path(watch_dir) if watch_dir else get_demo_dir()
    agent = RansomGuardAgent(
        server_url=server_url,
        custom_hostname=device_name,
        watch_dir=target_path,
    )
    agent.start(block=True)
