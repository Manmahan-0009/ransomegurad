"""
RansomGuard - Simulator Controller (simulator/simulator_controller.py)

Manages controlled execution of RansomGuard attack simulations in isolated threads.
Exposes safe cooperative containment stopping mechanisms without affecting outside processes.
"""

import threading
import time
from typing import Optional, Dict, Any, Callable
from simulator.attack_simulator import run_attack_simulation


class SimulatorController:
    """
    Controller for launching and stopping controlled attack simulator runs safely.
    """

    def __init__(self):
        self._active_thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._current_run_id: Optional[str] = None
        self._result: Optional[Dict[str, Any]] = None
        self._lock: threading.Lock = threading.Lock()
        self._attack_start_time: Optional[float] = None
        self._ground_truth_ops: list = []

    def start_attack(
        self,
        speed: str = "medium",
        max_files: int = 20,
        seed: Optional[int] = None,
        run_id: Optional[str] = None,
        op_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> str:
        """
        Launches controlled attack simulator in a dedicated background thread.
        """
        with self._lock:
            if self.is_active():
                raise RuntimeError("An attack simulator run is already active under SimulatorController.")

            self._stop_event.clear()
            self._current_run_id = run_id or f"attack_{int(time.time())}"
            self._result = None
            self._ground_truth_ops = []

            def record_op_callback(op_rec):
                self._ground_truth_ops.append(op_rec)
                if op_callback:
                    op_callback(op_rec)

            def target():
                res = run_attack_simulation(
                    speed=speed,
                    max_files=max_files,
                    seed=seed,
                    run_id=self._current_run_id,
                    op_callback=record_op_callback,
                    stop_event=self._stop_event,
                )
                with self._lock:
                    self._result = res
                    self._attack_start_time = res.get("attack_start_time")

            self._active_thread = threading.Thread(target=target, daemon=True)
            self._active_thread.start()

            return self._current_run_id

    def stop_attack(self) -> Dict[str, Any]:
        """
        Requests safe cooperative containment of the active controlled attack simulator.
        Returns containment stop timing information.
        """
        request_time = time.time()
        with self._lock:
            if not self.is_active():
                return {
                    "status": "already_stopped" if self._result else "no_active_simulator",
                    "containment_request_time": request_time,
                    "containment_complete_time": request_time,
                    "duration_seconds": 0.0,
                }

            self._stop_event.set()
            thread = self._active_thread

        if thread:
            thread.join(timeout=5.0)

        complete_time = time.time()
        return {
            "status": "stopped_successfully",
            "containment_request_time": request_time,
            "containment_complete_time": complete_time,
            "duration_seconds": complete_time - request_time,
        }

    def is_active(self) -> bool:
        return self._active_thread is not None and self._active_thread.is_alive()

    def get_run_id(self) -> Optional[str]:
        return self._current_run_id

    def get_ground_truth_ops(self) -> list:
        with self._lock:
            return list(self._ground_truth_ops)

    def get_result(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._result


# Global singleton instance for controller
simulator_controller = SimulatorController()
