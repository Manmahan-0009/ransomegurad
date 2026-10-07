"""
RansomGuard - Debounce & Alert Confirmation Module (backend/app/debounce.py)

Implements a consecutive-window alert confirmation mechanism to stabilize alerts.
- Confirms alert when raw severity is HIGH/CRITICAL for 2 consecutive windows.
- Allows immediate alert bypass for very high threat score (>= 85.0).
- Tracks state per active session and supports pipeline reset.
"""

from typing import Dict, Any, Optional
from .config import config, DetectionConfig


class DebounceEngine:
    """
    Evaluates raw window severity against consecutive window history to produce
    a debounced alert state.
    """

    def __init__(self, cfg: Optional[DetectionConfig] = None):
        self.cfg = cfg or config
        self.consecutive_high_count = 0

    def evaluate(self, threat_score: float, raw_severity: str) -> Dict[str, Any]:
        """
        Evaluates raw threat score and raw severity against consecutive window rule.

        Returns:
            Dict containing debounced_severity, debounced_alert (bool), and consecutive_windows (int).
        """
        # Immediate alert bypass for severe CRITICAL score
        if threat_score >= self.cfg.immediate_critical_score:
            self.consecutive_high_count += 1
            return {
                "debounced_severity": raw_severity,
                "debounced_alert": True,
                "consecutive_windows": self.consecutive_high_count,
                "immediate_bypass": True,
            }

        if raw_severity in ["HIGH", "CRITICAL"]:
            self.consecutive_high_count += 1
            if self.consecutive_high_count >= self.cfg.consecutive_windows_required:
                return {
                    "debounced_severity": raw_severity,
                    "debounced_alert": True,
                    "consecutive_windows": self.consecutive_high_count,
                    "immediate_bypass": False,
                }
            else:
                return {
                    "debounced_severity": "MEDIUM",
                    "debounced_alert": False,
                    "consecutive_windows": self.consecutive_high_count,
                    "immediate_bypass": False,
                }
        else:
            self.consecutive_high_count = 0
            return {
                "debounced_severity": raw_severity,
                "debounced_alert": False,
                "consecutive_windows": 0,
                "immediate_bypass": False,
            }

    def reset(self) -> None:
        """Resets consecutive window counter."""
        self.consecutive_high_count = 0
