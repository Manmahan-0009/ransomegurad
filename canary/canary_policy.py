"""
RansomGuard - Canary Policy Engine (canary/canary_policy.py)

Evaluates canary evidence against behavioral signals (RF probability, rules,
extension changes, entropy) to decide whether to trigger early alert confirmation.
"""

from typing import Dict, Any, List, Optional, Tuple
from .canary_config import canary_config, CanaryConfig
from .canary_models import CanaryEvent


class CanaryPolicyEngine:
    """
    Evaluates policy rules combining canary evidence with ML & rule engine metrics.
    """

    def __init__(self, config: Optional[CanaryConfig] = None):
        self.cfg = config or canary_config

    def evaluate(
        self,
        canary_events: List[CanaryEvent],
        ml_result: Dict[str, Any],
        rule_result: Dict[str, Any],
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluates canary events + behavioral metrics.

        Returns:
            Dict containing:
                - early_confirmation: bool
                - confirmation_source: str ("CANARY_ASSISTED" or "STANDARD_DEBOUNCE")
                - debounced_alert: bool
                - debounced_severity: str
                - policy_mode: str ("DISABLED", "CANARY_ONLY", "CANARY_ASSISTED_CONFIRMED")
                - reason: str
                - primary_canary_event: Optional[CanaryEvent]
        """
        if not self.cfg.enabled or not self.cfg.early_confirm_enabled or not canary_events:
            return {
                "early_confirmation": False,
                "confirmation_source": "STANDARD_DEBOUNCE",
                "debounced_alert": False,
                "debounced_severity": "LOW",
                "policy_mode": "DISABLED" if not self.cfg.enabled else "NO_CANARY_EVENT",
                "reason": "Canary disabled or no canary event",
                "primary_canary_event": None,
            }

        # Select primary (destructive) canary event
        primary_ce = next(
            (ce for ce in canary_events if ce.event_type in ("EXTENSION_CHANGED", "MODIFIED", "DELETED", "RENAMED")),
            canary_events[0]
        )

        rf_prob = float(ml_result.get("threat_probability", 0.0))
        rule_score = int(rule_result.get("rule_score", 0))
        rules_triggered = rule_result.get("triggered_rules", [])

        ext_changes = int(features.get("extension_changes", 0))
        mean_ent = float(features.get("mean_entropy", 0.0))
        ent_change = float(features.get("entropy_change", 0.0))

        # Check behavioral agreement indicators
        has_ext_signal = ext_changes >= 1 or "EXTENSION_CHANGES" in rules_triggered
        has_ent_signal = mean_ent >= 6.0 or ent_change > 0.05 or "HIGH_ENTROPY" in rules_triggered
        has_rule_signal = rule_score >= 30

        # Enforce configurable signal requirements if set
        if self.cfg.require_extension_signal and not has_ext_signal:
            behavioral_agreement = False
        elif self.cfg.require_entropy_signal and not has_ent_signal:
            behavioral_agreement = False
        else:
            behavioral_agreement = has_ext_signal or has_ent_signal or has_rule_signal

        rf_satisfied = rf_prob >= self.cfg.rf_threshold

        # CANARY_ML_ASSISTED EARLY CONFIRMATION TRIGGER
        if rf_satisfied and behavioral_agreement:
            reason = (
                f"Canary '{primary_ce.event_type}' touched with strong ML + behavioral agreement "
                f"(RF prob={rf_prob:.2f} >= {self.cfg.rf_threshold}, rules={rules_triggered})"
            )
            return {
                "early_confirmation": True,
                "confirmation_source": "CANARY_ML_ASSISTED",
                "debounced_alert": True,
                "debounced_severity": "HIGH",
                "policy_mode": "CANARY_ML_ASSISTED_CONFIRMED",
                "reason": reason,
                "primary_canary_event": primary_ce,
                "fresh_rf_evidence": True,
            }

        # CANARY_RULE_ASSISTED TRIGGER (Deterministic rule evidence without ML threshold)
        if behavioral_agreement and (has_ext_signal and has_ent_signal):
            reason = (
                f"Canary '{primary_ce.event_type}' touched with deterministic rule signals "
                f"(extension_changes={ext_changes}, entropy={mean_ent:.2f}, rules={rules_triggered})"
            )
            return {
                "early_confirmation": True,
                "confirmation_source": "CANARY_RULE_ASSISTED",
                "debounced_alert": True,
                "debounced_severity": "HIGH",
                "policy_mode": "CANARY_RULE_ASSISTED_CONFIRMED",
                "reason": reason,
                "primary_canary_event": primary_ce,
                "fresh_rf_evidence": False,
            }

        # CANARY_ONLY MODE (Single canary touch without sufficient behavioral evidence)
        reason = (
            f"Canary '{primary_ce.event_type}' touched without sufficient behavioral agreement "
            f"(RF prob={rf_prob:.2f}, rule_score={rule_score}). Logged event; no automatic containment."
        )
        return {
            "early_confirmation": False,
            "confirmation_source": "STANDARD_DEBOUNCE",
            "debounced_alert": False,
            "debounced_severity": "MEDIUM",
            "policy_mode": "CANARY_ONLY",
            "reason": reason,
            "primary_canary_event": primary_ce,
        }


canary_policy_engine = CanaryPolicyEngine()
