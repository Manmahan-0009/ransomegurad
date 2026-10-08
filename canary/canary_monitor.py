"""
RansomGuard - Canary Monitor (canary/canary_monitor.py)

Monitors filesystem events for interactions with registered canary files,
resolving process context and producing normalized CanaryEvent objects.
"""

import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from process_telemetry.process_resolver import process_resolver
from .canary_models import CanaryRecord, CanaryEvent
from .canary_registry import canary_registry, CanaryRegistry


class CanaryMonitor:
    """
    Evaluates filesystem events against registered canaries.
    """

    def __init__(self, registry: Optional[CanaryRegistry] = None):
        self.registry = registry or canary_registry

    def inspect_event(
        self,
        event_dict: Dict[str, Any],
        device_id: str,
        ml_prob: float = 0.0,
        threat_score: float = 0.0,
        rule_score: int = 0,
        severity: str = "LOW",
    ) -> Optional[CanaryEvent]:
        """
        Inspects a single filesystem event dictionary (e.g. from StructuredEvent or Watchdog)
        and returns a CanaryEvent if a registered canary file was touched.
        """
        src_path = event_dict.get("src_path") or event_dict.get("path") or ""
        dest_path = event_dict.get("dest_path")
        event_type_raw = str(event_dict.get("event_type", "")).lower()

        # Check src_path against registry
        canary_rec = self.registry.get_by_path(src_path)
        matched_path = src_path

        # If dest_path present (e.g. rename), check dest_path as well
        if not canary_rec and dest_path:
            canary_rec = self.registry.get_by_path(dest_path)
            matched_path = dest_path

        if not canary_rec:
            return None

        # Determine normalized CanaryEvent event_type
        if event_type_raw in ("moved", "renamed"):
            if dest_path and dest_path.endswith(".locked"):
                evt_type = "EXTENSION_CHANGED"
            else:
                evt_type = "RENAMED"
        elif event_type_raw in ("deleted", "removed"):
            evt_type = "DELETED"
        elif event_type_raw in ("modified", "written"):
            if matched_path.endswith(".locked"):
                evt_type = "EXTENSION_CHANGED"
            else:
                evt_type = "MODIFIED"
        elif matched_path.endswith(".locked"):
            evt_type = "EXTENSION_CHANGED"
        else:
            evt_type = "MODIFIED"

        # Resolve process context for this event
        proc_ctx = process_resolver.resolve_event_process(event_dict)
        proc_dict = proc_ctx.to_dict()

        canary_evt = CanaryEvent(
            canary_id=canary_rec.canary_id,
            device_id=device_id,
            timestamp=event_dict.get("timestamp", time.time()),
            event_type=evt_type,
            old_path=src_path,
            new_path=dest_path,
            process_context=proc_dict,
            attribution_confidence=proc_ctx.attribution_confidence,
            current_threat_probability=ml_prob,
            current_threat_score=threat_score,
            current_rule_score=rule_score,
            current_severity=severity,
        )

        return canary_evt

    def inspect_events_batch(
        self,
        events: List[Dict[str, Any]],
        device_id: str,
        ml_prob: float = 0.0,
        threat_score: float = 0.0,
        rule_score: int = 0,
        severity: str = "LOW",
    ) -> List[CanaryEvent]:
        """
        Inspects a batch of events and returns all matching CanaryEvents.
        """
        canary_events: List[CanaryEvent] = []
        seen_canaries = set()

        for ev in events:
            ce = self.inspect_event(
                event_dict=ev,
                device_id=device_id,
                ml_prob=ml_prob,
                threat_score=threat_score,
                rule_score=rule_score,
                severity=severity,
            )
            if ce and ce.canary_id not in seen_canaries:
                canary_events.append(ce)
                seen_canaries.add(ce.canary_id)

        return canary_events


canary_monitor = CanaryMonitor()
