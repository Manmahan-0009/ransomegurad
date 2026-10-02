"""
RansomGuard - Event Deduplication Module (monitoring/deduplicator.py)

Filters out duplicate filesystem events caused by Watchdog / OS buffer flushes.
Deduplicates rapid repeated 'modified' events for the same file while preserving
all critical 'created', 'moved', and 'deleted' event sequences.
"""

from typing import List, Dict, Tuple
from monitoring.event_schema import StructuredEvent


class EventDeduplicator:
    """
    Configurable event deduplication filter.
    
    Default parameters:
    - dedupe_ms: 200 milliseconds (0.2s)
    """

    def __init__(self, dedupe_ms: float = 200.0):
        self.dedupe_window_seconds = dedupe_ms / 1000.0
        # Map: (src_path, event_type) -> last_seen_event_time
        self._last_seen: Dict[Tuple[str, str], float] = {}

        # Counter metrics
        self.raw_event_count = 0
        self.kept_event_count = 0
        self.duplicate_event_count = 0

    def should_keep(self, event: StructuredEvent) -> bool:
        """
        Determines whether a structured event should be kept or dropped as a duplicate.

        Rules:
        - 'modified': If same src_path was modified within dedupe_window_seconds, drop.
        - 'created', 'deleted', 'moved': Only drop if exact identical event arrives within 50ms.
        """
        self.raw_event_count += 1
        key = (event.src_path, event.event_type)
        last_time = self._last_seen.get(key)

        # Use event_time or arrival_time
        evt_time = event.event_time

        if last_time is not None:
            time_delta = evt_time - last_time

            # Rule for MODIFIED events: drop if within deduplication window
            if event.event_type == "modified" and time_delta < self.dedupe_window_seconds:
                self.duplicate_event_count += 1
                return False

            # Rule for other events (created, moved, deleted): drop only if < 50ms
            if event.event_type in ["created", "moved", "deleted"] and time_delta < 0.05:
                self.duplicate_event_count += 1
                return False

        # Update last seen timestamp and keep event
        self._last_seen[key] = evt_time
        self.kept_event_count += 1
        return True

    def deduplicate_list(self, events: List[StructuredEvent]) -> List[StructuredEvent]:
        """
        Filters a list of structured events, returning only non-duplicate events.
        """
        return [evt for evt in events if self.should_keep(evt)]

    def reset_stats(self) -> None:
        """Resets event counter metrics."""
        self.raw_event_count = 0
        self.kept_event_count = 0
        self.duplicate_event_count = 0
