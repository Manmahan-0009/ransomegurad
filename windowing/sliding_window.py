"""
RansomGuard - Sliding Window Buffer Module (windowing/sliding_window.py)

Maintains a 5-second sliding window buffer of structured events with 1-second stride.
Purges events older than window_seconds and provides current window events for feature extraction.
"""

import time
from typing import List, Optional
from monitoring.event_schema import StructuredEvent


class SlidingWindowBuffer:
    """
    In-memory event buffer representing a sliding time window.
    
    Default Configuration:
    - window_seconds: 5.0 seconds
    - stride_seconds: 1.0 second
    """

    def __init__(self, window_seconds: float = 5.0, stride_seconds: float = 1.0):
        self.window_seconds = window_seconds
        self.stride_seconds = stride_seconds
        self._events: List[StructuredEvent] = []

    def add_event(self, event: StructuredEvent) -> None:
        """Adds a single structured event to the window buffer."""
        self._events.append(event)

    def add_events(self, events: List[StructuredEvent]) -> None:
        """Adds a list of structured events to the window buffer."""
        self._events.extend(events)

    def remove_expired_events(self, current_time: Optional[float] = None) -> int:
        """
        Purges events from the buffer that occurred prior to (current_time - window_seconds).
        Returns the count of purged events.
        """
        now = current_time if current_time is not None else time.time()
        cutoff = now - self.window_seconds
        
        initial_count = len(self._events)
        # Keep events whose event_time or arrival_time >= cutoff
        self._events = [evt for evt in self._events if evt.arrival_time >= cutoff]
        return initial_count - len(self._events)

    def get_current_events(self, current_time: Optional[float] = None) -> List[StructuredEvent]:
        """
        Returns all active events within the current sliding window [now - window_seconds, now].
        Automatically purges expired events first.
        """
        self.remove_expired_events(current_time=current_time)
        return list(self._events)

    def build_window(self, current_time: Optional[float] = None) -> List[StructuredEvent]:
        """Alias for get_current_events."""
        return self.get_current_events(current_time=current_time)

    def clear(self) -> None:
        """Clears all events from the buffer."""
        self._events.clear()

    def count(self) -> int:
        """Returns current number of active events in the window."""
        return len(self._events)
