"""
RansomGuard - Event Queue Module (monitoring/event_queue.py)

Provides a thread-safe, non-blocking event queue (queue.Queue wrapper).
Enables Watchdog callbacks to enqueue structured events instantly without delay.
"""

import queue
from typing import List, Optional
from monitoring.event_schema import StructuredEvent


class EventQueue:
    """
    Thread-safe FIFO event queue wrapping queue.Queue.
    """

    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)

    def push(self, event: StructuredEvent) -> bool:
        """
        Pushes a structured event into the queue quickly without blocking watcher thread.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            # Handle full queue gracefully by discarding oldest item if needed
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(event)
                return True
            except Exception:
                return False

    def get(self, timeout: Optional[float] = None) -> Optional[StructuredEvent]:
        """
        Retrieves a single structured event from the queue, blocking up to timeout seconds.
        """
        try:
            return self._queue.get(block=(timeout is not None), timeout=timeout)
        except queue.Empty:
            return None

    def flush(self) -> List[StructuredEvent]:
        """
        Drains all currently queued events into a list and returns them.
        """
        events = []
        while not self._queue.empty():
            try:
                evt = self._queue.get_nowait()
                events.append(evt)
            except queue.Empty:
                break
        return events

    def qsize(self) -> int:
        return self._queue.qsize()

    def clear(self) -> None:
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break


# Global default event queue instance for convenience
_GLOBAL_EVENT_QUEUE = EventQueue()


def get_event_queue() -> EventQueue:
    """Returns the global default EventQueue instance."""
    return _GLOBAL_EVENT_QUEUE


def push_event(event: StructuredEvent) -> bool:
    """Helper function to push an event to the global queue."""
    return _GLOBAL_EVENT_QUEUE.push(event)


def get_event(timeout: Optional[float] = None) -> Optional[StructuredEvent]:
    """Helper function to get an event from the global queue."""
    return _GLOBAL_EVENT_QUEUE.get(timeout=timeout)


def flush_events() -> List[StructuredEvent]:
    """Helper function to flush all events from the global queue."""
    return _GLOBAL_EVENT_QUEUE.flush()
