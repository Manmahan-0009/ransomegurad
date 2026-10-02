# RansomGuard Monitoring Package
from monitoring.watcher import start_monitoring, RansomGuardHandler
from monitoring.event_schema import StructuredEvent, create_structured_event
from monitoring.event_queue import EventQueue, get_event_queue, push_event, get_event, flush_events
from monitoring.deduplicator import EventDeduplicator

__all__ = [
    "start_monitoring",
    "RansomGuardHandler",
    "StructuredEvent",
    "create_structured_event",
    "EventQueue",
    "get_event_queue",
    "push_event",
    "get_event",
    "flush_events",
    "EventDeduplicator",
]
