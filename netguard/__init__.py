"""netguard - a lightweight network IDS for learning and SOC demos."""

from .models import Alert, Event, Severity
from .engine import IDSEngine
from .detectors import build_engine, DEFAULT_DETECTORS
from .pipeline import AlertManager, JsonlSink, SqliteSink, Stats

__version__ = "0.1.0"

__all__ = [
    "Alert", "Event", "Severity", "IDSEngine",
    "build_engine", "DEFAULT_DETECTORS",
    "AlertManager", "JsonlSink", "SqliteSink", "Stats",
    "__version__",
]
