"""Core data models for NetGuard IDS."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 10
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 95

    @property
    def label(self) -> str:
        return self.name.title()


SEVERITY_ORDER = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


@dataclass(slots=True)
class Event:
    """A single normalised network event handed to the detection engine.

    Detectors never touch raw scapy packets - they only see this
    normalised view. That keeps them unit-testable without a NIC.
    """

    ts: float
    src_ip: str
    dst_ip: str
    proto: str                      # TCP / UDP / ARP / DNS / OTHER
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""                 # e.g. "S", "SA", "A"
    payload_len: int = 0
    ttl: int = 0
    dns_qname: str | None = None     # lowercased query name
    dns_qtype: str | None = None
    arp_op: int | None = None        # 1=request 2=reply
    arp_psrc: str | None = None      # claimed sender MAC/IP in ARP
    arp_hwsrc: str | None = None
    arp_target_ip: str | None = None
    ttl_seen: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class Alert:
    """A detection raised by a rule."""

    ts: float
    rule_id: str
    title: str
    severity: Severity
    src_ip: str
    dst_ip: str
    description: str
    evidence: dict = field(default_factory=dict)
    mitre_attack: str = ""
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def mitre(self) -> str:
        """Shorthand alias used by tests and the report layer."""
        return self.mitre_attack

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = SEVERITY_ORDER[self.severity]
        d["severity_value"] = int(self.severity)
        return d

    def to_line(self) -> str:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
        return (
            f"[{t}] {self.severity.label:<8} {self.rule_id:<22} "
            f"{self.src_ip} -> {self.dst_ip} :: {self.title}"
        )


class Detection:
    """Wrapper returned by a rule: either nothing, or one Alert."""

    __slots__ = ("alert",)

    def __init__(self, alert: Alert | None = None):
        self.alert = alert
