"""Detection rules.

Each detector is a class with:
  rule_id, title, severity, mitre_attack
  inspect(event) -> Alert | None      (called per event)
  flush(now) -> Alert | None          (called periodically, for windowed rules)

All state is in-memory sliding windows keyed by IP. No external deps.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict, deque

from .models import Alert, Event, Severity

# Tunables - exposed via CLI so you can demo different thresholds live.
DEFAULT_SYN_THRESHOLD = 30          # SYNs to one host within the window
DEFAULT_SWEEP_DISTINCT_PORTS = 12   # distinct dst ports => sweep
DEFAULT_BURST_EVENTS = 40           # events to one host => flood/burst
PORT_SCAN_WINDOW = 10.0             # seconds
BURST_WINDOW = 5.0
ARP_WINDOW = 30.0
DNS_WINDOW = 60.0
TOP_TALKERS_LIMIT = 10


class BaseDetector:
    rule_id = "NG-BASE"
    title = "base"
    severity = Severity.INFO
    mitre = ""
    category = "other"

    def inspect(self, ev: Event) -> Alert | None:
        return None

    def flush(self, now: float) -> Alert | None:
        return None

    def _alert(self, ev_or_ts, **kw) -> Alert:
        ts = ev_or_ts if isinstance(ev_or_ts, float) else ev_or_ts.ts
        return Alert(
            ts=ts,
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            mitre_attack=self.mitre,
            **kw,
        )


# --------------------------------------------------------------------------
# 1. SYN scan / port sweep detection
# --------------------------------------------------------------------------
class SynScanDetector(BaseDetector):
    """Flags one source opening many connections to one destination.

    Two thresholds instead of one, because a vertical scan and a horizontal
    sweep look identical in a single counter but mean different things:
      - many SYNs to many ports  -> horizontal port sweep (T1046)
      - many SYNs to few ports   -> single-host SYN flood / scan (T1046)

    Key design decision - *unanswered* SYNs are the evidence, not all SYNs.
    A naive "count SYNs" rule flags every normal browser that visits two
    pages on the same web server, because the first visit to each port looks
    like an unknown probe. What actually separates reconnaissance from
    business as usual is that a scanner's SYNs go unanswered: nothing ever
    replies, whereas a real server always answers with SYN-ACK/RST. So each
    SYN is held pending until either a server response arrives (cleared as
    legitimate) or it is left hanging (counted as scan evidence).
    """

    rule_id = "NG-SYN-SCAN"
    title = "Possible SYN scan / port sweep"
    severity = Severity.HIGH
    mitre = "T1046 - Network Service Discovery"
    category = "reconnaissance"

    def __init__(self, threshold: int = DEFAULT_SYN_THRESHOLD,
                 sweep_ports: int = DEFAULT_SWEEP_DISTINCT_PORTS,
                 window: float = PORT_SCAN_WINDOW):
        self.threshold = threshold
        self.sweep_ports = sweep_ports
        self.window = window
        # (src, dst) -> deque of (ts, port) for SYNs still awaiting a reply
        self.pending: dict[tuple[str, str], deque] = defaultdict(deque)
        # (src, dst) -> ports the server is known to answer on
        self.responsive: dict[tuple[str, str], set[int]] = defaultdict(set)
        self.fired: set[tuple[str, str]] = set()

    def _mark_responsive(self, ev: Event) -> None:
        """Any ACK/RST from the server proves the service is live.

        On a SYN-ACK the packet runs server->client, so ``src_port`` is the
        service port; the pending entry belongs to the (client, server) pair.
        """
        if "A" not in ev.flags:
            return
        client, server, service_port = ev.dst_ip, ev.src_ip, ev.src_port
        self.responsive[(client, server)].add(service_port)
        # The server answered, so any pending SYN to that port was legitimate.
        dq = self.pending[(client, server)]
        kept = deque((t, p) for (t, p) in dq if p != service_port)
        dq.clear()
        dq.extend(kept)

    def inspect(self, ev: Event) -> Alert | None:
        if ev.proto != "TCP":
            return None

        if "A" in ev.flags:
            self._mark_responsive(ev)
            return None
        if "R" in ev.flags or "F" in ev.flags:
            # RST also proves the host is up and the port closed - a scanner
            # probing closed ports looks exactly like this.
            self.responsive[(ev.dst_ip, ev.src_ip)].add(ev.dst_port)
            return None
        if not ("S" in ev.flags):
            return None

        key = (ev.src_ip, ev.dst_ip)
        dq = self.pending[key]
        dq.append((ev.ts, ev.dst_port))
        cutoff = ev.ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq or key in self.fired:
            return None

        count = len(dq)
        ports = {p for _, p in dq}
        # Subtract ports the server already proved it answers on: those SYNs
        # were ordinary reconnects to a live service.
        ports -= self.responsive.get(key, set())
        if not ports:
            return None

        horizontal = len(ports) >= self.sweep_ports
        vertical = count >= self.threshold and len(ports) <= max(2, self.sweep_ports // 2)

        if horizontal or vertical:
            self.fired.add(key)
            shape = "horizontal port sweep" if horizontal else "vertical SYN burst"
            return self._alert(
                ev,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                description=(
                    f"Source {ev.src_ip} sent {len(ports)} unanswered SYNs to "
                    f"{ev.dst_ip} within {self.window:.0f}s across {len(ports)} ports "
                    f"({shape}). Ports never answered: {sorted(ports)[:20]}"
                ),
                evidence={
                    "unanswered_syns": len(ports),
                    "distinct_unanswered_ports": len(ports),
                    "sample_ports": sorted(ports)[:20],
                    "window_seconds": self.window,
                },
            )
        return None


# --------------------------------------------------------------------------
# 2. Brute-force / failed-login style detection
# --------------------------------------------------------------------------
class BruteForceDetector(BaseDetector):
    """Repeated connection attempts to an auth service port.

    Built for the common 'many short-lived attempts to port 22/21/23/3389'
    pattern: high attempt rate with many RST/FIN teardowns (failed logins).
    """

    rule_id = "NG-BRUTE-FORCE"
    title = "Possible brute-force against authentication service"
    severity = Severity.HIGH
    mitre = "T1110 - Brute Force"
    category = "credential-access"

    AUTH_PORTS = {22, 21, 23, 3389, 5900, 445, 3306, 5432}

    def __init__(self, threshold: int = 15, window: float = 60.0):
        self.threshold = threshold
        self.window = window
        self.attempts: dict[tuple[str, int], deque] = defaultdict(deque)
        self.fired: set[tuple[str, int]] = set()
        # (src, dst, service_port) pairs where we saw genuine session data.
        #
        # Deliberately NOT marked on SYN/SYN-ACK: a brute-forcer receives
        # SYN-ACKs too, so the handshake alone cannot distinguish a real
        # client from a password guesser. What separates them is what
        # happens next - a real login transfers payload bytes, whereas a
        # failed attempt is torn down with RST/FIN and carries no data.
        self.legit: set[tuple[str, str, int]] = set()

    def _mark_established(self, ev: Event) -> None:
        """Record a service port as genuinely used only on observed data."""
        if "A" not in ev.flags:
            return
        service_port = ev.dst_port if ev.dst_port in self.AUTH_PORTS else (
            ev.src_port if ev.src_port in self.AUTH_PORTS else None)
        if service_port is None:
            return
        if ev.payload_len > 0:
            self.legit.add((ev.src_ip, ev.dst_ip, service_port))
            self.legit.add((ev.dst_ip, ev.src_ip, service_port))

    def inspect(self, ev: Event) -> Alert | None:
        if ev.proto != "TCP":
            return None

        if "A" in ev.flags or "R" in ev.flags or "F" in ev.flags:
            self._mark_established(ev)

        if ev.dst_port not in self.AUTH_PORTS:
            return None
        # only new-connection attempts, not established data transfer
        if "S" not in ev.flags or "A" in ev.flags:
            return None
        if (ev.src_ip, ev.dst_ip, ev.dst_port) in self.legit:
            return None
        if (ev.dst_ip, ev.src_ip, ev.dst_port) in self.legit:
            return None

        key = (ev.src_ip, ev.dst_port)
        dq = self.attempts[key]
        dq.append(ev.ts)
        cutoff = ev.ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.threshold and key not in self.fired:
            self.fired.add(key)
            return self._alert(
                ev,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                description=(
                    f"{len(dq)} connection attempts from {ev.src_ip} to port "
                    f"{ev.dst_port} on {ev.dst_ip} within {self.window:.0f}s."
                ),
                evidence={"attempts": len(dq), "target_port": ev.dst_port,
                          "window_seconds": self.window},
            )
        return None


# --------------------------------------------------------------------------
# 3. ARP spoofing / MITM detection
# --------------------------------------------------------------------------
class ArpSpoofDetector(BaseDetector):
    """A given IP claiming a new MAC, or one MAC answering for many IPs.

    Both are ARP-poisoning shapes. Also catches gratuitous ARP storms used
    to silently insert an attacker into the L2 path.
    """

    rule_id = "NG-ARP-SPOOF"
    title = "Possible ARP spoofing / MITM"
    severity = Severity.CRITICAL
    mitre = "T1557 - ARP Cache Poisoning (MITM)"
    category = "credential-access"

    def __init__(self, window: float = ARP_WINDOW):
        self.window = window
        self.ip_to_mac: dict[str, tuple[str, float]] = {}
        self.mac_to_ips: dict[str, set[str]] = defaultdict(set)
        self.fired: set[str] = set()

    def inspect(self, ev: Event) -> Alert | None:
        if ev.proto != "ARP" or ev.arp_op != 2:   # look at replies
            return None
        ip, mac = ev.arp_psrc or "", ev.arp_hwsrc or ""
        if not ip or not mac:
            return None

        prior = self.ip_to_mac.get(ip)
        self.mac_to_ips[mac].add(ip)

        # Case 1: IP now answers with a different MAC than before
        if prior and prior[0] != mac and ip not in self.fired:
            self.fired.add(ip)
            return self._alert(
                ev,
                src_ip=ip,
                dst_ip=ev.dst_ip,
                description=(
                    f"IP {ip} previously mapped to MAC {prior[0]} but now claims "
                    f"MAC {mac}. This is the classic ARP cache poisoning signature."
                ),
                evidence={"ip": ip, "old_mac": prior[0], "new_mac": mac,
                          "first_seen": prior[1], "now": ev.ts},
            )

        # Case 2: one MAC claiming many IPs
        if len(self.mac_to_ips[mac]) >= 5 and mac not in self.fired:
            self.fired.add(mac)
            return self._alert(
                ev,
                src_ip=ip,
                dst_ip=ev.dst_ip,
                description=(
                    f"MAC {mac} is answering ARP for {len(self.mac_to_ips[mac])} "
                    f"different IPs - attacker-controlled gateway behaviour."
                ),
                evidence={"mac": mac, "claimed_ips": sorted(self.mac_to_ips[mac])},
            )

        self.ip_to_mac[ip] = (mac, ev.ts)
        return None


# --------------------------------------------------------------------------
# 4. DNS anomaly - possible tunnelling / exfiltration
# --------------------------------------------------------------------------
class DnsAnomalyDetector(BaseDetector):
    """Long, high-entropy-looking subdomains + volume = classic DNS
    exfiltration / C2-over-DNS behaviour. Also flags known-bad TLDs."""

    rule_id = "NG-DNS-EXFIL"
    title = "Suspicious DNS activity (possible tunneling/exfiltration)"
    severity = Severity.MEDIUM
    mitre = "T1048 - Exfiltration Over Alternative Protocol (T1071.004 DNS)"
    category = "exfiltration"

    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".zip", ".mov"}

    def __init__(self, window: float = DNS_WINDOW, volume_threshold: int = 60,
                 long_label: int = 30):
        self.window = window
        self.volume_threshold = volume_threshold
        self.long_label = long_label
        self.queries: dict[str, deque] = defaultdict(deque)
        self.fired: set[str] = set()

    def inspect(self, ev: Event) -> Alert | None:
        name = ev.dns_qname
        if not name or ev.src_ip in self.fired:
            return None
        labels = name.split(".")
        longest = max((len(x) for x in labels), default=0)

        # ---- structural signals: these are what actually indicate tunnelling
        structural = []
        if longest >= self.long_label:
            structural.append(f"abnormally long DNS label ({longest} chars)")
        if any(name.endswith(t) for t in self.SUSPICIOUS_TLDS):
            structural.append("high-abuse TLD")

        dq = self.queries[ev.src_ip]
        dq.append((ev.ts, name))
        cutoff = ev.ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # ---- volume is only corroborating evidence, never sufficient alone.
        # A busy resolver or a browser with many tabs legitimately generates
        # hundreds of short queries to real domains; alerting on that alone
        # is the classic DNS-rule false-positive trap.
        volume = len(dq) >= self.volume_threshold
        if not structural:
            return None

        reasons = list(structural)
        if volume:
            reasons.append(f"{len(dq)} queries in {self.window:.0f}s")

        self.fired.add(ev.src_ip)
        return self._alert(
            ev,
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            description=(
                f"{ev.src_ip} showed DNS behaviour consistent with tunneling or "
                f"exfiltration ({', '.join(reasons)}). Example: {name[:80]}"
            ),
            evidence={"sample_query": name[:120], "reasons": reasons,
                      "max_label_len": longest,
                      "queries_in_window": len(dq)},
        )


# --------------------------------------------------------------------------
# 5. Traffic burst / DoS pattern
# --------------------------------------------------------------------------
class BurstDetector(BaseDetector):
    """Any single host sending an unusual volume of packets to one target.

    Deliberately protocol-agnostic: volumetric anomalies show up long
    before a payload-based IDS would have anything to say.
    """

    rule_id = "NG-BURST"
    title = "Traffic burst toward single host (possible DoS)"
    severity = Severity.HIGH
    mitre = "T1498 - Network Denial of Service"
    category = "impact"

    def __init__(self, threshold: int = DEFAULT_BURST_EVENTS, window: float = BURST_WINDOW):
        self.threshold = threshold
        self.window = window
        self.hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self.fired: set[tuple[str, str]] = set()

    def inspect(self, ev: Event) -> Alert | None:
        if ev.proto in ("ARP",) or ev.proto == "DNS":
            return None
        key = (ev.src_ip, ev.dst_ip)
        dq = self.hits[key]
        dq.append(ev.ts)
        cutoff = ev.ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.threshold and key not in self.fired:
            self.fired.add(key)
            return self._alert(
                ev,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                description=(
                    f"{len(dq)} packets from {ev.src_ip} to {ev.dst_ip} in "
                    f"{self.window:.0f}s - volumetric anomaly."
                ),
                evidence={"packets": len(dq), "window_seconds": self.window,
                          "protocol": ev.proto},
            )
        return None


# --------------------------------------------------------------------------
# 6. Suspicious TTL (OS fingerprinting / TTL-limping evasion)
# --------------------------------------------------------------------------
class TtlAnomalyDetector(BaseDetector):
    """TTL manipulation / TTL-limping detection.

    Naive version of this rule (alert on any non-standard TTL) is very noisy:
    normal traffic sits at 63 or 64 depending on hop count, so a hardcoded
    allow-list floods the analyst. Instead this learns a network-wide TTL
    baseline and only alerts when a host is *stably* far from it.

    Attack shape: attacker rewrites TTL (usually low, e.g. 4-8) so replies
    die before they can be traced, or varies TTL to break session
    reconstruction in the defender's tooling.
    """

    rule_id = "NG-TTL-ANOM"
    title = "Unusual TTL (possible TTL manipulation)"
    severity = Severity.LOW
    mitre = "T1071 - Application Layer Protocol (evasion)"
    category = "defense-evasion"

    def __init__(self, jitter: int = 8, min_samples: int = 10,
                 deviation: int = 8):
        self.deviation = deviation
        self.min_samples = min_samples
        # src -> list of TTLs seen (sliding)
        self.seen: dict[str, list[int]] = defaultdict(list)
        self.fired: set[str] = set()

    def _baseline(self, exclude: str | None = None) -> float:
        """Most common TTL observed across all *other* hosts - the norm.

        Excluding the inspected host matters: in an isolated capture of a
        single attacker the baseline would otherwise be the attacker's own
        TTL, giving a delta of 0 and silencing the rule entirely.
        """
        allv: Counter[int] = Counter()
        for host, ttls in self.seen.items():
            if host == exclude:
                continue
            allv.update(ttls[-40:])
        if not allv:
            # No peers observed yet - fall back to the conventional default
            # rather than trusting the single host we are judging.
            return 64.0
        return float(allv.most_common(1)[0][0])

    def inspect(self, ev: Event) -> Alert | None:
        if not ev.ttl or ev.proto in ("ARP", "DNS"):
            return None
        ttls = self.seen[ev.src_ip]
        ttls.append(ev.ttl)
        if len(ttls) > 60:
            ttls.pop(0)
        if len(ttls) < self.min_samples or ev.src_ip in self.fired:
            return None
        # A jumping TTL is also suspicious, but we only report a *stable*
        # value first; jitter gets picked up as variance in evidence.
        uniq = set(ttls)
        if len(uniq) > 1:
            return None
        t = float(ttls[0])
        base = self._baseline(exclude=ev.src_ip)
        if abs(t - base) < self.deviation:
            return None
        self.fired.add(ev.src_ip)
        return self._alert(
            ev,
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            description=(
                f"Host {ev.src_ip} sends a stable TTL of {int(t)} while the "
                f"network baseline is {int(base)} (delta {int(abs(t - base))}). "
                f"Consistent with TTL-limping or manually crafted packets."
            ),
            evidence={"ttl": int(t), "network_baseline_ttl": int(base),
                      "delta": int(abs(t - base)), "samples": len(ttls)},
        )


DEFAULT_DETECTORS = [
    SynScanDetector,
    BruteForceDetector,
    ArpSpoofDetector,
    DnsAnomalyDetector,
    BurstDetector,
    TtlAnomalyDetector,
]


def build_engine(syn_threshold: int = DEFAULT_SYN_THRESHOLD,
                 sweep_ports: int = DEFAULT_SWEEP_DISTINCT_PORTS,
                 brute_threshold: int = 15,
                 burst_threshold: int = DEFAULT_BURST_EVENTS) -> list[BaseDetector]:
    return [
        SynScanDetector(threshold=syn_threshold, sweep_ports=sweep_ports),
        BruteForceDetector(threshold=brute_threshold),
        ArpSpoofDetector(),
        DnsAnomalyDetector(),
        BurstDetector(threshold=burst_threshold),
        TtlAnomalyDetector(),
    ]
