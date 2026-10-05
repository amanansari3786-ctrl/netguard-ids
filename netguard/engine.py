"""The IDS engine: wires capture source -> parser -> detectors -> pipeline."""

from __future__ import annotations

import time

from .detectors import build_engine
from .models import Alert
from .parser import event_from_packet
from .pipeline import AlertManager, Stats


class IDSEngine:
    def __init__(self, detectors=None, manager: AlertManager | None = None,
                 stats: Stats | None = None, verbose_every: int = 500):
        self.detectors = detectors if detectors is not None else build_engine()
        self.manager = manager or AlertManager()
        self.stats = stats or Stats()
        self.verbose_every = verbose_every
        self._since_report = 0

    def process_event(self, ev) -> None:
        self.stats.note_event(ev.proto)
        for d in self.detectors:
            alert = d.inspect(ev)
            if alert is not None:
                self.stats.note_alert(alert)
                self.manager.emit(alert)

    def process_packet(self, pkt) -> None:
        """Called per raw scapy packet."""
        self.stats.packets += 1
        try:
            ev = event_from_packet(pkt)
        except Exception:
            ev = None
        if ev is None:
            return
        self.process_event(ev)

        if self.verbose_every and self._since_report >= self.verbose_every:
            self._since_report = 0
            print("  " + self.stats.snapshot(), flush=True)
        self._since_report += 1

    def run_offline(self, pcap_path: str) -> Stats:
        """Replay a pcap file - no NIC, no admin rights, fully deterministic."""
        from scapy.utils import PcapReader  # type: ignore

        print(f"[netguard] replaying {pcap_path}", flush=True)
        with PcapReader(pcap_path) as rd:
            for pkt in rd:
                self.process_packet(pkt)
        self.finish()
        return self.stats

    def run_live(self, iface: str, bpf: str | None = None,
                 count: int = 0, duration: int = 0) -> Stats:
        """Sniff a real interface. Needs admin/Npcap for full capture."""
        from scapy.all import sniff  # type: ignore

        print(f"[netguard] live capture on {iface} bpf={bpf!r} "
              f"count={count} duration={duration}", flush=True)
        t0 = time.time()
        try:
            sniff(iface=iface, filter=bpf, store=False,
                  prn=self.process_packet, count=count or None,
                  timeout=duration or None)
        except KeyboardInterrupt:
            print("\n[netguard] interrupted", flush=True)
        except PermissionError:
            print("[netguard] PermissionError: run as Administrator, or use "
                  "--pcap <file> for offline analysis.", flush=True)
        except Exception as e:
            print(f"[netguard] capture error: {e}", flush=True)
        self.finish()
        return self.stats

    def finish(self) -> None:
        # Give windowed rules a final chance to report.
        now = time.time()
        for d in self.detectors:
            try:
                a = d.flush(now)
                if a is not None:
                    self.manager.emit(a)
            except Exception:
                pass
        for s in self.manager.sinks:
            if hasattr(s, "commit"):
                s.commit()
        print(f"[netguard] done. {self.stats.snapshot()}", flush=True)
