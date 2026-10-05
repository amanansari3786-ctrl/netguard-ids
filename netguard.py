#!/usr/bin/env python
"""netguard CLI.

  netguard gen                       build sample pcaps (benign + attacks)
  netguard scan --pcap FILE          offline analysis, no admin needed
  netguard watch --iface IFACE       live capture
  netguard report                    build HTML report from the alert DB
  netguard summary                   console summary from the alert DB
  netguard rules                     list detection rules
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from netguard.detectors import build_engine, DEFAULT_DETECTORS, DEFAULT_SYN_THRESHOLD, DEFAULT_SWEEP_DISTINCT_PORTS, DEFAULT_BURST_EVENTS  # noqa: E402
from netguard.engine import IDSEngine  # noqa: E402
from netguard.pipeline import AlertManager, JsonlSink, SqliteSink, Stats  # noqa: E402


def _manager(args) -> AlertManager:
    sinks = []
    if args.db:
        sinks.append(SqliteSink(args.db))
    if args.jsonl:
        sinks.append(JsonlSink(args.jsonl))
    return AlertManager(sinks=sinks, console=not args.quiet,
                        min_severity=args.min_severity)


def cmd_gen(args):
    from netguard import traffic
    out = args.out or os.path.join(HERE, "samples")
    clean = os.path.join(out, "clean.pcap")
    attack = os.path.join(out, "attacks.pcap")
    n1 = traffic.build_clean_pcap(clean)
    n2 = traffic.build_attack_pcap(attack)
    print(f"[gen] samples/clean.pcap   {n1} packets (benign baseline)")
    print(f"[gen] samples/attacks.pcap {n2} packets (benign + 7 simulated attacks)")
    print("[gen] now run:  netguard scan --pcap samples/attacks.pcap")


def cmd_scan(args):
    engine = IDSEngine(detectors=build_engine(
        syn_threshold=args.syn_threshold,
        sweep_ports=args.sweep_ports,
        brute_threshold=args.brute_threshold,
        burst_threshold=args.burst_threshold,
    ), manager=_manager(args), stats=Stats(), verbose_every=args.progress_every)
    engine.run_offline(args.pcap)
    if not args.no_summary:
        from netguard.report import print_console_summary
        if args.db:
            print_console_summary(args.db)


def cmd_watch(args):
    engine = IDSEngine(detectors=build_engine(
        syn_threshold=args.syn_threshold,
        sweep_ports=args.sweep_ports,
        brute_threshold=args.brute_threshold,
        burst_threshold=args.burst_threshold,
    ), manager=_manager(args), stats=Stats(), verbose_every=args.progress_every)
    engine.run_live(args.iface, bpf=args.filter, count=args.count,
                    duration=args.duration)


def cmd_report(args):
    from netguard.report import build_report
    out = build_report(args.db, args.out, title=args.title)
    print(f"[report] wrote {out}")


def cmd_summary(args):
    from netguard.report import print_console_summary
    print_console_summary(args.db)


def cmd_rules(args):
    print("NetGuard detection rules")
    print("=" * 78)
    for cls in DEFAULT_DETECTORS:
        d = cls()
        print(f"{d.rule_id:<22} [{d.severity.label:<8}] {d.title}")
        print(f"{'':<22} category : {d.category}")
        print(f"{'':<22} ATT&CK  : {d.mitre}")
        print()


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard - lightweight network IDS (learning / SOC demo)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--db", default=os.path.join(HERE, "data", "alerts.db"),
                        help="SQLite alert database")
        sp.add_argument("--jsonl", help="also append alerts to a JSONL file")
        sp.add_argument("--min-severity", type=int, default=0,
                        help="only emit alerts >= this severity (0-95)")
        sp.add_argument("--quiet", action="store_true", help="no console alerts")
        sp.add_argument("--progress-every", type=int, default=500,
                        help="print stats every N packets (0=off)")

    def add_thresholds(sp):
        sp.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_THRESHOLD)
        sp.add_argument("--sweep-ports", type=int, default=DEFAULT_SWEEP_DISTINCT_PORTS)
        sp.add_argument("--brute-threshold", type=int, default=15)
        sp.add_argument("--burst-threshold", type=int, default=DEFAULT_BURST_EVENTS)

    g = sub.add_parser("gen", help="generate sample pcaps")
    g.add_argument("--out", help="output directory")
    g.set_defaults(func=cmd_gen)

    s = sub.add_parser("scan", help="offline pcap analysis")
    s.add_argument("--pcap", required=True)
    s.add_argument("--no-summary", action="store_true")
    add_common(s); add_thresholds(s)
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="live capture")
    w.add_argument("--iface", default="\\Device\\NPF_{GUID}", help="interface or NPF GUID")
    w.add_argument("--filter", help="BPF filter, e.g. 'tcp or arp'")
    w.add_argument("--count", type=int, default=0, help="stop after N packets")
    w.add_argument("--duration", type=int, default=0, help="stop after N seconds")
    add_common(w); add_thresholds(w)
    w.set_defaults(func=cmd_watch)

    r = sub.add_parser("report", help="build HTML report")
    r.add_argument("--db", default=os.path.join(HERE, "data", "alerts.db"))
    r.add_argument("--out", default=os.path.join(HERE, "data", "report.html"))
    r.add_argument("--title", default="NetGuard IDS - SOC Report")
    r.set_defaults(func=cmd_report)

    m = sub.add_parser("summary", help="console summary of alert DB")
    m.add_argument("--db", default=os.path.join(HERE, "data", "alerts.db"))
    m.set_defaults(func=cmd_summary)

    ru = sub.add_parser("rules", help="list detection rules")
    ru.set_defaults(func=cmd_rules)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
