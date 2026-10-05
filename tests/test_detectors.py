"""Unit tests for the detection rules. No network, no NIC, fast."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard.detectors import (  # noqa: E402
    SynScanDetector, BruteForceDetector, ArpSpoofDetector,
    DnsAnomalyDetector, BurstDetector, TtlAnomalyDetector, build_engine,
)
from netguard.models import Event, Severity, Alert  # noqa: E402
from netguard.parser import event_from_packet, tcp_flags_str  # noqa: E402
from netguard.traffic import (  # noqa: E402
    benign_background, attack_horizontal_sweep, attack_vertical_flood,
    attack_brute_force, attack_arp_spoof, attack_dns_tunnel,
    attack_ttl_limping, attack_udp_flood,
)

T0 = 1_700_000_000.0


def run(det, packets):
    alerts = []
    for i, p in enumerate(packets):
        p.time = T0 + i * 0.002
        ev = event_from_packet(p)
        assert ev is not None, f"parser dropped packet {i}"
        a = det.inspect(ev)
        if a:
            alerts.append(a)
    return alerts


# ---------------------------------------------------------------- parser
def test_parser_tcp():
    from scapy.all import IP, TCP, Ether
    p = Ether()/IP(src="1.2.3.4", dst="5.6.7.8", ttl=64)/TCP(sport=1, dport=80, flags="S")
    ev = event_from_packet(p)
    assert ev.proto == "TCP" and ev.src_ip == "1.2.3.4" and ev.dst_port == 80
    assert ev.flags == "S" and ev.ttl == 64


def test_parser_flags():
    from scapy.all import IP, TCP, Ether
    p = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(flags="SA")
    assert tcp_flags_str(p[TCP]) == "SA"


def test_parser_dns():
    from scapy.all import IP, UDP, Ether, DNS, DNSQR
    p = (Ether()/IP(src="10.0.0.5", dst="10.0.0.1")/UDP(sport=5353, dport=53) /
         DNS(rd=0, qd=DNSQR(qname="Example.COM.")))
    ev = event_from_packet(p)
    assert ev.proto == "DNS" and ev.dns_qname == "example.com"


def test_parser_arp():
    from scapy.all import Ether, ARP
    p = Ether()/ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.1", pdst="10.0.0.2")
    ev = event_from_packet(p)
    assert ev.proto == "ARP" and ev.arp_hwsrc == "aa:bb:cc:dd:ee:ff"


def test_parser_ignores_noise():
    from scapy.all import Ether
    assert event_from_packet(Ether()) is None


# ---------------------------------------------------------------- syn scan
def test_syn_scan_detects_horizontal_sweep():
    alerts = run(SynScanDetector(threshold=1000, sweep_ports=12), attack_horizontal_sweep(T0, ports=40))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "NG-SYN-SCAN"
    assert a.severity >= Severity.HIGH
    assert a.evidence["distinct_unanswered_ports"] >= 12


def test_syn_scan_detects_vertical_burst():
    alerts = run(SynScanDetector(threshold=30, sweep_ports=12), attack_vertical_flood(T0, pkts=60))
    assert len(alerts) == 1
    assert "vertical" in alerts[0].description


def test_syn_scan_ignores_normal_traffic():
    assert run(SynScanDetector(), benign_background(T0)) == []


def test_syn_scan_ignores_established_sessions():
    pkts = benign_background(T0)
    alerts = run(SynScanDetector(threshold=3, sweep_ports=2), pkts)
    assert alerts == []


# ---------------------------------------------------------------- brute force
def test_brute_force_detected():
    alerts = run(BruteForceDetector(threshold=15), attack_brute_force(T0, attempts=30))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "NG-BRUTE-FORCE"
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].mitre_attack.startswith("T1110")


def test_brute_force_ignores_web_traffic():
    assert run(BruteForceDetector(threshold=5), benign_background(T0)) == []


# ---------------------------------------------------------------- arp
def test_arp_spoof_mac_change():
    alerts = run(ArpSpoofDetector(), attack_arp_spoof(T0))
    assert alerts, "expected an ARP alert"
    a = alerts[0]
    assert a.rule_id == "NG-ARP-SPOOF"
    assert a.severity == Severity.CRITICAL
    assert a.mitre.startswith("T1557")


def test_arp_quiet_when_stable():
    from scapy.all import Ether, ARP
    pkts = []
    for i in range(20):
        pkts.append(Ether()/ARP(op=2, hwsrc="aa:bb:cc:00:00:01", psrc="10.0.0.1", pdst="10.0.0.66"))
    assert run(ArpSpoofDetector(), pkts) == []


# ---------------------------------------------------------------- dns
def test_dns_tunnel_detected():
    alerts = run(DnsAnomalyDetector(volume_threshold=50), attack_dns_tunnel(T0, n=80))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "NG-DNS-EXFIL"
    assert "exfil" in a.evidence["sample_query"] or "label length" in " ".join(a.evidence["reasons"])


def test_dns_normal_queries_quiet():
    assert run(DnsAnomalyDetector(volume_threshold=5), benign_background(T0)) == []


# ---------------------------------------------------------------- burst
def test_burst_detected():
    alerts = run(BurstDetector(threshold=40, window=5.0), attack_udp_flood(T0, n=100))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "NG-BURST"
    assert alerts[0].mitre.startswith("T1498")


def test_burst_quiet_on_normal():
    assert run(BurstDetector(threshold=1000), benign_background(T0)) == []


# ---------------------------------------------------------------- ttl
def test_ttl_anomaly_detected():
    alerts = run(TtlAnomalyDetector(), attack_ttl_limping(T0, n=25))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "NG-TTL-ANOM"
    assert alerts[0].evidence["ttl"] == 7


def test_ttl_normal_quiet():
    assert run(TtlAnomalyDetector(), benign_background(T0)) == []


# ---------------------------------------------------------------- engine / pipeline
def test_engine_detects_multiple_attack_types():
    from netguard.engine import IDSEngine
    from netguard.pipeline import AlertManager, Stats, CallbackSink

    pkts = []
    pkts += benign_background(T0)
    t = T0 + 4
    pkts += attack_horizontal_sweep(t)
    pkts += attack_brute_force(t + 2)
    pkts += attack_arp_spoof(t + 4)
    pkts += attack_dns_tunnel(t + 6)
    pkts.sort(key=lambda p: float(p.time))

    caught = []
    mgr = AlertManager(sinks=[CallbackSink(caught.append)], console=False)
    eng = IDSEngine(detectors=build_engine(), manager=mgr, stats=Stats())
    for i, p in enumerate(pkts):
        p.time = T0 + i * 0.002
        eng.process_packet(p)
    eng.finish()

    rule_ids = {a.rule_id for a in caught}
    assert {"NG-SYN-SCAN", "NG-BRUTE-FORCE", "NG-ARP-SPOOF", "NG-DNS-EXFIL"} <= rule_ids, rule_ids
    assert eng.stats.packets == len(pkts)


def test_clean_traffic_produces_no_alerts():
    from netguard.engine import IDSEngine
    from netguard.pipeline import AlertManager, Stats, CallbackSink
    caught = []
    mgr = AlertManager(sinks=[CallbackSink(caught.append)], console=False)
    eng = IDSEngine(detectors=build_engine(), manager=mgr, stats=Stats())
    pkts = benign_background(T0)
    for i, p in enumerate(pkts):
        p.time = T0 + i * 0.05
        eng.process_packet(p)
    eng.finish()
    assert caught == [], [a.to_line() for a in caught]


def test_sqlite_roundtrip(tmp_path=None):
    import tempfile
    from netguard.pipeline import SqliteSink
    d = tempfile.mkdtemp()
    s = SqliteSink(os.path.join(d, "a.db"))
    a = Alert(ts=T0, rule_id="NG-TEST", title="t", severity=Severity.HIGH,
              src_ip="1.1.1.1", dst_ip="2.2.2.2", description="d",
              evidence={"k": 1}, mitre_attack="T1046")
    s.write(a)
    s.commit()
    rows = s.recent()
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "NG-TEST"
    assert rows[0]["evidence"] == {"k": 1}
    summ = s.summary()
    assert summ["total"] == 1
    s.close()


def test_min_severity_filter():
    from netguard.pipeline import AlertManager
    seen = []
    class _S:
        def write(self, a): seen.append(a)
    m = AlertManager(sinks=[_S()], console=False, min_severity=70)
    m.emit(Alert(ts=T0, rule_id="X", title="low", severity=Severity.LOW,
                 src_ip="a", dst_ip="b", description=""))
    m.emit(Alert(ts=T0, rule_id="Y", title="high", severity=Severity.CRITICAL,
                 src_ip="a", dst_ip="b", description=""))
    assert len(seen) == 1
    assert seen[0].rule_id == "Y"


def test_report_generates_html():
    import tempfile
    from netguard.pipeline import SqliteSink, CallbackSink
    from netguard.report import build_report
    d = tempfile.mkdtemp()
    db = os.path.join(d, "r.db")
    s = SqliteSink(db)
    s.write(Alert(ts=T0, rule_id="NG-SYN-SCAN", title="scan", severity=Severity.HIGH,
                  src_ip="10.0.0.99", dst_ip="10.0.0.10", description="sweep",
                  evidence={"syn_count": 60}, mitre_attack="T1046 - Discovery"))
    s.commit(); s.close()
    out = build_report(db, os.path.join(d, "rep.html"))
    html_text = open(out, encoding="utf-8").read()
    assert "<html" in html_text
    assert "NG-SYN-SCAN" in html_text
    assert "10.0.0.99" in html_text
    assert "T1046" in html_text
