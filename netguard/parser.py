"""Protocol parser: scapy packets -> normalised netguard Event objects.

Keeping this separate is what lets the whole detection engine run against
pcap files with no network interface and no elevated privileges.
"""

from __future__ import annotations

from scapy.all import IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, Raw  # type: ignore
from scapy.layers.inet import IPerror  # type: ignore

from .models import Event


def tcp_flags_str(tcp) -> str:
    """Compact TCP flag string like 'S', 'SA', 'FA'."""
    out = ""
    if tcp.flags.F:
        out += "F"
    if tcp.flags.S:
        out += "S"
    if tcp.flags.R:
        out += "R"
    if tcp.flags.P:
        out += "P"
    if tcp.flags.A:
        out += "A"
    if tcp.flags.U:
        out += "U"
    if tcp.flags.E:
        out += "E"
    return out or "-"


def parse_dns(payload) -> tuple[str | None, str | None]:
    """Return (lowercased qname, qtype). Only queries are reported.

    Note: scapy leaves ``qdcount`` as None on locally *constructed* packets
    (it is only populated when parsing from the wire), so iterating
    ``dns.qd`` directly is the reliable path for both pcap replay and
    in-process generation.
    """
    try:
        if not payload.haslayer(DNS):
            return None, None
        dns = payload[DNS]
        if dns.qr != 0:
            return None, None
        questions = getattr(dns, "qd", None)
        if not questions:
            return None, None
        q = questions[0]
        name = q.qname
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        name = name.rstrip(".").lower()
        if not name:
            return None, None
        return name, str(getattr(q, "qtype", None))
    except Exception:
        return None, None


def event_from_packet(pkt) -> Event | None:
    """Normalise one scapy packet. Returns None for irrelevant traffic."""
    import time as _t

    ts = float(getattr(pkt, "time", 0.0)) or _t.time()

    # ---- ARP ----
    if ARP in pkt:
        a = pkt[ARP]
        op = int(a.op)
        return Event(
            ts=ts,
            src_ip=str(a.psrc),
            dst_ip=str(a.pdst),
            proto="ARP",
            arp_op=op,
            arp_psrc=str(a.psrc),
            arp_hwsrc=str(a.hwsrc),
            arp_target_ip=str(a.pdst),
        )

    # ---- DNS over UDP/TCP ----
    if DNS in pkt:
        qname, qtype = parse_dns(pkt)
        if qname:
            if TCP in pkt:
                t = pkt[TCP]
                src, dst, sp, dp = str(pkt[IP].src) if IP in pkt else "?", str(pkt[IP].dst) if IP in pkt else "?", int(t.sport), int(t.dport)
                proto = "DNS"
            else:
                u = pkt[UDP]
                src, dst = str(pkt[IP].src) if IP in pkt else "?", str(pkt[IP].dst) if IP in pkt else "?"
                sp, dp = int(u.sport), int(u.dport)
                proto = "DNS"
            return Event(
                ts=ts, src_ip=src, dst_ip=dst, proto=proto,
                src_port=sp, dst_port=dp, dns_qname=qname, dns_qtype=qtype,
                payload_len=len(pkt), ttl=int(pkt[IP].ttl) if IP in pkt else 0,
            )

    # ---- TCP ----
    if TCP in pkt and (IP in pkt or IPv6 in pkt):
        net = pkt[IP] if IP in pkt else pkt[IPv6]
        t = pkt[TCP]
        return Event(
            ts=ts,
            src_ip=str(net.src),
            dst_ip=str(net.dst),
            proto="TCP",
            src_port=int(t.sport),
            dst_port=int(t.dport),
            flags=tcp_flags_str(t),
            payload_len=len(bytes(t.payload)),
            ttl=int(net.ttl),
        )

    # ---- UDP (non-DNS) ----
    if UDP in pkt and (IP in pkt or IPv6 in pkt):
        net = pkt[IP] if IP in pkt else pkt[IPv6]
        u = pkt[UDP]
        return Event(
            ts=ts,
            src_ip=str(net.src),
            dst_ip=str(net.dst),
            proto="UDP",
            src_port=int(u.sport),
            dst_port=int(u.dport),
            payload_len=len(bytes(u.payload)),
            ttl=int(net.ttl),
        )

    return None
