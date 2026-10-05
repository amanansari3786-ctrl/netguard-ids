"""Synthetic traffic generator.

Produces pcaps containing both benign baseline traffic and simulated
attacks, so the IDS can be demonstrated and tested end-to-end with no live
target. This doubles as the test fixture generator.

Everything here is loopback / RFC1918 / documentation addresses only.
"""

from __future__ import annotations

import random
import time

from scapy.all import (Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw,  # type: ignore
                       wrpcap)

random.seed(1337)   # deterministic fixtures

BENIGN = {
    "web": [("10.0.0.10", 80), ("10.0.0.10", 443)],
    "dns": [("10.0.0.1", 53)],
    "mail": [("10.0.0.20", 25)],
}


def _ts(base: float, step: int = 1) -> float:
    base += step * 0.001
    return base


# ---------------------------------------------------------------- benign
def benign_tcp_flow(base: float, client="10.0.0.50", server="10.0.0.10",
                     sport=49152, dport=80, pkts=8) -> list:
    out = []
    ts = base
    c, s = f"{client}:{sport}", f"{server}:{dport}"
    out.append(Ether()/IP(src=client, dst=server, ttl=64)/TCP(sport=sport, dport=dport, flags="S", seq=1000))
    ts = _ts(ts); out[-1].time = ts
    out.append(Ether()/IP(src=server, dst=client, ttl=63)/TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001))
    out[-1].time = _ts(ts)
    ts = out[-1].time
    out.append(Ether()/IP(src=client, dst=server, ttl=64)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001))
    out[-1].time = _ts(ts)
    for i in range(pkts - 3):
        ts = _ts(ts)
        out.append(Ether()/IP(src=client, dst=server, ttl=64)/
                   TCP(sport=sport, dport=dport, flags="PA", seq=1001 + i * 100, ack=5001)/Raw(b"x" * 300))
        out[-1].time = ts
        ts = _ts(ts)
        out.append(Ether()/IP(src=server, dst=client, ttl=63)/
                   TCP(sport=dport, dport=sport, flags="PA", seq=5001 + i * 100, ack=1101 + i * 100)/Raw(b"y" * 900))
        out[-1].time = ts
    return out


def benign_dns(base: float, client="10.0.0.50", server="10.0.0.1",
               names=("google.com", "youtube.com", "github.com", "amazon.com")) -> list:
    out = []
    ts = base
    for i, n in enumerate(names):
        ts = _ts(ts)
        out.append(Ether()/IP(src=client, dst=server, ttl=64) /
                   UDP(sport=40000 + i, dport=53) /
                   DNS(rd=0, qd=DNSQR(qname=n)))
        out[-1].time = ts
        resp = (Ether()/IP(src=server, dst=client, ttl=63) /
                UDP(sport=53, dport=40000 + i) /
                DNS(qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=n),
                    an="1.2.3.4"))
        resp.time = _ts(ts)
        out.append(resp)
        ts = resp.time
    return out


def benign_background(base: float, seconds=6.0) -> list:
    """Realistic noise: several hosts browsing/downloading."""
    out = []
    clients = ["10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53"]
    servers = [("10.0.0.10", 80), ("10.0.0.10", 443), ("10.0.0.20", 25),
               ("10.0.0.30", 445)]
    t = base
    for i in range(28):
        c = random.choice(clients)
        s, p = random.choice(servers)
        out.extend(benign_tcp_flow(t, client=c, server=s, dport=p,
                                    sport=random.randint(49152, 65535), pkts=6))
        t += 0.35
        if i % 4 == 0:
            out.extend(benign_dns(t, client=c))
            t += 0.2
    return out


# ---------------------------------------------------------------- attacks
def attack_horizontal_sweep(base: float, attacker="10.0.0.99",
                            target="10.0.0.10", ports=60, start=20) -> list:
    """Vertical-ish horizontal port sweep: one host, many ports, SYN only,
    each unanswered - the textbook nmap -sS signature."""
    out = []
    t = base
    for i in range(ports):
        p = start + i
        pkt = (Ether()/IP(src=attacker, dst=target, ttl=52) /
               TCP(sport=random.randint(40000, 65000), dport=p, flags="S", seq=random.randint(1, 2**31)))
        pkt.time = t = _ts(t, 2)     # 2ms apart -> fast sweep
        out.append(pkt)
    return out


def attack_vertical_flood(base: float, attacker="10.0.0.98",
                          target="10.0.0.10", dport=80, pkts=90) -> list:
    """Vertical scan / SYN flood: many SYNs, few ports, no handshake."""
    out = []
    t = base
    for _ in range(pkts):
        pkt = (Ether()/IP(src=attacker, dst=target, ttl=52) /
               TCP(sport=random.randint(40000, 65000), dport=dport, flags="S", seq=random.randint(1, 2**31)))
        pkt.time = t = _ts(t, 1)
        out.append(pkt)
    return out


def attack_brute_force(base: float, attacker="10.0.0.97",
                       target="10.0.0.40", dport=22, attempts=40) -> list:
    """SSH brute force: repeated SYN -> SYN-ACK -> RST teardown, like a
    failed password attempt."""
    out = []
    t = base
    for i in range(attempts):
        sport = random.randint(40000, 65000)
        s1 = Ether()/IP(src=attacker, dst=target, ttl=52)/TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1, 2**31))
        s1.time = t = _ts(t, 3)
        out.append(s1)
        s2 = Ether()/IP(src=target, dst=attacker, ttl=63)/TCP(sport=dport, dport=sport, flags="SA", seq=random.randint(1, 2**31), ack=1)
        s2.time = t = _ts(t, 1)
        out.append(s2)
        s3 = Ether()/IP(src=attacker, dst=target, ttl=52)/TCP(sport=sport, dport=dport, flags="R", seq=1)
        s3.time = t = _ts(t, 1)
        out.append(s3)
    return out


def attack_arp_spoof(base: float, victim="10.0.0.1", attacker="10.0.0.66",
                     gateway_mac="aa:bb:cc:00:00:01") -> list:
    """First bind the victim to the attacker's MAC, then flip to the real
    gateway MAC - producing an IP->MAC change plus one-MAC-many-IPs."""
    out = []
    t = base
    # normal: gateway answers for victim-side query
    a1 = Ether(src=gateway_mac)/ARP(op=2, hwsrc=gateway_mac, psrc=victim, hwdst="00:00:00:00:00:00", pdst="10.0.0.66")
    a1.time = t = _ts(t)
    out.append(a1)
    # now the attacker answers for the same IP with their own MAC
    for _ in range(3):
        a2 = Ether(src="de:ad:be:ef:00:01")/ARP(op=2, hwsrc="de:ad:be:ef:00:01", psrc=victim, hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.66")
        a2.time = t = _ts(t, 10)
        out.append(a2)
    # attacker MAC answers for many IPs
    for ip in ["10.0.0.1", "10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40"]:
        a3 = Ether(src="de:ad:be:ef:00:01")/ARP(op=2, hwsrc="de:ad:be:ef:00:01", psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.66")
        a3.time = t = _ts(t, 10)
        out.append(a3)
    return out


def attack_dns_tunnel(base: float, attacker="10.0.0.95", dns="10.0.0.1",
                      n=90) -> list:
    """DNS exfil: many long random subdomain queries."""
    out = []
    t = base
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(n):
        label = "".join(random.choice(alphabet) for _ in range(48))
        q = f"{label}.exfil.attacker-c2.xyz"
        p = Ether()/IP(src=attacker, dst=dns, ttl=64)/UDP(sport=random.randint(40000, 65000), dport=53)/DNS(rd=0, qd=DNSQR(qname=q))
        p.time = t = _ts(t, 2)
        out.append(p)
    return out


def attack_ttl_limping(base: float, attacker="10.0.0.94",
                       target="10.0.0.10", n=25) -> list:
    """Stable non-standard TTL (7) to confuse hop attribution."""
    out = []
    t = base
    for i in range(n):
        p = (Ether()/IP(src=attacker, dst=target, ttl=7) /
             TCP(sport=40000 + i, dport=443, flags="S", seq=1000 + i))
        p.time = t = _ts(t, 2)
        out.append(p)
    return out


def attack_udp_flood(base: float, attacker="10.0.0.93", target="10.0.0.10",
                     dport=53, n=120) -> list:
    """Volumetric UDP burst - caught by the burst detector, not payload rules."""
    out = []
    t = base
    for i in range(n):
        p = Ether()/IP(src=attacker, dst=target, ttl=52)/UDP(sport=random.randint(40000, 65000), dport=dport)/Raw(random.randbytes(64))
        p.time = t = _ts(t, 1)
        out.append(p)
    return out


# ---------------------------------------------------------------- builders
def build_clean_pcap(path: str) -> int:
    t = time.time() - 60
    pkts = benign_background(t, seconds=6.0)
    wrpcap(path, pkts)
    return len(pkts)


def build_attack_pcap(path: str) -> int:
    """One capture containing benign traffic interleaved with every attack."""
    t = time.time() - 120
    pkts = []
    pkts += benign_background(t)
    t += 3
    pkts += attack_horizontal_sweep(t)
    t += 2
    pkts += benign_background(t, seconds=2.0)
    t += 2
    pkts += attack_vertical_flood(t)
    t += 2
    pkts += attack_brute_force(t)
    t += 2
    pkts += attack_arp_spoof(t)
    t += 2
    pkts += attack_dns_tunnel(t)
    t += 2
    pkts += attack_ttl_limping(t)
    t += 2
    pkts += attack_udp_flood(t)
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(path, pkts)
    return len(pkts)


if __name__ == "__main__":
    import os
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
    os.makedirs(base_dir, exist_ok=True)
    n1 = build_clean_pcap(os.path.join(base_dir, "clean.pcap"))
    n2 = build_attack_pcap(os.path.join(base_dir, "attacks.pcap"))
    print(f"wrote samples/clean.pcap  ({n1} packets)")
    print(f"wrote samples/attacks.pcap ({n2} packets)")
