# NetGuard IDS

[![CI](https://github.com/amanansari3786-ctrl/netguard-ids/actions/workflows/ci.yml/badge.svg)](https://github.com/amanansari3786-ctrl/netguard-ids/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

A lightweight, from-scratch **network intrusion detection system** written in
Python. Built for learning network/SOC fundamentals and as a portfolio project.

NetGuard reads network traffic, normalises it into a common event shape, runs it
past a set of stateful detection rules, and stores severity-ranked alerts in
SQLite with a generated SOC-style HTML report.

Every alert is tagged with a **MITRE ATT&CK** technique ID.

---

## What it detects

| Rule ID | Detection | ATT&CK | Severity |
|---|---|---|---|
| `NG-SYN-SCAN` | SYN scan / horizontal port sweep / SYN flood | T1046 | HIGH |
| `NG-BRUTE-FORCE` | Brute force against auth services (22/21/3389/445/...) | T1110 | HIGH |
| `NG-ARP-SPOOF` | ARP cache poisoning / MITM | T1557 | CRITICAL |
| `NG-DNS-EXFIL` | DNS tunnelling / exfiltration | T1048, T1071.004 | MEDIUM |
| `NG-BURST` | Volumetric traffic burst (possible DoS) | T1498 | HIGH |
| `NG-TTL-ANOM` | TTL manipulation / TTL-limping evasion | T1071 | LOW |

---

## Quick start

Works on Windows, macOS and Linux. Needs Python 3.10+ (uses `dataclass(slots=True)`).

```bash
# 1. get the code
git clone https://github.com/amanansari3786-ctrl/netguard-ids.git
cd netguard-ids

# 2. create a virtual environment and install dependencies
python -m venv .venv

# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 3. install dependencies
pip install -r requirements.txt
```

That's the whole setup. From here, `python netguard.py ...` works directly.

### 1. Run the test suite (24 tests, ~3 seconds)

```bash
python -m pytest tests/ -q
```

### 2. Generate sample traffic

```bash
python netguard.py gen
```

Creates two pcaps:
- `samples/clean.pcap` — benign baseline only (browsing, DNS, downloads)
- `samples/attacks.pcap` — benign traffic **plus 7 simulated attacks**

All addresses are RFC1918 / documentation ranges. Nothing leaves your machine.

### 2. Analyse a capture

```bash
python netguard.py scan --pcap samples/attacks.pcap --jsonl data/alerts.jsonl
```

### 3. Generate the report

```bash
python netguard.py report
# open data/report.html in your browser
```

### 4. Live capture (needs Administrator + Npcap)

```bash
netguard watch --iface "\\Device\\NPF_{YOUR-GUID}" --filter "tcp or arp" --duration 60
```

Find your interface GUID in Wireshark, or run as admin to avoid the privilege error.

---

## CLI reference

```
netguard gen                                  build sample pcaps
netguard scan  --pcap FILE                    offline pcap analysis
netguard watch --iface IFACE [--filter BPF]    live capture
netguard report [--db DB] [--out HTML]         build HTML SOC report
netguard summary [--db DB]                    console summary
netguard rules                                list detection rules
```

Useful tuning flags on `scan` / `watch`:

```
--syn-threshold N      SYNs before a vertical-burst alert   (default 30)
--sweep-ports N        distinct unanswered ports = sweep   (default 12)
--brute-threshold N    attempts before brute-force alert   (default 15)
--burst-threshold N    packets before burst alert          (default 40)
--min-severity N       only emit alerts >= N (0-95)
--quiet                no console output
```

---

## Architecture

```
  capture source                pipeline                  output
 ┌──────────────────┐      ┌──────────────────┐      ┌─────────────────┐
 │ live NIC (scapy  │      │ netguard/parser  │      │ console         │
 │   sniff)         │─────▶│  packet → Event  │─────▶│ SQLite (alerts) │
 │                  │      │                  │      │ JSONL           │
 │ pcap replay      │      │ netguard/        │      │ HTML report     │
 │ (PcapReader)     │      │  detectors  ×6   │      └─────────────────┘
 └──────────────────┘      │  stateful rules  │
                           └──────────────────┘
```

### Why this structure

**Detectors never see raw packets.** `parser.py` converts every scapy packet
into a normalised `Event` dataclass. Rules therefore:

- need no NIC and no elevated privileges to test
- run identically offline and live
- are unit-testable in milliseconds

**Stateful rules, not just per-packet matching.** A per-packet IDS ("is this a
SYN? alert!") is useless in practice because normal traffic is full of SYNs.
Real detections are *behavioural* — counts over time windows, state machines
tracking handshake completion, IP→MAC bindings over time. Each rule keeps
in-memory sliding-window state keyed by IP.

**One-alert-per-source throttling.** Every rule keeps a `fired` set so a single
ongoing scan produces one alert rather than hundreds. This is exactly the
real-world difference between an analyst-usable IDS and alert fatigue.

### Key detection logic

**Port sweep — unanswered SYN tracking.** The naive rule ("many SYNs to one
host = port scan") flags every normal browser that visits two pages on the same
web server. NetGuard instead holds each SYN *pending* until a response arrives:

- server replies SYN-ACK/RST → the port is marked responsive, the pending SYN
  is cleared as legitimate traffic
- SYN never answered → it stays pending and counts as reconnaissance evidence

Scanners leave unanswered SYNs everywhere; real clients do not.

**Brute force — data-transfer confirmation.** A brute-forcer *does* receive
SYN-ACKs, so the handshake alone cannot distinguish it from a real client. What
separates them is what happens next: a successful login transfers payload
bytes, while a failed attempt is torn down with RST/FIN carrying no data. The
rule only marks a service port as legitimately used on observed payload.

**TTL anomaly — learned baseline.** Alerting on "non-standard TTL" is pure
noise, since normal traffic sits at 63 *or* 64 depending on hop count. NetGuard
learns the network's most common TTL across *other* hosts and only alerts on a
stably different value. Excluding the inspected host matters: otherwise an
isolated capture of one attacker sets its own baseline and silences the rule.

**DNS exfil — structural signal required.** Query *volume alone* is not
evidence; busy resolvers and multi-tab browsers legitimately produce hundreds of
queries. The rule requires a structural signal (abnormally long DNS label, or a
high-abuse TLD) and uses volume only as corroboration.

---

## Testing

```bash
python -m pytest tests/ -q
```

24 tests covering the parser, every rule's true-positive and false-positive
behaviour, the engine, the SQLite pipeline, severity filtering, and report
generation.

Measured results on the generated captures:

| Capture | Packets | Alerts | Result |
|---|---|---|---|
| `clean.pcap` | 308 | **0** | no false positives |
| `attacks.pcap` | 1130 | 17 | all 7 attack types detected |

The zero-alert result on clean traffic is the number that matters most for an
IDS — detection rate is easy, false-positive rate is what kills real deployments.

---

## Project layout

```
netguard-ids/
├── netguard.py              CLI entry point
├── netguard/
│   ├── models.py            Event / Alert / Severity
│   ├── parser.py            scapy packet → normalised Event
│   ├── detectors.py         the 6 detection rules
│   ├── engine.py            capture → parse → detect → alert loop
│   ├── pipeline.py          SQLite / JSONL / console sinks, stats
│   ├── report.py            HTML SOC report + console summary
│   └── traffic.py           synthetic benign + attack pcap generator
├── tests/test_detectors.py  24 tests
├── samples/                 generated pcaps
└── data/                    alerts.db, alerts.jsonl, report.html
```

## Extending it

Good next steps, in rough order of value:

1. **Add rules** — add a class to `detectors.py` with `rule_id`, `severity`,
   `mitre`, and `inspect()`. No other wiring needed.
2. **TCP session reassembly** — currently per-packet. Reassembling streams
   enables payload inspection (the classic Snort approach).
3. **Alert tuning** — the pcap fixtures make it easy to measure precision and
   recall per rule; treat thresholds as tunable config, not constants.
4. **Ship alerts onward** — the JSONL sink already pipes into ELK/Loki; add a
   webhook sink for Slack/Teams.
5. **PCAP over TLS** — decrypting loopback TLS captures to inspect plaintext.

## Responsible use

NetGuard is a defensive tool. The included traffic generator only produces
synthetic RFC1918 traffic written to local files — it does not transmit
anything, and it targets no external host. Keep it that way: point detection
tooling at systems you own or are authorised to test.
