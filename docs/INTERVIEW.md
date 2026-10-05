# NetGuard — Interview Notes

Talking points for explaining this project in a security interview. The goal is
to sound like someone who *built and debugged* it, not someone who ran a tutorial.

---

## 30-second elevator pitch

> "I built a network intrusion detection system in Python that analyses packet
> captures, runs six stateful detection rules over normalised network events,
> and stores severity-ranked alerts in SQLite with MITRE ATT&CK mappings and a
> generated SOC report. It detects SYN scans, brute force, ARP spoofing, DNS
> exfiltration, traffic bursts and TTL evasion. I validated it against a
> synthetic attack capture and it produces zero false positives on clean
> traffic."

---

## Architecture questions (mUST be ready)

**"Walk me through the data flow."**
Capture source (live NIC or pcap replay) → `parser.py` converts each scapy
packet into a normalised `Event` dataclass → each of six detector classes gets
every event and returns an `Alert` or `None` → alerts fan out to sinks
(console, SQLite, JSONL) → `report.py` reads the database and renders HTML.

**"Why normalise events instead of matching on raw packets?"**
Three reasons. Detectors stay unit-testable with no NIC and no admin rights.
The same rule code runs identically offline and live. And it decouples the
rules from scapy, so a rule could be fed from any other capture source later.
The `Event` dataclass is the contract between the capture layer and the
detection layer.

**"Why is it stateful rather than per-packet matching?"**
Because a per-packet rule is useless in production. A naive "is this a SYN?
alert" rule fires on all normal web traffic. Real detections are behavioural:
counts over time windows, handshake state machines, IP-to-MAC bindings tracked
over time. That's the difference between a toy and something an analyst can
actually use.

---

## The questions that actually separate candidates

These are the real design decisions in this project. Being able to explain
*why* is what reads as genuine engineering.

### 1. "Your port-scan rule flags normal browsers. How did you fix that?"

This is the single best thing to talk about in this project.

The naive version counts SYNs per source/destination pair and alerts on a
threshold. But a normal user opening `example.com` and `example.com/api` sends
SYNs to two ports on the same host — indistinguishable from a small port scan
by count alone.

The fix: **stop counting all SYNs, and start tracking which ones go
unanswered.** Each SYN is held in a pending queue. If the server replies
(SYN-ACK for an open port, RST for a closed one), that port is marked
responsive and the pending SYN is cleared as legitimate. Only SYNs that are
never answered stay in the queue and count as scan evidence.

That works because scanners probe ports that are closed or filtered and nothing
ever comes back, while a real client always gets an answer from a live service.
The false positive rate on my benign capture dropped to zero as a result.

### 2. "How do you tell brute force from a legitimate SSH user?"

Not by the handshake — that's the trap. A brute-forcer *does* get SYN-ACKs
because the server is real and listening. So handshake state can't separate
them.

What separates them is what happens *after* the handshake completes. A
successful login transfers payload bytes — the SSH banner, the auth request. A
failed attempt carries no application data and gets torn down with RST or FIN.

So the rule only marks an auth port as legitimately used once it has observed
actual payload on that (client, server, port) triple. Attempts from a source
that never once transferred data on that service are the ones that count toward
the brute-force threshold.

### 3. "Your TTL rule seems like it would be noisy. Isn't 64 just normal?"

Alerting on non-standard TTL is the textbook version and it is genuinely bad —
normal traffic sits at 63 *or* 64 depending on hop count, so a hardcoded
allow-list floods the analyst.

My version learns a baseline: the most common TTL observed across *other* hosts
in the capture, and only alerts when a host is *stably* far from it. The
subtle part is excluding the host under inspection when computing the baseline.
If you don't, and the capture happens to contain only the attacker, the
baseline becomes the attacker's own TTL, the delta is zero, and the rule
silently never fires. I hit that bug during testing.

### 4. "Your DNS exfil rule checks query volume. Isn't that a false-positive machine?"

Right, which is why volume alone doesn't alert in my implementation. Busy
resolvers and a browser with thirty tabs open legitimately generate hundreds of
queries per minute to real domains. That rule is exactly how you get an IDS
nobody trusts.

My rule requires a **structural** signal — an abnormally long DNS label (the
actual encoding substrate for DNS tunnelling) or a high-abuse TLD — and uses
query volume only as corroborating evidence added to the alert description.

### 5. "What's the most interesting bug you hit?"

Good candidates:

- **The ephemeral port bug.** My handshake-tracking allow-list was keying on the
  wrong port. On a SYN-ACK the packet travels server→client, so the *source*
  port is the service port and the *destination* port is the client's throwaway
  ephemeral port. I was recording the ephemeral port, so the allow-list never
  matched a later real SYN and legitimate traffic kept alerting. Found it by
  dumping the internal state and reading the actual tuples.
- **The scapy DNS gotcha.** My parser iterated `qdcount` to walk DNS questions,
  but scapy leaves `qdcount` as `None` on locally constructed packets — it's
  only populated when parsing from the wire. Since I both generate and replay
  pcaps, queries were silently dropped. Iterate the `qd` list directly instead.
- **Alert storm from one attack.** My first full run produced 30 alerts against
  17 real ones, with 17 of them TTL noise. Fixed by the baseline learning and
  by adding one-alert-per-source throttling to every rule.

---

## Concepts to be fluent in

Make sure you can define these without hesitating:

- **TCP three-way handshake** — SYN, SYN-ACK, ACK. A scanner's SYN gets no reply
  on a closed/filtered port; that absence is the detection signal.
- **SYN scan vs SYN flood vs port sweep** — horizontal (many ports on one host),
  vertical (many packets to few ports), and the difference in intent.
- **ARP spoofing / ARP cache poisoning** — attacker forges ARP replies so hosts
  send traffic through the attacker's MAC. Enables MITM. Detected by an IP
  changing MAC, or one MAC answering for many IPs.
- **DNS tunnelling / exfiltration over DNS** — encoding stolen data as
  subdomain labels so it leaves the network inside DNS queries, which is usually
  allowed outbound.
- **TTL-limping** — attacker rewrites the TTL field to a low value so replies
  die before reaching them, frustrating attribution.
- **MITRE ATT&CK** — the standard knowledge base of adversary tactics and
  techniques. T1046 network service discovery, T1110 brute force, T1557
  ARP cache poisoning, T1498 network DoS, T1048 exfiltration over alternative
  protocol.
- **False positives vs false negatives, precision vs recall** — in security
  tooling, false positives are usually the bigger problem because alert fatigue
  causes real alerts to be missed.
- **Sliding time windows** — detections are computed over a time window, not
  the whole capture, so an hour-long scan and a ten-second burst look different.
- **BPF filter** — Berkeley Packet Filter syntax used to select which packets to
  capture at the driver level, so you don't copy traffic you'll never inspect.

---

## Questions you should ask THEM

Shows you're thinking like a defender, not just a builder:

- What's your alert-to-incident ratio, and how do analysts triage when it's
  high?
- What's your detection stack — signature-based, behavioural, or both?
- How do you validate detections, and do you measure false-positive rates?
- What's your retention and correlation story across hosts and time?
- What's the difference between an alert and an incident in your workflow?

---

## Honest framing (important)

Be accurate about scope. If asked what the limitations are, say them — it reads
as competence, not weakness:

- **No TCP stream reassembly.** Analysis is per-packet, so encrypted payloads
  and split TCP segments aren't inspected. This is the biggest gap versus a
  real IDS like Snort or Suricata, which reassemble streams first.
- **No TLS decryption**, so HTTPS content is invisible.
- **Thresholds are hand-tuned, not learned.** Production systems tune against
  real traffic baselines.
- **Memory-only state.** Long-running captures would need bounded state; the
  sliding windows cap this but a very long capture would need eviction.
- **Offline and low-volume oriented.** It handles thousands of packets per
  second on pcap replay; it is not built for production line-rate throughput
  the way Suricata is.

That last set is genuinely the right answer, because it shows you know what
NetGuard is and isn't — which is the difference between a project and a
tool you understand.
