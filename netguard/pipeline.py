"""Alert pipeline: sink selection, SQLite persistence, JSON export."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections import Counter, deque

from .models import Alert, Severity


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id     TEXT PRIMARY KEY,
    ts           REAL NOT NULL,
    rule_id      TEXT,
    title        TEXT,
    severity     TEXT,
    severity_val INTEGER,
    src_ip       TEXT,
    dst_ip       TEXT,
    description  TEXT,
    evidence     TEXT,
    mitre        TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_sev ON alerts(severity_val DESC);
CREATE INDEX IF NOT EXISTS idx_src ON alerts(src_ip);
"""


class SqliteSink:
    """Durable alert store. One row per alert, JSON evidence column."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.count = 0

    def write(self, alert: Alert) -> None:
        d = alert.to_dict()
        self.conn.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (d["alert_id"], d["ts"], d["rule_id"], d["title"], d["severity"],
             d["severity_value"], d["src_ip"], d["dst_ip"], d["description"],
             json.dumps(d["evidence"]), d["mitre_attack"]),
        )
        self.count += 1
        if self.count % 50 == 0:
            self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    # ---- read helpers used by the reporter ----
    def summary(self) -> dict:
        cur = self.conn.cursor()
        sev = dict(cur.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
        top_src = cur.execute(
            "SELECT src_ip, COUNT(*) c FROM alerts GROUP BY src_ip "
            "ORDER BY c DESC LIMIT 10").fetchall()
        rules = cur.execute(
            "SELECT rule_id, COUNT(*) c FROM alerts GROUP BY rule_id "
            "ORDER BY c DESC").fetchall()
        total = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        span = cur.execute("SELECT MIN(ts), MAX(ts) FROM alerts").fetchone()
        return {"total": total, "by_severity": sev, "top_sources": top_src,
                "by_rule": rules, "first_ts": span[0], "last_ts": span[1]}

    def recent(self, limit: int = 200, min_severity: int = 0) -> list[dict]:
        cur = self.conn.cursor()
        rows = cur.execute(
            "SELECT alert_id,ts,rule_id,title,severity,severity_val,src_ip,"
            "dst_ip,description,evidence,mitre FROM alerts "
            "WHERE severity_val >= ? ORDER BY ts DESC LIMIT ?",
            (min_severity, limit)).fetchall()
        out = []
        for r in rows:
            out.append({"alert_id": r[0], "ts": r[1], "rule_id": r[2], "title": r[3],
                        "severity": r[4], "severity_value": r[5], "src_ip": r[6],
                        "dst_ip": r[7], "description": r[8],
                        "evidence": json.loads(r[9] or "{}"), "mitre": r[10]})
        return out


class Stats:
    """Lightweight counters shown live while sniffing."""

    def __init__(self):
        self.packets = 0
        self.events = 0
        self.alerts = 0
        self.by_proto: Counter[str] = Counter()
        self.started = time.time()
        self.recent_titles: deque[str] = deque(maxlen=8)

    def note_event(self, proto: str) -> None:
        self.events += 1
        self.by_proto[proto] += 1

    def note_alert(self, alert: Alert) -> None:
        self.alerts += 1
        self.recent_titles.append(alert.to_line())

    @property
    def pps(self) -> float:
        el = max(time.time() - self.started, 0.001)
        return self.packets / el

    def snapshot(self) -> str:
        el = time.time() - self.started
        return (f"packets={self.packets} events={self.events} "
                f"alerts={self.alerts} pps={self.pps:.1f} up={el:.0f}s "
                f"proto={dict(self.by_proto)}")


class AlertManager:
    """Fans one alert out to every configured sink."""

    def __init__(self, sinks: list | None = None, console: bool = True,
                 min_severity: int = 0):
        self.sinks = sinks or []
        self.console = console
        self.min_severity = min_severity

    def emit(self, alert: Alert) -> None:
        if int(alert.severity) < self.min_severity:
            return
        if self.console:
            print(alert.to_line(), flush=True)
        for s in self.sinks:
            try:
                s.write(alert)
            except Exception as e:            # never let a sink kill the IDS
                print(f"[alert-pipeline] sink error: {e}", flush=True)


class JsonlSink:
    """Append-only JSON lines - pipe into ELK/Grafana Loki easily."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.f = open(path, "a", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        self.f.write(json.dumps(alert.to_dict()) + "\n")
        self.f.flush()

    def close(self) -> None:
        self.f.close()


class CallbackSink:
    def __init__(self, fn):
        self.fn = fn

    def write(self, alert: Alert) -> None:
        self.fn(alert)
