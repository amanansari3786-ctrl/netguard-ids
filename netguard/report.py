"""HTML/SOC-style report generator - reads the SQLite alert store."""

from __future__ import annotations

import html
import json
import os
import time

from .pipeline import SqliteSink

SEV_COLORS = {
    "CRITICAL": "#ff3b47",
    "HIGH": "#ff8c1a",
    "MEDIUM": "#ffd21a",
    "LOW": "#4fc3f7",
    "INFO": "#8d93a5",
}

MITRE_COLORS = {
    "T1046": "#ff8c1a", "T1110": "#ff3b47", "T1557": "#ff3b47",
    "T1048": "#ffd21a", "T1071": "#ffd21a", "T1498": "#ff8c1a",
}


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def build_report(db_path: str, out_path: str, title: str = "NetGuard IDS - SOC Report") -> str:
    sink = SqliteSink(db_path)
    s = sink.summary()
    alerts = sink.recent(limit=500)
    sink.close()

    # Sort by numeric severity so CRITICAL cards come first.
    SEV_ORDER = {k: i for i, k in enumerate(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}

    sev_rows = "".join(
        f'<div class="card" style="border-color:{SEV_COLORS.get(k, "#555")}">'
        f'<div class="num" style="color:{SEV_COLORS.get(k, "#555")}">{v}</div>'
        f'<div class="lbl">{html.escape(k)}</div></div>'
        for k, v in sorted(s["by_severity"].items(),
                           key=lambda kv: SEV_ORDER.get(kv[0], 99))
    ) or '<div class="card"><div class="num">0</div><div class="lbl">no alerts</div></div>'

    top_src = "".join(
        f"<tr><td class='mono'>{html.escape(str(ip))}</td><td>{c}</td></tr>"
        for ip, c in s["top_sources"]) or "<tr><td colspan=2>none</td></tr>"

    rules = "".join(
        f"<tr><td class='mono'>{html.escape(r)}</td><td>{c}</td></tr>"
        for r, c in s["by_rule"]) or "<tr><td colspan=2>none</td></tr>"

    rows = []
    for a in alerts:
        mitre = a["mitre"] or ""
        tid = mitre.split()[0] if mitre else ""
        color = SEV_COLORS.get(a["severity"], "#8d93a5")
        ev = json.dumps(a["evidence"], indent=2) if a["evidence"] else "{}"
        rows.append(f"""
        <tr>
          <td class="mono nowrap">{_fmt_ts(a['ts'])}</td>
          <td><span class="pill" style="background:{color}">{a['severity']}</span></td>
          <td class="mono">{html.escape(a['rule_id'])}</td>
          <td><b>{html.escape(a['title'])}</b><br><span class="dim">{html.escape(a['description'])}</span></td>
          <td class="mono">{html.escape(a['src_ip'])}</td>
          <td class="mono">{html.escape(a['dst_ip'])}</td>
          <td>{f'<span class="pill mitre" style="background:{MITRE_COLORS.get(tid, "#333")}">{html.escape(tid)}</span>' if tid else ''}</td>
          <td><details><summary>evidence</summary><pre>{html.escape(ev)}</pre></details></td>
        </tr>""")

    span = ""
    if s["first_ts"] and s["last_ts"]:
        span = f"{_fmt_ts(s['first_ts'])} &rarr; {_fmt_ts(s['last_ts'])}"

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
 body{{background:#0b0e14;color:#c9d1d9;font:14px/1.5 'Segoe UI',Consolas,monospace;margin:0;padding:28px}}
 h1{{color:#e6edf3;font-size:22px;margin:0 0 4px}}
 .dim{{color:#8d93a5;font-size:12px}}
 h2{{color:#e6edf3;font-size:15px;margin:26px 0 8px;border-bottom:1px solid #21262d;padding-bottom:6px}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
 .card{{border:1px solid #21262d;border-left:4px solid #58a6ff;border-radius:6px;padding:12px 20px;min-width:110px;background:#11151c}}
 .num{{font-size:26px;font-weight:700}} .lbl{{color:#8d93a5;font-size:11px;letter-spacing:1px}}
 table{{width:100%;border-collapse:collapse;margin-top:8px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #1b2028;vertical-align:top}}
 th{{color:#8d93a5;font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
 .mono{{font-family:Consolas,monospace;font-size:12px}} .nowrap{{white-space:nowrap}}
 .pill{{color:#0b0e14;font-weight:700;font-size:10px;padding:2px 7px;border-radius:9px}}
 .pill.mitre{{color:#fff}}
 details summary{{cursor:pointer;color:#58a6ff;font-size:11px}}
 pre{{background:#0b0e14;border:1px solid #21262d;padding:8px;border-radius:4px;font-size:11px;
      max-height:190px;overflow:auto;white-space:pre-wrap}}
 a{{color:#58a6ff}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="dim">generated {_fmt_ts(time.time())} &middot; source <span class="mono">{html.escape(os.path.basename(db_path))}</span> &middot; {span}</div>
<div class="cards">
  <div class="card"><div class="num" style="color:#58a6ff">{s['total']}</div><div class="lbl">TOTAL ALERTS</div></div>
  {sev_rows}
</div>
<h2>Top alert sources</h2>
<table><tr><th>source IP</th><th>alerts</th></tr>{top_src}</table>
<h2>Alerts by rule</h2>
<table><tr><th>rule</th><th>count</th></tr>{rules}</table>
<h2>Alert log ({len(alerts)} shown, newest first)</h2>
<table>
<tr><th>time</th><th>sev</th><th>rule</th><th>detail</th><th>src</th><th>dst</th><th>ATT&amp;CK</th><th></th></tr>
{"".join(rows) or "<tr><td colspan=8>No alerts recorded.</td></tr>"}
</table>
</body></html>"""

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def print_console_summary(db_path: str) -> None:
    sink = SqliteSink(db_path)
    s = sink.summary()
    sink.close()
    print("\n================ NETGUARD SOC SUMMARY ================")
    print(f"total alerts     : {s['total']}")
    if s["first_ts"]:
        print(f"window           : {_fmt_ts(s['first_ts'])} -> {_fmt_ts(s['last_ts'])}")
    print("by severity      :", s["by_severity"] or "-")
    print("by rule          :")
    for r, c in s["by_rule"]:
        print(f"   {r:<22} {c}")
    print("top sources      :")
    for ip, c in s["top_sources"]:
        print(f"   {ip:<22} {c}")
    print("=====================================================\n")


if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else "data/alerts.db"
    out = sys.argv[2] if len(sys.argv) > 2 else "data/report.html"
    print("wrote", build_report(db, out))
