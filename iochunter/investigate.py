"""Run a full investigation over one case folder and score it against ground truth.

case/
  auth.log            syslog-format auth log (sshd, sudo, useradd, cron)
  zeek/conn.log       optional
  zeek/dns.log        optional
  ground_truth.json   optional; enables scoring
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from dataclasses import asdict
from pathlib import Path

import duckdb
import pandas as pd

from . import dga, hunts, parse, sigma

LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TECHNIQUE_NAMES = {
    "T1110.001": "Brute Force: Password Guessing", "T1078": "Valid Accounts", "T1105": "Ingress Tool Transfer",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell", "T1136.001": "Create Account: Local Account",
    "T1053.003": "Scheduled Task/Job: Cron", "T1496": "Resource Hijacking", "T1071": "Application Layer Protocol",
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms", "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol", "T1078.003": "Valid Accounts: Local Accounts",
}


def load_auth(path: Path, base_year: int) -> tuple[duckdb.DuckDBPyConnection, pd.DataFrame]:
    auth = parse.read_syslog(path, base_year)
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.register("_a", auth)
    con.execute("CREATE TABLE auth AS SELECT * FROM _a")
    return con, auth


def _sigma_findings(con, rules) -> list[hunts.Finding]:
    out = []
    for r in rules:
        df = con.execute(r.sql).df()
        if df.empty or r.name == "ssh_auth_failure":
            continue
        tech = " / ".join(t.split(".", 1)[1].upper() for t in r.tags if t.startswith("attack.t"))
        if r.kind == "correlation":
            for ip, g in df.groupby("src_ip"):
                out.append(hunts.Finding(f"sigma:{r.name}", tech, r.level, ip, g.first_ts.min(), g.last_ts.max(),
                                         f"{r.title}: {int(g.event_count.sum())} failures in {len(g)} ten-minute window(s)",
                                         {"ip": [ip]}, [int(x) for x in g.lines.iloc[0][:20]]))
        else:
            # one finding per (rule, user, source, command): a cron job firing every 10 minutes is one finding
            df["key"] = df["user"].fillna("") + "|" + df["src_ip"].fillna("") + "|" + df["command"].fillna(df["message"].str[:80])
            for _, g in df.groupby("key", sort=False):
                row = g.iloc[0]
                ioc = {}
                if row.src_ip:
                    ioc["ip"] = [row.src_ip]
                if row.user and row.action != "cron_command":  # a cron job's owner is not an attacker identity
                    ioc["user"] = [row.user]
                times = f" ({len(g)} times until {g.ts.max():%Y-%m-%d %H:%M})" if len(g) > 1 else ""
                out.append(hunts.Finding(f"sigma:{r.name}", tech, r.level, row.user or row.src_ip or row.program, g.ts.min(), g.ts.max(),
                                         f"{r.title}: {row.message[:160]}{times}", ioc, [int(x) for x in g.line_no.head(20)]))
    return out


INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                               "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "::1/128")]


def _external(ip: str) -> bool:
    """Outside the organisation's own address space. (ipaddress.is_private would also drop
    the RFC 5737 documentation ranges the scenario uses for attackers.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a in n for n in INTERNAL)


def investigate(case: Path, base_year: int = 2026, internet_noise_floor: int = 20) -> dict:
    con, auth = load_auth(case / "auth.log", base_year)
    rules = sigma.load_rules(con)
    findings = _sigma_findings(con, rules)
    findings += hunts.brute_force_then_success(con, internet_noise_floor)
    findings += hunts.new_login_source_for_new_account(con)
    findings += hunts.linked_bruteforce_sources(con, [f for f in findings if f.hunt == "brute_force_then_success"])
    model, dga_metrics = dga.train_and_evaluate()
    zeek = case / "zeek"
    conn = dns = None
    if (zeek / "conn.log").exists():
        conn = parse.read_zeek(zeek / "conn.log")
        findings += hunts.beacons(conn)
        findings += hunts.large_uploads(conn)
    if (zeek / "dns.log").exists():
        dns = parse.read_zeek(zeek / "dns.log")
        findings += hunts.dga_lookups(dns, model)
        if conn is not None:
            findings += hunts.suspicious_resolutions(dns, conn, auth.loc[auth.action == "sudo_command", "command"])
    sus_cmds = auth.loc[auth.action.isin(["sudo_command", "cron_command"]), "command"]
    sus_cmds = sus_cmds[sus_cmds.str.contains(r"/\.|/tmp/|/dev/shm/", regex=True, na=False)]
    files = hunts.file_iocs_from_commands(sus_cmds)
    findings.sort(key=lambda f: f.first_seen)

    # ---- IOC consolidation: only indicators raised by medium+ findings, external IPs only ----
    iocs = {"ip": {}, "domain": {}, "user": {}, "file": {}}
    for f in findings:
        if LEVEL_RANK[f.severity] < 2:
            continue
        for kind, vals in f.iocs.items():
            for v in vals:
                if kind == "ip" and not _external(v):
                    continue
                e = iocs[kind].setdefault(v, dict(value=v, type=kind, first_seen=f.first_seen, last_seen=f.last_seen, sources=set(), max_severity=f.severity))
                e["first_seen"], e["last_seen"] = min(e["first_seen"], f.first_seen), max(e["last_seen"], f.last_seen)
                e["sources"].add(f.hunt)
                if LEVEL_RANK[f.severity] > LEVEL_RANK[e["max_severity"]]:
                    e["max_severity"] = f.severity
    # an IP that only brute-forced (never logged in, never received traffic) is internet noise, not an incident IOC
    noise_only = {ip for ip, e in iocs["ip"].items() if e["sources"] <= {"sigma:ssh_bruteforce"}}
    for ip in noise_only:
        iocs["ip"].pop(ip)
    for p in files:
        iocs["file"][p] = dict(value=p, type="file", first_seen=None, last_seen=None, sources={"command_paths"}, max_severity="high")

    result = dict(case=str(case), events=int(len(auth)), sigma_rules=[r.title for r in rules], findings=findings,
                  iocs=iocs, dga=dga_metrics, noise_ips_suppressed=len(noise_only))
    gt = case / "ground_truth.json"
    if gt.exists():
        result["score"] = score(result, json.loads(gt.read_text()))
    return result


def score(result: dict, truth: dict) -> dict:
    out = {}
    for kind in ("ip", "domain", "user", "file"):
        got, want = set(result["iocs"][kind]), set(truth["iocs"][kind])
        tp = len(got & want)
        out[kind] = dict(found=tp, expected=len(want), extra=sorted(got - want), missed=sorted(want - got),
                         precision=round(tp / len(got), 4) if got else None, recall=round(tp / len(want), 4) if want else None)
    techs = {t.strip() for f in result["findings"] if LEVEL_RANK[f.severity] >= 2 for t in f.technique.split("/")}
    stages = []
    for s in truth["stages"]:
        hit = s["technique"] in techs or s["technique"].split(".")[0] in {t.split(".")[0] for t in techs}
        stages.append(dict(**s, detected=hit))
    out["stages"] = stages
    out["stage_recall"] = round(sum(s["detected"] for s in stages) / len(stages), 4)
    return out


# ---------- exports ----------

def stix_bundle(result: dict, name: str = "ioc-hunter case") -> dict:
    """STIX 2.1 bundle with one indicator per IOC so it can be loaded into a TIP or SIEM."""
    def pattern(e):
        v = e["value"].replace("'", "\\'")
        return {"ip": f"[ipv4-addr:value = '{v}']", "domain": f"[domain-name:value = '{v}']",
                "user": f"[user-account:account_login = '{v}']", "file": f"[file:name = '{v.rsplit('/', 1)[-1]}']"}[e["type"]]
    now = pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objs = []
    for kind, items in result["iocs"].items():
        for e in items.values():
            first = e["first_seen"].strftime("%Y-%m-%dT%H:%M:%S.000Z") if e["first_seen"] is not None else now
            objs.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, kind + e['value'])}",
                         "created": now, "modified": now, "name": f"{kind} {e['value']}", "pattern": pattern(e), "pattern_type": "stix",
                         "valid_from": first, "indicator_types": ["malicious-activity"],
                         "labels": sorted(e["sources"]), "confidence": {"critical": 90, "high": 75, "medium": 50}.get(e["max_severity"], 30),
                         "description": f"Raised by {', '.join(sorted(e['sources']))} in {name}"})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, name)}", "objects": objs}


def to_jsonable(result: dict) -> dict:
    def conv(o):
        if isinstance(o, pd.Timestamp):
            return o.strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(o, set):
            return sorted(o)
        return o
    r = dict(result)
    r["findings"] = [{k: conv(v) for k, v in asdict(f).items()} for f in result["findings"]]
    r["iocs"] = {k: [{kk: conv(vv) for kk, vv in e.items()} for e in v.values()] for k, v in result["iocs"].items()}
    return json.loads(json.dumps(r, default=conv))
