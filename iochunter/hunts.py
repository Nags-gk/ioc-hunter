"""Hypothesis-driven hunts over auth logs (DuckDB SQL) and Zeek logs (pandas).

Each hunt states its hypothesis, returns findings with the evidence lines or
connection IDs behind them, and maps to an ATT&CK technique. Sigma rules cover
single events and counts; these hunts cover what needs ordering or statistics:
brute force followed by success, beacon timing, DGA scoring, and exfil volume.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .dga import DGAModel


@dataclass
class Finding:
    hunt: str
    technique: str
    severity: str
    entity: str
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    summary: str
    iocs: dict = field(default_factory=dict)  # {"ip": [...], "domain": [...], "user": [...], "file": [...]}
    evidence: list = field(default_factory=list)  # auth line numbers or zeek uids


FAILS = "('failed_password', 'failed_password_invalid_user', 'invalid_user', 'auth_failure')"


def brute_force_then_success(con, min_failures: int = 20, within_h: int = 24) -> list[Finding]:
    """Hypothesis: a source that fails many times and then logs in has guessed a password."""
    df = con.execute(f"""
      WITH f AS (SELECT src_ip, count(*) n, min(ts) first_fail, max(ts) last_fail, count(DISTINCT user) users
                 FROM auth WHERE action IN {FAILS} AND src_ip IS NOT NULL GROUP BY src_ip HAVING count(*) >= {min_failures}),
           s AS (SELECT src_ip, user, ts, line_no FROM auth WHERE action LIKE 'accepted%')
      SELECT f.src_ip, f.n, f.users, f.first_fail, f.last_fail, s.user, s.ts AS success_ts, s.line_no
      FROM f JOIN s ON s.src_ip = f.src_ip AND s.ts >= f.first_fail AND s.ts <= f.last_fail + INTERVAL {within_h} HOUR
      ORDER BY s.ts""").df()
    out = []
    for (ip, user), g in df.groupby(["src_ip", "user"], sort=False):
        r = g.iloc[0]
        out.append(Finding("brute_force_then_success", "T1110.001 / T1078", "critical", ip, r.first_fail, g.success_ts.max(),
                           f"{r.n} failed attempts on {r.users} usernames from {ip}, then {len(g)} successful login(s) as '{user}'",
                           {"ip": [ip], "user": [user]}, g.line_no.tolist()))
    return out


def linked_bruteforce_sources(con, compromises: list[Finding], window_min: int = 90, min_jaccard: float = 0.5) -> list[Finding]:
    """Hypothesis: sources guessing the same usernames at the same time as the source that
    got in are the same operator's infrastructure, even though they never succeeded."""
    out = []
    for c in compromises:
        ip = c.entity
        df = con.execute(f"""
          WITH s AS (SELECT src_ip, list_distinct(list(user)) users, min(ts) t0, max(ts) t1, count(*) n
                     FROM auth WHERE action IN {FAILS} AND src_ip IS NOT NULL AND user IS NOT NULL GROUP BY src_ip),
               ref AS (SELECT * FROM s WHERE src_ip = ?)
          SELECT s.src_ip, s.n, s.t0, s.t1, len(list_intersect(s.users, ref.users)) * 1.0 / len(list_distinct(list_concat(s.users, ref.users))) AS jac
          FROM s, ref WHERE s.src_ip <> ref.src_ip
            AND s.t0 <= ref.t1 + INTERVAL {window_min} MINUTE AND s.t1 >= ref.t0 - INTERVAL {window_min} MINUTE""", [ip]).df()
        df = df[df.jac >= min_jaccard]
        if len(df):
            out.append(Finding("linked_bruteforce_sources", "T1110.001", "high", ip, df.t0.min(), df.t1.max(),
                               f"{len(df)} other sources guessed the same usernames (Jaccard >= {min_jaccard}) within {window_min} min of {ip}: "
                               + ", ".join(df.src_ip.head(5)), {"ip": df.src_ip.tolist()}, []))
    return out


def multi_account_source(con, min_accounts: int = 3) -> list[Finding]:
    """Hypothesis: one source successfully logging in to several different accounts is
    credential sharing or a stolen credential list. Shared NAT (a lab or campus gateway)
    is the usual benign explanation, so this is a lead, not a verdict."""
    df = con.execute(f"""SELECT src_ip, list_distinct(list(user)) users, count(*) logins, min(ts) t0, max(ts) t1, list(line_no) lines
        FROM auth WHERE action LIKE 'accepted%' AND src_ip IS NOT NULL GROUP BY src_ip HAVING count(DISTINCT user) >= {min_accounts}""").df()
    return [Finding("multi_account_source", "T1078", "medium", r.src_ip, r.t0, r.t1,
                    f"{r.src_ip} logged in successfully to {len(r.users)} accounts ({', '.join(sorted(r.users))}); check for shared NAT before treating as compromise",
                    {"ip": [r.src_ip], "user": sorted(r.users)}, [int(x) for x in r.lines[:20]]) for r in df.itertuples()]


def dictionary_fingerprints(con, min_attempts: int = 100) -> list[Finding]:
    """Hypothesis: brute-force tools ship fixed username lists, so sources replaying the
    exact same list (and often the same attempt count) belong to one tool or operator."""
    df = con.execute(f"""SELECT src_ip, count(*) n, list_sort(list_distinct(list(user))) users, min(ts) t0, max(ts) t1
        FROM auth WHERE action IN {FAILS} AND src_ip IS NOT NULL AND user IS NOT NULL
        GROUP BY src_ip HAVING count(*) >= {min_attempts} AND count(DISTINCT user) >= 5""").df()
    df["sig"] = df.users.apply(lambda u: "|".join(u))
    out = []
    for _sig, g in df.groupby("sig"):
        if len(g) < 2:
            continue
        users = g.users.iloc[0]
        out.append(Finding("dictionary_fingerprint", "T1110.001", "medium", f"{len(g)} sources", g.t0.min(), g.t1.max(),
                           f"{len(g)} sources replayed the same {len(users)}-username list ({', '.join(users[:6])}...); "
                           f"attempts per source: {', '.join(str(x) for x in sorted(g.n.unique()))}; active {g.t0.min():%m-%d} to {g.t1.max():%m-%d}",
                           {"ip": g.src_ip.tolist()}, []))
    return out


def password_guessing_summary(con) -> pd.DataFrame:
    return con.execute(f"""SELECT src_ip, count(*) attempts, count(DISTINCT user) usernames, min(ts) first_seen, max(ts) last_seen,
        count(*) FILTER (WHERE action LIKE '%invalid_user%' OR action = 'invalid_user') invalid_user_attempts
        FROM auth WHERE action IN {FAILS} AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY attempts DESC""").df()


def new_login_source_for_new_account(con) -> list[Finding]:
    """Hypothesis: an account created during the window that logs in remotely is a backdoor."""
    df = con.execute("""
      WITH n AS (SELECT user, min(ts) created FROM auth WHERE action = 'user_added' GROUP BY user)
      SELECT a.user, a.src_ip, a.ts, a.line_no, n.created FROM auth a JOIN n USING (user)
      WHERE a.action LIKE 'accepted%' AND a.ts > n.created""").df()
    return [Finding("backdoor_account_login", "T1078 / T1136.001", "critical", r.user, r.created, r.ts,
                    f"Account '{r.user}' was created at {r.created:%Y-%m-%d %H:%M} and later logged in over SSH from {r.src_ip}",
                    {"ip": [r.src_ip], "user": [r.user]}, [int(r.line_no)]) for r in df.itertuples()]


def beacons(conn: pd.DataFrame, min_conns: int = 30, max_cv: float = 0.15) -> list[Finding]:
    """Hypothesis: malware calls home on a timer, so its connections are evenly spaced.
    Score each (destination, port) by the coefficient of variation of inter-arrival
    times; humans and normal software are bursty (high CV)."""
    out = []
    for (dst, port), g in conn.groupby(["resp_h", "resp_p"]):
        if len(g) < min_conns:
            continue
        gaps = g.ts.sort_values().diff().dt.total_seconds().dropna()
        mean, cv = gaps.mean(), gaps.std() / gaps.mean() if gaps.mean() else np.inf
        if cv > max_cv:
            continue
        sev = "low" if mean > 30 * 60 else "high"  # hourly-ish timers are usually NTP, update checks
        out.append(Finding("beaconing", "T1071 / T1496" if port in (3333, 4444, 5555, 14444) else "T1071", sev, f"{dst}:{int(port)}",
                           g.ts.min(), g.ts.max(),
                           f"{len(g)} connections to {dst}:{int(port)}, every {mean:.0f}s (CV {cv:.3f}), {g.orig_bytes.sum() / 1e6:.1f} MB out",
                           {"ip": [dst]}, g.uid.head(20).tolist()))
    return out


def dga_lookups(dns: pd.DataFrame, model: DGAModel, threshold: float = 0.5) -> list[Finding]:
    """Hypothesis: algorithmically generated domains look random and mostly do not resolve.
    The model alone also scores some real names highly (login.microsoftonline.com), so a
    high-severity finding needs both a high score and NXDOMAIN; resolving high scorers are
    listed at low severity for an analyst to review, without becoming IOCs."""
    q = dns.dropna(subset=["query"]).copy()
    q["score"] = model.score(q["query"].tolist())
    q["nx"] = q.rcode_name.eq("NXDOMAIN")
    out = []
    hits = q[(q.score >= threshold) & q.nx]
    if len(hits):
        out.append(Finding("dga_lookups", "T1568.002", "high", f"{hits['query'].nunique()} domains", hits.ts.min(), hits.ts.max(),
                           f"{hits['query'].nunique()} likely generated domains, all NXDOMAIN, e.g. {', '.join(hits['query'].unique()[:3])}",
                           {"domain": sorted(hits["query"].unique())}, hits.uid.tolist()))
    review = q[(q.score >= 0.9) & ~q.nx].drop_duplicates("query")
    if len(review):
        out.append(Finding("dga_review", "T1568.002", "low", f"{len(review)} resolving domains", review.ts.min(), review.ts.max(),
                           f"Random-looking but resolving: {', '.join(review['query'].head(5))}. Check against other hunts before acting.",
                           {"domain": review["query"].tolist()}, review.uid.tolist()))
    return out


def suspicious_resolutions(dns: pd.DataFrame, conn: pd.DataFrame, sudo_cmds: pd.Series) -> list[Finding]:
    """Hypothesis: a domain that appears in a download-and-execute command is the stager."""
    out = []
    for cmd in sudo_cmds.dropna():
        for q in dns["query"].dropna().unique():
            if q in cmd:
                ans = dns.loc[dns["query"] == q, "answers"].dropna().unique().tolist()
                c = conn[conn.resp_h.isin(ans)]
                out.append(Finding("stager_download", "T1105", "high", q, dns.loc[dns["query"] == q, "ts"].min(),
                                   c.ts.max() if len(c) else dns.loc[dns["query"] == q, "ts"].max(),
                                   f"{q} ({', '.join(ans)}) appears in a sudo download command; host pulled {c.resp_bytes.sum() / 1e6:.1f} MB from it",
                                   {"domain": [q], "ip": ans}, c.uid.tolist()))
    return out


def large_uploads(conn: pd.DataFrame, min_mb: float = 100, rare_max: int = 3) -> list[Finding]:
    """Hypothesis: a large outbound transfer to a destination the host rarely talks to is exfiltration."""
    seen = conn.groupby("resp_h").size()
    big = conn[(conn.orig_bytes >= min_mb * 1e6) & conn.resp_h.map(lambda h: seen[h] <= rare_max)]
    return [Finding("large_upload", "T1041 / T1048", "critical", f"{r.resp_h}:{int(r.resp_p)}", r.ts, r.ts + pd.Timedelta(seconds=r.duration or 0),
                    f"{r.orig_bytes / 1e6:.0f} MB sent to {r.resp_h}:{int(r.resp_p)} over {r.duration / 60:.0f} min; host contacted it {seen[r.resp_h]} time(s) in total",
                    {"ip": [r.resp_h]}, [r.uid]) for r in big.itertuples()]


def file_iocs_from_commands(cmds: pd.Series) -> list[str]:
    import re
    paths = set()
    for c in cmds.dropna():
        for p in re.findall(r"(/(?:tmp|dev/shm|var/tmp|usr/local/bin|etc)/\.[\w.-]+|/tmp/[\w.-]+)", c):
            paths.add(p)
    return sorted(paths)
