"""Hunt a real server's SSH log: Loghub's OpenSSH dataset (655,146 lines from an
internet-facing lab server, about four weeks; He et al., "Loghub", ISSRE 2023).

There is no ground truth, so the output is hunt notes: what was ruled out, what
stands out, and which leads need someone with access to the host to confirm.
The log has no year; timestamps use a placeholder base year.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from . import hunts, investigate, sigma

URL = "https://zenodo.org/records/8196385/files/SSH.tar.gz"
SHA256 = "296610a35773f58b7c295e5407fc5ccdf48beb3c544fc14a6309addf904a2712"


def hunt(path: Path, base_year: int = 2015) -> dict:
    con, auth = investigate.load_auth(path, base_year)
    rules = sigma.load_rules(con)
    sig = {r.name: int(len(con.execute(r.sql).df())) for r in rules}
    summary = hunts.password_guessing_summary(con)
    fails = "('failed_password', 'failed_password_invalid_user', 'invalid_user', 'auth_failure')"
    stats = con.execute(f"""SELECT count(*) lines, min(ts) t0, max(ts) t1,
        count(*) FILTER (WHERE action IN {fails}) failures,
        count(DISTINCT src_ip) FILTER (WHERE action IN {fails}) failing_sources,
        count(*) FILTER (WHERE action LIKE 'accepted%') successes,
        count(DISTINCT user) FILTER (WHERE action LIKE 'accepted%') success_accounts,
        count(DISTINCT src_ip) FILTER (WHERE action LIKE 'accepted%') success_sources,
        count(*) FILTER (WHERE action IN {fails} AND user = 'root') root_failures
        FROM auth""").df().iloc[0].to_dict()
    overlap = con.execute(f"""WITH s AS (SELECT src_ip, list_distinct(list(user)) logged_in_as FROM auth WHERE action LIKE 'accepted%' GROUP BY 1),
        f AS (SELECT src_ip, count(*) n, list_distinct(list(user)) tried FROM auth WHERE action IN {fails} GROUP BY 1)
        SELECT s.src_ip, s.logged_in_as, coalesce(f.n, 0) failures, f.tried FROM s LEFT JOIN f USING (src_ip) ORDER BY failures DESC""").df()
    top_users = con.execute("""SELECT user, count(*) n FROM auth WHERE action IN ('failed_password','failed_password_invalid_user','invalid_user')
        GROUP BY 1 ORDER BY 2 DESC LIMIT 15""").df()
    daily = con.execute(f"""SELECT date_trunc('day', ts) AS day, count(*) AS failures, count(DISTINCT src_ip) sources
        FROM auth WHERE action IN {fails} GROUP BY 1 ORDER BY 1""").df()
    leads = hunts.brute_force_then_success(con, 20) + hunts.multi_account_source(con) + hunts.dictionary_fingerprints(con)
    neighbours = {}
    for lead in [x for x in leads if x.hunt == "multi_account_source"]:
        pfx = ".".join(lead.entity.split(".")[:2]) + "."
        nb = summary[summary.src_ip.str.startswith(pfx) & (summary.src_ip != lead.entity)]
        neighbours[lead.entity] = nb.head(5)
    return dict(neighbours=neighbours, source=dict(url=URL, sha256=SHA256, base_year_placeholder=base_year), stats=stats, sigma_hits=sig,
                top_sources=summary.head(15), success_sources=overlap, top_usernames=top_users, daily=daily,
                brute_force_successes=[asdict(f) for f in leads if f.hunt == "brute_force_then_success"],
                leads=[asdict(f) for f in leads])


def notes(h: dict) -> str:
    s = h["stats"]
    so = h["success_sources"]
    max_fail = int(so.failures.max()) if len(so) else 0
    mult = [lead for lead in h["leads"] if lead["hunt"] == "multi_account_source"]
    fp = [lead for lead in h["leads"] if lead["hunt"] == "dictionary_fingerprint"]
    out = ["# Hunt notes: real OpenSSH server log (Loghub)", "",
           f"Source: Loghub OpenSSH dataset ({h['source']['url']}, sha256 `{h['source']['sha256'][:16]}...`). "
           f"{int(s['lines']):,} lines over {(s['t1'] - s['t0']).days} days. The log has no year; dates below use a placeholder year.", "",
           "## Scale", "",
           f"- {int(s['failures']):,} failed authentication events from **{int(s['failing_sources']):,} sources**; "
           f"{int(s['root_failures']):,} of them ({s['root_failures'] / s['failures']:.0%}) targeted `root`.",
           f"- {int(s['successes'])} successful logins to {int(s['success_accounts'])} accounts from {int(s['success_sources'])} sources.",
           f"- Sigma: `ssh_bruteforce` fired {h['sigma_hits'].get('ssh_bruteforce', 0):,} times (source x 10-minute window); "
           f"`ssh_root_login` {h['sigma_hits'].get('ssh_root_login', 0)}, `linux_uid0_account` {h['sigma_hits'].get('linux_uid0_account', 0)}, "
           f"`sudo_download_execute` {h['sigma_hits'].get('sudo_download_execute', 0)} (this log has no sudo or useradd lines).", "",
           "## Hypothesis 1: a brute-forcing source got in. Not supported.", "",
           f"No source with 20 or more failures ever logged in. Of {len(so)} sources with a successful login, "
           f"{int((so.failures > 0).sum())} had any failures at all (at most {max_fail}):", "",
           "| Source | Logged in as | Failures | Usernames that failed |", "|---|---|---:|---|"]
    out += [f"| {r.src_ip} | {', '.join(r.logged_in_as)} | {r.failures} | {', '.join(u for u in (r.tried if r.tried is not None else []) if u) or '(not logged)'} |"
            for r in so[so.failures > 0].itertuples()]
    out += ["", "Most are a handful of failures on the same account that then succeeds, the pattern of a mistyped password. "
            "The exception is noted under hypothesis 2.", "",
           "## Hypothesis 2: credentials are shared or stolen. Two leads.", ""]
    out += [f"- {lead['summary']}" for lead in mult]
    for ip, nb in h["neighbours"].items():
        if len(nb):
            out.append(f"  - Same /16 as {ip}: " + "; ".join(f"{r.src_ip} ({r.attempts:,} failed attempts on {r.usernames} usernames)" for r in nb.itertuples()))
    out += ["", "Both are consistent with a shared campus or lab gateway. Next step: ask the account owners, and compare "
            "these sources with each account's usual login locations.", "",
            "## Hypothesis 3: the noise is a few operators, not a thousand. Supported.", "",
            f"{len(fp)} groups of sources replayed identical username dictionaries, often with identical attempt counts, which points "
            "to shared tooling or one operator rotating IPs:", ""]
    out += [f"- {lead['summary']}" for lead in fp]
    out += ["", "## Recommendations for this server", "",
            "1. Disable password authentication for SSH (`PasswordAuthentication no`) and root login (`PermitRootLogin no`); "
            f"{s['root_failures'] / s['failures']:.0%} of guessing targets root.",
            "2. Rate-limit new SSH connections per source (fail2ban or nftables meters) to cut log volume and guessing speed.",
            "3. Alert on the sequence rule (failures then success from one source); it found nothing here, which is the expected baseline.",
            "4. Feed the dictionary fingerprints into blocklists by tool signature rather than by single IP.", ""]
    return "\n".join(out)
