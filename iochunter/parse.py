"""Parsers for the log formats an investigation on a Linux host usually starts from.

* syslog-style auth logs (OpenSSH, PAM, su, cron, useradd) -> one row per line with
  normalized fields: ts, host, program, pid, action, user, src_ip, src_port, message
* Zeek conn.log / dns.log (TSV with #fields header) -> DataFrames

Syslog lines carry no year. `base_year` is applied to the first line and the year
rolls forward whenever the month goes backwards (Dec -> Jan).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pandas as pd

SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
                    r"(?P<prog>[^\[:\s]+(?:\([^)]*\))?)(?:\[(?P<pid>\d+)\])?:? (?P<msg>.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})"

# (action, regex) in priority order; first match wins
PATTERNS = [
    ("accepted_password", re.compile(rf"Accepted password for (?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("accepted_publickey", re.compile(rf"Accepted publickey for (?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("failed_password_invalid_user", re.compile(rf"Failed password for invalid user ?(?P<user>.*?) from {IP} port (?P<port>\d+)")),
    ("failed_password", re.compile(rf"Failed password for (?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("invalid_user", re.compile(rf"Invalid user ?(?P<user>.*?) from {IP}(?: port (?P<port>\d+))?")),
    ("auth_failure", re.compile(r"authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("reverse_mapping_failed", re.compile(rf"reverse mapping checking getaddrinfo for \S+ \[{IP}\] failed - POSSIBLE BREAK-IN ATTEMPT")),
    ("too_many_failures", re.compile(rf"(?:Disconnecting: Too many authentication failures|error: maximum authentication attempts exceeded) for (?:invalid user )?(?P<user>\S+) from {IP}")),
    ("no_identification", re.compile(rf"Did not receive identification string from {IP}")),
    ("disconnect", re.compile(rf"Received disconnect from {IP}(?: port (?P<port>\d+))?")),
    ("connection_closed", re.compile(rf"Connection closed by {IP}(?: port (?P<port>\d+))?")),
    ("session_opened", re.compile(r"session opened for user (?P<user>\S+)")),
    ("session_closed", re.compile(r"session closed for user (?P<user>\S+)")),
    ("user_added", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("sudo_command", re.compile(r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$")),
    ("cron_command", re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.+)\)$")),
    ("ftp_connection", re.compile(rf"connection from {IP}")),
]


def _valid_ip(s: str | None) -> str | None:
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None  # hostnames in rhost= are kept in the message, not as IPs


def parse_syslog(lines, base_year: int = 2000) -> pd.DataFrame:
    rows, year, last_month = [], base_year, None
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        m = SYSLOG.match(line)
        if not m:
            continue
        mon = MONTHS[m["mon"]]
        if last_month is not None and mon < last_month:
            year += 1
        last_month = mon
        msg = m["msg"]
        action, user, ip, port, cmd = "other", None, None, None, None
        for name, rx in PATTERNS:
            p = rx.search(msg)
            if p:
                g = p.groupdict()
                action, user, ip, port, cmd = name, g.get("user"), g.get("ip"), g.get("port"), g.get("cmd")
                break
        rows.append(dict(line_no=n, ts=pd.Timestamp(f"{year}-{mon:02d}-{int(m['day']):02d} {m['time']}", tz="UTC"),
                         host=m["host"], program=re.sub(r"\(.*\)", "", m["prog"]), pid=int(m["pid"]) if m["pid"] else None,
                         action=action, user=(user or "").strip() or None,  # attackers send usernames with spaces
                         src_ip=_valid_ip(ip), src_port=int(port) if port else None,
                         command=cmd, message=msg))
    return pd.DataFrame(rows)


def read_syslog(path: str | Path, base_year: int = 2000) -> pd.DataFrame:
    with open(path, errors="replace") as fh:
        return parse_syslog(fh, base_year)


def read_zeek(path: str | Path) -> pd.DataFrame:
    """Zeek TSV log: '#fields' header, '-' for unset, '(empty)' for empty sets."""
    fields, rows = None, []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#"):
                rows.append(line.split("\t"))
    if fields is None:
        raise ValueError(f"{path}: no #fields header")
    df = pd.DataFrame(rows, columns=fields).replace({"-": None, "(empty)": None})
    df["ts"] = pd.to_datetime(df["ts"].astype(float), unit="s", utc=True)
    for c in ("duration", "orig_bytes", "resp_bytes", "id.orig_p", "id.resp_p", "orig_pkts", "resp_pkts"):
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df.rename(columns={"id.orig_h": "orig_h", "id.orig_p": "orig_p", "id.resp_h": "resp_h", "id.resp_p": "resp_p"})
