"""Incident report: timeline, ATT&CK mapping, IOCs, containment, and the detections
this case says should exist. Optional Gemini executive summary, checked so it cannot
mention an IP, domain or account that is not in the evidence."""
from __future__ import annotations

import os
import re

from .investigate import LEVEL_RANK, TECHNIQUE_NAMES

CONTAINMENT = {
    "brute_force_then_success": "Reset the password of the compromised account, revoke its SSH keys and sessions, and disable password authentication for SSH.",
    "linked_bruteforce_sources": "Block the linked brute-force sources at the firewall alongside the source that got in.",
    "sigma:sudo_download_execute": "Remove the downloaded files, review sudo rights for the account, and block the download domain at DNS.",
    "stager_download": "Sinkhole the stager domain and block its IP at egress.",
    "sigma:linux_uid0_account": "Lock and remove the UID-0 account after imaging the host; diff /etc/passwd and /etc/shadow against the last known-good copy.",
    "backdoor_account_login": "Remove attacker SSH keys from every authorized_keys file and block the source IP.",
    "sigma:cron_hidden_binary": "Remove the cron entry and the binary after collecting a copy and its hash for analysis.",
    "beaconing": "Block the destination at egress and confirm the process holding the connection is gone.",
    "dga_lookups": "Sinkhole the generated domains and alert on further NXDOMAIN bursts from this host.",
    "large_upload": "Block the destination, estimate what data was readable by the compromised accounts, and start breach assessment.",
    "multi_account_source": "Confirm with the account owners whether this source is a shared gateway; if not, reset the affected accounts.",
}
NEW_DETECTIONS = [
    ("Brute force followed by success from the same source", "Sequence over auth logs: >= 20 failures then an accepted login from that IP within 24 h"),
    ("UID-0 account creation", "Sigma rule linux_uid0_account (already in sigma/)"),
    ("Download-and-execute through sudo", "Sigma rule sudo_download_execute; add the domain to an allow-list review"),
    ("Timer-driven egress", "Inter-arrival coefficient of variation < 0.15 over >= 30 connections to one destination"),
    ("NXDOMAIN burst from a server", "Servers rarely look up names that do not exist; alert on >= 10 NXDOMAIN per hour per host"),
    ("Large upload to a first-seen destination", ">= 100 MB outbound to a destination contacted <= 3 times"),
]


def _ts(t):
    return t.strftime("%Y-%m-%d %H:%M") if t is not None else "-"


def executive_summary(result: dict, api_key: str | None = None) -> tuple[str, str]:
    """Return (summary, mode). With a key, Gemini drafts it; any IP, domain or user it
    mentions must appear in the IOCs or findings, otherwise the template is used."""
    sev = [f for f in result["findings"] if LEVEL_RANK[f.severity] >= 3]
    first = min((f.first_seen for f in sev), default=None)
    by = {}
    for f in sev:
        by.setdefault(f.hunt, f)
    parts = []
    if "brute_force_then_success" in by:
        f = by["brute_force_then_success"]
        parts.append(f"An attacker guessed the SSH password of '{f.iocs['user'][0]}' from {f.entity} at {_ts(f.last_seen)}")
    if "stager_download" in by:
        parts.append(f"then used sudo to download and run a script from {by['stager_download'].entity}")
    persist = [h for h in ("sigma:linux_uid0_account", "sigma:cron_hidden_binary") if h in by]
    if persist:
        parts.append("and installed persistence (" + ", ".join({"sigma:linux_uid0_account": "a root-equivalent account",
                                                                "sigma:cron_hidden_binary": "a cron job running a hidden binary"}[h] for h in persist) + ")")
    lead = (", ".join(parts) + ".") if parts else f"{len(sev)} high or critical findings were raised."
    impact = []
    if "beaconing" in by:
        impact.append(f"The host then beaconed to {by['beaconing'].entity} on a fixed timer, consistent with a cryptominer")
    if "large_upload" in by:
        impact.append(f"and uploaded {by['large_upload'].summary.split(' sent')[0]} to {by['large_upload'].entity}")
    if "dga_lookups" in by:
        impact.append("while resolving algorithmically generated domains as fallback command and control")
    template = (f"Between {_ts(first)} and {_ts(max((f.last_seen for f in sev), default=None))} UTC: {lead} "
                + (" ".join(impact) + "." if impact else "")
                + (" The attacker later returned through the backdoor account." if "backdoor_account_login" in by else ""))
    key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
    if not key:
        return template, "template"
    try:
        from google import genai
        client = genai.Client(api_key=key)
        facts = "\n".join(f"- [{f.severity}] {f.hunt} {f.technique}: {f.summary} ({_ts(f.first_seen)} to {_ts(f.last_seen)})" for f in sev)
        text = client.models.generate_content(
            model=os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite"),
            contents="Write a 4-sentence executive summary of this security incident for a director. Use only these facts; "
                     "do not speculate about attribution.\n" + facts).text.strip()
    except Exception as e:  # quota, network
        return template, f"template (llm error: {type(e).__name__})"
    unknown = unknown_indicators(text, result)
    if unknown:
        return template, f"template (llm mentioned unknown indicators: {unknown[:3]})"
    return text, "llm"


def unknown_indicators(text: str, result: dict) -> list[str]:
    """IPs and domains in `text` that appear in no IOC and no finding: a hallucination check."""
    known = {v for items in result["iocs"].values() for v in items}
    blob = " ".join(f.summary for f in result["findings"])
    mentioned = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:top|xyz|info|com|net|org|biz)\b", text))
    return sorted(m for m in mentioned if m not in known and m not in blob)


def markdown(result: dict, title: str = "Incident report") -> str:
    summary, mode = executive_summary(result)
    incident_ips = set(result["iocs"]["ip"])
    f_sorted = [f for f in result["findings"] if LEVEL_RANK[f.severity] >= 3
                or (LEVEL_RANK[f.severity] == 2 and set(f.iocs.get("ip", [])) & incident_ips)]
    background = [f for f in result["findings"] if LEVEL_RANK[f.severity] == 2 and f not in f_sorted]
    techs = sorted({t.strip() for f in f_sorted for t in f.technique.split("/") if t.strip()})
    out = [f"# {title}", "", f"_Case: `{result['case']}` · {result['events']:,} auth events · summary by {mode}_", "",
           "## Executive summary", "", summary, "", "## Timeline (medium and above)", "", "| First seen (UTC) | Severity | Finding | ATT&CK |", "|---|---|---|---|"]
    for f in f_sorted:
        out.append(f"| {_ts(f.first_seen)} | {f.severity} | {f.summary.replace('|', '/')[:170]} | {f.technique} |")
    if background:
        out.append(f"\nBackground: {len(background)} medium findings not linked to this incident "
                   f"({len({f.entity for f in background})} unrelated sources brute-forcing SSH). Listed in findings.json.")
    out += ["", "## ATT&CK techniques observed", ""] + [f"- **{t}** {TECHNIQUE_NAMES.get(t, '')}" for t in techs]
    out += ["", "## Indicators of compromise", "", "| Type | Value | First seen | Raised by |", "|---|---|---|---|"]
    for kind, items in result["iocs"].items():
        for e in sorted(items.values(), key=lambda e: str(e["first_seen"])):
            out.append(f"| {kind} | `{e['value']}` | {_ts(e['first_seen'])} | {', '.join(sorted(e['sources']))} |")
    steps = list(dict.fromkeys(CONTAINMENT[f.hunt] for f in f_sorted if f.hunt in CONTAINMENT))
    out += ["", "## Containment and eradication", ""] + [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    out += ["", "## Detections to keep", "", "| Detection | Logic |", "|---|---|"] + [f"| {a} | {b} |" for a, b in NEW_DETECTIONS]
    if "score" in result:
        sc = result["score"]
        out += ["", "## Scored against ground truth", "", "| IOC type | Found / expected | Extra |", "|---|---|---|"]
        for k in ("ip", "domain", "user", "file"):
            out.append(f"| {k} | {sc[k]['found']} / {sc[k]['expected']} | {len(sc[k]['extra'])} |")
        out.append(f"\nAttack stages detected: {sum(s['detected'] for s in sc['stages'])} / {len(sc['stages'])}")
    return "\n".join(out) + "\n"
