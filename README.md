# IOC Hunter

**Hypothesis-driven threat hunting and incident response for Linux servers.** IOC Hunter
parses auth logs and Zeek network logs, runs Sigma rules compiled to DuckDB SQL, runs
sequence and statistical hunts the rules cannot express (brute force *then* success,
beacon timing, DGA lookups, exfil volume, campaign linkage), and turns the results into
an incident report, a STIX 2.1 IOC bundle and a blocklist. Shell scripts handle the
parts of an investigation that happen on the box itself: first-look triage with
grep/awk, and read-only evidence collection with a SHA-256 manifest.

**Dashboard: https://nags-gk.github.io/ioc-hunter/** · [Sigma rules](sigma/) ·
[Incident report](results/case/report.md) · [Real-server hunt notes](results/loghub/hunt-notes.md)

[![CI](https://github.com/Nags-gk/ioc-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Nags-gk/ioc-hunter/actions/workflows/ci.yml)

## Two investigations

### 1. A real internet-facing server (no ground truth)

[Loghub's OpenSSH dataset](https://github.com/logpai/loghub): 655,147 lines from a real lab
server over 28 days. CI downloads it and checks its SHA-256 on every run.
[Full hunt notes](results/loghub/hunt-notes.md).

| Hypothesis | Result |
|---|---|
| A brute-forcing source got in | **Not supported.** 367,393 failed attempts from 1,011 sources (86% on `root`), 182 successful logins. No source with 20+ failures ever logged in; the few successful sources with any failures had at most 13, almost all on the account they then logged into. |
| Credentials are shared or stolen | **Two leads.** `183.62.156.108` logged in to three different accounts after two failed `root` attempts, and sits in the same /16 as one of the heaviest brute-force sources (22,115 failures). `137.189.88.215` also logged in to three accounts. Both may be a shared campus gateway; the next step needs the account owners. |
| The noise is a few operators, not a thousand IPs | **Supported.** 8 groups of sources replayed identical username dictionaries, e.g. 8 sources each made exactly 122 attempts from the same 18-name list. Blocking by tool signature beats blocking single IPs. |

### 2. A labeled intrusion (scored)

A generator writes three days of real-format logs for one web server (`auth.log`, Zeek
`conn.log` and `dns.log`) with background traffic and internet brute-force noise, plus one
intrusion: SSH brute force and a valid login → sudo download-and-execute of a stager →
UID-0 backdoor account and cron persistence → cryptominer beaconing every ~60 s → DGA
lookups → a 452 MB night-time upload → the attacker returns through the backdoor.
[Generated incident report](results/case/report.md).

| Over 20 generated cases | Random-character DGA (10) | Dictionary DGA, unseen in training (10) |
|---|---:|---:|
| Attack stages detected | 100% | 100% |
| Attacker IPs: recall / precision | 100% / 100% | 100% / 100% |
| Malicious domains: recall / precision | 98.9% / 100% | **49.6%** / 100% |
| Compromised accounts and dropped files | 100% | 100% |

The dictionary-DGA row is the honest weak spot: a character-n-gram model trained on
random-looking domains catches only about half of word-based generated domains. NXDOMAIN
rate is the signal that still separates them; a per-host NXDOMAIN-burst rule is listed as
the next detection to build. The scenario is self-written, so these numbers show the
pipeline works end to end, not how it would score on someone else's intrusion.

## What is in it

| Piece | What it does |
|---|---|
| `iochunter/parse.py` | syslog auth parser (sshd, PAM, sudo, useradd, cron) with year rollover; Zeek TSV reader |
| `sigma/` + `iochunter/sigma.py` | 7 Sigma rules (ATT&CK-tagged) and a Sigma-to-DuckDB compiler: selections, modifiers (`contains`, `startswith`, `endswith`, `re`, `all`), `1 of sel*` conditions, and `event_count` correlation rules. Values are escaped and field names checked against the schema, so a rule file cannot inject SQL |
| `iochunter/hunts.py` | brute force then success, same-campaign source linkage (username-set Jaccard within 90 min), backdoor-account login, multi-account sources, dictionary fingerprints, beaconing (inter-arrival coefficient of variation), DGA lookups, stager resolution, large uploads to rare destinations |
| `iochunter/dga.py` | scikit-learn char 2-4-gram TF-IDF + logistic regression with entropy features; evaluated on a held-out family |
| `iochunter/investigate.py` | runs everything, consolidates IOCs (internet noise kept out), scores against ground truth, exports STIX 2.1 |
| `iochunter/report.py` | incident report: summary, timeline, ATT&CK mapping, IOCs, containment steps, detections to keep. Optional Gemini summary, rejected if it names an indicator absent from the evidence |
| `scripts/ssh-triage.sh` | grep/awk triage for a live box; a test asserts its counts match the Python parser |
| `scripts/collect.sh` | read-only live-response collection (volatile state first), SHA-256 manifest and hashed tarball for chain of custody |

## Engineering notes

* **Two parsers keep each other honest.** The shell triage and the Python parser first
  disagreed on the real log in two ways. The shell counted 1,671 sources instead of 1,011
  because part of the log has CRLF line endings, so `1.2.3.4\r` and `1.2.3.4` looked
  different. Python missed 378 attempts because attackers send usernames containing spaces
  (`Invalid user  0101 from ...`), which the regex did not allow. Both are fixed, and a test
  now requires the two to agree.
* **The DGA model alone flagged `login.microsoftonline.com`.** High-severity DGA findings now
  require both a high score and NXDOMAIN; resolving high scorers become low-severity review
  items that never turn into IOCs.
* **Noise vs. incident.** Every internet-facing server is brute-forced all day. Sources that
  only failed are reported as background, and become IOCs only when linked to the source
  that got in (same usernames, same 90-minute window).

## Run it

```bash
pip install -e .
iochunter scenario examples/my-case --seed 7          # generate a labeled intrusion
iochunter investigate examples/my-case                 # report.md, findings.json, iocs.stix.json, blocklist.txt
iochunter loghub "$(scripts/fetch_loghub.sh data | tail -1)"   # hunt the real server log
iochunter evaluate --cases 20                          # score over generated intrusions
scripts/ssh-triage.sh /var/log/auth.log                # on a live Linux host
sudo scripts/collect.sh /mnt/evidence                  # read-only collection with manifest
pytest -q
```

## Limitations
* Auth logs and Zeek only; no EDR, process or file-system telemetry.
* Hunts run in batch over a case folder, not as a streaming service.
* The labeled scenario is mine, so its scores measure the pipeline, not real-world recall.

## Data credit
Real-server data: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu,
"Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics", ISSRE 2023.

## License
MIT
