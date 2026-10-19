import json
import subprocess
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from iochunter import investigate, parse, report, scenario, sigma

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    d = tmp_path_factory.mktemp("case")
    scenario.generate(d, seed=5)
    return d


@pytest.fixture(scope="module")
def result(case):
    return investigate.investigate(case)


def test_parses_real_openssh_lines():
    df = parse.read_syslog(FIX / "ssh_sample.log", 2015)
    assert len(df) == 400
    assert {"invalid_user", "failed_password", "auth_failure", "reverse_mapping_failed"} <= set(df.action)
    assert df.loc[df.action == "invalid_user", "src_ip"].notna().all()


def test_usernames_with_spaces_crlf_and_year_rollover():
    lines = ["Dec 31 23:59:59 h sshd[1]: Invalid user  0101 from 5.188.10.180\r\n",
             "Jan  1 00:00:01 h sshd[2]: Failed password for invalid user  0101 from 5.188.10.180 port 22 ssh2\n"]
    df = parse.parse_syslog(lines, 2015)
    assert list(df.action) == ["invalid_user", "failed_password_invalid_user"]
    assert list(df.user) == ["0101", "0101"]
    assert df.ts.iloc[1].year == 2016


def test_hostname_rhost_is_not_an_ip():
    df = parse.parse_syslog(["Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 \n",
                             "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=host.example.com \n"])
    assert list(df.src_ip.fillna("none")) == ["218.188.2.4", "none"]


def test_zeek_reader(case):
    conn = parse.read_zeek(case / "zeek" / "conn.log")
    assert {"ts", "orig_h", "resp_h", "resp_p", "orig_bytes"} <= set(conn.columns)
    assert pd.api.types.is_numeric_dtype(conn.orig_bytes)


def _con(rows):
    con = duckdb.connect()
    con.register("t", pd.DataFrame(rows))
    con.execute("CREATE TABLE auth AS SELECT * FROM t")
    return con


def test_sigma_compiler_escapes_values_and_rejects_unknown_fields():
    con = _con([{"action": "x", "message": "it's; DROP TABLE auth; --", "user": "a"}])
    where = sigma.compile_condition("sel", {"sel": {"message|contains": "it's; DROP TABLE auth; --"}}, {"action", "message", "user"})
    assert len(con.execute(f"SELECT * FROM auth WHERE {where}").df()) == 1
    assert con.execute("SELECT count(*) FROM auth").fetchone()[0] == 1
    with pytest.raises(sigma.SigmaError):
        sigma.compile_condition("sel", {"sel": {"nope": 1}}, {"action"})


@pytest.mark.parametrize("cond,expected", [("a and not b", 1), ("1 of sel*", 2), ("all of sel*", 0), ("(a or b) and not c", 2)])
def test_sigma_conditions(cond, expected):
    con = _con([{"action": "x", "user": "u1"}, {"action": "y", "user": "u2"}, {"action": "z", "user": "u3"}])
    sels = {"a": {"action": "x"}, "b": {"action": "y"}, "c": {"user": "u3"}, "sel1": {"action": "x"}, "sel2": {"action": "y"}}
    where = sigma.compile_condition(cond, sels, {"action", "user"})
    assert con.execute(f"SELECT count(*) FROM auth WHERE {where}").fetchone()[0] == expected


def test_every_sigma_rule_compiles_and_has_attack_tags(case):
    con, _ = investigate.load_auth(case / "auth.log", 2026)
    rules = sigma.load_rules(con)
    assert len(rules) >= 7
    for r in rules:
        con.execute(r.sql)
        assert any(t.startswith("attack.t") for t in r.tags), r.name


def test_investigation_recovers_the_intrusion(result):
    sc = result["score"]
    for k in ("ip", "user", "file"):
        assert sc[k]["recall"] == 1.0 and sc[k]["extra"] == [], k
    assert sc["domain"]["recall"] >= 0.9 and sc["domain"]["precision"] == 1.0
    assert sc["stage_recall"] == 1.0


def test_internet_noise_does_not_become_iocs(result):
    noise = {f.entity for f in result["findings"] if f.hunt == "sigma:ssh_bruteforce"} - set(result["iocs"]["ip"])
    assert noise and result["noise_ips_suppressed"] >= len(noise) - 3


def test_ntp_is_not_reported_as_a_high_beacon(result):
    ntp = [f for f in result["findings"] if f.hunt == "beaconing" and f.entity.endswith(":123")]
    assert all(f.severity == "low" for f in ntp)


def test_stix_bundle(result):
    b = investigate.stix_bundle(result, "test")
    assert b["type"] == "bundle" and b["objects"]
    assert all(o["spec_version"] == "2.1" and o["pattern"].startswith("[") for o in b["objects"])


def test_report_and_hallucination_check(result):
    md = report.markdown(result)
    assert "## Indicators of compromise" in md and "T1136.001" in md
    assert report.unknown_indicators("Attacker used 203.0.113.77 and evil-example.top", result) == ["evil-example.top"]


def test_shell_triage_matches_python(case):
    out = subprocess.run(["bash", str(ROOT / "scripts" / "ssh-triage.sh"), str(case / "auth.log")], capture_output=True, text=True, check=True).stdout
    con, _ = investigate.load_auth(case / "auth.log", 2026)
    n, srcs = con.execute("""SELECT count(*), count(DISTINCT src_ip) FROM auth WHERE src_ip IS NOT NULL AND action IN
        ('failed_password','failed_password_invalid_user','invalid_user','auth_failure')""").fetchone()
    assert f"failed auth events : {n}" in out and f"failing sources    : {srcs}" in out
    assert "!! 203.0.113.77" in out


def test_collector_writes_verifiable_manifest(tmp_path):
    subprocess.run(["bash", str(ROOT / "scripts" / "collect.sh"), str(tmp_path)], capture_output=True, text=True, check=True, timeout=300)
    bundle = next(tmp_path.glob("*.tar.gz"))
    folder = next(p for p in tmp_path.iterdir() if p.is_dir())
    assert (folder / "MANIFEST.sha256").exists() and (folder / "processes.txt").exists()
    check = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"], cwd=folder, capture_output=True, text=True)
    assert check.returncode == 0, check.stdout[-500:]
    assert json.dumps(str(bundle))
