"""iochunter investigate CASE_DIR [--out OUT] [--base-year 2026]
iochunter scenario OUT_DIR [--seed 11] [--dga random|dictionary]
iochunter loghub SSH.log [--out OUT]
iochunter evaluate [--cases 20]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import evaluate, investigate, loghub, report, scenario


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="iochunter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("investigate"); i.add_argument("case"); i.add_argument("--out"); i.add_argument("--base-year", type=int, default=2026)
    s = sub.add_parser("scenario"); s.add_argument("out"); s.add_argument("--seed", type=int, default=11)
    s.add_argument("--dga", choices=["random", "dictionary"], default="random")
    lh = sub.add_parser("loghub"); lh.add_argument("log"); lh.add_argument("--out", default="results/loghub")
    e = sub.add_parser("evaluate"); e.add_argument("--cases", type=int, default=20); e.add_argument("--out", default="results")
    a = ap.parse_args(argv)

    if a.cmd == "scenario":
        t = scenario.generate(Path(a.out), a.seed, a.dga)
        print(f"wrote {a.out}: {len(t['iocs']['ip'])} attacker IPs, {len(t['iocs']['domain'])} domains, {len(t['stages'])} stages")
    elif a.cmd == "investigate":
        r = investigate.investigate(Path(a.case), a.base_year)
        out = Path(a.out or Path(a.case) / "report"); out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(report.markdown(r))
        (out / "findings.json").write_text(json.dumps(investigate.to_jsonable(r), indent=2))
        (out / "iocs.stix.json").write_text(json.dumps(investigate.stix_bundle(r, str(a.case)), indent=2))
        (out / "blocklist.txt").write_text("\n".join(sorted(r["iocs"]["ip"]) + sorted(r["iocs"]["domain"])) + "\n")
        hi = sum(1 for f in r["findings"] if f.severity in ("high", "critical"))
        print(f"{len(r['findings'])} findings ({hi} high/critical), {sum(len(v) for v in r['iocs'].values())} IOCs -> {out}")
        if "score" in r:
            sc = r["score"]
            print("score: " + ", ".join(f"{k} {sc[k]['found']}/{sc[k]['expected']} (+{len(sc[k]['extra'])})" for k in ("ip", "domain", "user", "file"))
                  + f", stages {sum(x['detected'] for x in sc['stages'])}/{len(sc['stages'])}")
    elif a.cmd == "loghub":
        h = loghub.hunt(Path(a.log))
        out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
        (out / "hunt-notes.md").write_text(loghub.notes(h))
        js = {k: (v.to_dict("records") if hasattr(v, "to_dict") else v) for k, v in h.items() if k != "neighbours"}
        (out / "hunt.json").write_text(json.dumps(js, indent=2, default=str))
        print(f"wrote {out}/hunt-notes.md")
    elif a.cmd == "evaluate":
        res = evaluate.run(a.cases)
        Path(a.out).mkdir(exist_ok=True)
        (Path(a.out) / "evaluation.json").write_text(json.dumps(res, indent=2))
        for fam, r in res.items():
            print(fam, {k: (v["recall"], v["precision"]) for k, v in r["iocs"].items()}, "stages", min(r["stage_detection"].values()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
