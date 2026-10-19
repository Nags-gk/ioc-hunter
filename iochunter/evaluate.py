"""Score the investigation over many generated intrusions.

Seeds vary attack timing, brute-force volume, background internet noise and the DGA
domains. Half the cases use a dictionary DGA the classifier never saw in training, to
show where the domain hunt breaks down.
"""
from __future__ import annotations

import tempfile
from collections import defaultdict
from pathlib import Path

from . import investigate, scenario


def run(n: int = 20) -> dict:
    per_family = {}
    for family in ("random", "dictionary"):
        agg, stages, cases = defaultdict(lambda: [0, 0, 0]), defaultdict(lambda: [0, 0]), 0
        for seed in range(1, n // 2 + 1):
            with tempfile.TemporaryDirectory() as d:
                case = Path(d)
                scenario.generate(case, seed + (0 if family == "random" else 1000), family)
                sc = investigate.investigate(case)["score"]
            cases += 1
            for k in ("ip", "domain", "user", "file"):
                agg[k][0] += sc[k]["found"]; agg[k][1] += sc[k]["expected"]; agg[k][2] += sc[k]["found"] + len(sc[k]["extra"])
            for s in sc["stages"]:
                stages[s["stage"]][0] += s["detected"]; stages[s["stage"]][1] += 1
        per_family[family] = dict(
            cases=cases,
            iocs={k: dict(recall=round(tp / exp, 4), precision=round(tp / got, 4) if got else None, found=tp, expected=exp)
                  for k, (tp, exp, got) in agg.items()},
            stage_detection={k: round(a / b, 4) for k, (a, b) in stages.items()})
    return per_family
