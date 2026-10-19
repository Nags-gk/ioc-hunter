"""Stage results for the GitHub Pages dashboard."""
import json
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent.parent
data = root / "web" / "data"
data.mkdir(parents=True, exist_ok=True)
for src, dst in [("results/case/findings.json", "case.json"), ("results/evaluation.json", "evaluation.json"),
                 ("results/loghub/hunt.json", "loghub.json"), ("results/case/report.md", "report.md"),
                 ("results/loghub/hunt-notes.md", "hunt-notes.md"), ("examples/case-web01/ground_truth.json", "truth.json")]:
    shutil.copy(root / src, data / dst)
case = json.loads((data / "case.json").read_text())
case.pop("dga", None)
(data / "case.json").write_text(json.dumps(case))
print("web/data ready")
