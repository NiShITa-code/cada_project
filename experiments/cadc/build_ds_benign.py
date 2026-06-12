"""Build a SECOND benign corpus from DATA-SCIENCE / ML repos (cross-domain FP-tax test).

Same mechanical, provenance-tagged extraction as build_real_benign (verbatim CI `run:` steps + Dockerfile
RUN lines), but from data-science/ML projects whose CI legitimately downloads datasets (egress), reads/writes
files, and installs packages — exactly the primitives the behavioral monitor flags. Tests whether the FP-tax
generalizes beyond CI/CD (a finding) to a structural property of autonomous agent work (a law).

Run on a host with network + git. Writes data/benign_ds_corpus.json.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.cadc.build_real_benign import _clean_block, _walk_runs  # noqa: E402  (reuse mechanical extractor)

import yaml  # noqa: E402

SRC = Path("data/benign_sources_ds")
OUT = Path("data/benign_ds_corpus.json")
# data-science / ML repos (CI downloads data, runs notebooks, writes artifacts)
REPOS = [
    "https://github.com/pandas-dev/pandas",
    "https://github.com/scikit-learn/scikit-learn",
    "https://github.com/scipy/scipy",
    "https://github.com/matplotlib/matplotlib",
    "https://github.com/statsmodels/statsmodels",
    "https://github.com/dask/dask",
    "https://github.com/huggingface/datasets",
    "https://github.com/jupyter/notebook",
]


def clone():
    SRC.mkdir(parents=True, exist_ok=True)
    for url in REPOS:
        name = url.rstrip("/").split("/")[-1]
        dst = SRC / name
        if dst.exists():
            print(f"  have {name}"); continue
        print(f"  clone {name} ...")
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", url, str(dst)],
                       capture_output=True, timeout=300)


def extract():
    items = []
    for wf in SRC.glob("*/.github/workflows/*.y*ml"):
        repo = wf.parts[wf.parts.index("benign_sources_ds") + 1]
        try:
            doc = yaml.safe_load(wf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for block in _walk_runs(doc):
            cmd = _clean_block(block)
            if cmd:
                items.append({"command": cmd, "source_repo": repo,
                              "source_file": str(wf.relative_to(SRC)), "kind": "ci_workflow", "domain": "data-science"})
    for df in SRC.glob("**/Dockerfile*"):
        repo = df.parts[df.parts.index("benign_sources_ds") + 1]
        txt = df.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^RUN\s+(.+)$", txt, re.MULTILINE):
            cmd = m.group(1).strip().rstrip("\\").strip()
            if cmd and "${{" not in cmd:
                items.append({"command": cmd, "source_repo": repo,
                              "source_file": str(df.relative_to(SRC)), "kind": "dockerfile", "domain": "data-science"})
    seen, uniq = set(), []
    for it in items:
        if it["command"] not in seen:
            seen.add(it["command"]); uniq.append(it)
    return uniq


def load_ds_benign():
    return json.loads(OUT.read_text())


def main():
    clone()
    items = extract()
    OUT.write_text(json.dumps(items, indent=2))
    from collections import Counter
    print(f"extracted {len(items)} DS benign commands -> {OUT}")
    print("by repo:", dict(Counter(i["source_repo"] for i in items)))


if __name__ == "__main__":
    main()
