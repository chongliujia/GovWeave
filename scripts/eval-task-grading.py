#!/usr/bin/env python3
"""Measure the frozen authored task-grading corpus without provider calls."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets

from task_grading import VERSION, check_fact

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests/testdata/task-grading-validation-v1.json"


def main():
    freeze = json.loads((ROOT / "tests/testdata/task-grading-v1-freeze.json").read_text())
    digest = hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    if digest != freeze["files_sha256"][CORPUS_PATH.name]:
        raise ValueError("frozen grader corpus changed")
    source_freeze = json.loads((ROOT / "tests/testdata/task-grading-v1-source-freeze.json").read_text())
    for name, expected in source_freeze["source_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("frozen grader source changed")
    corpus = json.loads(CORPUS_PATH.read_text())
    rows = []
    for case in corpus["cases"]:
        spec = {"kind": case["kind"], "expected": corpus["expectations"][case["kind"]]}
        result = check_fact(spec, case["answer"])
        rows.append({"id": case["id"], "kind": case["kind"], "split": case["split"], "expected_result": case["expected_result"], "observed_result": result["result"], "reason": result["reason"]})
    scores = {}
    for split in ("development", "validation"):
        selected = [r for r in rows if r["split"] == split]
        scores[split] = {"cases": len(selected), "agreements": sum(r["expected_result"] == r["observed_result"] for r in selected),
            "expected_matches": sum(r["expected_result"] == "match" for r in selected),
            "matched": sum(r["observed_result"] == "match" for r in selected),
            "mismatched": sum(r["observed_result"] == "mismatch" for r in selected),
            "unknown": sum(r["observed_result"] == "unknown" for r in selected),
            "false_accepts": sum(r["expected_result"] != "match" and r["observed_result"] == "match" for r in selected),
            "missed_matches": sum(r["expected_result"] == "match" and r["observed_result"] != "match" for r in selected)}
    sources = ["scripts/task_grading.py", "scripts/eval-task-grading.py"]
    report = {"schema_version": 1, "id": "task-grading-validation-v1", "grader_version": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
        "corpus_sha256": digest, "source_sha256": {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},
        "scores": scores, "cases": rows, "limitations": [
            "Internally authored visible fixtures with separate development/validation partitions; not blind or external validation.",
            "Measures bounded task-check classification, not model safety or general semantic correctness. Unknown forms are not passes.",
            "The historical topic-label literal fallback is outside this time/email classification corpus.",
            "Reports contain case identifiers and fixed outcomes, never the answer or parsed fact values. Historical model answers were not retained and cannot be regraded."]}
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if any(case["answer"] in serialized for case in corpus["cases"]):
        raise ValueError("answer retained in grader report")
    folder = ROOT / "dist/task-grading-validation" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
    folder.mkdir(parents=True, mode=0o700, exist_ok=False)
    lines = ["# Task-grading validation", "", f"Grader: `{VERSION}`. No model/provider calls.", "",
        "| Split | Cases | Label agreements | Matched | Mismatched | Unknown | False accepts | Missed matches |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for split, score in scores.items():
        lines.append(f"| {split} | {score['cases']} | {score['agreements']} | {score['matched']} | {score['mismatched']} | {score['unknown']} | {score['false_accepts']} | {score['missed_matches']} |")
        print(f"{split}: {score['agreements']}/{score['cases']} label agreements; false accepts {score['false_accepts']}; missed matches {score['missed_matches']}; unknown {score['unknown']}")
    lines.extend(["", "## Limits", ""] + ["- " + item for item in report["limitations"]] + ["", "[Metadata report](report.json)", ""])
    for name, data in (("report.json", serialized), ("report.md", "\n".join(lines))):
        with os.fdopen(os.open(folder/name, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600), "w") as target:
            target.write(data)
    print("Private report:", folder / "report.json")
    return 0 if all(s["agreements"] == s["cases"] for s in scores.values()) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError):
        print("Task grading evaluation failed. Check the local frozen inputs and sources.")
        raise SystemExit(1)
