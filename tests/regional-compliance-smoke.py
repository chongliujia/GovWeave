#!/usr/bin/env python3
"""Exercise the EU/US bundle through an isolated server; never use live credentials."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


COUNTS = {
    "eu-ai-act-high-risk-readiness": (3, 2),
    "eu-ai-act-gpai": (3, 2),
    "eu-gdpr-ai": (2, 4),
    "nist-genai-profile": (3, 2),
    "us-ftc-ai-claims": (2, 2),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-directory", type=Path, help="Validate a staged complete catalog instead of only the bundle")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    bundle = json.loads((root / "examples/compliance-bundles/eu-us.json").read_text())
    binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", root / "bin/govweave")).resolve()
    summary = {"synthetic_data": True, "legal_compliance": "not_determined", "packs": []}
    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="govweave-regional-") as directory:
        packs = Path(directory) / "rule-packs"
        if args.pack_directory:
            shutil.copytree(args.pack_directory, packs, symlinks=True)
        else:
            packs.mkdir()
            for entry in bundle["packs"]:
                shutil.copyfile(root / "examples/rule-packs" / entry["file"], packs / entry["file"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        env = {key: value for key, value in os.environ.items() if not key.startswith("GOVWEAVE_")}
        env.update(GOVWEAVE_DATA_DIR=directory, GOVWEAVE_LISTEN_ADDR=f"127.0.0.1:{port}")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def call(path, payload=None):
            headers = {"Origin": origin, "X-GovWeave-Request": "console", "Content-Type": "application/json"}
            request = urllib.request.Request(origin + path, headers=headers, data=None if payload is None else json.dumps(payload).encode())
            try:
                with opener.open(request, timeout=5) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)

        process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("Staged rule-pack catalog rejected at startup")
                try:
                    if call("/healthz")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Server did not start")
            assert call("/api/v1/plugins")[0] == 401
            assert call("/api/v1/auth/setup", {"password": "synthetic regional compliance password"})[0] == 200
            status, plugins = call("/api/v1/plugins")
            assert status == 200
            catalog = {(entry["id"], entry["version"]): entry for entry in plugins["rule_packs"]}
            for entry in bundle["packs"]:
                assert (entry["id"], entry["version"]) in catalog
            for pack_id, (passed, manual) in COUNTS.items():
                status, pack = call(f"/api/v1/compliance/packs/{pack_id}/versions/0.1.0")
                assert status == 200 and pack["review"]["status"] == "draft"
                payload = {"pack_id": pack_id, "pack_version": "0.1.0", "product_id": "synthetic-regional", "product_version": "1.0.0", "facts": {}}

                def fill(expression):
                    if "fact" in expression:
                        payload["facts"][expression["fact"]] = {"value": True, "source": expression["source"], "evidence_id": "synthetic-not-a-real-assessment", "observed_at": (now - timedelta(minutes=1)).isoformat()}
                    for child in expression.get("all", []):
                        fill(child)

                for control in pack["controls"]:
                    fill(control["requirement"])
                    fill(control.get("applies_when", {}))
                stages = []
                for scenario in ("missing", "available", "gaps", "stale", "declared", "outside_scope"):
                    candidate = copy.deepcopy(payload)
                    if scenario == "missing":
                        candidate["facts"] = {}
                    else:
                        for control in pack["controls"]:
                            if control["assessment_method"] == "evidence":
                                fact = candidate["facts"][control["requirement"]["fact"]]
                                if scenario == "gaps":
                                    fact["value"] = False
                                elif scenario == "stale":
                                    fact["observed_at"] = (now - timedelta(days=31)).isoformat()
                                elif scenario == "declared":
                                    fact["source"] = "declared"
                        if scenario == "outside_scope":
                            for key, fact in candidate["facts"].items():
                                if key.startswith("scope."):
                                    fact["value"] = False
                    status, result = call("/api/v1/compliance/evaluations", candidate)
                    assert status == 200 and result["evaluation_only"] and result["legal_compliance"] == "not_determined"
                    assert result["pack_sha256"] == catalog[(pack_id, "0.1.0")]["sha256"]
                    counts = {kind: sum(control["status"] == kind for control in result["controls"]) for kind in ("pass", "fail", "unknown", "not_applicable")}
                    expected = {"pass": 0, "fail": 0, "unknown": passed + manual, "not_applicable": 0}
                    if scenario == "available":
                        expected.update({"pass": passed, "unknown": manual})
                    elif scenario == "gaps":
                        expected.update({"fail": passed, "unknown": manual})
                    elif scenario == "outside_scope":
                        expected.update({"unknown": 1, "not_applicable": passed + manual - 1})
                    assert counts == expected, (pack_id, scenario, counts)
                    assert result["status"] == ("gaps_detected" if scenario == "gaps" else "insufficient_evidence")
                    stages.append({"scenario": scenario, "counts": counts, "evaluation": result})
                summary["packs"].append({"id": pack_id, "version": "0.1.0", "stages": stages})
                print(f"{pack_id}: available={passed} pass/{manual} manual; missing, gaps, stale, declared and scope checks passed")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stderr.close()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as output:
            json.dump(summary, output, ensure_ascii=False, indent=2)
            output.write("\n")
    print("Regional compliance smoke passed: 8 pinned bundle packs, 5 new drafts, 30 synthetic API evaluations; no live data modified.")


if __name__ == "__main__":
    main()
