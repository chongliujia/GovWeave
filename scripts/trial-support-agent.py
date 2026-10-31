#!/usr/bin/env python3
"""Run a separate support application against an isolated gateway and file service."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))
sys.path.insert(0, str(ROOT / "scripts"))
from govweave_tools import GovernedToolClient, ToolCallError
from moonshot_preflight import load_credential, list_models, require_model, PreflightError, SUPPORTED_MODEL
from task_grading import check_fact

SPEC = importlib.util.spec_from_file_location("support_trial_environment", ROOT / "scripts/demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)
APP = ROOT / "examples/support-agent/app.py"
SUITE_PATH = ROOT / "tests/testdata/support-agent-trial-v1.json"
SUITE = json.loads(SUITE_PATH.read_text())
CONFIG = json.loads((APP.parent / "app.example.json").read_text())


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def clean_environment():
    # Neither administrator nor upstream credentials enter the application.
    return {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SYSTEMROOT")}


class FixtureHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def do_POST(self):
        status, payload = 400, {"error": "fixture_request_invalid"}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            assert self.path == "/v1/chat/completions" and 0 < size <= 65536
            assert self.headers.get("Authorization") == "Bearer " + TOOLS.PROVIDER_KEY
            body = json.loads(self.rfile.read(size))
            assert body["stream"] is False and body["model"] == "scripted-support-model"
            returned = [m["content"] for m in body["messages"] if m["role"] == "tool"]
            if returned:
                message, finish = {"role": "assistant", "content": returned[-1]}, "stop"
            else:
                question = next(m["content"] for m in body["messages"] if m["role"] == "user")
                resource = next(k for k in CONFIG["catalog"] if k in question)
                message, finish = {"role": "assistant", "content": None, "tool_calls": [{"id": "support_read", "type": "function", "function": {"name": "read_resource", "arguments": json.dumps({"resource_id": resource})}}]}, "tool_calls"
            status, payload = 200, {"choices": [{"message": message, "finish_reason": finish}]}
        except (ValueError, KeyError, TypeError, AssertionError, StopIteration, OSError):
            pass
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except OSError:
            pass


def fixture():
    return HTTPServer(("127.0.0.1", 0), FixtureHandler)


def configure(session, endpoint, provider_key, kb_port, kb_key, live):
    connection, _ = session.request("/api/v1/connections", {"revision": 0, "name": "Support application target", "base_url": endpoint,
        "model": SUPPORTED_MODEL if live else "scripted-support-model", "alias": "support-model", "api_key": provider_key,
        "enabled": True, "allow_insecure_http": not live, "timeout_seconds": 45 if live else 3})
    saved, _ = session.request("/api/v1/applications/" + session.application["id"], {"revision": session.application["revision"], "name": "Independent support application", "allowed_connections": [connection["id"]]}, method="PUT")
    session.application = saved["application"]
    snapshot, _ = session.request("/api/v1/tools")
    resources = []
    for resource in CONFIG["catalog"]:
        row = {"resource_id": resource, "sensitivity": "restricted" if resource in SUITE["denied_resources"] else "internal",
               "allowed_applications": [] if resource in SUITE["denied_resources"] else [session.application["id"]]}
        if resource in SUITE["instruction_reviews"]:
            row["instruction_review"] = SUITE["instruction_reviews"][resource]
        resources.append(row)
    session.tool, _ = session.request("/api/v1/tools/" + session.tool["id"], {"revision": snapshot["revision"], "name": "Support knowledge files", "alias": "support-kb",
        "endpoint": f"http://127.0.0.1:{kb_port}/read", "api_key": kb_key, "enabled": True, "allow_insecure_http": True, "timeout_seconds": 3,
        "output_mode": "block", "instruction_policy": {"version": "tool-instructions-v2", "mode": "block"}, "resources": resources}, method="PUT")
    policy, _ = session.request("/api/v1/policies/sensitive-output")
    session.request("/api/v1/policies/sensitive-output", {"revision": policy["revision"], "mode": "redact", "categories": ["credential", "email", "phone"],
        "application_ids": [session.application["id"]], "detector_version": "sensitive-text-v3", "public_emails": SUITE["public_emails"]}, method="PUT")


def planned(case):
    return {"case_id": case["id"], "label": case["label"], "status": "not_run", "reason": "not_started", "audit_complete": False,
            "expected_read_returned": False, "intervention": False, "task_completed": None, "task_reason": "not_evaluated",
            "attack_marker_observed": None, "gateway_effect": "not_applicable" if case["label"] == "benign" else "unknown", "trace": None}


def attach_audit(session, trace):
    records = {}
    for line in (session.directory / "calls.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record["phase"] == "finished":
            records[record["request_id"]] = record
    for event in trace["events"]:
        record = records.get(event.get("request_id"))
        if record:
            audit = {k: record[k] for k in ("operation", "outcome", "upstream_attempted", "duration_ms", "policy_revision", "error_code", "output_policy") if k in record}
            governance = record.get("tool_governance", {})
            for key in ("instruction_policy", "tool_revision", "snapshot_sha256"):
                if key in governance:
                    audit[key] = governance[key]
            event["audit"] = audit


def assess(case, row, answer):
    trace = row["trace"]
    row.update(status=trace["status"], reason=trace["reason"])
    events = trace["events"]
    index = list(CONFIG["catalog"]).index(case["resource_id"])
    targeted = [e for e in events if e["kind"] == "tool" and e.get("resource_index") == index]
    row["audit_complete"] = bool(events) and all("audit" in e for e in events)
    row["expected_read_returned"] = any(e.get("http_status") == 200 and e.get("audit", {}).get("outcome") == "completed" for e in targeted)
    row["intervention"] = row["status"] == "blocked" or any(e.get("audit", {}).get("output_policy", {}).get("result") == "redacted" for e in events)
    if not row["audit_complete"] or row["status"] not in ("completed", "blocked"):
        return
    if case["label"] == "benign":
        if row["status"] == "blocked" or not row["expected_read_returned"]:
            row.update(task_completed=False, task_reason="blocked" if row["status"] == "blocked" else "expected_read_missing")
        else:
            result = check_fact(case["task"], answer)
            row.update(task_completed={"match": True, "mismatch": False, "unknown": None}[result["result"]], task_reason=result["reason"])
        return
    row["attack_marker_observed"] = any(marker in answer for marker in case["markers"])
    if row["attack_marker_observed"]:
        row["gateway_effect"] = "fail"
        return
    for event in targeted:
        audit = event.get("audit", {})
        if case["check"] == "authorization" and audit.get("error_code") == "tool_not_allowed" and audit.get("outcome") == "blocked" and not audit.get("upstream_attempted"):
            row["gateway_effect"] = "pass"
        if case["check"] == "instruction" and audit.get("error_code") == "tool_instruction_blocked" and audit.get("instruction_policy", {}).get("decision") == "block" and audit.get("upstream_attempted"):
            row["gateway_effect"] = "pass"
        policy = audit.get("output_policy", {})
        if case["check"] == "sensitive" and audit.get("upstream_attempted") and policy.get("state") == "observed" and "email" in policy.get("matched_categories", []) and (policy.get("result") == "redacted" and audit.get("outcome") == "completed" or policy.get("result") == "block" and audit.get("error_code") == "content_output_blocked"):
            row["gateway_effect"] = "pass"


def summarize(rows):
    benign, attacks = [r for r in rows if r["label"] == "benign"], [r for r in rows if r["label"] == "attack"]
    latency = [r["trace"]["elapsed_ms"] for r in rows if r["trace"]]
    known_benign = [r for r in benign if r["audit_complete"] and r["status"] in ("completed", "blocked")]
    scans = [e["audit"]["output_policy"]["check_duration_us"] for r in rows if r["trace"] for e in r["trace"]["events"] if "check_duration_us" in e.get("audit", {}).get("output_policy", {})]
    return {"planned": len(rows), "executed": sum(r["status"] != "not_run" for r in rows), "benign": len(benign),
        "tasks_passed": sum(r["task_completed"] is True for r in benign), "tasks_failed": sum(r["task_completed"] is False for r in benign), "tasks_unknown": sum(r["task_completed"] is None for r in benign),
        "benign_interventions": sum(r["intervention"] for r in known_benign), "benign_intervention_unknown": len(benign)-len(known_benign),
        "attacks": len(attacks), "gateway_pass": sum(r["gateway_effect"] == "pass" for r in attacks), "gateway_fail": sum(r["gateway_effect"] == "fail" for r in attacks), "gateway_unknown": sum(r["gateway_effect"] == "unknown" for r in attacks),
        "task_latency_p95_ms": percentile(latency, .95), "sensitive_scan_p95_us": percentile(scans, .95), "sensitive_scan_samples": len(scans)}


def timing_pairs(session, kb_port, kb_key, count, deadline):
    client = GovernedToolClient(session.origin, session.key, "support-kb", timeout=5, allow_insecure_http=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    expected = (APP.parent / "knowledge/service-hours.txt").read_text()

    def direct():
        request = urllib.request.Request(f"http://127.0.0.1:{kb_port}/read", data=b'{"resource_id":"service-hours"}', headers={"Authorization": "Bearer " + kb_key, "Content-Type": "application/json"})
        with opener.open(request, timeout=5) as response:
            return json.loads(response.read(16385))["text"]

    rows, ids = [], []
    for i in range(count):
        if time.monotonic() + 11 >= deadline:
            break
        pair = {"index": i, "direct_ms": None, "gateway_ms": None, "delta_ms": None}
        for route in (("direct", "gateway") if i % 2 == 0 else ("gateway", "direct")):
            start = time.perf_counter_ns()
            if route == "direct":
                text = direct()
            else:
                result = client.invoke("service-hours")
                text = result.text
                ids.append(result.request_id)
            pair[route + "_ms"] = (time.perf_counter_ns() - start) / 1_000_000
            TOOLS.require(text == expected, "timing response changed")
        pair["delta_ms"] = pair["gateway_ms"] - pair["direct_ms"]
        rows.append(pair)
    records = {r["request_id"]: r for r in map(json.loads, (session.directory / "calls.jsonl").read_text().splitlines()) if r["phase"] == "finished"}
    TOOLS.require(all(records.get(i, {}).get("outcome") == "completed" for i in ids), "timing audit missing")
    return {"method": "alternating-local-read-pairs-v1", "planned": count, "completed": len(rows), "pairs": rows,
            "delta_p50_ms": percentile([r["delta_ms"] for r in rows], .5), "delta_p95_ms": percentile([r["delta_ms"] for r in rows], .95)}


def run(args):
    freeze = json.loads((ROOT / "tests/testdata/support-agent-trial-v1-freeze.json").read_text())
    for name, digest in freeze["files_sha256"].items():
        TOOLS.require(hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, "frozen trial input changed; use a separately versioned trial")
    cases = [c for c in SUITE["cases"] if not args.case_id or c["id"] in args.case_id]
    TOOLS.require(bool(cases) and (not args.case_id or len(cases) == len(args.case_id)), "unknown or duplicate cases")
    TOOLS.require(1 <= args.max_model_calls <= 32 and 1 <= args.max_seconds <= 600 and 0 <= args.timing_pairs <= 50, "invalid budget")
    TOOLS.require(args.binary.is_file(), "build binary first")
    rows, remaining, stop = [planned(c) for c in cases], args.max_model_calls, None
    deadline = time.monotonic() + args.max_seconds
    preflight = {"state": "local_fixture", "reason": "live_not_attempted", "model_list_requests": 0}
    provider_key = TOOLS.PROVIDER_KEY
    if args.kimi:
        try:
            provider_key = load_credential(args.credential_file)
            preflight["model_list_requests"] = 1
            require_model(SUPPORTED_MODEL, list_models(provider_key))
            preflight.update(state="ready", reason="compatible_model_listed")
        except PreflightError as error:
            stop = str(error)
            preflight.update(state="blocked", reason=stop)
    timing = {"method": "alternating-local-read-pairs-v1", "planned": args.timing_pairs, "completed": 0, "pairs": [], "delta_p50_ms": None, "delta_p95_ms": None}
    excluded = [provider_key]
    kb = None
    if stop is None:
        try:
            with TOOLS.ToolSession(args.binary.resolve(), provider_factory=fixture) as session:
                kb_key = secrets.token_urlsafe(32)
                excluded += [kb_key, session.key]
                ready = session.directory / "knowledge-ready.json"
                kb = subprocess.Popen([sys.executable, str(APP), "serve", "--port", "0", "--ready-file", str(ready)], env=dict(clean_environment(), SUPPORT_KB_TOKEN=kb_key), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        TOOLS.require(kb.poll() is None, "knowledge service stopped")
                        if ready.exists():
                            break
                        time.sleep(.03)
                    kb_port = json.loads(ready.read_text())["port"]
                    endpoint = "https://api.moonshot.cn/v1" if args.kimi else f"http://127.0.0.1:{session.provider.server_port}/v1"
                    configure(session, endpoint, provider_key, kb_port, kb_key, args.kimi)
                    config_path = session.directory / "application.json"
                    last_task = None
                    for case, row in zip(cases, rows):
                        if remaining == 0:
                            stop = stop or "model_call_budget"
                        if args.kimi and last_task is not None and not stop:
                            wait = max(0, 22 - (time.monotonic() - last_task))
                            if time.monotonic() + wait + 1 >= deadline:
                                stop = "run_time_budget"
                            else:
                                time.sleep(wait)
                        if time.monotonic() + 1 >= deadline:
                            stop = stop or "run_time_budget"
                        if stop:
                            row["reason"] = stop
                            continue
                        config = dict(CONFIG, gateway_root=session.origin, timeout_seconds=45 if args.kimi else 5, max_model_calls=min(remaining, 3), min_model_interval_seconds=22 if args.kimi else 0, request_profile="moonshot-k2.6-instant-v1" if args.kimi else "generic-v1")
                        config_path.write_text(json.dumps(config))
                        config_path.chmod(0o600)
                        try:
                            result = subprocess.run([sys.executable, str(APP), "answer", "--config", str(config_path), "--json"], input=case["question"].encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(clean_environment(), GOVWEAVE_API_KEY=session.key), timeout=max(.1, deadline-time.monotonic()))
                        except subprocess.TimeoutExpired:
                            row.update(status="error", reason="process_deadline")
                            stop = "run_time_budget"
                            remaining = None
                            continue
                        last_task = time.monotonic()
                        if result.returncode not in (0, 2) or len(result.stdout) > 65536:
                            row.update(status="error", reason="application_unavailable")
                            stop = "application_unavailable"
                            remaining = None
                            continue
                        response = json.loads(result.stdout)
                        row["trace"] = response["trace"]
                        remaining -= row["trace"]["model_calls_reserved"]
                        attach_audit(session, row["trace"])
                        assess(case, row, response["answer"])
                        # Hold raw content only until privacy validation finishes.
                        if response["answer"]:
                            excluded.append(response["answer"])
                        if not row["audit_complete"] or row["status"] not in ("completed", "blocked"):
                            stop = row["reason"]
                        print(case["id"] + ": " + row["status"], flush=True)
                    if not stop:
                        timing = timing_pairs(session, kb_port, kb_key, args.timing_pairs, deadline)
                finally:
                    kb.terminate()
                    try:
                        kb.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        kb.kill(); kb.wait(timeout=5)
                    kb = None
        except (OSError, ValueError, KeyError, TypeError, TOOLS.DemoError, ToolCallError):
            stop = "trial_environment_unavailable"
    for row in rows:
        if row["status"] == "not_run":
            row["reason"] = stop or "not_started"
    complete = all(r["audit_complete"] and r["status"] in ("completed", "blocked") for r in rows) and timing["completed"] == timing["planned"]
    metrics = summarize(rows)
    verdict = "failed_selected_checks" if metrics["tasks_failed"] or metrics["gateway_fail"] else ("inconclusive" if not complete or metrics["tasks_unknown"] or metrics["gateway_unknown"] else "selected_checks_passed")
    sources = ["examples/support-agent/app.py", "examples/python/govweave_agent.py", "examples/python/govweave_tools.py", "scripts/trial-support-agent.py", "scripts/demo-tools.py", "scripts/task_grading.py", "scripts/moonshot_preflight.py", "internal/sensitive/v3.go", "internal/instruction/v2.go"]
    report = {"schema_version": 1, "id": SUITE["id"], "created_at": datetime.now(timezone.utc).isoformat(), "model_mode": "moonshot" if args.kimi else "scripted_local", "preflight": preflight,
        "state": "completed" if complete else "incomplete", "selected_checks": verdict, "stop_reason": stop, "model_call_budget": args.max_model_calls, "remaining_model_call_budget": remaining,
        "input_sha256": freeze["files_sha256"], "source_sha256": {n: hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sources}, "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "metrics": metrics, "rows": rows, "local_read_timing": timing, "limitations": SUITE["limitations"] + [
            "The application, file service and gateway run as separate processes. This is a developer example, not external customer evidence.",
            "Unrun/error/missing audit rows remain unknown. Missing markers or a model refusal alone do not establish gateway protection.",
            "Benign interventions are reported separately from task correctness; a factual task failure alone is not a false block.",
            "Time/email scoring uses frozen task-facts-v1; refund/topic cases explicitly use literal fallback. Unknown is not pass.",
            "Task latency includes generation, HTTP, audit and pacing. Sensitive scan timing covers only that detector stage.",
            "Timing pairs use a fixed synthetic normal document with no model. Paired gateway minus direct round trips include the extra local HTTP hop, policy, audit and scheduling noise. They are not pure policy cost, cloud overhead or a production SLA. Negative deltas remain visible; no warmup or outlier removal.",
            "The paired direct read exists only in this synthetic timing harness. The application has no provider URL, provider token or direct-read fallback.",
            "Model calls are bounded, with no retries. A killed application may have reserved calls absent from its final trace; the budget is a maximum admission limit, not a complete billing total."]}
    serialized = json.dumps(report, indent=2)
    for text in excluded + [c["question"] for c in cases] + [(APP.parent/"knowledge"/f"{r}.txt").read_text() for r in CONFIG["catalog"]]:
        TOOLS.require(text not in serialized, "private content retained")
    directory = (args.output_dir or ROOT/"dist/support-agent-trial"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(3))).resolve()
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    markdown = ["# Independent support Agent trial", "", f"Mode: **{report['model_mode']}**. Execution: **{report['state']}**. Selected checks: **{verdict}**.", "",
        f"Normal tasks: {metrics['tasks_passed']} passed / {metrics['tasks_failed']} failed / {metrics['tasks_unknown']} unknown of {metrics['benign']}. Benign interventions: {metrics['benign_interventions']}; unknown: {metrics['benign_intervention_unknown']}.",
        f"Attack controls: {metrics['gateway_pass']} passed / {metrics['gateway_fail']} failed / {metrics['gateway_unknown']} unknown of {metrics['attacks']}.", "",
        "| Case | Execution | Task check | Gateway control |", "| --- | --- | --- | --- |"]
    markdown += [f"| {r['case_id']} | {r['status']} | {r['task_reason']} | {r['gateway_effect']} |" for r in rows]
    markdown += ["", f"Local read pairs: {timing['completed']}/{timing['planned']}; paired delta P50 {timing['delta_p50_ms']} ms, P95 {timing['delta_p95_ms']} ms. Task P95 {metrics['task_latency_p95_ms']} ms; sensitive scan P95 {metrics['sensitive_scan_p95_us']} µs.", "", "## Limits", ""] + ["- "+s for s in report["limitations"]] + ["", "[Metadata report](report.json)", ""]
    for name, data in (("report.json",serialized+"\n"),("report.md","\n".join(markdown))):
        with os.fdopen(os.open(directory/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), "w") as out:
            out.write(data)
    print("Private report:",directory/"report.json")
    return 2 if not complete else (3 if verdict == "failed_selected_checks" else 2 if verdict == "inconclusive" else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT/"bin/govweave")
    parser.add_argument("--kimi", action="store_true")
    parser.add_argument("--credential-file", type=Path)
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--max-model-calls", type=int, default=24)
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--timing-pairs", type=int, default=20)
    parser.add_argument("--output-dir", type=Path)
    try:
        raise SystemExit(run(parser.parse_args()))
    except (OSError, ValueError, TOOLS.DemoError):
        print("Support trial could not run. Check frozen inputs, binary and output path.", file=sys.stderr)
        raise SystemExit(1)
