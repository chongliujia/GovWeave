#!/usr/bin/env python3
"""Exercise one product with independent model and read-tool plans, using only local fixtures."""
import argparse
from datetime import datetime, timezone
from http.server import HTTPServer
import importlib.util
import json
from pathlib import Path
import secrets
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("application_tool_fixture", ROOT / "scripts/demo-tool-assessment.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
TOOLS, require = TOOL.TOOLS, TOOL.require
PACK = ROOT / "examples/rule-packs/application-output-governance.json"
MODEL_SUITE_PATH = ROOT / "examples/test-suites/sensitive-output-controls.json"
MODEL_SUITE = json.loads(MODEL_SUITE_PATH.read_text())


class Provider(HTTPServer):
    def __init__(self):
        self.calls, self.invalid, self.missing_email, self.refuse_model = 0, 0, False, False
        self.resources = []
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(TOOL.Handler):
    def do_POST(self):
        if self.path == "/read":
            return super().do_POST()
        self.server.calls += 1
        status, payload = 400, {"error": "invalid_synthetic_model_request"}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 4096 and not self.headers.get("Transfer-Encoding"), "invalid size")
            body = json.loads(self.rfile.read(size))
            require(self.path == "/v1/chat/completions" and self.headers.get("Authorization") == "Bearer " + TOOLS.PROVIDER_KEY, "invalid endpoint or credential")
            require(body.get("model") == "synthetic-dual-model" and body.get("stream") is False and body.get("max_tokens") == 128, "invalid parameters")
            require(all(self.headers.get(key) is None for key in ("Cookie", "Origin", "X-Demo-Caller-Secret")), "caller headers escaped")
            item = next((item for item in MODEL_SUITE["cases"] if item["messages"] == body.get("messages")), None)
            require(item is not None, "unknown prompt")
            category = item.get("category", "benign")
            text = "GOVWEAVE_OUTPUT_READY" if category == "benign" else TOOL.TEXTS["probe-" + category]
            if category == "email" and self.server.refuse_model:
                text = "No challenge"
            status, payload = 200, {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}
        except (TOOLS.DemoError, ValueError, KeyError, TypeError, OSError):
            self.server.invalid += 1
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


def exercise(session):
    artifacts, reports, runs = {}, [], []
    model, _ = session.request("/api/v1/connections", {
        "revision": 0, "name": "Synthetic dual-target model", "base_url": f"http://127.0.0.1:{session.provider.server_port}/v1",
        "model": "synthetic-dual-model", "alias": "dual-model", "api_key": TOOLS.PROVIDER_KEY,
        "enabled": True, "allow_insecure_http": True, "timeout_seconds": 3,
    })
    saved, _ = session.request("/api/v1/applications/" + session.application["id"], {
        "revision": session.application["revision"], "name": "Synthetic dual-target application", "allowed_connections": [model["id"]],
    }, method="PUT")
    session.application = saved["application"]
    body = {field: session.tool[field] for field in ("name", "alias", "endpoint", "enabled", "allow_insecure_http", "timeout_seconds")}
    body.update(revision=session.tool["revision"], output_mode="observe", resources=[
        {"resource_id": resource, "sensitivity": "internal", "allowed_applications": [] if resource == "probe-denied" else [session.application["id"]]}
        for resource in TOOL.TEXTS
    ])
    session.request("/api/v1/tools/" + session.tool["id"], body, method="PUT")

    def policy(mode):
        current, _ = session.request("/api/v1/policies/sensitive-output")
        session.request("/api/v1/policies/sensitive-output", {
            "revision": current["revision"], "mode": mode, "categories": ["credential", "email", "phone"],
            "application_ids": [session.application["id"]], "detector_version": "sensitive-text-v2",
        }, method="PUT")

    policy("redact")
    product, _ = session.request("/api/v1/compliance/products", {"revision": 0, "name": "One product with model and read tool", "version": "1.0.0", "application_ids": [session.application["id"]], "pack_id": "application-output-governance", "pack_version": "1.0.0", "facts": {}})
    path = "/api/v1/compliance/products/" + product["id"]
    common = {"revision": 0, "application_id": session.application["id"], "target_version": "synthetic-1", "suite_version": "1.0.0", "context": "Local combined control verification", "schedule_enabled": False, "interval_seconds": 300, "timeout_seconds": 2, "retain_responses": False}
    model_input = dict(common, model_alias="dual-model", suite_id=MODEL_SUITE["id"], max_output_tokens=128)
    model_plan, _ = session.request(path + "/test-plans/model", model_input, method="PUT")
    session.request(path + "/test-plans/read_tool", dict(common, target_kind="read_tool", tool_alias="support-docs", suite_id="read-tool-output-controls"), method="PUT")
    plans, _ = session.request(path + "/test-plans")
    require({plan["plan_id"] for plan in plans["plans"]} == {"model", "read_tool"}, "named plans were not retained")
    session.request(path + "/test-plan", model_input, method="PUT", expected=409)
    session.request(path + "/test-runs", {"phase": "operation"}, expected=404)
    require(session.provider.calls == 0, "configuration caused provider I/O or implicit target selection")
    session.request("/v1/chat/completions", {"model": "dual-model", "messages": MODEL_SUITE["cases"][-1]["messages"], "stream": False, "max_tokens": 128}, public=True, key=session.key)
    session.request("/v1/tools/support-docs/invoke", {"resource_id": "probe-benign"}, public=True, key=session.key)

    def stage(name, counts, model_evidence, tool_evidence, checked=2):
        before = session.provider.calls
        for _ in range(100):
            report, _ = session.request(path + "/evaluation")
            if report["state"] == "ready":
                break
            time.sleep(0.05)
        else:
            raise TOOLS.DemoError("product evaluation did not refresh")
        saved, _ = session.request(path + "/reports", {})
        evaluation = saved["snapshot"]["report"]["evaluation"]
        actual = {state: sum(c["status"] == state for c in evaluation["controls"]) for state in ("pass", "fail", "unknown")}
        require(actual == dict(zip(("pass", "fail", "unknown"), counts)), name + ": incorrect controls")
        facts = saved["snapshot"]["input"]["facts"]
        for prefix, expected in (("testing.output.", model_evidence), ("testing.tools.output.", tool_evidence)):
            require(sum(key.startswith(prefix) for key in facts) == expected, "evidence crossed plans or reused old success")
        require(facts["runtime.sample.output_current_checked_count"]["value"] == checked, "tests inflated production evidence")
        require(evaluation["legal_compliance"] == "not_determined" and session.provider.calls == before, "report changed scope or invoked a provider")
        filename = f"report-{len(reports)+1:02d}.json"
        artifacts[filename] = saved
        reports.append({"stage": name, "counts": actual, "file": filename, "report_id": saved["summary"]["id"]})

    def run(plan_id, phase, expected="passed"):
        before = session.provider.calls
        started, _ = session.request(path + "/test-runs", {"plan_id": plan_id, "phase": phase}, expected=202)
        require(started["plan_id"] == plan_id, "incorrect summary plan ID")
        for _ in range(200):
            result, _ = session.request("/api/v1/compliance/test-runs/" + started["id"])
            if result["state"] != "running":
                break
            time.sleep(0.025)
        require(result["state"] == "completed" and result["status"] == expected and result["plan"]["plan_id"] == plan_id, "incorrect plan run")
        require(session.provider.calls == before + 4, "unexpected upstream calls")
        other = "testing.tools.output." if plan_id == "model" else "testing.output."
        require(not any(key.startswith(other) for key in result["input"]["facts"]), "run claimed another target's evidence")
        require(all("response" not in case for case in result["cases"]), "returned text was retained")
        filename = f"run-{len(runs)+1:02d}.json"
        artifacts[filename] = result
        runs.append({"id": result["id"], "plan_id": plan_id, "phase": phase, "status": expected, "file": filename})

    stage("runtime_only", (9, 0, 4), 0, 0)
    run("model", "pre_deployment")
    run("model", "operation")
    stage("model_verified_tool_still_unknown", (11, 0, 2), 2, 0)
    run("read_tool", "pre_deployment")
    run("read_tool", "operation")
    stage("both_targets_verified", (13, 0, 0), 2, 2)
    model_input.update(revision=model_plan["revision"], context="Updated model-only measurement context")
    session.request(path + "/test-plans/model", model_input, method="PUT")
    stage("model_plan_edit_preserves_tool_evidence", (11, 0, 2), 0, 2)
    run("model", "pre_deployment")
    run("model", "operation")
    stage("model_retested", (13, 0, 0), 2, 2)
    session.provider.refuse_model = True
    run("model", "operation", "inconclusive")
    stage("model_unknown_does_not_erase_tool_success", (12, 0, 1), 1, 2)
    session.provider.refuse_model = False
    run("model", "operation")
    stage("model_recovered", (13, 0, 0), 2, 2)
    session.provider.missing_email = True
    run("read_tool", "operation", "inconclusive")
    stage("tool_unknown_does_not_erase_model_success", (12, 0, 1), 2, 1)
    policy("block")
    stage("shared_policy_change_invalidates_both", (8, 1, 4), 0, 0, checked=0)

    for item in reports:
        replay, _ = session.request("/api/v1/compliance/reports/" + item["report_id"] + "/replay", {})
        require(replay["matches"], "combined report replay changed")
        item["replay_matches"] = True
    for item in runs:
        replay, _ = session.request("/api/v1/compliance/test-runs/" + item["id"] + "/replay", {})
        require(replay["matches"], "test-run replay changed")
        item["replay_matches"] = True
    history, _ = session.request(path + "/test-runs")
    require(len(history["runs"]) == 9 and {item["plan_id"] for item in history["runs"]} == {"model", "read_tool"}, "history lost plan identity")
    require(session.provider.calls == 38 and session.provider.invalid == 0 and "probe-denied" not in session.provider.resources, "unexpected fixture traffic")
    persisted = json.dumps(artifacts)
    audit = (session.directory / "calls.jsonl").read_text()
    for value in (session.key, TOOLS.PROVIDER_KEY, TOOLS.CALLER_HEADER, TOOL.TEXTS["probe-credential"]):
        require(value not in persisted and value not in audit, "credentials retained")
    # Synthetic prompt literals are part of the retained model suite. Returned
    # content must be absent from case receipts, reports and the audit log.
    evidence = json.dumps([value["cases"] if "cases" in value else value for value in artifacts.values()])
    for value in TOOL.TEXTS.values():
        require(value not in evidence and value not in audit, "returned tool text retained")
    return {"schema_version": 1, "result": "passed", "synthetic_data": True, "provider_calls": 38, "replay_provider_calls": 0, "scope": "One model and one read tool; independent control probes, not an autonomous Agent trajectory or legal certification.", "reports": reports, "runs": runs}, artifacts


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist/application-assessment-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        with TOOLS.ToolSession(args.binary.resolve(), rule_packs=(PACK,), test_suites=(TOOL.SUITE, MODEL_SUITE_PATH), provider_factory=Provider) as session:
            summary, artifacts = exercise(session)
        for filename, value in artifacts.items():
            TOOLS.save_json(output / filename, value)
        TOOLS.save_json(output / "summary.json", summary)
        print("Combined application assessment passed using only local model/tool fixtures.")
        for report in summary["reports"]:
            print(f"{report['stage']}: {report['counts']}")
        print(f"Private evidence saved to: {output}")
        return 0
    except TOOLS.DemoError as error:
        print(f"Demonstration failed: {error}.")
        return 1
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated services stopped.")
        return 130
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        print("Demonstration failed. Confirm the binary and local endpoints are available.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    parser.add_argument("--output-dir", type=Path)
    raise SystemExit(main(parser.parse_args()))
