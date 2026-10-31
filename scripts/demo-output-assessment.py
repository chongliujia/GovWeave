#!/usr/bin/env python3
"""Verify active output probes, product evidence, drift and replay against a local scripted model."""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import secrets
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("output_assessment_fixture", ROOT / "scripts" / "demo-sensitive.py")
SENSITIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SENSITIVE)
TOOLS = SENSITIVE.TOOLS
require = TOOLS.require
PACK = ROOT / "examples" / "rule-packs" / "sensitive-output-governance-v1.1.json"
SUITE_PATH = ROOT / "examples" / "test-suites" / "sensitive-output-controls.json"
SUITE = json.loads(SUITE_PATH.read_text())
TEXTS = {"credential": "sk-SyntheticOutputProbeNeverReal12345678901234567890", "email": "probe.person@example.com", "phone": "+86 138 0000 0017", "benign": "GOVWEAVE_OUTPUT_READY"}


class Provider(HTTPServer):
    def __init__(self):
        self.calls, self.invalid_requests, self.refuse_email = 0, 0, False
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def do_POST(self):
        self.server.calls += 1
        status, payload = 400, {"error": "invalid_synthetic_request"}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 4096 and not self.headers.get("Transfer-Encoding"), "invalid request size")
            body = json.loads(self.rfile.read(size))
            require(self.path == "/v1/chat/completions" and self.headers.get("Authorization") == "Bearer " + SENSITIVE.SYNTHETIC_KEY, "invalid model request")
            require(body.get("model") == "synthetic-sensitive-model" and body.get("stream") is False and body.get("max_tokens") == 128, "invalid generation parameters")
            require(all(self.headers.get(key) is None for key in ("Cookie", "Origin", "X-Demo-Caller-Secret")), "caller headers escaped")
            item = next((item for item in SUITE["cases"] if item["messages"] == body.get("messages")), None)
            require(item is not None, "unknown prompt")
            category = item.get("category", "benign")
            content = "I cannot provide that." if category == "email" and self.server.refuse_email else TEXTS[category]
            status, payload = 200, {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}
        except (TOOLS.DemoError, ValueError, KeyError, TypeError, OSError):
            self.server.invalid_requests += 1
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
    artifacts, stages, runs = {}, [], []
    product, _ = session.request("/api/v1/compliance/products", {
        "revision": 0, "name": "Synthetic active output assessment", "version": "1.0.0",
        "application_ids": [session.application["id"]], "pack_id": "sensitive-output-governance", "pack_version": "1.1.0", "facts": {},
    })
    path = "/api/v1/compliance/products/" + product["id"]
    plan, _ = session.request(path + "/test-plan", {
        "revision": 0, "application_id": session.application["id"], "model_alias": SENSITIVE.ALIAS,
        "target_version": "synthetic-model-1", "suite_id": SUITE["id"], "suite_version": SUITE["version"],
        "context": "Local synthetic control verification; no claim of detector accuracy or legal compliance.",
        "schedule_enabled": False, "interval_seconds": 300, "timeout_seconds": 2, "max_output_tokens": 128, "retain_responses": False,
    }, method="PUT")

    def baseline():
        status, result, _, _ = session.request_result("/v1/chat/completions", {
            "model": SENSITIVE.ALIAS, "messages": SUITE["cases"][-1]["messages"], "stream": False, "max_tokens": 128,
        }, public=True)
        require(status == 200 and result["choices"][0]["message"]["content"] == TEXTS["benign"], "benign baseline failed")

    def stage(name, expected_counts, checked):
        before = session.provider.calls
        report = None
        for _ in range(100):
            candidate, _ = session.request(path + "/evaluation")
            if candidate["state"] == "ready":
                report = candidate
                break
            time.sleep(0.05)
        require(report is not None, "product evaluation did not refresh")
        saved, _ = session.request(path + "/reports", {})
        evaluation = saved["snapshot"]["report"]["evaluation"]
        counts = {state: sum(c["status"] == state for c in evaluation["controls"]) for state in ("pass", "fail", "unknown")}
        require(counts == dict(zip(("pass", "fail", "unknown"), expected_counts)), name + ": unexpected control findings")
        require(evaluation == report["evaluation"] or evaluation["status"] == report["evaluation"]["status"], "cached result differs from archive")
        facts = saved["snapshot"]["input"]["facts"]
        require(facts["runtime.sample.output_current_checked_count"]["value"] == checked, "active probes inflated production evidence")
        require(facts["runtime.sample.output_observed_release_count"]["value"] == 0, "active releases polluted production sample")
        require(evaluation["legal_compliance"] == "not_determined", "technical report claimed legal compliance")
        require(session.provider.calls == before, "report capture invoked the model")
        filename = f"report-{len(stages)+1:02d}.json"
        artifacts[filename] = saved
        stages.append({"stage": name, "controls": counts, "file": filename, "report_id": saved["summary"]["id"], "status": evaluation["status"]})

    def run(phase, expected_status):
        before = session.provider.calls
        started, _ = session.request(path + "/test-runs", {"phase": phase}, expected=202)
        finished = None
        for _ in range(200):
            result, _ = session.request("/api/v1/compliance/test-runs/" + started["id"])
            if result["state"] != "running":
                finished = result
                break
            time.sleep(0.025)
        require(finished is not None and finished["state"] == "completed" and finished["status"] == expected_status, "unexpected active test result")
        require(session.provider.calls == before + 4, "active suite did not execute exactly four calls")
        require(finished["runner_version"] == "bounded-chat-tests-v4", "unexpected runner version")
        require(all("output_check" in case and "response" not in case for case in finished["cases"]), "missing receipts or retained response text")
        if expected_status == "inconclusive":
            require(finished["cases"][1]["reason"] == "output_challenge_not_observed", "refusal incorrectly classified")
        filename = f"run-{len(runs)+1:02d}.json"
        artifacts[filename] = finished
        runs.append({"run_id": started["id"], "phase": phase, "status": expected_status, "file": filename})

    session.policy("block")
    baseline()
    stage("runtime_only_needs_active_evidence", (8, 0, 2), 1)
    run("pre_deployment", "passed")
    stage("pre_deployment_verified", (9, 0, 1), 1)
    run("operation", "passed")
    stage("block_both_phases_verified", (10, 0, 0), 1)
    session.provider.refuse_email = True
    run("operation", "inconclusive")
    stage("new_refusal_does_not_reuse_old_pass", (9, 0, 1), 1)
    session.provider.refuse_email = False
    run("operation", "passed")
    stage("operation_reverified", (10, 0, 0), 1)
    session.policy("redact")
    stage("policy_change_invalidates_evidence", (7, 1, 2), 0)
    baseline()
    run("pre_deployment", "passed")
    run("operation", "passed")
    stage("redact_both_phases_verified", (10, 0, 0), 1)
    session.policy("observe")
    baseline()
    run("pre_deployment", "failed")
    run("operation", "failed")
    stage("observe_probes_fail", (7, 3, 0), 1)
    update = {key: value for key, value in plan.items() if key not in ("product_id", "next_run_at", "last_run_id", "last_error")}
    update["context"] = "Changed validation context requires new evidence."
    session.request(path + "/test-plan", update, method="PUT")
    stage("plan_change_invalidates_both_phases", (7, 1, 2), 1)

    before = session.provider.calls
    for item in stages:
        replay, _ = session.request("/api/v1/compliance/reports/" + item["report_id"] + "/replay", {})
        require(replay["matches"] and replay["evaluation"] == artifacts[item["file"]]["snapshot"]["report"]["evaluation"], "historical report replay changed")
        item["replay_matches"] = True
    for item in runs:
        replay, _ = session.request("/api/v1/compliance/test-runs/" + item["run_id"] + "/replay", {})
        require(replay["matches"], "historical test replay changed")
        item["replay_matches"] = True
    require(session.provider.calls == before == 35 and session.provider.invalid_requests == 0, "unexpected provider traffic")
    persisted = json.dumps(artifacts)
    audit = (session.directory / "calls.jsonl").read_text()
    for secret in (session.key, SENSITIVE.SYNTHETIC_KEY, TOOLS.CALLER_HEADER, TEXTS["credential"]):
        require(secret not in persisted and secret not in audit, "credential or raw credential response retained")
    for text in TEXTS.values():
        require(text not in audit, "audit retained fixture text")
    # Suite prompts and benign expected text are intentionally retained; the
    # evidence privacy claim concerns returned content and instance secrets.
    return {"schema_version": 1, "result": "passed", "synthetic_data": True, "provider_calls": before,
            "scope": "One planned model target, four authored probes per run; not detector accuracy or legal certification.",
            "reports": stages, "runs": runs, "replay_provider_calls": 0}, artifacts


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist" / "output-assessment-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        with SENSITIVE.SensitiveSession(args.binary.resolve(), detector_version="sensitive-text-v2", rule_packs=(PACK,), test_suites=(SUITE_PATH,), provider_factory=Provider) as session:
            summary, artifacts = exercise(session)
        for filename, value in artifacts.items():
            TOOLS.save_json(output / filename, value)
        TOOLS.save_json(output / "summary.json", summary)
        print("Active output assessment passed using a local synthetic model.")
        for stage in summary["reports"]:
            print(f"{stage['stage']}: {stage['controls']}")
        print(f"Private evidence saved to: {output}")
        return 0
    except TOOLS.DemoError as error:
        print(f"Demonstration failed: {error}.")
        return 1
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated services stopped.")
        return 130
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        print("Demonstration failed. Confirm the current binary is built and local endpoints are available.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "govweave")
    parser.add_argument("--output-dir", type=Path)
    raise SystemExit(main(parser.parse_args()))
