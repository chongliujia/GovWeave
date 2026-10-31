#!/usr/bin/env python3
"""Verify active read-tool authorization/output probes and retained product reports locally."""
import argparse
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import importlib.util
import json
from pathlib import Path
import secrets
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tool_assessment_helpers", ROOT / "scripts" / "demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)
require = TOOLS.require
PACK = ROOT / "examples/rule-packs/sensitive-tool-governance.json"
SUITE = ROOT / "examples/test-suites/read-tool-output-controls.json"
TEXTS = {"probe-credential":"sk-SyntheticToolProbeNeverReal12345678901234567890", "probe-email":"probe.person@example.com", "probe-phone":"+86 138 0000 0017", "probe-benign":"GOVWEAVE_TOOL_READY", "probe-denied":"Synthetic restricted content"}


class Provider(HTTPServer):
    def __init__(self):
        self.calls, self.invalid, self.missing_email = 0, 0, False
        self.resources = []
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def do_POST(self):
        self.server.calls += 1
        status, payload = 400, {"error":"invalid_fixture_request"}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 4096 and not self.headers.get("Transfer-Encoding"), "invalid size")
            body = json.loads(self.rfile.read(size))
            require(self.path == "/read" and set(body) == {"resource_id"} and body["resource_id"] in TEXTS, "invalid resource")
            require(self.headers.get("Authorization") == "Bearer " + TOOLS.PROVIDER_KEY, "invalid upstream credential")
            require(all(self.headers.get(key) is None for key in ("Cookie", "Origin", "X-Demo-Caller-Secret")), "forwarded caller header")
            resource = body["resource_id"]
            self.server.resources.append(resource)
            text = "No result" if self.server.missing_email and resource == "probe-email" else TEXTS[resource]
            status, payload = 200, {"text":text}
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
    artifacts, phases, runs = {}, [], []

    def tool_config(mode="block", allow_denied=False):
        snapshot, _ = session.request("/api/v1/tools")
        fields = ("name", "alias", "endpoint", "enabled", "allow_insecure_http", "timeout_seconds")
        body = {field:session.tool[field] for field in fields}
        body.update(revision=snapshot["revision"], output_mode=mode, resources=[
            {"resource_id":resource, "sensitivity":"internal", "allowed_applications":[session.application["id"]] if resource != "probe-denied" or allow_denied else []}
            for resource in TEXTS
        ])
        session.tool, _ = session.request("/api/v1/tools/" + session.tool["id"], body, method="PUT")

    def policy(mode):
        current, _ = session.request("/api/v1/policies/sensitive-output")
        saved, _ = session.request("/api/v1/policies/sensitive-output", {
            "revision":current["revision"], "mode":mode, "categories":["credential","email","phone"],
            "application_ids":[session.application["id"]], "detector_version":"sensitive-text-v2",
        }, method="PUT")
        return saved

    def baseline():
        result, _ = session.request("/v1/tools/support-docs/invoke", {"resource_id":"probe-benign"}, public=True, key=session.key)
        require(result["text"] == TEXTS["probe-benign"], "benign baseline failed")

    tool_config()
    policy("block")
    product, _ = session.request("/api/v1/compliance/products", {"revision":0,"name":"Synthetic actively assessed read tool","version":"1.0.0","application_ids":[session.application["id"]],"pack_id":"sensitive-tool-governance","pack_version":"1.0.0","facts":{}})
    path = "/api/v1/compliance/products/" + product["id"]
    session.request(path + "/test-plan", {"revision":0,"target_kind":"read_tool","tool_alias":"support-docs","application_id":session.application["id"],"target_version":"synthetic-reader-1","suite_id":"read-tool-output-controls","suite_version":"1.0.0","context":"Dedicated synthetic read resources; no general Agent coverage claim.","schedule_enabled":False,"interval_seconds":300,"timeout_seconds":2,"retain_responses":False}, method="PUT")

    def phase(name, expected, checked):
        before = session.provider.calls
        for _ in range(100):
            report, _ = session.request(path + "/evaluation")
            if report["state"] == "ready":
                break
            time.sleep(0.05)
        else:
            raise TOOLS.DemoError("automatic product evaluation did not refresh")
        saved, _ = session.request(path + "/reports", {})
        evaluation = saved["snapshot"]["report"]["evaluation"]
        counts = {state:sum(c["status"] == state for c in evaluation["controls"]) for state in ("pass","fail","unknown")}
        require(counts == dict(zip(("pass","fail","unknown"),expected)), name + ": incorrect findings")
        facts = saved["snapshot"]["input"]["facts"]
        require(facts["runtime.sample.output_current_checked_count"]["value"] == checked, "active probes inflated production evidence")
        require(not any(key.startswith("testing.output.") for key in facts), "tool evidence became model evidence")
        require(evaluation["legal_compliance"] == "not_determined" and session.provider.calls == before, "report evaluation changed scope or performed I/O")
        filename = f"report-{len(phases)+1:02d}.json"
        artifacts[filename] = saved
        phases.append({"phase":name,"counts":counts,"file":filename,"report_id":saved["summary"]["id"]})

    def run(stage, status="passed", credential_reason=None, grant_drift=False):
        before = session.provider.calls
        started, _ = session.request(path + "/test-runs", {"phase":stage}, expected=202)
        for _ in range(200):
            result, _ = session.request("/api/v1/compliance/test-runs/" + started["id"])
            if result["state"] != "running":
                break
            time.sleep(0.025)
        require(result["state"] == "completed" and result["status"] == status and len(result["cases"]) == 5, "unexpected active run")
        require(result["runner_version"] == "bounded-tool-tests-v1" and result["tool_revision"] == session.tool["revision"], "wrong target provenance")
        require(session.provider.calls - before == (5 if grant_drift else 4), "denial did not preserve upstream boundary")
        denied = result["cases"][4]
        require(denied["reason"] == ("tool_resource_was_authorized" if grant_drift else "tool_resource_denied_before_execution"), "wrong denial evidence")
        if credential_reason:
            require(result["cases"][0]["reason"] == credential_reason, "credential protection path was mislabeled")
        require(all("response" not in case for case in result["cases"]), "probe returned text was retained")
        filename = f"run-{len(runs)+1:02d}.json"
        artifacts[filename] = result
        runs.append({"id":started["id"],"phase":stage,"status":status,"file":filename})

    baseline()
    phase("runtime_only", (9,0,2), 1)
    run("pre_deployment", credential_reason="legacy_tool_credential_blocked")
    phase("pre_deployment_verified", (10,0,1), 1)
    run("operation", credential_reason="legacy_tool_credential_blocked")
    phase("block_both_phases", (11,0,0), 1)
    policy("redact")
    phase("policy_change_invalidates_evidence", (8,1,2), 0)
    baseline()
    run("pre_deployment", credential_reason="legacy_tool_credential_blocked")
    run("operation", credential_reason="legacy_tool_credential_blocked")
    phase("redact_with_legacy_credential_block", (11,0,0), 1)
    tool_config("observe")
    run("pre_deployment", credential_reason="sensitive_output_redacted")
    run("operation", credential_reason="sensitive_output_redacted")
    phase("all_categories_redacted", (11,0,0), 1)
    tool_config("observe", allow_denied=True)
    run("operation", status="failed", grant_drift=True)
    phase("expanded_grant_detected", (9,1,1), 1)
    tool_config("observe")
    run("pre_deployment")
    run("operation")
    phase("restored_and_retested", (11,0,0), 1)
    session.provider.missing_email = True
    run("operation", status="inconclusive")
    phase("missing_challenge_replaces_old_success", (10,0,1), 1)

    before = session.provider.calls
    for item in phases:
        replay, _ = session.request("/api/v1/compliance/reports/" + item["report_id"] + "/replay", {})
        require(replay["matches"] and replay["evaluation"] == artifacts[item["file"]]["snapshot"]["report"]["evaluation"], "historical product report changed")
        item["replay_matches"] = True
    for item in runs:
        replay, _ = session.request("/api/v1/compliance/test-runs/" + item["id"] + "/replay", {})
        require(replay["matches"], "historical test replay changed")
        item["replay_matches"] = True
    require(session.provider.calls == before == 43 and session.provider.invalid == 0, "unexpected fixture traffic")
    require(session.provider.resources.count("probe-denied") == 1, "denied resource reached provider outside the explicit grant-drift phase")
    persisted = json.dumps(artifacts)
    audit = (session.directory / "calls.jsonl").read_text()
    for value in (session.key, TOOLS.PROVIDER_KEY, TOOLS.CALLER_HEADER, TEXTS["probe-credential"], TEXTS["probe-email"], TEXTS["probe-phone"], TEXTS["probe-denied"]):
        require(value not in persisted and value not in audit, "instance secrets or returned sensitive output were retained")
    return {"schema_version":1,"result":"passed","synthetic_data":True,"provider_calls":43,"expected_denial_provider_calls":1,"scope":"One scripted read tool and five synthetic resources; not general Agent safety or legal certification.","reports":phases,"runs":runs,"replay_provider_calls":0}, artifacts


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist/tool-assessment-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        with TOOLS.ToolSession(args.binary.resolve(), rule_packs=(PACK,), test_suites=(SUITE,), provider_factory=Provider) as session:
            summary, artifacts = exercise(session)
        for filename, value in artifacts.items():
            TOOLS.save_json(output / filename, value)
        TOOLS.save_json(output / "summary.json", summary)
        print("Active read-tool assessment passed using only a local synthetic provider.")
        for phase in summary["reports"]:
            print(f"{phase['phase']}: {phase['counts']}")
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
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    parser.add_argument("--output-dir", type=Path)
    raise SystemExit(main(parser.parse_args()))
