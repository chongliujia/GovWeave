#!/usr/bin/env python3
"""Run scripted Agent tool proposals through the reference client and technical-control reports."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("govweave_tool_fixture", ROOT / "scripts" / "demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)
sys.path.insert(0, str(ROOT / "examples" / "python"))
from govweave_tools import GovernedToolClient, ToolCallError  # noqa: E402


PACK = ROOT / "examples" / "rule-packs" / "read-tool-governance.json"
CONTROL_IDS = {
    "TOOL-APPLICATIONS-ACTIVE", "TOOL-GRANT-COVERAGE", "TOOL-OUTPUT-BLOCKING",
    "TOOL-AUDIT-AVAILABLE", "TOOL-OUTPUT-EVIDENCE", "TOOL-SAMPLE-RELEASES",
}
require = TOOLS.require


def set_output_mode(session, mode):
    snapshot, _ = session.request("/api/v1/tools")
    fields = (
        "name", "alias", "endpoint", "enabled", "allow_insecure_http",
        "timeout_seconds", "resources",
    )
    payload = {name: session.tool[name] for name in fields}
    payload.update(revision=snapshot["revision"], output_mode=mode)
    session.tool, _ = session.request("/api/v1/tools/" + session.tool["id"], payload, method="PUT")


def reject_unknown_arguments(session, client):
    calls_before = session.provider.state()[0]
    audit_before = (session.directory / "calls.jsonl").stat().st_size
    try:
        client.execute({"resource_id": "public-guide", "application_id": session.application["id"]})
    except ToolCallError as error:
        require(error.code == "invalid_arguments" and error.http_status == 0, "client did not reject extra arguments locally")
        require(not error.request_id, "invalid arguments reached the gateway")
    else:
        raise TOOLS.DemoError("client accepted an unexpected argument")
    require(session.provider.state()[0] == calls_before, "client validation invoked the provider")
    require((session.directory / "calls.jsonl").stat().st_size == audit_before, "client validation sent an HTTP request")


def exercise(session):
    # This executor has one route: every accepted proposal uses GovWeave. There
    # is no direct-provider fallback when the client reports a denied call.
    client = GovernedToolClient(session.origin, session.key, "support-docs", timeout=5, allow_insecure_http=True)
    reject_unknown_arguments(session, client)
    product, _ = session.request("/api/v1/compliance/products", {
        "revision": 0, "name": "Synthetic Agent read-tool integration", "version": "1.0.0",
        "application_ids": [session.application["id"]],
        "pack_id": "read-tool-governance", "pack_version": "1.0.0", "facts": {},
    })
    product_path = "/api/v1/compliance/products/" + product["id"]
    proposals = []
    phases = []
    artifacts = {}

    def execute(label, resource_id, status, provider_delta, expected_code=None, expected_decision=None):
        before = session.provider.state()[0]
        try:
            result = client.execute({"resource_id": resource_id})
        except ToolCallError as error:
            require(status != 200 and error.http_status == status, f"{label}: unexpected client failure")
            require(error.code == expected_code, f"{label}: unexpected denial reason")
            require(bool(error.request_id), f"{label}: missing request identifier")
            request_id, decision = error.request_id, "block"
            # Do not retry, call the provider directly, or fabricate tool text.
        else:
            require(status == 200, f"{label}: expected the tool call to be denied")
            require(result.governance.get("decision") == expected_decision, f"{label}: unexpected decision")
            require(result.governance.get("tool_revision") == session.tool["revision"], f"{label}: stale tool revision")
            expected_text = TOOLS.FIXTURE_CREDENTIAL if resource_id == "credential-guide" else TOOLS.NORMAL_TEXT
            require(result.text == expected_text, f"{label}: fixture content did not match")
            request_id, decision = result.request_id, result.governance["decision"]
        delta = session.provider.state()[0] - before
        require(delta == provider_delta, f"{label}: executor did not honor the upstream boundary")
        proposals.append({"scenario": label, "http_status": status, "decision": decision, "upstream_calls": delta, "request_id": request_id})

    def archive_phase(name, action, checked, releases, expected_failed):
        report, _ = session.request(product_path + "/evaluate", {})
        expected_status = "gaps_detected" if expected_failed else "satisfied"
        require(report["state"] == "ready" and report["evaluation"]["status"] == expected_status, f"{name}: unexpected assessment status")
        require(report["snapshot"]["tool_revision"] == session.tool["revision"], f"{name}: source configuration was stale")
        archived, _ = session.request(product_path + "/reports", {})
        snapshot = archived["snapshot"]
        evaluation = snapshot["report"]["evaluation"]
        require(evaluation["evaluation_only"] and evaluation["legal_compliance"] == "not_determined", f"{name}: technical assessment scope changed")
        require(evaluation["status"] == expected_status, f"{name}: archived assessment did not match")
        require(snapshot["report"]["snapshot"]["tool_revision"] == session.tool["revision"], f"{name}: archived tool revision did not match")
        controls = {control["id"]: control["status"] for control in evaluation["controls"]}
        require(set(controls) == CONTROL_IDS, f"{name}: unexpected technical-control catalog")
        failed = {identifier for identifier, value in controls.items() if value == "fail"}
        require(failed == expected_failed and all(value in ("pass", "fail") for value in controls.values()), f"{name}: control findings did not match")
        facts = snapshot["input"]["facts"]
        expected = {
            "runtime.tools.sample.output_checked_count": checked,
            "runtime.tools.sample.observed_release_count": releases,
            "runtime.tools.sample.unknown_output_count": 0,
            "runtime.tools.sample.incomplete_count": 0,
        }
        for key, value in expected.items():
            require(facts[key]["value"] == value and facts[key]["source"] == "runtime", f"{name}: runtime evidence did not match")
        before = session.provider.state()[0]
        replay, _ = session.request("/api/v1/compliance/reports/" + archived["summary"]["id"] + "/replay", {})
        require(replay["matches"] and replay["evaluation"]["status"] == expected_status, f"{name}: saved evidence replay did not match")
        require(session.provider.state()[0] == before, f"{name}: report replay invoked a tool")
        filename = f"phase-{len(phases) + 1:02d}.json"
        artifacts[filename] = archived
        phases.append({
            "phase": name, "operator_action": action, "tool_revision": session.tool["revision"],
            "status": expected_status,
            "controls": {state: sum(value == state for value in controls.values()) for state in ("pass", "fail", "unknown")},
            "failed_controls": sorted(failed), "output_checked_count": checked,
            "observed_release_count": releases, "report_id": archived["summary"]["id"],
            "file": filename, "replay_matches": True, "replay_tool_calls": 0,
        })

    execute("authorized_read", "public-guide", 200, 1, expected_decision="allow")
    execute("unauthorized_read", "restricted-guide", 403, 0, expected_code="tool_not_allowed")
    execute("credential_blocked", "credential-guide", 403, 1, expected_code="tool_output_blocked")
    archive_phase("blocking_baseline", "initial_block_configuration", 2, 0, set())

    # This is an explicit scripted operator change to demonstrate drift; it is
    # neither a model decision nor an autonomous repair policy.
    set_output_mode(session, "observe")
    execute("observe_release", "credential-guide", 200, 1, expected_decision="observe")
    archive_phase("observe_configuration", "operator_sets_observe", 3, 1, {"TOOL-OUTPUT-BLOCKING", "TOOL-SAMPLE-RELEASES"})

    set_output_mode(session, "block")
    execute("blocking_restored", "credential-guide", 403, 1, expected_code="tool_output_blocked")
    archive_phase("blocking_restored_history_retained", "operator_restores_block", 4, 1, {"TOOL-SAMPLE-RELEASES"})

    audit, _ = session.request("/api/v1/requests?limit=100")
    calls, header_errors = session.provider.state()
    require(calls == 4 and header_errors == 0, "unexpected tool invocation count or header forwarding")
    audit_data = (session.directory / "calls.jsonl").read_text()
    excluded = [TOOLS.NORMAL_TEXT, TOOLS.FIXTURE_CREDENTIAL, TOOLS.PROVIDER_KEY, session.key, TOOLS.CALLER_HEADER, *TOOLS.RESOURCE_IDS]
    persisted = json.dumps(artifacts)
    require(all(value not in persisted and value not in audit_data and value not in json.dumps(audit) for value in excluded), "report or audit retained tool data")
    require("http://" not in persisted and "https://" not in persisted, "retained report unexpectedly included an endpoint")
    summary = {
        "schema_version": 1, "result": "passed", "synthetic_data": True,
        "target_kind": "scripted_agent_executor",
        "scope": "Scripted proposals use the Python reference client and actual gateway; no model, general Agent framework, automatic repair or legal conclusion.",
        "provider_calls": calls, "local_argument_rejection": True, "direct_provider_fallback": False,
        "metadata_only_artifacts": True, "historical_observe_release_retained": True,
        "proposals": proposals, "phases": phases,
    }
    return summary, artifacts


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist" / "agent-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        with TOOLS.ToolSession(args.binary.resolve(), rule_packs=(PACK,)) as session:
            summary, artifacts = exercise(session)
            for filename, value in artifacts.items():
                TOOLS.save_json(output / filename, value)
            TOOLS.save_json(output / "summary.json", summary)
        print("Scripted Agent integration passed. Proposals and provider responses are synthetic; no model is used.")
        for phase in summary["phases"]:
            counts = phase["controls"]
            print(f"{phase['phase']}: {counts['pass']} technical checks passed, {counts['fail']} failed; observed releases in sample {phase['observed_release_count']}")
        print("Restoring block mode was an explicit operator action; the earlier observed release remains in the sample.")
        print(f"Private report snapshots and summary saved to: {output}")
        return 0
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated processes were stopped.")
        return 130
    except TOOLS.DemoError as error:
        print(f"Demonstration failed: {error}.")
        return 1
    except (OSError, ValueError, KeyError, ToolCallError, urllib.error.URLError):
        print("Demonstration failed. Confirm the current binary was built and the local endpoints are available.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "govweave", help="Built GovWeave executable")
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, help="New private directory (default: dist/agent-demo/<unique-run>)")
    raise SystemExit(main(parser.parse_args()))
