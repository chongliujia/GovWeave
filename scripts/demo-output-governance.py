#!/usr/bin/env python3
"""Verify sensitive-output controls, retained evidence and replay using local synthetic services."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import secrets
import time
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("output_governance_fixture", ROOT / "scripts" / "demo-sensitive.py")
SENSITIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SENSITIVE)
TOOLS = SENSITIVE.TOOLS
require = TOOLS.require
PACK = ROOT / "examples" / "rule-packs" / "sensitive-output-governance.json"
PACK_ID = "sensitive-output-governance"
CONTROL_IDS = {"OUTPUT-" + name for name in (
    "APPLICATIONS-ACTIVE", "PROTECTIVE-MODE", "SCOPE-COVERAGE", "CATEGORY-COVERAGE",
    "AUDIT-AVAILABLE", "CURRENT-EVIDENCE", "SAMPLE-RELEASES", "SAMPLE-COMPLETENESS",
)}


class Reports:
    def __init__(self, session, calls, artifacts, phases, prefix):
        self.session, self.calls = session, calls
        self.artifacts, self.phases, self.prefix = artifacts, phases, prefix
        self.saved = []
        product, _ = session.request("/api/v1/compliance/products", {
            "revision": 0, "name": "Synthetic sensitive-output integration", "version": "1.0.0",
            "application_ids": [session.application["id"]], "pack_id": PACK_ID, "pack_version": "1.0.0", "facts": {},
        })
        self.path = "/api/v1/compliance/products/" + product["id"]

    def archive(self, name, policy, failed, checked, blocked=0, redacted=0, observed=0, unchecked=0):
        before = self.calls()
        wanted = {"OUTPUT-" + identifier for identifier in failed}
        # Latest may schedule refresh; no explicit evaluate is needed. A Go
        # service test separately verifies background refresh without reads.
        for _ in range(100):
            report, _ = self.session.request(self.path + "/evaluation")
            if report["state"] == "ready" and report["snapshot"].get("output_policy_revision", 0) == policy["revision"]:
                break
            time.sleep(0.05)
        else:
            raise TOOLS.DemoError(name + ": assessment did not refresh")
        archived, _ = self.session.request(self.path + "/reports", {})
        snapshot = archived["snapshot"]
        evaluation = snapshot["report"]["evaluation"]
        statuses = {control["id"]: control["status"] for control in evaluation["controls"]}
        require(set(statuses) == CONTROL_IDS, name + ": unexpected control catalog")
        require({key for key, value in statuses.items() if value == "fail"} == wanted, name + ": incorrect failed controls")
        require(all(value in ("pass", "fail") for value in statuses.values()), name + ": unexpected unknown evidence")
        require(evaluation["status"] == ("gaps_detected" if wanted else "satisfied"), name + ": incorrect summary")
        require(evaluation["evaluation_only"] and evaluation["legal_compliance"] == "not_determined" and evaluation["pack_review_status"] == "draft", name + ": incorrect assurance claim")
        require(report["evaluation"]["status"] == evaluation["status"], name + ": latest assessment did not match archive")
        require(snapshot["report"]["snapshot"]["output_policy_revision"] == policy["revision"], name + ": incorrect revision")
        facts = snapshot["input"]["facts"]
        expected = {
            "output_policy_revision": policy["revision"], "output_policy_mode": policy["mode"],
            "output_detector_version": policy["detector_version"],
            "sample.output_current_checked_count": checked, "sample.output_block_count": blocked,
            "sample.output_redacted_count": redacted, "sample.output_observed_release_count": observed,
            "sample.output_unchecked_release_count": unchecked, "sample.output_unknown_count": 0,
            "sample.output_incomplete_count": 0,
        }
        for key, value in expected.items():
            require(facts["runtime." + key]["value"] == value and facts["runtime." + key]["source"] == "runtime", name + ": incorrect runtime evidence " + key)
        require(self.calls() == before, name + ": assessment called the provider")
        filename = f"{self.prefix}-phase-{len(self.saved) + 1:02d}.json"
        self.artifacts[filename] = archived
        phase = {
            "phase": name, "path": self.prefix, "output_policy_revision": policy["revision"], "mode": policy["mode"],
            "status": evaluation["status"], "controls": {state: sum(value == state for value in statuses.values()) for state in ("pass", "fail", "unknown")},
            "failed_controls": sorted(wanted), "current_checked_count": checked, "output_block_count": blocked,
            "output_redacted_count": redacted, "observed_release_count": observed, "unchecked_release_count": unchecked,
            "report_id": archived["summary"]["id"], "file": filename,
        }
        self.phases.append(phase)
        self.saved.append(phase)

    def verify_retained(self):
        before = self.calls()
        for phase in self.saved:
            path = "/api/v1/compliance/reports/" + phase["report_id"]
            retained, _ = self.session.request(path)
            require(retained == self.artifacts[phase["file"]], "later policy changes rewrote an old report")
            replay, _ = self.session.request(path + "/replay", {})
            require(replay["matches"] and replay["evaluation"] == retained["snapshot"]["report"]["evaluation"], "retained report replay changed")
            phase.update(replay_matches=True, replay_provider_calls=0)
        require(self.calls() == before, "replay invoked a provider")
        persisted = json.dumps({key: self.artifacts[key] for key in (phase["file"] for phase in self.saved)})
        audit = (self.session.directory / "calls.jsonl").read_text()
        excluded = [self.session.key, SENSITIVE.SYNTHETIC_KEY, TOOLS.PROVIDER_KEY, TOOLS.CALLER_HEADER,
                    *SENSITIVE.TEXTS.values(), *SENSITIVE.PROMPTS.values(), TOOLS.FIXTURE_CREDENTIAL, TOOLS.NORMAL_TEXT]
        require(all(value not in persisted and value not in audit for value in excluded), "audit or report retained synthetic content or credentials")
        require("http://" not in persisted and "https://" not in persisted, "report retained provider endpoints")


def model_exercise(session, artifacts, phases):
    reports = Reports(session, lambda: session.provider.calls, artifacts, phases, "model")
    policy = session.policy("disabled")
    reports.archive("disabled_without_calls", policy, {"PROTECTIVE-MODE", "SCOPE-COVERAGE", "CURRENT-EVIDENCE"}, 0)

    def invoke(name, expected_status, expected_text=None):
        before = session.provider.calls
        status, result, _, _ = session.request_result("/v1/chat/completions", {
            "model": SENSITIVE.ALIAS, "messages": [{"role": "user", "content": SENSITIVE.PROMPTS[name]}],
            "stream": False, "max_tokens": 128, "thinking": {"type": "disabled"},
        }, public=True)
        require(status == expected_status and session.provider.calls == before + 1, "unexpected model result or provider count")
        if expected_status == 200:
            require(result["choices"][0]["message"]["content"] == expected_text, "model response transformation did not match")
        else:
            require(result["error"]["code"] == "content_output_blocked" and "choices" not in result, "blocked model output was released")

    policy = session.policy("block")
    status, result, _, _ = session.request_result("/v1/content/evaluations", {"text": SENSITIVE.TEXTS["email"]}, public=True)
    require(status == 200 and result["policy"]["result"] == "block" and session.provider.calls == 0, "standalone evaluation invoked a model")
    reports.archive("standalone_is_not_execution_evidence", policy, {"CURRENT-EVIDENCE"}, 0)
    invoke("email", 403)
    invoke("harmless", 200, SENSITIVE.TEXTS["harmless"])
    reports.archive("block_verified", policy, set(), 2, blocked=1)

    policy = session.policy("redact")
    reports.archive("new_revision_needs_own_evidence", policy, {"CURRENT-EVIDENCE"}, 0, blocked=1)
    invoke("email", 200, "Synthetic email: [REDACTED]")
    invoke("credential", 200, "[REDACTED]")
    reports.archive("redact_verified", policy, set(), 2, blocked=1, redacted=2)

    policy = session.policy("observe")
    invoke("email", 200, SENSITIVE.TEXTS["email"])
    reports.archive("observe_release", policy, {"PROTECTIVE-MODE", "SAMPLE-RELEASES"}, 1, blocked=1, redacted=2, observed=1)
    policy = session.policy("block")
    invoke("email", 403)
    reports.archive("block_restored_history_retained", policy, {"SAMPLE-RELEASES"}, 1, blocked=2, redacted=2, observed=1)

    policy = session.policy("disabled")
    invoke("harmless", 200, SENSITIVE.TEXTS["harmless"])
    reports.archive("disabled_unchecked_release", policy, {"PROTECTIVE-MODE", "SCOPE-COVERAGE", "CURRENT-EVIDENCE", "SAMPLE-RELEASES"}, 0, blocked=2, redacted=2, observed=1, unchecked=1)
    policy = session.policy("block")
    invoke("email", 403)
    reports.archive("restored_without_erasing_missing_checks", policy, {"SAMPLE-RELEASES"}, 1, blocked=3, redacted=2, observed=1, unchecked=1)
    reports.verify_retained()
    require(session.provider.calls == 8 and session.provider.invalid_requests == 0, "unexpected local model traffic")
    return session.provider.calls


def tool_exercise(session, artifacts, phases):
    # Deliberately choose legacy observe so this demonstrates the new policy's
    # block/redact actions. The independent legacy block still wins elsewhere.
    fields = ("name", "alias", "endpoint", "enabled", "allow_insecure_http", "timeout_seconds", "resources")
    payload = {name: session.tool[name] for name in fields}
    payload.update(revision=session.tool["revision"], output_mode="observe")
    session.tool, _ = session.request("/api/v1/tools/" + session.tool["id"], payload, method="PUT")
    reports = Reports(session, lambda: session.provider.state()[0], artifacts, phases, "tool")
    for mode, expected in (("block", 403), ("redact", 200)):
        current, _ = session.request("/api/v1/policies/sensitive-output")
        policy, _ = session.request("/api/v1/policies/sensitive-output", {
            "revision": current["revision"], "mode": mode, "categories": SENSITIVE.CATEGORIES,
            "application_ids": [session.application["id"]], "detector_version": "sensitive-text-v2",
        }, method="PUT")
        result, _ = session.request("/v1/tools/support-docs/invoke", {"resource_id": "credential-guide"}, public=True, key=session.key, expected=expected)
        if mode == "block":
            require(result["error"]["code"] == "content_output_blocked" and "text" not in result, "sensitive tool blocking failed")
        else:
            require(result["text"] == "[REDACTED]" and result["governance"]["output_policy"]["result"] == "redacted", "tool redaction was not performed")
        reports.archive("tool_" + mode + "_verified", policy, set(), 1, blocked=1, redacted=int(mode == "redact"))
    reports.verify_retained()
    calls, invalid_headers = session.provider.state()
    require(calls == 2 and invalid_headers == 0, "unexpected local tool traffic")
    return calls


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist" / "output-governance-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        artifacts, phases = {}, []
        with SENSITIVE.SensitiveSession(args.binary.resolve(), detector_version="sensitive-text-v2", rule_packs=(PACK,)) as session:
            model_calls = model_exercise(session, artifacts, phases)
        with TOOLS.ToolSession(args.binary.resolve(), rule_packs=(PACK,)) as session:
            tool_calls = tool_exercise(session, artifacts, phases)
        for filename, value in artifacts.items():
            TOOLS.save_json(output / filename, value)
        summary = {
            "schema_version": 1, "result": "passed", "synthetic_data": True, "pack_id": PACK_ID, "pack_version": "1.0.0",
            "scope": "Draft internal technical controls, local scripted model and tool services; no external provider or legal conclusion.",
            "model_provider_calls": model_calls, "tool_provider_calls": tool_calls, "metadata_only_artifacts": True,
            "historical_findings_retained": True, "phases": phases,
        }
        TOOLS.save_json(output / "summary.json", summary)
        print("Sensitive-output governance integration passed using synthetic local services.")
        for phase in phases:
            print(f"{phase['phase']}: {phase['controls']['pass']} passed, {phase['controls']['fail']} failed; replay matched")
        print(f"Private report snapshots and summary saved to: {output}")
        return 0
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated processes were stopped.")
        return 130
    except TOOLS.DemoError as error:
        print(f"Demonstration failed: {error}.")
        return 1
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        print("Demonstration failed. Confirm the current binary was built and the local endpoints are available.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "govweave")
    parser.add_argument("--output-dir", type=Path, help="New private directory (default: dist/output-governance-demo/<unique-run>)")
    raise SystemExit(main(parser.parse_args()))
