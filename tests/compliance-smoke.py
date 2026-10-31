#!/usr/bin/env python3
"""Local binary/plugin/API smoke test. Standard library only; synthetic evidence."""
import argparse
import copy
from datetime import datetime, timezone
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


def main(output_dir=None):
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    exported = {}
    root = Path(__file__).resolve().parents[1]
    binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", root / "bin/govweave")).resolve()
    with tempfile.TemporaryDirectory(prefix="govweave-compliance-") as directory:
        data_dir = Path(directory)
        packs = data_dir / "rule-packs"
        packs.mkdir()
        shutil.copyfile(root / "examples/rule-packs/demo-ai-governance.json", packs / "demo.json")
        shutil.copyfile(root / "examples/rule-packs/eu-ai-act-chatbot-transparency.json", packs / "eu.json")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        env = {**os.environ, "GOVWEAVE_DATA_DIR": directory, "GOVWEAVE_LISTEN_ADDR": f"127.0.0.1:{port}"}
        for key in ("GOVWEAVE_PUBLIC_URL", "GOVWEAVE_ORGANIZATION_NAME", "GOVWEAVE_ADMIN_TOKEN_FILE"):
            env.pop(key, None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def call(path, payload=None, method=None, application_key=None):
            headers = {"X-GovWeave-Request": "console", "Origin": origin}
            body = None
            if payload is not None:
                body = json.dumps(payload).encode()
                headers["Content-Type"] = "application/json"
            if application_key is not None:
                headers["Authorization"] = "Bearer " + application_key
            request = urllib.request.Request(origin + path, data=body, headers=headers, method=method)
            try:
                with opener.open(request, timeout=5) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)

        child = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise AssertionError(child.stderr.read().decode())
                try:
                    if call("/healthz")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError("Gateway did not start")
            assert call("/api/v1/compliance/packs")[0] == 401
            assert call("/api/v1/auth/setup", {"password": "synthetic compliance administrator password"})[0] == 200
            status, catalog = call("/api/v1/compliance/packs")
            assert status == 200 and len(catalog["packs"]) == 2
            descriptor = next(pack for pack in catalog["packs"] if pack["id"] == "demo-ai-governance")
            assert descriptor["id"] == "demo-ai-governance" and len(descriptor["sha256"]) == 64
            payload = json.loads((root / "examples/compliance-evaluation.json").read_text())
            status, result = call("/api/v1/compliance/evaluations", payload)
            assert status == 200 and result["status"] == "insufficient_evidence"
            assert result["controls"][1]["status"] == "pass"
            assert result["pack_sha256"] == descriptor["sha256"]
            payload["facts"]["transparency.disclosure_verified"] = {
                "value": True, "evidence_id": "synthetic-review-001", "source": "assessment",
                "observed_at": "2026-01-01T00:00:00Z",
            }
            payload["facts"]["unused.private"] = {
                **payload["facts"]["transparency.disclosure_verified"], "value": "synthetic-private-fact-value",
            }
            status, result = call("/api/v1/compliance/evaluations", payload)
            assert status == 200 and result["status"] == "satisfied"
            assert result["evaluation_only"] and result["legal_compliance"] == "not_determined"
            assert "synthetic-private-fact-value" not in json.dumps(result)
            payload["facts"]["transparency.disclosure_verified"]["value"] = False
            assert call("/api/v1/compliance/evaluations", payload)[1]["status"] == "gaps_detected"
            missing = copy.deepcopy(payload)
            missing["pack_version"] = "missing"
            assert call("/api/v1/compliance/evaluations", missing)[0] == 404
            status, connection = call("/api/v1/connections", {
                "name": "Synthetic provider", "base_url": "http://127.0.0.1:1/v1", "model": "test",
                "alias": "assistant", "enabled": True, "allow_insecure_http": True, "timeout_seconds": 1,
            })
            assert status == 200
            status, application = call("/api/v1/applications", {"name": "Synthetic product app", "allowed_connections": [connection["id"]]})
            assert status == 200
            policy = {"revision": 0, "mode": "block", "rules": ["private_key", "api_key"], "application_ids": [], "connection_ids": []}
            assert call("/api/v1/policies/credential-egress", policy, "PUT")[0] == 200
            profile = {
                "revision": 0, "name": "Synthetic product", "version": "1.0.0",
                "application_ids": [application["application"]["id"]],
                "pack_id": descriptor["id"], "pack_version": descriptor["version"],
                "facts": {key: copy.deepcopy(payload["facts"][key]) for key in ("product.user_facing", "transparency.disclosure_verified")},
            }
            profile["facts"]["transparency.disclosure_verified"]["value"] = True
            status, product = call("/api/v1/compliance/products", profile)
            assert status == 200
            product_path = "/api/v1/compliance/products/" + product["id"]

            def await_report(expected, min_audit_bytes=-1):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    status, report = call(product_path + "/evaluation")
                    assert status == 200
                    if report["state"] == "ready" and report["evaluation"]["status"] == expected and report["snapshot"]["audit_bytes"] > min_audit_bytes:
                        return report
                    assert report["state"] != "pending" or "evaluation" not in report
                    time.sleep(0.02)
                raise AssertionError("Automatic product evaluation did not update")

            report = await_report("satisfied")
            assert report["evaluation"]["legal_compliance"] == "not_determined"
            policy.update(revision=1, mode="observe")
            assert call("/api/v1/policies/credential-egress", policy, "PUT")[0] == 200
            await_report("gaps_detected")
            policy.update(revision=2, mode="block")
            assert call("/api/v1/policies/credential-egress", policy, "PUT")[0] == 200
            report = await_report("satisfied")
            status, blocked = call("/v1/chat/completions", {
                "model": "assistant", "messages": [{"role": "user", "content": "sk-synthetic-private-runtime-012345678901234567890"}],
            }, application_key=application["api_key"])
            assert status == 403 and blocked["error"]["code"] == "policy_blocked"
            blocked_status = status
            runtime_report = await_report("satisfied", report["snapshot"]["audit_bytes"])
            status, call_view = call("/api/v1/requests?limit=100")
            assert status == 200
            blocked_record = next(record for record in call_view["records"] if record["request_id"] == blocked["request_id"])
            assert blocked_record["upstream_attempted"] is False
            assert "sk-synthetic-private-runtime" not in json.dumps(runtime_report)
            assert call(product_path + "/evaluate", {"facts": {}})[0] == 400
            assert call(product_path + "/evaluate", {})[0] == 200
            status, demo_archive = call(product_path + "/reports", {})
            assert status == 200 and demo_archive["snapshot"]["report"]["evaluation"]["status"] == "satisfied"
            status, eu_pack = call("/api/v1/compliance/packs/eu-ai-act-chatbot-transparency/versions/0.1.0")
            assert status == 200 and eu_pack["review"]["status"] == "draft"
            assert len(eu_pack["controls"]) == 6
            eu_profile = json.loads((root / "examples/eu-customer-support-product.json").read_text())
            eu_profile["application_ids"] = [application["application"]["id"]]
            observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
            for fact in eu_profile["facts"].values():
                fact["observed_at"] = observed_at
            status, eu_product = call("/api/v1/compliance/products", eu_profile)
            assert status == 200
            eu_product_path = "/api/v1/compliance/products/" + eu_product["id"]
            status, eu_archive = call(eu_product_path + "/reports", {})
            assert status == 200 and eu_archive["summary"]["status"] == "insufficient_evidence"
            categories = {finding["category"] for finding in eu_archive["snapshot"]["report"]["evaluation"]["findings"]}
            assert categories == {"evidence_gap", "manual_review"}
            eu_profile.update(revision=eu_product["revision"], version="2.0.0")
            eu_profile["facts"]["transparency.notice_present"] = {
                "value": False, "evidence_id": "synthetic-ui-001", "source": "assessment", "observed_at": observed_at,
            }
            status, updated_eu = call(eu_product_path, eu_profile, "PUT")
            assert status == 200
            status, gap_archive = call(eu_product_path + "/reports", {})
            assert status == 200 and gap_archive["summary"]["status"] == "gaps_detected"
            eu_profile["revision"] = updated_eu["revision"]
            for name in ("transparency.notice_present", "transparency.notice_identifies_ai", "transparency.notice_at_first_interaction", "assurance.ui_evidence_current", "transparency.clarity_review_recorded", "transparency.accessibility_review_recorded"):
                eu_profile["facts"][name] = {
                    "value": True, "evidence_id": "synthetic-ui-002", "source": "assessment", "observed_at": observed_at,
                }
            eu_profile["facts"]["scope.review_document_present"] = {
                "value": True, "evidence_id": "synthetic-scope-doc", "source": "document", "observed_at": observed_at,
            }
            assert call(eu_product_path, eu_profile, "PUT")[0] == 200
            status, reviewed_inputs_archive = call(eu_product_path + "/reports", {})
            assert status == 200 and reviewed_inputs_archive["summary"]["status"] == "insufficient_evidence"
            findings = reviewed_inputs_archive["snapshot"]["report"]["evaluation"]["findings"]
            assert len(findings) == 3 and all(finding["category"] == "manual_review" for finding in findings)
            for retained in (eu_archive, gap_archive, reviewed_inputs_archive):
                archived_path = "/api/v1/compliance/reports/" + retained["summary"]["id"]
                assert call(archived_path)[1]["summary"] == retained["summary"]
                assert call(archived_path + "/replay", {})[1]["matches"] is True
            assert len(call(eu_product_path + "/reports")[1]["reports"]) == 3
            profile["facts"]["runtime.audit_available"] = profile["facts"]["product.user_facing"]
            profile["revision"] = product["revision"]
            assert call(product_path, profile, "PUT")[0] == 400
            saved_registry = json.loads((data_dir / "products.json").read_text())
            assert saved_registry["products"][0]["id"] == product["id"]
            assert (data_dir / "products.json").stat().st_mode & 0o777 == 0o600
            (packs / "demo.json").unlink()
            assert call("/api/v1/compliance/packs")[1] == catalog  # Immutable loaded plugin.
            for path in data_dir.rglob("*"):
                if path.is_file():
                    assert b"synthetic-private-fact-value" not in path.read_bytes()
                    assert b"sk-synthetic-private-runtime" not in path.read_bytes()
        finally:
            child.terminate()
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            child.stderr.close()
        # A restart reloads the product registry and recomputes reports instead
        # of replaying a passing result cached before shutdown.
        shutil.copyfile(root / "examples/rule-packs/demo-ai-governance.json", packs / "demo.json")
        changed_pack = json.loads((root / "examples/rule-packs/eu-ai-act-chatbot-transparency.json").read_text())
        changed_pack["description"] += " Synthetic restart metadata change."
        (packs / "eu.json").write_text(json.dumps(changed_pack))
        child = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise AssertionError(child.stderr.read().decode())
                try:
                    if call("/healthz")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError("Restarted gateway did not start")
            assert call("/api/v1/compliance/products")[0] == 401
            assert call("/api/v1/auth/login", {"password": "synthetic compliance administrator password"})[0] == 200
            assert call(product_path)[1]["id"] == product["id"]
            assert await_report("satisfied")["snapshot"]["policy_revision"] == 3
            report_path = "/api/v1/compliance/reports/" + eu_archive["summary"]["id"]
            assert call(report_path)[1]["summary"] == eu_archive["summary"]
            status, restart_replay = call(report_path + "/replay", {})
            assert status == 200 and restart_replay["matches"] is True
            new_catalog = call("/api/v1/compliance/packs")[1]["packs"]
            current_eu = next(pack for pack in new_catalog if pack["id"] == eu_profile["pack_id"])
            assert current_eu["sha256"] != eu_archive["summary"]["pack_sha256"]
            if output_dir is not None:
                def stage(label, filename, retained):
                    evaluation = retained["snapshot"]["report"]["evaluation"]
                    exported[filename] = retained
                    return {
                        "label": label, "file": filename, "report_id": retained["summary"]["id"],
                        "product_revision": retained["summary"]["product_revision"],
                        "product_version": retained["summary"]["product_version"],
                        "evaluation": evaluation,
                        "counts": {kind: sum(control["status"] == kind for control in evaluation["controls"]) for kind in ("pass", "fail", "unknown", "not_applicable")},
                    }
                summary = {
                    "schema_version": 1, "started_at": started_at,
                    "synthetic_data": True, "result": "passed",
                    "gateway": {
                        "http_status": blocked_status, "request_id": blocked_record["request_id"],
                        "outcome": blocked_record["outcome"], "error_code": blocked_record["error_code"],
                        "upstream_attempted": blocked_record["upstream_attempted"],
                        "audit_bytes_before": report["snapshot"]["audit_bytes"],
                        "audit_bytes_after": runtime_report["snapshot"]["audit_bytes"],
                        "request_count": demo_archive["snapshot"]["input"]["facts"]["runtime.sample.request_count"]["value"],
                        "policy_block_count": demo_archive["snapshot"]["input"]["facts"]["runtime.sample.policy_block_count"]["value"],
                    },
                    "stages": [
                        stage("证据尚未提供", "eu-missing-evidence.json", eu_archive),
                        stage("告知指标不满足", "eu-notice-gap.json", gap_archive),
                        stage("补齐指标，保留人工复核", "eu-manual-review.json", reviewed_inputs_archive),
                    ],
                    "checks": {
                        "historical_replay_matches": restart_replay["matches"],
                        "retained_after_restart": True, "active_pack_changed": current_eu["sha256"] != eu_archive["summary"]["pack_sha256"],
                        "runtime_override_rejected": True, "request_secret_not_persisted": True,
                    },
                }
                exported.update({"runtime-report.json": runtime_report, "blocked-call-record.json": blocked_record, "replay-after-restart.json": restart_replay})
        finally:
            child.terminate()
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            child.stderr.close()
        (packs / "invalid.json").write_text('{"schema_version":999}')
        failed = subprocess.run([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
        assert failed.returncode != 0 and b"load compliance rule packs" in failed.stderr
        if output_dir is not None:
            summary.update(finished_at=datetime.now(timezone.utc).isoformat(), duration_ms=round((time.perf_counter() - started) * 1000, 1))
            output_dir = Path(output_dir).resolve()
            output_dir.mkdir(parents=True, exist_ok=False)
            exported["summary.json"] = summary
            for filename, value in exported.items():
                destination = output_dir / filename
                destination.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
                destination.chmod(0o600)
            print(f"Test results: {output_dir}")
    print("Compliance smoke passed: plugins, product events, EU transparency draft, control/evidence/manual findings, immutable report snapshots, historical replay after profile/plugin changes and restart, private persistence, privacy and invalid-pack startup rejection.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="Retain synthetic API reports and a summary in a new directory after all checks pass")
    main(parser.parse_args().output_dir)
