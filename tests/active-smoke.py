#!/usr/bin/env python3
"""Real-binary active assessment acceptance with a local synthetic model only."""
import argparse
from datetime import datetime, timedelta, timezone
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def main(output_dir=None):
    root = Path(__file__).resolve().parents[1]
    model = {"fail": False, "calls": 0}

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            assert self.path == "/v1/chat/completions"
            assert self.headers.get("Authorization") == "Bearer synthetic-provider-secret"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["model"] == "fixture-model" and body["stream"] is False
            assert body["max_tokens"] == 64
            model["calls"] += 1
            content = '{"status":"ok"}' if "JSON" in body["messages"][0]["content"] else "GOVWEAVE_TEST_OK"
            if model["fail"]:
                content = "unexpected"
            payload = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix="govweave-active-") as directory:
            data_dir = Path(directory)
            for category, filename in [("rule-packs", "nist-ai-rmf-lifecycle.json"), ("test-suites", "chat-contract-smoke.json")]:
                destination = data_dir / category
                destination.mkdir()
                shutil.copyfile(root / "examples" / category / filename, destination / filename)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            env = {**os.environ, "GOVWEAVE_DATA_DIR": directory, "GOVWEAVE_LISTEN_ADDR": f"127.0.0.1:{port}"}
            for key in ("GOVWEAVE_PUBLIC_URL", "GOVWEAVE_ORGANIZATION_NAME", "GOVWEAVE_ADMIN_TOKEN_FILE"):
                env.pop(key, None)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

            def call(path, payload=None, method=None, authenticated=True):
                headers = {"Content-Type": "application/json", "X-GovWeave-Request": "console", "Origin": origin}
                request = urllib.request.Request(origin + path, data=None if payload is None else json.dumps(payload).encode(), headers=headers, method=method)
                client = opener if authenticated else urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with client.open(request, timeout=5) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    return error.code, json.load(error)

            def start():
                process = subprocess.Popen([str(root / "bin/govweave")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError(process.stderr.read().decode())
                    try:
                        if call("/healthz")[0] == 200:
                            return process
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.05)
                process.kill()
                process.wait()
                raise AssertionError("Gateway did not start")

            def stop(process):
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process.stderr.close()

            def await_run(run_id):
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    status, run = call("/api/v1/compliance/test-runs/" + run_id)
                    assert status == 200, run
                    if run["state"] != "running":
                        return run
                    time.sleep(0.02)
                raise AssertionError("Test run did not complete")

            def execute(phase):
                status, summary = call(product_path + "/test-runs", {"phase": phase})
                assert status == 202, summary
                return await_run(summary["id"])

            child = start()
            assert call("/api/v1/compliance/test-suites", authenticated=False)[0] == 401
            assert call("/api/v1/auth/setup", {"password": "synthetic active assessment administrator password"})[0] == 200
            assert len(call("/api/v1/compliance/test-suites")[1]["suites"]) == 1
            assert call("/api/v1/compliance/test-suites/chat-contract-smoke/versions/1.0.0")[0] == 200
            status, connection = call("/api/v1/connections", {"name": "Synthetic provider", "base_url": f"http://127.0.0.1:{provider.server_port}/v1", "model": "fixture-model", "alias": "assistant", "enabled": True, "api_key": "synthetic-provider-secret", "allow_insecure_http": True, "timeout_seconds": 2})
            assert status == 200
            status, app = call("/api/v1/applications", {"name": "Synthetic tested app", "allowed_connections": [connection["id"]]})
            assert status == 200
            status, product = call("/api/v1/compliance/products", {"revision": 0, "name": "Synthetic lifecycle product", "version": "1.0.0", "application_ids": [app["application"]["id"]], "pack_id": "nist-ai-rmf-lifecycle", "pack_version": "0.1.0", "facts": {}})
            assert status == 200
            product_path = "/api/v1/compliance/products/" + product["id"]
            plan = json.loads((root / "examples/test-plan.json").read_text())
            plan.update(application_id=app["application"]["id"], timeout_seconds=2, max_output_tokens=64, retain_responses=True, schedule_enabled=True, interval_seconds=300)
            assert call(product_path + "/test-plan", plan, "PUT")[0] == 200
            assert model["calls"] == 0  # Saving a recurring plan does not immediately execute it.
            assert call(product_path + "/test-runs", {"phase": "bad"})[0] == 400
            assert call(product_path + "/test-runs", {"phase": "operation", "application_id": "forged"})[0] == 400
            pre = execute("pre_deployment")
            operation = execute("operation")
            assert pre["status"] == operation["status"] == "passed"
            assert model["calls"] == 4
            controls = {control["id"]: control["status"] for control in operation["evaluation"]["controls"]}
            assert controls["NIST-PREDEPLOYMENT-TEST"] == controls["NIST-OPERATION-TEST"] == "pass"
            assert sum(value == "unknown" for value in controls.values()) == 5
            assert operation["evaluation"]["legal_compliance"] == "not_determined"
            model["fail"] = True
            regression = execute("operation")
            assert regression["status"] == "failed" and regression["comparison"]["regressions"] == 2
            assert all(record["operation"] == "assessment.chat.completions" for record in call("/api/v1/requests?limit=100")[1]["records"])
            assert call(product_path + "/test-runs")[1]["runs"][0]["id"] == regression["id"]
            stop(child)
            child = None
            # Simulate elapsed wall time while stopped, then exercise the real
            # persisted-plan scheduler after restart, not a manual POST.
            state_path = data_dir / "test-plans.json"
            state = json.loads(state_path.read_text())
            state["plans"][0]["next_run_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            state_path.write_text(json.dumps(state))
            model["fail"] = False
            child = start()
            assert call("/api/v1/auth/login", {"password": "synthetic active assessment administrator password"})[0] == 200
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                current = call(product_path + "/test-plan")[1]
                if current["last_run_id"] != regression["id"]:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("Persisted periodic plan did not execute")
            recovery = await_run(current["last_run_id"])
            assert recovery["trigger"] == "scheduled" and recovery["status"] == "passed"
            assert recovery["comparison"]["recoveries"] == 2
            count = model["calls"]
            replay = call("/api/v1/compliance/test-runs/" + pre["id"] + "/replay", {})[1]
            assert replay["matches"] and model["calls"] == count
            for run in (pre, operation, regression, recovery):
                data = json.dumps(run)
                assert app["api_key"] not in data and "synthetic-provider-secret" not in data
                assert run["cases"][0].get("response") is not None
            assert (data_dir / "test-plans.json").stat().st_mode & 0o777 == 0o600
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in (data_dir / "test-runs").glob("*.json"))
            stop(child)
            child = None
            summary = {"result": "passed", "synthetic_data": True, "provider_calls": count, "pre_deployment": pre["status"], "operation": operation["status"], "regressions": regression["comparison"]["regressions"], "scheduled_recoveries": recovery["comparison"]["recoveries"], "replay_without_inference": replay["matches"], "manual_reviews_remaining": 5}
            if output_dir is not None:
                output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
                for name, value in {"summary.json": summary, "pre-deployment.json": pre, "operation.json": operation, "regression.json": regression, "scheduled-recovery.json": recovery}.items():
                    path = output_dir / name
                    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
                    path.chmod(0o600)
            print(json.dumps(summary, ensure_ascii=False))
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            child.stderr.close()
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="Retain synthetic test runs in a new directory")
    main(parser.parse_args().output_dir)
