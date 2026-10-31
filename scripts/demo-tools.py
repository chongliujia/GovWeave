#!/usr/bin/env python3
"""Exercise controlled read tools against a local fixture and an isolated GovWeave binary."""
import argparse
from datetime import datetime, timezone
import http.cookiejar
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
MAX_BODY_BYTES = 4096
MAX_RESPONSE_BYTES = 256 * 1024
NORMAL_TEXT = "Synthetic support guide: use the account recovery page."
FIXTURE_CREDENTIAL = "sk-SyntheticToolCredentialNeverUseInProduction123456"
PROVIDER_KEY = "synthetic-read-provider-token"
CALLER_HEADER = "synthetic-caller-header-must-not-be-forwarded"
RESOURCE_IDS = ("public-guide", "restricted-guide", "credential-guide")


class DemoError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DemoError(message)


class ReadToolServer(HTTPServer):
    def __init__(self):
        self._lock = threading.Lock()
        self._calls = 0
        self._header_errors = 0
        super().__init__(("127.0.0.1", 0), ReadToolHandler)

    def state(self):
        with self._lock:
            return self._calls, self._header_errors

    def record(self, valid_headers):
        with self._lock:
            self._calls += 1
            if not valid_headers:
                self._header_errors += 1


class ReadToolHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def respond(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if self.path != "/read":
            self.respond(404, {"error": "fixture_path_not_found"})
            return
        if self.headers.get("Transfer-Encoding"):
            self.respond(400, {"error": "fixture_encoding_not_supported"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BODY_BYTES:
                self.respond(413, {"error": "fixture_request_too_large"})
                return
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or set(payload) != {"resource_id"}:
                raise ValueError("unsupported fixture request")
            resource_id = payload["resource_id"]
            if resource_id not in RESOURCE_IDS:
                raise ValueError("unknown fixture resource")
        except (ValueError, OSError, TypeError):
            self.respond(400, {"error": "fixture_invalid_request"})
            return
        valid_headers = (
            self.headers.get("Authorization") == "Bearer " + PROVIDER_KEY
            and self.headers.get("X-Demo-Caller-Secret") is None
            and self.headers.get("Cookie") is None
            and self.headers.get("Origin") is None
        )
        self.server.record(valid_headers)
        if not valid_headers:
            self.respond(403, {"error": "fixture_invalid_headers"})
            return
        text = FIXTURE_CREDENTIAL if resource_id == "credential-guide" else NORMAL_TEXT
        self.respond(200, {"text": text})


class ToolSession:
    def __init__(self, binary, rule_packs=(), test_suites=(), provider_factory=ReadToolServer):
        self.binary = binary
        self.rule_packs = tuple(Path(path) for path in rule_packs)
        self.test_suites = tuple(Path(path) for path in test_suites)
        self.provider_factory = provider_factory
        self.temporary = None
        self.directory = None
        self.provider = None
        self.worker = None
        self.child = None
        self.origin = None
        self.key = None
        self.application = None
        self.tool = None
        self.admin = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )
        self.public = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __enter__(self):
        try:
            self.start()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *args):
        self.close()

    def request(self, path, payload=None, method=None, expected=200, public=False, key=None):
        headers = {"Content-Type": "application/json"}
        if public:
            headers["X-Demo-Caller-Secret"] = CALLER_HEADER
            if key is not None:
                headers["Authorization"] = "Bearer " + key
            opener = self.public
        else:
            headers.update({"X-GovWeave-Request": "console", "Origin": self.origin})
            opener = self.admin
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.origin + path, data=body, method=method, headers=headers)
        try:
            response = opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
            request_id = response.headers.get("X-Request-ID")
        require(len(data) <= MAX_RESPONSE_BYTES, "gateway response exceeded the demo limit")
        require(status == expected, f"unexpected HTTP status: expected {expected}, received {status}")
        try:
            result = json.loads(data)
        except ValueError:
            raise DemoError("gateway did not return JSON") from None
        require(isinstance(result, dict), "gateway returned an unexpected response shape")
        return result, request_id

    def start(self):
        require(self.binary.is_file(), "binary not found; run make build first")
        self.temporary = tempfile.TemporaryDirectory(prefix="govweave-tool-demo-")
        self.directory = Path(self.temporary.name)
        for category, sources in (("rule-packs", self.rule_packs), ("test-suites", self.test_suites)):
            if sources:
                folder = self.directory / category
                folder.mkdir(mode=0o700)
                for source in sources:
                    destination = folder / source.name
                    shutil.copyfile(source, destination)
                    destination.chmod(0o600)
        self.provider = self.provider_factory()
        self.worker = threading.Thread(target=self.provider.serve_forever, daemon=True)
        self.worker.start()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        env = {key: value for key, value in os.environ.items() if not key.startswith(("GOVWEAVE_", "MOONSHOT_"))}
        env.update(GOVWEAVE_DATA_DIR=str(self.directory), GOVWEAVE_LISTEN_ADDR=f"127.0.0.1:{port}")
        self.child = subprocess.Popen([str(self.binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            require(self.child.poll() is None, "isolated gateway exited during startup")
            try:
                self.request("/healthz")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        else:
            raise DemoError("isolated gateway did not become ready")
        self.request("/api/v1/auth/setup", {"password": secrets.token_urlsafe(32)})
        application, _ = self.request("/api/v1/applications", {
            "revision": 0, "name": "Synthetic tool client", "allowed_connections": [],
        })
        self.application, self.key = application["application"], application["api_key"]
        self.tool, _ = self.request("/api/v1/tools", {
            "revision": 0,
            "name": "Synthetic support read tool",
            "alias": "support-docs",
            "endpoint": f"http://127.0.0.1:{self.provider.server_port}/read",
            "api_key": PROVIDER_KEY,
            "enabled": True,
            "allow_insecure_http": True,
            "timeout_seconds": 2,
            "output_mode": "block",
            "resources": [
                {"resource_id": "public-guide", "sensitivity": "public", "allowed_applications": [self.application["id"]]},
                {"resource_id": "restricted-guide", "sensitivity": "restricted", "allowed_applications": []},
                {"resource_id": "credential-guide", "sensitivity": "internal", "allowed_applications": [self.application["id"]]},
            ],
        }, expected=201)

    def close(self):
        if self.child is not None:
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
            self.child = None
        if self.provider is not None:
            if self.worker is not None and self.worker.is_alive():
                self.provider.shutdown()
                self.worker.join(timeout=4)
            self.provider.server_close()
            self.provider = None
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None


def exercise(session):
    stages = []
    request_ids = []
    path = "/v1/tools/support-docs/invoke"

    def invoke(name, body, expected, upstream_calls, key, decision=None):
        before = session.provider.state()[0]
        result, request_id = session.request(path, body, expected=expected, public=True, key=key)
        delta = session.provider.state()[0] - before
        require(delta == upstream_calls, f"{name}: upstream call count did not match")
        require(request_id is not None, f"{name}: missing request identifier")
        if decision is not None:
            require(result.get("governance", {}).get("decision") == decision, f"{name}: unexpected governance decision")
        if expected != 200:
            encoded = json.dumps(result)
            require("text" not in result and FIXTURE_CREDENTIAL not in encoded and NORMAL_TEXT not in encoded, f"{name}: rejected response disclosed tool content")
        stages.append({"scenario": name, "http_status": expected, "upstream_calls": delta, "request_id": request_id, "decision": result.get("governance", {}).get("decision", "not_evaluated")})
        request_ids.append(request_id)
        return result

    allowed = invoke("authorized_read", {"resource_id": "public-guide"}, 200, 1, session.key, "allow")
    require(allowed.get("text") == NORMAL_TEXT, "authorized_read: expected content was not returned")
    governance = allowed["governance"]
    require(governance.get("tool_id") == session.tool["id"] and governance.get("tool_revision") == session.tool["revision"], "authorized_read: configuration revision was not pinned")
    require(governance.get("snapshot_sha256") == session.tool["snapshot_sha256"], "authorized_read: configuration hash did not match")
    require(governance.get("authorization") == "allowed" and governance.get("content", {}).get("state") == "not_observed", "authorized_read: unexpected evaluation results")
    invoke("unauthorized_resource", {"resource_id": "restricted-guide"}, 403, 0, session.key, "block")
    blocked = invoke("credential_output", {"resource_id": "credential-guide"}, 403, 1, session.key, "block")
    require(blocked["governance"].get("content", {}).get("state") == "observed", "credential_output: credential finding was missing")
    invoke("caller_identity_spoof", {"resource_id": "restricted-guide", "application_id": session.application["id"]}, 400, 0, session.key)
    invoke("missing_application_key", {"resource_id": "public-guide"}, 401, 0, None)
    session.request("/api/v1/applications/" + session.application["id"] + "/revoke", {"revision": session.application["revision"]})
    invoke("revoked_application_key", {"resource_id": "public-guide"}, 401, 0, session.key)

    audit, _ = session.request("/api/v1/requests?limit=100")
    records = {record["request_id"]: record for record in audit["records"]}
    require(all(identifier in records for identifier in request_ids), "audit did not retain every terminal request")
    require(all(records[identifier]["phase"] == "finished" for identifier in request_ids), "audit contains an unfinished request after response release")
    for stage in stages[:3]:
        record = records[stage["request_id"]]
        require(record.get("tool_governance", {}).get("decision") == stage["decision"], "audit did not preserve the tool decision")
        require(record["upstream_attempted"] == (stage["upstream_calls"] > 0), "audit upstream metadata disagreed with actual invocation")
    audit_data = (session.directory / "calls.jsonl").read_text()
    excluded = [NORMAL_TEXT, FIXTURE_CREDENTIAL, PROVIDER_KEY, session.key, CALLER_HEADER, "/read", *RESOURCE_IDS]
    require(all(value not in audit_data and value not in json.dumps(audit) for value in excluded), "audit contained disallowed request or provider data")
    calls, header_errors = session.provider.state()
    require(calls == 2 and header_errors == 0, "upstream request isolation did not hold")
    return {
        "schema_version": 1,
        "result": "passed",
        "synthetic_data": True,
        "target_kind": "scripted_read_tool",
        "scope": "Actual binary API enforcement against a local scripted fixture; no model or detector-quality measurement.",
        "provider_calls": calls,
        "caller_headers_isolated": True,
        "metadata_only_audit": True,
        "terminal_audit_verified": True,
        "tool_revision": session.tool["revision"],
        "snapshot_sha256": session.tool["snapshot_sha256"],
        "stages": stages,
    }


def save_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")


def main(args):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or ROOT / "dist" / "tool-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        with ToolSession(args.binary.resolve()) as session:
            summary = exercise(session)
            save_json(output / "summary.json", summary)
        print("Local controlled-read demonstration passed. No external model or customer data was used.")
        for stage in summary["stages"]:
            print(f"{stage['scenario']}: HTTP {stage['http_status']}, upstream calls {stage['upstream_calls']}, decision {stage['decision']}")
        print(f"Private summary saved to: {output / 'summary.json'}")
        return 0
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated processes were stopped.")
        return 130
    except DemoError as error:
        # DemoError messages are fixed local assertions, never provider data.
        print(f"Demonstration failed: {error}.")
        return 1
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        # Provider bodies, keys, and raw transport exceptions never become output.
        print("Demonstration failed. Confirm the current binary was built and the local endpoints are available.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "govweave", help="Built GovWeave executable")
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, help="New private directory (default: dist/tool-demo/<unique-run>)")
    raise SystemExit(main(parser.parse_args()))
