#!/usr/bin/env python3
"""Exercise sensitive-output protection locally; --kimi opts into three synthetic model calls."""
import argparse
from datetime import datetime, timezone
import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import warnings


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("govweave_sensitive_demo_helpers", ROOT / "scripts" / "demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)
require = TOOLS.require
DemoError = TOOLS.DemoError
ALIAS = "sensitive-demo"
MODEL = "kimi-k2.6"
ENDPOINT = "https://api.moonshot.cn/v1"
SYNTHETIC_KEY = "synthetic-sensitive-provider-token"
CATEGORIES = ["credential", "email", "phone"]
TEXTS = {
    "harmless": "The synthetic demonstration is ready.",
    "email": "Synthetic email: demo.person@example.com",
    "phone": "Synthetic phone: +86 138 0000 0017",
    "credential": "sk-SyntheticSensitiveDemoNeverARealCredential123456",
}
PROMPTS = {
    name: "For a synthetic software test, reply with exactly the following single line, without explanation: " + text
    for name, text in TEXTS.items()
}


class ModelFixture(HTTPServer):
    def __init__(self):
        self.calls = 0
        self.invalid_requests = 0
        super().__init__(("127.0.0.1", 0), ModelHandler)


class ModelHandler(BaseHTTPRequestHandler):
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
            require(0 < size <= 4096 and not self.headers.get("Transfer-Encoding"), "invalid size")
            body = json.loads(self.rfile.read(size))
            require(self.path == "/v1/chat/completions", "invalid path")
            require(self.headers.get("Authorization") == "Bearer " + SYNTHETIC_KEY, "invalid auth")
            require(all(self.headers.get(name) is None for name in ("Cookie", "Origin", "X-Demo-Caller-Secret")), "caller headers forwarded")
            require(body.get("model") == "synthetic-sensitive-model" and body.get("stream") is False, "invalid model mode")
            require(body.get("max_tokens") == 128 and body.get("thinking") == {"type": "disabled"}, "unexpected generation parameters")
            messages = body.get("messages")
            require(isinstance(messages, list) and len(messages) == 1 and messages[0].get("role") == "user", "invalid messages")
            name = next((key for key, prompt in PROMPTS.items() if prompt == messages[0].get("content")), None)
            require(name is not None, "unknown synthetic prompt")
            status, payload = 200, {
                "id": "synthetic-provider-id", "model": "synthetic-sensitive-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": TEXTS[name]}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 24, "completion_tokens": 16, "total_tokens": 40},
                "provider_extension": "synthetic-extension-must-be-dropped",
            }
        except (DemoError, ValueError, TypeError, KeyError, AttributeError, OSError):
            self.server.invalid_requests += 1
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass


class SensitiveSession(TOOLS.ToolSession):
    def __init__(self, binary, kimi=False, provider_key=SYNTHETIC_KEY, detector_version="sensitive-text-v1", rule_packs=(), test_suites=(), provider_factory=ModelFixture):
        super().__init__(binary, rule_packs=rule_packs)
        self.test_suites = tuple(Path(path) for path in test_suites)
        self.provider_factory = provider_factory
        self.detector_version = detector_version
        self.kimi = kimi
        self.provider_key = provider_key

    def request_result(self, path, payload=None, method=None, public=False):
        headers = {"Content-Type": "application/json"}
        opener = self.admin
        if public:
            opener = self.public
            headers.update(Authorization="Bearer " + self.key)
            headers["X-Demo-Caller-Secret"] = TOOLS.CALLER_HEADER
        else:
            headers.update({"X-GovWeave-Request": "console", "Origin": self.origin})
        request = urllib.request.Request(self.origin + path, data=None if payload is None else json.dumps(payload).encode(), method=method, headers=headers)
        start = time.perf_counter_ns()
        try:
            response = opener.open(request, timeout=55 if self.kimi else 5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(TOOLS.MAX_RESPONSE_BYTES + 1)
            status, request_id = response.status, response.headers.get("X-Request-ID")
        require(len(data) <= TOOLS.MAX_RESPONSE_BYTES, "gateway response exceeded the demo limit")
        try:
            result = json.loads(data)
        except ValueError:
            raise DemoError("gateway did not return JSON") from None
        require(isinstance(result, dict), "gateway response shape was invalid")
        return status, result, request_id, round((time.perf_counter_ns() - start) / 1_000_000, 3)

    def start(self):
        require(self.binary.is_file(), "binary not found; run make build first")
        self.temporary = tempfile.TemporaryDirectory(prefix="govweave-sensitive-demo-")
        self.directory = Path(self.temporary.name)
        for category, sources in (("rule-packs", self.rule_packs), ("test-suites", self.test_suites)):
            if sources:
                folder = self.directory / category
                folder.mkdir(mode=0o700)
                for source in sources:
                    destination = folder / source.name
                    shutil.copyfile(source, destination)
                    destination.chmod(0o600)
        endpoint = ENDPOINT
        if not self.kimi:
            self.provider = self.provider_factory()
            self.worker = threading.Thread(target=self.provider.serve_forever, daemon=True)
            self.worker.start()
            endpoint = f"http://127.0.0.1:{self.provider.server_port}/v1"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        env = {name: value for name, value in os.environ.items() if not name.startswith("GOVWEAVE_") and name != "MOONSHOT_API_KEY"}
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
        connection, _ = self.request("/api/v1/connections", {
            "revision": 0, "name": "Synthetic sensitive-output demo", "base_url": endpoint,
            "model": MODEL if self.kimi else "synthetic-sensitive-model", "alias": ALIAS,
            "api_key": self.provider_key, "enabled": True, "allow_insecure_http": not self.kimi,
            "timeout_seconds": 45 if self.kimi else 3,
        })
        application, _ = self.request("/api/v1/applications", {
            "revision": 0, "name": "Synthetic sensitive-output client", "allowed_connections": [connection["id"]],
        })
        self.application, self.key = application["application"], application["api_key"]
        persisted = (self.directory / "gateway.json").read_text()
        require(self.provider_key not in persisted and "credential_ciphertext" in persisted, "provider credential was not encrypted at rest")
        require((self.directory / "gateway.json").stat().st_mode & 0o077 == 0, "gateway configuration permissions were not private")

    def policy(self, mode):
        current, _ = self.request("/api/v1/policies/sensitive-output")
        updated, _ = self.request("/api/v1/policies/sensitive-output", {
            "revision": current["revision"], "mode": mode,
            "categories": CATEGORIES, "application_ids": [self.application["id"]], "detector_version": self.detector_version,
        }, method="PUT")
        return updated


def exercise(session):
    stages, expected = [], {}
    policy = session.policy("block")

    def stage(name, path, payload, wanted_status, wanted_result, categories, upstream):
        before = session.provider.calls if session.provider else None
        status, result, request_id, duration = session.request_result(path, payload, public=True)
        require(isinstance(request_id, str) and 1 <= len(request_id) <= 128, "missing request identifier")
        require(request_id not in expected, "duplicate request identifier")
        if session.provider:
            require(session.provider.calls - before == int(upstream), "fixture upstream call count did not match")
        if status != 200:
            encoded = json.dumps(result)
            require("choices" not in result and all(text not in encoded for text in TEXTS.values()), "withheld response disclosed synthetic model text")
        elif path.endswith("completions"):
            require("provider_extension" not in result and result.get("model") == ALIAS, "protected response projection did not hold")
        stages.append({"scenario": name, "http_status": status, "request_id": request_id, "round_trip_duration_ms": duration})
        expected[request_id] = (wanted_status, wanted_result, categories, upstream, policy["revision"])
        return result

    if not session.kimi:
        for category in CATEGORIES:
            result = stage("evaluate_" + category, "/v1/content/evaluations", {"text": TEXTS[category]}, 200, "block", [category], False)
            require(result.get("detection", {}).get("state") == "observed", "evaluation did not observe the synthetic category")
            require("text" not in result, "evaluation echoed input text")

    names = ("harmless", "email", "phone") if session.kimi else ("harmless", "email", "phone", "credential")
    for name in names:
        if session.kimi:
            print("Running synthetic Kimi scenario: " + name, flush=True)
        body = {"model": ALIAS, "messages": [{"role": "user", "content": PROMPTS[name]}],
                "stream": False, "max_tokens": 128, "thinking": {"type": "disabled"}}
        result = stage("block_" + name, "/v1/chat/completions", body, 200 if name == "harmless" else 403,
                       "allow" if name == "harmless" else "block", [] if name == "harmless" else [name], True)
        if not session.kimi and name == "harmless":
            require(result["choices"][0]["message"]["content"] == TEXTS[name], "harmless output changed")

    if not session.kimi:
        policy = session.policy("observe")
        result = stage("observe_email", "/v1/chat/completions", {
            "model": ALIAS, "messages": [{"role": "user", "content": PROMPTS["email"]}],
            "stream": False, "max_tokens": 128, "thinking": {"type": "disabled"},
        }, 200, "observe", ["email"], True)
        require(result["choices"][0]["message"]["content"] == TEXTS["email"], "observe mode did not release the checked text")

    if not session.kimi:
        policy = session.policy("redact")
        result = stage("evaluate_redaction", "/v1/content/evaluations", {"text": TEXTS["email"]}, 200, "redact", ["email"], False)
        require("redaction" not in result.get("policy", {}) and "text" not in result, "evaluation claimed executed redaction")
        for name, wanted_text in (("email", "Synthetic email: [REDACTED]"), ("phone", "Synthetic phone: [REDACTED]"), ("credential", "[REDACTED]"), ("harmless", TEXTS["harmless"])):
            result = stage("redact_" + name, "/v1/chat/completions", {
                "model": ALIAS, "messages": [{"role": "user", "content": PROMPTS[name]}],
                "stream": False, "max_tokens": 128, "thinking": {"type": "disabled"},
            }, 200, "allow" if name == "harmless" else "redacted", [] if name == "harmless" else [name], True)
            require(result["choices"][0]["message"]["content"] == wanted_text, "redaction did not return exactly the intended safe text")

    stage("protected_stream", "/v1/chat/completions", {
        "model": ALIAS, "messages": [{"role": "user", "content": PROMPTS["harmless"]}], "stream": True, "max_tokens": 128,
    }, 400, "error", [], False)
    audit, _ = session.request("/api/v1/requests?limit=100")
    records = {record["request_id"]: record for record in audit["records"]}
    upstream_attempts = 0
    for item in stages:
        record = records.get(item["request_id"], {})
        require(record.get("phase") == "finished", "audit did not retain the terminal decision")
        assessment = record.get("output_policy", {})
        wanted_status, wanted_result, categories, upstream, revision = expected[item["request_id"]]
        require(assessment.get("detector_version") == session.detector_version, "audit detector version did not match")
        require(assessment.get("revision") == revision, "audit policy revision did not match")
        require(record.get("http_status") == item["http_status"], "audit status did not match")
        observed_upstream = record.get("upstream_attempted") is True
        upstream_attempts += int(observed_upstream)
        require(observed_upstream == upstream, "audit upstream attempt did not match")
        item.update({
            "detector_version": assessment["detector_version"], "policy_revision": assessment["revision"], "policy_mode": assessment.get("mode"),
            "policy_result": assessment.get("result"), "detector_state": assessment.get("state"),
            "matched_categories": assessment.get("matched_categories", []),
            "check_duration_us": assessment.get("check_duration_us"), "upstream_attempted": observed_upstream,
        })
        if wanted_result == "redacted":
            redaction = assessment.get("redaction", {})
            require(redaction.get("version") == "sensitive-redaction-v1" and redaction.get("replacements") == 1, "completed redaction evidence missing")
            require(redaction.get("scope") == ("full_output" if categories == ["credential"] else "matched_spans"), "redaction scope mismatch")
            item["redaction"] = redaction
        else:
            require("redaction" not in assessment, "unperformed redaction evidence fabricated")
        matches = item["http_status"] == wanted_status and item["policy_result"] == wanted_result and item["matched_categories"] == categories
        item["result"] = "passed" if matches else "inconclusive"
        require(session.kimi or matches, "local fixture decision did not match the expected category")
    excluded = [*TEXTS.values(), *PROMPTS.values(), session.provider_key, session.key, TOOLS.CALLER_HEADER]
    audit_text = (session.directory / "calls.jsonl").read_text()
    require(all(value not in audit_text and value not in json.dumps(audit) for value in excluded), "audit contained prohibited plaintext")
    require(upstream_attempts <= (3 if session.kimi else 9), "demo exceeded its provider call limit")
    if session.provider:
        require(session.provider.calls == 9 and session.provider.invalid_requests == 0, "fixture request isolation failed")
    summary = {
        "schema_version": 1, "result": "passed" if all(item["result"] == "passed" for item in stages) else "inconclusive",
        "synthetic_data": True, "target_kind": "kimi" if session.kimi else "local_scripted_model",
        "provider_model": MODEL if session.kimi else "synthetic-sensitive-model",
        "provider_host": "api.moonshot.cn" if session.kimi else "127.0.0.1",
        "scope": "Bounded integration demonstration; not detector quality, general model safety, or legal compliance evidence.",
        "upstream_attempts": upstream_attempts, "upstream_count_source": "gateway_audit" if session.kimi else "audit_and_local_fixture",
        "max_output_tokens_per_call": 128, "retries": 0, "metadata_only_audit": True,
        "terminal_audit_verified": True, "encrypted_temporary_credential": True, "stages": stages,
    }
    require(all(value not in json.dumps(summary) for value in excluded), "summary contained prohibited plaintext")
    return summary


def read_key():
    key = os.environ.pop("MOONSHOT_API_KEY", None)
    if key is None:
        require(sys.stdin.isatty(), "--kimi needs MOONSHOT_API_KEY or an interactive terminal for hidden key input")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Moonshot API key (hidden; temporary encrypted configuration): ")
        except getpass.GetPassWarning:
            raise DemoError("terminal cannot disable key echo; use a secret-managed MOONSHOT_API_KEY instead") from None
    require(isinstance(key, str) and 8 <= len(key) <= 4096 and all(33 <= ord(char) <= 126 for char in key), "invalid API key input")
    return key


def main(args):
    try:
        require(args.binary.resolve().is_file(), "binary not found; run make build first")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = (args.output_dir or ROOT / "dist" / "sensitive-demo" / (stamp + "-" + secrets.token_hex(3))).resolve()
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        key = read_key() if args.kimi else SYNTHETIC_KEY
        if args.kimi:
            print("Kimi opt-in: up to three synthetic requests, 128 output tokens each, no retries.", flush=True)
        if args.detector == "sensitive-text-v2" and not args.kimi:
            TEXTS.update(email="Synthetic email: demo.person [at] example [dot] com", phone="Synthetic phone: ＋８６ １３８ ００００ ００１７", credential="sk-\u200bSyntheticSensitiveDemoNeverARealCredential123456")
            PROMPTS.update({name: "For a synthetic software test, reply with exactly the following single line, without explanation: " + text for name, text in TEXTS.items()})
        with SensitiveSession(args.binary.resolve(), args.kimi, key, args.detector) as session:
            summary = exercise(session)
        summary["temporary_configuration_removed"] = not session.directory.exists()
        require(summary["temporary_configuration_removed"], "temporary configuration cleanup did not complete")
        TOOLS.save_json(output / "summary.json", summary)
        print("Sensitive-output demonstration: " + summary["result"] + ".")
        for item in summary["stages"]:
            print(f"{item['scenario']}: HTTP {item['http_status']}, policy {item['policy_result']}, categories {','.join(item['matched_categories']) or 'none'}")
        print(f"Private metadata summary: {output / 'summary.json'}")
        return 0 if summary["result"] == "passed" else 2
    except KeyboardInterrupt:
        print("Demonstration interrupted; isolated processes and temporary configuration were cleaned up.")
        return 130
    except DemoError as error:
        print(f"Demonstration failed: {error}.")
        return 1
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        print("Demonstration failed; confirm the current binary, local endpoints and optional provider availability. No raw error or response was saved.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "govweave", help="Built GovWeave executable; run make build first")
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, help="New private directory (default: dist/sensitive-demo/<unique-run>)")
    parser.add_argument("--detector", choices=["sensitive-text-v1", "sensitive-text-v2"], default="sensitive-text-v1", help="Explicit policy detector generation; v2 local fixtures use obfuscated text")
    parser.add_argument("--kimi", action="store_true", help="Opt in to at most three real Moonshot calls; hidden key prompt or MOONSHOT_API_KEY")
    raise SystemExit(main(parser.parse_args()))
