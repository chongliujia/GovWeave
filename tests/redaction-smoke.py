#!/usr/bin/env python3
"""Verify the Python reference client against actual redacted tool HTTP output."""
import importlib.util
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("redaction_demo", ROOT / "scripts" / "demo-sensitive.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
sys.path.insert(0, str(ROOT / "examples" / "python"))
from govweave_tools import GovernedToolClient, ToolCallError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.connection.settimeout(3)
        self.server.calls += 1
        size = int(self.headers.get("Content-Length", "0"))
        valid = self.path == "/read" and self.headers.get("Authorization") == "Bearer synthetic-redaction-provider"
        valid = valid and 0 < size <= 4096 and json.loads(self.rfile.read(size)) == {"resource_id": "example"}
        body = json.dumps({"text": self.server.text} if valid else {"error": "invalid_fixture_request"}).encode()
        self.send_response(200 if valid else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    with HTTPServer(("127.0.0.1", 0), Handler) as provider:
        provider.calls = 0
        provider.text = "Email: private [at] example [dot] net"
        worker = threading.Thread(target=provider.serve_forever, daemon=True)
        worker.start()
        try:
            with demo.SensitiveSession(ROOT / "bin" / "govweave", detector_version="sensitive-text-v2") as session:
                session.policy("redact")
                settings = {"revision": 0, "name": "Redaction fixture", "alias": "redaction-read", "enabled": True,
                            "endpoint": f"http://127.0.0.1:{provider.server_port}/read", "api_key": "synthetic-redaction-provider",
                            "allow_insecure_http": True, "timeout_seconds": 3, "output_mode": "block",
                            "resources": [{"resource_id": "example", "sensitivity": "internal", "allowed_applications": [session.application["id"]]}]}
                tool, _ = session.request("/api/v1/tools", settings, expected=201)
                client = GovernedToolClient(session.origin, session.key, "redaction-read", allow_insecure_http=True)
                response = client.invoke("example")
                demo.require(response.text == "Email: [REDACTED]" and response.governance["decision"] == "redact", "reference client did not accept verified redaction")
                demo.require(response.governance["output_policy"]["redaction"]["scope"] == "matched_spans", "missing partial redaction evidence")
                provider.text = "-----BEGIN PRIVATE KEY-----\nsynthetic-private-body\n-----END PRIVATE KEY-----"
                try:
                    client.invoke("example")
                except ToolCallError as error:
                    demo.require(error.code == "tool_output_blocked", "legacy credential control did not block")
                else:
                    raise demo.DemoError("legacy credential block was bypassed")
                settings.update(revision=tool["revision"], output_mode="observe")
                session.request("/api/v1/tools/" + tool["id"], settings, method="PUT")
                response = client.invoke("example")
                demo.require(response.text == "[REDACTED]" and response.governance["output_policy"]["redaction"]["scope"] == "full_output", "credential body was not completely withheld")
                provider.text = " ".join(f"user{i} [at] example [dot] net" for i in range(33))
                try:
                    client.invoke("example")
                except ToolCallError as error:
                    demo.require(error.code == "content_output_unavailable", "unknown detection was not withheld")
                else:
                    raise demo.DemoError("unknown output escaped")
                demo.require(provider.calls == 4, "unexpected retries")
                audit = (session.directory / "calls.jsonl").read_text()
                demo.require(all(value not in audit for value in ["synthetic-private-body", "private [at] example", "start_byte", "end_byte", "synthetic-redaction-provider"]), "audit contained source content")
            demo.require(not session.directory.exists(), "temporary configuration remained")
        finally:
            provider.shutdown()
            worker.join(timeout=3)
    print("Redaction smoke passed: real Python client, contact masking, whole credential replacement, independent block, unknown withholding, privacy and cleanup.")


if __name__ == "__main__":
    main()
