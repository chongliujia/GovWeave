"""Exercise the installed OpenAI Python SDK against temporary, local services.

Development-only dependencies: openai and httpx. No real API key or model call.
"""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

import httpx
import openai
from openai import OpenAI


class Provider(BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, *_):
        pass

    def do_POST(self):
        assert self.path == "/v1/chat/completions"
        assert self.headers["Authorization"] == "Bearer test-provider-secret"
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert request["model"] == "local-model"
        type(self).calls += 1
        envelope = {"id": "chat_local", "created": 1, "model": "local-model"}
        self.send_response(200)
        if request.get("stream"):
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for piece in ["local ", "stream"]:
                chunk = {**envelope, "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]}
                self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
                self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n')
        else:
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {**envelope, "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "local response"}, "finish_reason": "stop"}]}
            self.wfile.write(json.dumps(response).encode())


def main():
    root = Path(__file__).resolve().parents[1]
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix="govweave-sdk-") as data:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            env = {k: v for k, v in os.environ.items() if not k.startswith("GOVWEAVE_")}
            env.update(GOVWEAVE_LISTEN_ADDR=f"127.0.0.1:{port}", GOVWEAVE_DATA_DIR=data)
            with open(Path(data) / "process.log", "w+") as process_log:
                child = subprocess.Popen([str(root / "bin/govweave")], env=env, stdout=process_log, stderr=process_log)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                for _ in range(100):
                    try:
                        with opener.open(origin + "/healthz", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("Local gateway did not start")

                def configure(path, value):
                    req = urllib.request.Request(origin + path, method="POST", data=json.dumps(value).encode(), headers={"X-GovWeave-Request": "console", "Content-Type": "application/json"})
                    with opener.open(req, timeout=5) as response:
                        return json.load(response)

                configure("/api/v1/auth/setup", {"password": "SDK test administrator password"})
                connection = configure("/api/v1/connections", {"name": "SDK provider", "base_url": f"http://127.0.0.1:{upstream.server_port}/v1", "model": "local-model", "alias": "internal-assistant", "api_key": "test-provider-secret", "enabled": True, "allow_insecure_http": True, "timeout_seconds": 10})
                app = configure("/api/v1/applications", {"name": "SDK application", "allowed_connections": [connection["id"]]})
                key = app["api_key"]
                with OpenAI(base_url=origin + "/v1", api_key=key, max_retries=0, timeout=15, http_client=httpx.Client(trust_env=False)) as client:
                    assert [model.id for model in client.models.list()] == ["internal-assistant"]
                    response = client.chat.completions.create(model="internal-assistant", messages=[{"role": "user", "content": "sdk-private-prompt"}])
                    assert response.choices[0].message.content == "local response"
                    stream = client.chat.completions.create(model="internal-assistant", messages=[{"role": "user", "content": "sdk-private-prompt"}], stream=True)
                    assert "".join(chunk.choices[0].delta.content or "" for chunk in stream) == "local stream"
                    try:
                        client.chat.completions.create(model="ungranted", messages=[{"role": "user", "content": "sdk-private-prompt"}])
                        raise AssertionError("Unauthorized model accepted")
                    except openai.PermissionDeniedError:
                        pass
                    configure(f'/api/v1/applications/{app["application"]["id"]}/revoke', {"revision": app["application"]["revision"]})
                    try:
                        client.models.list()
                        raise AssertionError("Revoked key accepted")
                    except openai.AuthenticationError:
                        pass
                assert Provider.calls == 2
                child.terminate()
                child.wait(timeout=10)
                audit = (Path(data) / "calls.jsonl").read_text()
                disk = (Path(data) / "gateway.json").read_text()
                for secret in [key, "test-provider-secret", "sdk-private-prompt", "local response", "local stream"]:
                    assert secret not in audit
                assert key not in disk and "test-provider-secret" not in disk
                print(f"OpenAI Python SDK {openai.__version__}: model list, normal response, SSE, permission rejection, revocation, metadata privacy passed (local mock only).")
    finally:
        if child and child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
