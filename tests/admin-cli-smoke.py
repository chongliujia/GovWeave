#!/usr/bin/env python3
"""Verify headless setup, model/application configuration and application policies."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("GOVWEAVE_TEST_BINARY", ROOT / "bin/govweave")).resolve()
EMAIL = "synthetic-terminal@example.test"


class Model(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            self.send_error(400)
            return
        data = json.loads(self.rfile.read(size))
        assert self.path == "/v1/chat/completions" and data["model"] == "terminal-fixture"
        assert self.headers.get("Authorization") == "Bearer synthetic-terminal-provider"
        self.server.calls += 1
        result = json.dumps({"choices": [{"index": 0, "message": {"role": "assistant", "content": EMAIL}, "finish_reason": "stop"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


def main():
    with tempfile.TemporaryDirectory(prefix="govweave-admin-cli-") as temporary:
        directory = Path(temporary)
        provider = HTTPServer(("127.0.0.1", 0), Model)
        provider.calls = 0
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        child = None
        password = secrets.token_urlsafe(30)
        session = directory / "session.json"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        env = {key: value for key, value in os.environ.items() if not key.startswith("GOVWEAVE_")}
        env.update(GOVWEAVE_LISTEN_ADDR=f"127.0.0.1:{port}", GOVWEAVE_DATA_DIR=str(directory / "data"))

        def start():
            process = subprocess.Popen([str(BINARY)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    assert process.poll() is None, "temporary service exited"
                    try:
                        with opener.open(origin + "/healthz", timeout=1) as response:
                            assert response.status == 200
                        return process
                    except urllib.error.URLError:
                        time.sleep(0.05)
                raise AssertionError("temporary service did not become ready")
            except BaseException:
                stop(process)
                raise

        def stop(process):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

        def cli(*args, auth="session", ok=True):
            command = [str(BINARY), "admin", "--url", origin]
            if auth == "session":
                command += ["--session-file", str(session)]
            elif auth == "password":
                command += ["--password-stdin"]
            elif auth == "login":
                command += ["--session-file", str(session), "--password-stdin"]
            result = subprocess.run(command + list(args), input=password + "\n" if auth in ("password", "login") else None,
                                    text=True, capture_output=True, timeout=20)
            assert password not in result.stdout + result.stderr, "password was printed"
            assert (result.returncode == 0) == ok, "CLI command failed: " + " ".join(args[:2]) + ": " + result.stderr
            if ok:
                return json.loads(result.stdout)
            assert not result.stdout, "failed operation emitted success data"
            return result.stderr

        def config(name, value):
            path = directory / name
            with path.open("x") as stream:
                path.chmod(0o600)
                json.dump(value, stream)
            return str(path)

        try:
            child = start()
            assert cli("status", auth="none")["status"] == "ok"
            assert cli("setup", auth="password")["setup_complete"]
            assert cli("login", auth="login")["session_saved"]
            assert session.stat().st_mode & 0o777 == 0o600
            connection = cli("connections", "create", "--file", config("connection.json", {
                "revision": 0, "name": "Terminal model", "alias": "terminal", "model": "terminal-fixture",
                "base_url": f"http://127.0.0.1:{provider.server_port}/v1", "api_key": "synthetic-terminal-provider",
                "enabled": True, "allow_insecure_http": True, "timeout_seconds": 3,
            }))
            applications = []
            for index, mode in enumerate(("redact", "block", "observe")):
                app = cli("applications", "create", "--file", config(f"app-{index}.json", {
                    "revision": 0, "name": mode + " fixture", "allowed_connections": [connection["id"]],
                }))
                applications.append(app)
                cli("policy", "set", "--application", app["application"]["id"], "--revision", str(index),
                    "--mode", mode, "--detector", f"sensitive-text-v{3-index}", "--categories", "email")
            listed = cli("applications", "list")
            assert len(listed["applications"]) == 3 and all(app["api_key"] not in json.dumps(listed) for app in applications)
            assert provider.calls == 0, "management triggered model I/O"
            for index, app in enumerate(applications):
                body = {"model": "terminal", "messages": [{"role": "user", "content": "Synthetic CLI integration fixture"}], "stream": False}
                request = urllib.request.Request(origin + "/v1/chat/completions", data=json.dumps(body).encode(),
                                                 headers={"Authorization": "Bearer " + app["api_key"], "Content-Type": "application/json"})
                try:
                    response = opener.open(request, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    payload = response.read().decode()
                    assert response.status == (403 if index == 1 else 200)
                    assert (EMAIL in payload) == (index == 2)
                records = cli("requests", "list", "--application", app["application"]["id"], "--limit", "10")["records"]
                assert len(records) == 1 and records[0]["phase"] == "finished"
                assert records[0]["output_policy"]["result"] == ("redacted", "block", "observe")[index]
            assert provider.calls == 3
            selected = applications[0]["application"]["id"]
            cli("policy", "set", "--application", selected, "--revision", "0", "--mode", "disabled", ok=False)
            cli("policy", "inherit", "--application", selected, "--revision", "3")
            assert cli("policy", "show", "--application", selected)["policy"]["mode"] == "disabled"
            cli("policy", "restore", "--application", selected, "--revision", "4", "--from-revision", "3")
            before = cli("policy", "show")
            stop(child)
            child = start()
            assert "unauthorized" in cli("applications", "list", ok=False)
            session = directory / "restarted-session.json"
            cli("login", auth="login")
            assert cli("policy", "show") == before
            assert cli("policy", "show", "--application", selected)["policy"]["mode"] == "redact"
            assert cli("policy", "history", "--application", selected)["total"] == 6
            cli("logout")
            assert not session.exists()
            print("CLI smoke passed: headless setup/login, private sessions, model/app creation, three independent policies, audit, conflict rejection, inheritance, restore and restart. Three synthetic local model calls; no external services.")
        finally:
            stop(child)
            provider.shutdown()
            provider.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    main()
