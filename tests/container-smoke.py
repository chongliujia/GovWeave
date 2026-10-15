"""Optional Docker acceptance check; creates and removes only its own test project."""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    root = Path(__file__).resolve().parents[1]
    project = "govweave-smoke-" + uuid.uuid4().hex[:10]
    offline = project + "-offline"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "GOVWEAVE_PORT": str(port), "GOVWEAVE_BIND_IP": "127.0.0.1", "GOVWEAVE_CONFIG": str(root / "examples/deployment.json")}
    compose = ["docker", "compose", "-p", project, "-f", str(root / "compose.yaml")]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def run(args):
        result = subprocess.run(args, env=env, cwd=root, text=True, capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return result.stdout.strip()

    def request(path, token="", body=None, method=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["X-GovWeave-Request"] = "console"
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers, data=json.dumps(body).encode() if body is not None else None, method=method or ("PUT" if body is not None else "GET"))
        with opener.open(req, timeout=3) as response:
            return json.load(response)

    def ready():
        for _ in range(60):
            try:
                if request("/healthz")["status"] == "ok":
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.25)
        raise RuntimeError("Container did not become ready")

    try:
        run(compose + ["up", "-d", "--no-build", "--pull", "never"])
        ready()
        try:
            request("/api/v1/instance")
            raise AssertionError("Management API allowed unauthenticated access")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        with tempfile.TemporaryDirectory(prefix="govweave-container-") as temporary:
            password = "container test administrator password"
            request("/api/v1/auth/setup", body={"password": password}, method="POST")
            token = ""  # Management requests use the session cookie; model calls use API keys.
            initial = request("/api/v1/instance", token)
            assert initial["revision"] == 0
            saved = request("/api/v1/instance", token, {"schema_version": 1, "revision": 0, "organization_name": "Container test", "public_url": f"http://127.0.0.1:{port}"})
            assert saved["configured"] and saved["revision"] == 1
            connection = request("/api/v1/connections", token, {"name": "Container provider", "base_url": "https://models.example/v1", "model": "test-model", "alias": "internal-assistant", "api_key": "container-test-provider-secret", "enabled": True, "allow_insecure_http": False, "timeout_seconds": 10}, "POST")
            application = request("/api/v1/applications", token, {"name": "Container app", "allowed_connections": [connection["id"]]}, "POST")
            app_key = application["api_key"]
            assert request("/v1/models", app_key)["data"][0]["id"] == "internal-assistant"
            ca_path = Path(temporary) / "ca-certificates.crt"
            run(compose + ["cp", "govweave:/etc/ssl/certs/ca-certificates.crt", str(ca_path)])
            assert "BEGIN CERTIFICATE" in ca_path.read_text()
            run(compose + ["restart"])
            ready()
            request("/api/v1/auth/login", body={"password": password}, method="POST")
            restored = request("/api/v1/instance", token)
            assert restored["organization_name"] == "Container test"
            assert restored["revision"] == 1
            assert request("/v1/models", app_key)["data"][0]["id"] == "internal-assistant"
            snapshot = request("/api/v1/gateway", token)
            assert snapshot["connections"][0]["has_credential"]
            assert app_key not in json.dumps(snapshot) and "container-test-provider-secret" not in json.dumps(snapshot)
            assert len(request("/api/v1/requests", token)["records"]) >= 2
        container_id = run(compose + ["ps", "-q", "govweave"])
        details = json.loads(run(["docker", "inspect", container_id]))[0]
        assert details["Config"]["User"] == "65532:65532"
        assert details["HostConfig"]["ReadonlyRootfs"]
        assert "ALL" in details["HostConfig"]["CapDrop"]
        run(["docker", "run", "-d", "--pull", "never", "--name", offline, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/data:rw,uid=65532,gid=65532,mode=0700", "govweave:0.2.0-dev"])
        for _ in range(40):
            result = subprocess.run(["docker", "logs", offline], text=True, capture_output=True, timeout=10)
            if "listening on" in result.stdout + result.stderr:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Offline container did not start")
        details = json.loads(run(["docker", "inspect", offline]))[0]
        assert details["State"]["Running"] and details["HostConfig"]["NetworkMode"] == "none"
        print("Container smoke passed: Compose startup, authentication, persisted instance/model/application/records restart, private credential responses, CA trust bundle, non-root/read-only runtime, network-disabled startup.")
    finally:
        subprocess.run(["docker", "rm", "-f", offline], capture_output=True)
        subprocess.run(compose + ["down", "--volumes", "--remove-orphans"], env=env, cwd=root, capture_output=True)


if __name__ == "__main__":
    main()
