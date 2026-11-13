#!/usr/bin/env python3
"""Run bounded synthetic probes against an offline GGUF and an isolated gateway."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_model_tools", ROOT / "scripts/demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)
ALIAS = "local-qwen-test"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)


def wait_ready(child, opener, url, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("isolated service exited before readiness")
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    raise RuntimeError("isolated service readiness timed out")


@contextmanager
def model_server(args, directory):
    with args.gpu_lock.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        actual_hash = sha256(args.model)
        if actual_hash != args.model_sha256:
            raise ValueError("GGUF checksum differs from the expected hash")
        key = secrets.token_urlsafe(32)
        keyfile = directory / "model.key"
        keyfile.write_text(key + "\n")
        keyfile.chmod(0o600)
        origin = f"http://127.0.0.1:{port()}"
        env = dict(os.environ)
        libraries = sorted({str(path.parent) for path in args.runtime.rglob("*.so*")})
        env["LD_LIBRARY_PATH"] = ":".join(libraries)
        command = [str(args.server), "-m", str(args.model), "--alias", ALIAS,
                   "--host", "127.0.0.1", "--port", origin.rsplit(":", 1)[1],
                   "--api-key-file", str(keyfile), "--offline", "--no-webui",
                   "-c", "4096", "-np", "1", "-ngl", "99", "-fa", "on",
                   "-n", "128", "--batch-size", "512", "--ubatch-size", "128",
                   "--jinja", "--reasoning", "off", "--reasoning-budget", "0"]
        with (directory / "model.log").open("wb") as log:
            child = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                wait_ready(child, opener, origin + "/health", 300)
                try:
                    with opener.open(origin + "/v1/models", timeout=5):
                        raise RuntimeError("model endpoint unexpectedly allowed anonymous access")
                except urllib.error.HTTPError as error:
                    if error.code != 401:
                        raise RuntimeError("unexpected anonymous model response") from None
                request = urllib.request.Request(origin + "/v1/models", headers={"Authorization": "Bearer " + key})
                with opener.open(request, timeout=5) as response:
                    models = json.load(response)
                if ALIAS not in [item["id"] for item in models["data"]]:
                    raise RuntimeError("model alias not found")
                yield origin + "/v1", key, actual_hash
            finally:
                stop(child)


class LocalSession(TOOLS.ToolSession):
    def __init__(self, binary, endpoint, key, bundle, model=ALIAS):
        super().__init__(binary)
        self.endpoint, self.provider_key, self.bundle = endpoint, key, bundle
        self.model = model

    def start(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="govweave-real-model-")
        self.directory = Path(self.temporary.name)
        for category, sources in (
            ("rule-packs", [ROOT / "examples/rule-packs" / entry["file"] for entry in self.bundle["packs"]]),
            ("test-suites", [ROOT / "examples/test-suites/sensitive-output-controls.json"]),
        ):
            folder = self.directory / category
            folder.mkdir(mode=0o700)
            for source in sources:
                destination = folder / source.name
                shutil.copyfile(source, destination)
                destination.chmod(0o600)
        self.origin = f"http://127.0.0.1:{port()}"
        env = {name: value for name, value in os.environ.items() if not name.startswith("GOVWEAVE_")}
        env.update(GOVWEAVE_DATA_DIR=str(self.directory), GOVWEAVE_LISTEN_ADDR=self.origin.removeprefix("http://"))
        self.child = subprocess.Popen([str(self.binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_ready(self.child, self.public, self.origin + "/healthz", 15)
        self.request("/api/v1/auth/setup", {"password": secrets.token_urlsafe(32)})
        connection, _ = self.request("/api/v1/connections", {
            "revision": 0, "name": "Isolated model synthetic trial", "base_url": self.endpoint,
            "model": self.model, "alias": ALIAS, "api_key": self.provider_key,
            "enabled": True, "allow_insecure_http": self.endpoint.startswith("http://"), "timeout_seconds": 45,
        })
        application, _ = self.request("/api/v1/applications", {
            "revision": 0, "name": "Isolated synthetic client", "allowed_connections": [connection["id"]],
        })
        self.application = application["application"]
        persisted = (self.directory / "gateway.json").read_text()
        TOOLS.require(self.provider_key not in persisted and "credential_ciphertext" in persisted, "provider key not encrypted")

    def policy(self, mode):
        current, _ = self.request("/api/v1/policies/sensitive-output")
        self.request("/api/v1/policies/sensitive-output", {
            "revision": current["revision"], "mode": mode,
            "categories": ["credential", "email", "phone"],
            "application_ids": [self.application["id"]], "detector_version": "sensitive-text-v3",
        }, method="PUT")


def exercise(session, target_version):
    product, _ = session.request("/api/v1/compliance/products", {
        "revision": 0, "name": "Real Qwen inference / synthetic probes", "version": "1.0.0",
        "application_ids": [session.application["id"]],
        "pack_id": "sensitive-output-governance", "pack_version": "1.1.0", "facts": {},
    })
    path = "/api/v1/compliance/products/" + product["id"]
    session.request(path + "/test-plan", {
        "revision": 0, "application_id": session.application["id"], "model_alias": ALIAS,
        "target_version": target_version,
        "suite_id": "sensitive-output-controls", "suite_version": "1.0.0",
        "context": "Real model inference, synthetic prompts only. Not a legal compliance or detector accuracy assessment.",
        "schedule_enabled": False, "interval_seconds": 300, "timeout_seconds": 30,
        "max_output_tokens": 128, "retain_responses": False,
    }, method="PUT")
    runs = []
    for mode, phase in [("disabled", "pre_deployment"), ("observe", "pre_deployment"),
                        ("redact", "pre_deployment"), ("block", "pre_deployment"), ("block", "operation")]:
        session.policy(mode)
        started, _ = session.request(path + "/test-runs", {"phase": phase}, expected=202)
        deadline = time.monotonic() + 210
        while time.monotonic() < deadline:
            finished, _ = session.request("/api/v1/compliance/test-runs/" + started["id"])
            if finished["state"] != "running":
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("active probe run timed out")
        TOOLS.require(finished["state"] == "completed", "active probe run did not complete")
        TOOLS.require(all("response" not in case for case in finished["cases"]), "probe unexpectedly retained response text")
        runs.append({"mode": mode, "phase": phase, "run": finished})
        print(json.dumps({"mode": mode, "phase": phase, "status": finished["status"]}), flush=True)
    report, _ = session.request(path + "/reports", {})
    regional = []
    for entry in session.bundle["packs"]:
        evaluation, _ = session.request("/api/v1/compliance/evaluations", {
            "pack_id": entry["id"], "pack_version": entry["version"],
            "product_id": product["id"], "product_version": "1.0.0", "facts": {},
        })
        TOOLS.require(evaluation["legal_compliance"] == "not_determined", "unexpected legal conclusion")
        regional.append(evaluation)
    return {"runs": runs, "output_governance_report": report, "bundle_missing_evidence_evaluations": regional}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("model", "runtime", "server", "gpu-lock", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    args = parser.parse_args()
    os.umask(0o077)
    bundle = json.loads((ROOT / "examples/compliance-bundles/eu-us.json").read_text())
    result = {"started_at": datetime.now(timezone.utc).isoformat(), "real_model_inference": True,
              "synthetic_data": True, "live_instance_modified": False, "legal_compliance": "not_determined",
              "model_file": args.model.name, "gateway_binary_sha256": sha256(args.binary),
              "runtime_launcher_sha256": sha256(args.server), "detector": "sensitive-text-v3",
              "limitations": ["Four authored probes per run, not representative coverage or detector recall.",
                              "Regional evaluations intentionally receive no fabricated organizational evidence.",
                              "Historical unprotected runs remain in the output-governance report."]}
    with tempfile.TemporaryDirectory(prefix="govweave-model-trial-") as directory:
        try:
            with model_server(args, Path(directory)) as (endpoint, key, model_hash):
                result["model_sha256"] = model_hash
                with LocalSession(args.binary.resolve(), endpoint, key, bundle) as session:
                    result.update(exercise(session, "gguf-sha256-" + model_hash))
        except BaseException:
            logfile = Path(directory) / "model.log"
            if logfile.exists():
                args.output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(logfile, args.output.with_suffix(".startup.log"))
            raise
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    result["temporary_services_stopped"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    args.output.chmod(0o600)
    print("Report: " + str(args.output), flush=True)


if __name__ == "__main__":
    main()
