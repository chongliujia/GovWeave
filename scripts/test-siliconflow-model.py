#!/usr/bin/env python3
"""Test SiliconFlow with synthetic data and a disposable GovWeave instance."""
import argparse
from datetime import datetime, timezone
import getpass
import importlib.util
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("real_model_trial", ROOT / "scripts/test-local-model.py")
TRIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRIAL)
ENDPOINT = "https://api.siliconflow.cn/v1"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def preflight(key, model):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(path, payload=None):
        request = urllib.request.Request(ENDPOINT + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=60) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise RuntimeError("provider response exceeded limit")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"SiliconFlow preflight HTTP {error.code}; no further calls made") from None

    catalog = call("/models")
    if model not in [item.get("id") for item in catalog.get("data", [])]:
        raise RuntimeError("requested model is not in this account's model catalog; no replacement selected")
    result = call("/chat/completions", {
        "model": model, "messages": [{"role": "user", "content": "Return exactly GOVWEAVE_OUTPUT_READY and nothing else."}],
        "stream": False, "temperature": 0, "max_tokens": 128, "enable_thinking": False,
    })
    content = result.get("choices", [{}])[0].get("message", {}).get("content")
    if content != "GOVWEAVE_OUTPUT_READY":
        raise RuntimeError("provider did not complete the benign readiness probe exactly")
    return {"catalog_match": True, "benign_probe_passed": True,
            "usage": result.get("usage"), "reported_model": result.get("model")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="Qwen/Qwen3.8-27B")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    args = parser.parse_args()
    os.umask(0o077)
    key = os.environ.pop("SILICONFLOW_API_KEY", "") or getpass.getpass("SiliconFlow API key (hidden): ")
    if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise ValueError("invalid API key format")
    ready = preflight(key, args.model)
    print("Provider catalog and benign inference verified; starting isolated gateway.", flush=True)
    bundle = json.loads((ROOT / "examples/compliance-bundles/eu-us.json").read_text())
    result = {"started_at": datetime.now(timezone.utc).isoformat(), "provider": "SiliconFlow",
              "model": args.model, "model_revision": "provider_managed_not_pinned",
              "real_model_inference": True, "synthetic_data": True, "live_instance_modified": False,
              "legal_compliance": "not_determined", "detector": "sensitive-text-v3", "preflight": ready,
              "gateway_binary_sha256": TRIAL.sha256(args.binary),
              "limitations": ["Four authored probes per run, not representative coverage or detector recall.",
                              "Regional evaluations receive no fabricated organizational evidence.",
                              "Historical unprotected runs remain in the output-governance report.",
                              "Native active probes use provider-default reasoning settings."]}
    with TRIAL.LocalSession(args.binary.resolve(), ENDPOINT, key, bundle, args.model) as session:
        result.update(TRIAL.exercise(session, "siliconflow-qwen38-27b-trial"))
    result.update(completed_at=datetime.now(timezone.utc).isoformat(), temporary_services_stopped=True)
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if key in encoded:
        raise RuntimeError("refusing to save a report containing the API key")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded + "\n")
    args.output.chmod(0o600)
    print("Report: " + str(args.output), flush=True)


if __name__ == "__main__":
    main()
