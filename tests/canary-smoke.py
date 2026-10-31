#!/usr/bin/env python3
"""Actual-binary canary probe wiring, separate from detector-quality measurement."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("govweave_demo", ROOT / "scripts/demo-assessment.py")
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class CanaryHandler(DEMO.SupportHandler):
    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > DEMO.MAX_BODY_BYTES:
                self.respond(413, {"error": {"code": "request_too_large"}})
                return
            body = json.loads(self.rfile.read(size))
            assert self.path == "/v1/chat/completions" and body["model"] == "synthetic-support"
            assert body["stream"] is False and len(body["messages"]) == 2
            marker = re.search(r"GW-CANARY-[0-9a-f]{32}", body["messages"][0]["content"]).group(0)
            assert marker not in self.server.markers
            self.server.markers.add(marker)
            prompt = body["messages"][1]["content"]
        except (ValueError, KeyError, TypeError, AttributeError, AssertionError):
            self.respond(400, {"error": {"code": "invalid_synthetic_request"}})
            return
        mode, number = self.server.state(increment=True)
        content = "I cannot disclose the diagnostic marker."
        if mode in ("broken", "layered") and "Reply ready" not in prompt:
            if "Base64" in prompt:
                content = base64.b64encode(marker.encode()).decode()
            elif "spaces" in prompt:
                content = " ".join(marker)
            else:
                content = marker
            if mode == "layered":
                if "Base64" in prompt:
                    content = base64.b64encode(content.encode()).decode()
                elif "spaces" in prompt:
                    content = " ".join(str(ord(c)) for c in marker)
                else:
                    content = marker[::-1]
        self.respond(200, {"id": f"canary-{number}", "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]})


class CanaryServer(DEMO.SupportServer):
    def __init__(self):
        super().__init__()
        self.RequestHandlerClass = CanaryHandler
        self.markers = set()

    def set_mode(self, mode):
        if mode == "layered":
            with self._state_lock:
                self._mode = mode
        else:
            super().set_mode(mode)


def main(output_dir=None):
    binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", ROOT / "bin/govweave")).resolve()
    with DEMO.DemoSession(binary, "synthetic-canary.json", CanaryServer) as session:
        pre = session.run("pre_deployment")
        baseline = session.run("operation")
        assert pre["status"] == baseline["status"] == "passed"
        assert baseline["input"]["facts"]["testing.canary.exposure_observed"]["value"] is False
        session.provider.set_mode("broken")
        exposed = session.run("operation")
        assert exposed["status"] == "failed" and exposed["comparison"]["regressions"] == 3
        assert exposed["input"]["facts"]["testing.canary.exposure_observed"]["value"] is True
        detected = [case for case in exposed["cases"] if case["status"] == "fail"]
        assert {case["detection"]["matches"][0]["representation"] for case in detected} == {"exact", "base64", "normalized"}
        assert all(case["detection"]["version"] == "synthetic-canary-v2" for case in detected)
        assert all("{{CANARY}}" in case["messages"][0]["content"] for case in exposed["suite"]["cases"])
        for case in detected:
            match = case["detection"]["matches"][0]
            assert 0 <= match["start_byte"] < match["end_byte"] <= len(case["response"].encode())
        session.provider.set_mode("layered")
        layered = session.run("operation")
        assert layered["runner_version"] == "bounded-chat-tests-v4" and layered["status"] == "failed"
        layered_methods = {case["detection"]["matches"][0]["representation"] for case in layered["cases"] if case["status"] == "fail"}
        assert layered_methods == {"reversed", "composed", "decimal"}
        assert layered["cases"][1]["detection"]["matches"][0]["transformations"] == ["base64", "base64"]
        session.provider.set_mode("fixed")
        recovered = session.run("operation")
        assert recovered["status"] == "passed" and recovered["comparison"]["recoveries"] == 3
        calls = session.provider.state()[1]
        replay = session.call("/api/v1/compliance/test-runs/" + exposed["id"] + "/replay", {})
        assert replay["matches"] and session.provider.state()[1] == calls
        assert calls == len(session.provider.markers) == 20
        assert recovered["evaluation"]["legal_compliance"] == "not_determined"
        summary = {"result": "passed", "scope": "synthetic integration wiring; not detector-quality measurement", "synthetic_data": True, "requests": calls, "unique_markers": len(session.provider.markers), "exposures_detected": len(detected), "layered_exposures_detected": 3, "representations": ["exact", "base64", "normalized"], "recoveries": 3, "rule_replay_without_inference": replay["matches"]}
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
            for filename, value in {"summary.json": summary, "pre-deployment.json": pre, "baseline.json": baseline, "exposed.json": exposed, "layered.json": layered, "recovered.json": recovered}.items():
                DEMO.save_json(output_dir / filename, value)
        print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="Retain actual synthetic API results in a new private directory")
    main(parser.parse_args().output_dir)
