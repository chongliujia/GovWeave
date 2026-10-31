#!/usr/bin/env python3
"""Verify the reusable local demonstration, including interactive fault injection."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/demo-assessment.py"
SPEC = importlib.util.spec_from_file_location("govweave_demo", SCRIPT)
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class DemonstrationTests(unittest.TestCase):
    def run_demo(self, output, interactive=False):
        binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", ROOT / "bin/govweave")).resolve()
        command = [sys.executable, str(SCRIPT), "--binary", str(binary), "--output-dir", str(output)]
        commands = None
        if interactive:
            command += ["--interactive", "--lang", "zh-CN"]
            commands = "status\nbroken\nrun\nfixed\nrun\nunavailable\nrun\nquit\n"
        result = subprocess.run(command, input=commands, text=True, capture_output=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads((output / "summary.json").read_text())
        self.assertTrue(summary["synthetic_data"])
        self.assertEqual(summary["target_kind"], "scripted_fixture")
        self.assertFalse(summary["schedule_enabled"])
        self.assertEqual(summary["manual_reviews_remaining"], 5)
        stages = summary["stages"]
        self.assertEqual([stage["status"] for stage in stages[:4]], ["passed", "passed", "failed", "passed"])
        self.assertEqual(stages[2]["counts"], {"pass": 2, "fail": 2, "unknown": 0})
        self.assertEqual(stages[2]["regressions"], 2)
        self.assertEqual(stages[3]["recoveries"], 2)
        self.assertEqual(summary["provider_calls"], len(stages) * 4)
        for stage in stages:
            path = output / stage["file"]
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            run = json.loads(path.read_text())
            self.assertEqual(run["state"], "completed")
            self.assertEqual(run["suite"]["id"], "synthetic-support")
            self.assertEqual(run["evaluation"]["legal_compliance"], "not_determined")
        if interactive:
            self.assertIn("本机模拟客服 API 已就绪", result.stdout)
            self.assertEqual(stages[4]["status"], "inconclusive")
            self.assertEqual(stages[4]["counts"], {"pass": 0, "fail": 0, "unknown": 4})
            run = json.loads((output / stages[4]["file"]).read_text())
            controls = {control["id"]: control["status"] for control in run["evaluation"]["controls"]}
            self.assertEqual(controls["NIST-OPERATION-TEST"], "unknown")
        else:
            self.assertIn("No external model", result.stdout)
        self.assertEqual((output / "summary.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        return result

    def test_batch_demo_and_existing_reports(self):
        with tempfile.TemporaryDirectory(prefix="govweave-demo-verification-") as directory:
            output = Path(directory) / "batch"
            self.run_demo(output)
            before = (output / "summary.json").read_bytes()
            repeated = subprocess.run([sys.executable, str(SCRIPT), "--output-dir", str(output)], capture_output=True, timeout=5)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual((output / "summary.json").read_bytes(), before)

    def test_interactive_demo_and_unknown_outage(self):
        with tempfile.TemporaryDirectory(prefix="govweave-demo-verification-") as directory:
            self.run_demo(Path(directory) / "interactive", interactive=True)

    def test_fixture_rejects_invalid_and_oversized_requests(self):
        server = DEMO.SupportServer()
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            for payload, expected in [(b"[]", 400), (b"{}", 400), (b"x" * (DEMO.MAX_BODY_BYTES + 1), 413)]:
                request = urllib.request.Request(origin + "/v1/chat/completions", data=payload, headers={"Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    client.open(request, timeout=5)
                self.assertEqual(error.exception.code, expected)
                error.exception.close()
            self.assertEqual(server.state()[1], 0)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
