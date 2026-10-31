#!/usr/bin/env python3
"""Verify the controlled read-tool demonstration against an actual GovWeave binary."""
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
SCRIPT = ROOT / "scripts" / "demo-tools.py"
SPEC = importlib.util.spec_from_file_location("govweave_tool_demo", SCRIPT)
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class ToolDemonstrationTests(unittest.TestCase):
    def test_actual_binary_enforcement_and_private_summary(self):
        binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", ROOT / "bin" / "govweave")).resolve()
        with tempfile.TemporaryDirectory(prefix="govweave-tools-verification-") as directory:
            output = Path(directory) / "run"
            result = subprocess.run([sys.executable, str(SCRIPT), "--binary", str(binary), "--output-dir", str(output)], capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            path = output / "summary.json"
            data = path.read_bytes()
            summary = json.loads(data)
            self.assertEqual(summary["result"], "passed")
            self.assertTrue(summary["synthetic_data"])
            self.assertEqual(summary["target_kind"], "scripted_read_tool")
            self.assertEqual(summary["provider_calls"], 2)
            self.assertTrue(summary["caller_headers_isolated"])
            self.assertTrue(summary["metadata_only_audit"])
            self.assertTrue(summary["terminal_audit_verified"])
            self.assertEqual([stage["http_status"] for stage in summary["stages"]], [200, 403, 403, 400, 401, 401])
            self.assertEqual([stage["upstream_calls"] for stage in summary["stages"]], [1, 0, 1, 0, 0, 0])
            self.assertEqual([stage["decision"] for stage in summary["stages"][:3]], ["allow", "block", "block"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            all_output = data.decode() + result.stdout + result.stderr
            for excluded in [DEMO.FIXTURE_CREDENTIAL, DEMO.PROVIDER_KEY, DEMO.NORMAL_TEXT, DEMO.CALLER_HEADER, *DEMO.RESOURCE_IDS]:
                self.assertNotIn(excluded, all_output)
            repeated = subprocess.run([sys.executable, str(SCRIPT), "--output-dir", str(output)], capture_output=True, timeout=5)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(path.read_bytes(), data)

    def test_fixture_rejects_unknown_fields_and_large_requests(self):
        provider = DEMO.ReadToolServer()
        worker = threading.Thread(target=provider.serve_forever, daemon=True)
        worker.start()
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            origin = f"http://127.0.0.1:{provider.server_port}/read"
            for body, status in [(b"[]", 400), (b'{}', 400), (b'{"resource_id":"public-guide","application_id":"caller"}', 400), (b"x" * (DEMO.MAX_BODY_BYTES + 1), 413)]:
                request = urllib.request.Request(origin, data=body, headers={"Content-Type": "application/json"})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    client.open(request, timeout=5)
                self.assertEqual(error.exception.code, status)
                error.exception.close()
            self.assertEqual(provider.state(), (0, 0))
        finally:
            provider.shutdown()
            provider.server_close()
            worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
