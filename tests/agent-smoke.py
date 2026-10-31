#!/usr/bin/env python3
"""Verify actual-binary reference-client dispatch, runtime evidence, and report replay."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "demo-agent.py"


class AgentIntegrationTests(unittest.TestCase):
    def test_scripted_client_and_retained_historical_findings(self):
        binary = Path(os.environ.get("GOVWEAVE_TEST_BINARY", ROOT / "bin" / "govweave")).resolve()
        with tempfile.TemporaryDirectory(prefix="govweave-agent-verification-") as directory:
            output = Path(directory) / "run"
            result = subprocess.run([sys.executable, str(SCRIPT), "--binary", str(binary), "--output-dir", str(output)], capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            path = output / "summary.json"
            original = path.read_bytes()
            summary = json.loads(original)
            self.assertEqual(summary["result"], "passed")
            self.assertTrue(summary["synthetic_data"])
            self.assertTrue(summary["local_argument_rejection"])
            self.assertFalse(summary["direct_provider_fallback"])
            self.assertTrue(summary["historical_observe_release_retained"])
            self.assertTrue(summary["metadata_only_artifacts"])
            self.assertEqual(summary["provider_calls"], 4)
            self.assertEqual([proposal["http_status"] for proposal in summary["proposals"]], [200, 403, 403, 200, 403])
            self.assertEqual([proposal["upstream_calls"] for proposal in summary["proposals"]], [1, 0, 1, 1, 1])
            phases = summary["phases"]
            self.assertEqual([phase["status"] for phase in phases], ["satisfied", "gaps_detected", "gaps_detected"])
            self.assertEqual([phase["tool_revision"] for phase in phases], [1, 2, 3])
            self.assertEqual([phase["output_checked_count"] for phase in phases], [2, 3, 4])
            self.assertEqual([phase["observed_release_count"] for phase in phases], [0, 1, 1])
            self.assertEqual([phase["controls"]["fail"] for phase in phases], [0, 2, 1])
            self.assertEqual(phases[-1]["failed_controls"], ["TOOL-SAMPLE-RELEASES"])
            for phase in phases:
                self.assertTrue(phase["replay_matches"])
                self.assertEqual(phase["replay_tool_calls"], 0)
                report_path = output / phase["file"]
                self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
                report = json.loads(report_path.read_text())
                self.assertEqual(report["summary"]["id"], phase["report_id"])
                self.assertEqual(report["snapshot"]["report"]["evaluation"]["legal_compliance"], "not_determined")
                self.assertEqual(report["snapshot"]["input"]["facts"]["runtime.tools.sample.observed_release_count"]["value"], phase["observed_release_count"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            retained = "".join(file.read_text() for file in output.iterdir()) + result.stdout + result.stderr
            for excluded in ("sk-SyntheticToolCredential", "synthetic-read-provider-token", "Synthetic support guide:", "gw_app_", "public-guide", "restricted-guide", "credential-guide", "http://", "https://"):
                self.assertNotIn(excluded, retained)
            repeated = subprocess.run([sys.executable, str(SCRIPT), "--output-dir", str(output)], capture_output=True, timeout=5)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
