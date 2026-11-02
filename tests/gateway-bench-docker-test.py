#!/usr/bin/env python3
"""Opt-in Docker acceptance; build the trusted benchmark image first."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("GATEWAY_BENCH_IMAGE", "govweave-gateway-bench:local")


class DockerBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="govweave-docker-test-")
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "run"

    def command(self, *extra):
        return [sys.executable, str(ROOT / "scripts/benchmark-gateway-docker.py"),
                "--image", IMAGE, "--out", str(self.out), "--", "-requests", "12",
                "-warmup", "2", "-rounds", "1", "-concurrency", "4",
                "-sizes", "1024", "-protocols", "json,sse", *extra]

    def assert_cleaned(self, metadata):
        self.assertTrue(all(metadata["cleanup"].values()))
        for command, name in ((["inspect"], metadata["container_name"]),
                              (["volume", "inspect"], metadata["volume_name"])):
            result = subprocess.run(["docker", *command, name], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_linux_isolation_durability_and_cleanup(self):
        run = subprocess.run(self.command(), cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        m = json.loads((self.out / "docker-environment.json").read_text())
        self.assertEqual(m["state"], "completed")
        c = m["container_config"]
        self.assertEqual(c["network"], "none")
        self.assertTrue(c["readonly_rootfs"])
        self.assertEqual(c["user"], "65532:65532")
        self.assertEqual(c["nano_cpus"], 4000000000)
        self.assertEqual(c["memory_bytes"], 1073741824)
        self.assertEqual(c["memory_swap_bytes"], c["memory_bytes"])
        self.assertEqual(c["pids_limit"], 256)
        self.assertIn("ALL", [value.upper() for value in c["cap_drop"]])
        self.assertIn("no-new-privileges:true", c["security_opt"])
        report = json.loads((self.out / "result/report.json").read_text())
        self.assertEqual(report["os"], "linux")
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(report["results"]), 8)
        for row in report["results"]:
            self.assertEqual(row["succeeded"], 12)
            self.assertEqual(row["failed"], 0)
            self.assertTrue(row["provider_count_matches"])
            if row["mode"] != "direct":
                self.assertTrue(row["durability_verification"]["passed"])
        for path in self.out.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, str(path))
        self.assert_cleaned(m)

    def test_rejects_path_overrides_and_preserves_existing_output(self):
        invalid = subprocess.run(self.command("-out", "/tmp/escape"), capture_output=True, timeout=10)
        self.assertEqual(invalid.returncode, 2)
        self.assertFalse(self.out.exists())
        self.out.mkdir()
        marker = self.out / "keep"
        marker.write_text("existing output")
        existing = subprocess.run(self.command(), capture_output=True, timeout=10)
        self.assertEqual(existing.returncode, 2)
        self.assertEqual(marker.read_text(), "existing output")

    def test_interruption_cleans_only_its_container_and_volume(self):
        with subprocess.Popen(self.command("-requests", "512", "-warmup", "64",
                "-provider-delay-ms", "100", "-concurrency", "1", "-protocols", "json"),
                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            deadline = time.monotonic() + 20
            try:
                while True:
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    path = self.out / "docker-environment.json"
                    if path.exists() and json.loads(path.read_text())["state"] == "running":
                        log = self.out / "container.log"
                        if log.exists() and "Completed 0/" in log.read_text():
                            break
                    time.sleep(.05)
                process.terminate()
                self.assertEqual(process.wait(timeout=30), 1)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=30)
        m = json.loads((self.out / "docker-environment.json").read_text())
        self.assertEqual(m["state"], "interrupted")
        self.assertEqual(m["interruption_reason"], "signal")
        self.assertTrue(m["report_copied"])
        report = json.loads((self.out / "result/report.json").read_text())
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["failure"], "interrupted")
        self.assert_cleaned(m)

    def test_deadline_preserves_checkpoint_and_cleans_resources(self):
        command = self.command("-requests", "512", "-warmup", "64",
                               "-provider-delay-ms", "100", "-concurrency", "1", "-protocols", "json")
        index = command.index("--")
        command[index:index] = ["--timeout", "1"]
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=40)
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        m = json.loads((self.out / "docker-environment.json").read_text())
        self.assertEqual(m["state"], "interrupted")
        self.assertEqual(m["interruption_reason"], "deadline")
        self.assertTrue(m["report_copied"])
        report = json.loads((self.out / "result/report.json").read_text())
        self.assertEqual(report["state"], "failed")
        self.assert_cleaned(m)


if __name__ == "__main__":
    unittest.main()
