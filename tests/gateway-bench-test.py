#!/usr/bin/env python3
"""Real benchmark subprocess/HTTP/capture acceptance; standard library only."""
import json
import gzip
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin/gateway-bench"


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="govweave-bench-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workers = self.base / "workers"
        self.workers.mkdir(mode=0o700)
        self.env = dict(os.environ, TMPDIR=str(self.workers),
                        HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1",
                        SYNTHETIC_ENV_SECRET="must-not-appear-in-benchmark-report")

    def command(self, out, *extra):
        return [str(BINARY), "-source-root", str(ROOT), "-out", str(out),
                "-requests", "12", "-warmup", "2", "-rounds", "1",
                "-concurrency", "1,4", "-sizes", "1024", "-protocols", "json,sse", *extra]

    def test_matrix_records_and_privacy(self):
        out = self.base / "report"
        result = subprocess.run(self.command(out), cwd=ROOT, env=self.env,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        raw = (out / "report.json").read_text()
        report = json.loads(raw)
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(report["results"]), 16)
        self.assertEqual(len(report["comparisons"]), 12)
        self.assertEqual(report["planned_cells"], 16)
        self.assertRegex(report["benchmark_binary_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("internal/gateway/engine.go", report["source_sha256"])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        for name in ("report.json", "report.md"):
            self.assertEqual(stat.S_IMODE((out / name).stat().st_mode), 0o600)
        for forbidden in ("gw_app_", "provider_key", "Authorization", "Bearer ",
                          "must-not-appear-in-benchmark-report", "Synthetic gateway benchmark input."):
            self.assertNotIn(forbidden, raw)
        for row in report["results"]:
            self.assertEqual(row["succeeded"], 12)
            self.assertEqual(row["failed"], 0)
            self.assertEqual(row["warmup_failed"], 0)
            self.assertEqual(row["provider_calls_including_warmup"], 14)
            self.assertEqual(row["provider_invalid_requests"], 0)
            self.assertTrue(row["provider_count_matches"])
            self.assertEqual(len(row["samples"]), 12)
            self.assertTrue(row["success_latency"]["p99_is_max_rank"])
            for sample in row["samples"]:
                self.assertEqual(sample["http_status"], 200)
                self.assertGreater(sample["response_bytes"], row["output_text_bytes"])
                self.assertGreaterEqual(sample["elapsed_ms"], sample["first_body_byte_ms"])
            if row["mode"] == "direct":
                self.assertIsNone(row["gateway_resources"])
                self.assertIsNone(row["durability_verification"])
                continue
            v = row["durability_verification"]
            self.assertTrue(v["passed"])
            self.assertEqual(v["started_audit_calls"], 14)
            self.assertEqual(v["finished_audit_calls"], 14)
            self.assertEqual(v["successful_audits"], 14)
            expected = 0 if row["mode"] == "disabled" else 14
            self.assertEqual(v["verified_captures"], expected)
            self.assertEqual(v["evidence_files"], expected)
            self.assertGreater(v["audit_file_bytes"], 0)
            resources = row["gateway_resources"]
            self.assertTrue(all(value >= 0 for value in resources.values() if isinstance(value, (int, float))))
            for name in ("gc_stopping", "gc_total_pause"):
                h = resources[name]
                self.assertEqual(h["count"], sum(b["count"] for b in h["buckets"]))
                self.assertGreaterEqual(h["total_upper_ms"], h["total_lower_ms"])
            self.assertGreater(resources["process_user_cpu_ms"], 0)
            self.assertGreater(resources["peak_rss_bytes_since_process_start"], 0)
            self.assertGreater(row["verified_successes_per_durable_second"], 0)
            self.assertGreaterEqual(row["client_start_to_drained_ack_ms"], row["client_batch_elapsed_ms"])
        for comparison in report["comparisons"]:
            self.assertTrue(comparison["comparable"])
            g = report["results"][comparison["gateway_result_index"]]
            d = report["results"][comparison["direct_result_index"]]
            self.assertEqual(d["mode"], "direct")
            for key in ("round", "concurrency", "protocol", "output_text_bytes"):
                self.assertEqual(g[key], d[key])
            self.assertAlmostEqual(comparison["completion_p95_difference_ms"],
                                   g["success_latency"]["p95_ms"] - d["success_latency"]["p95_ms"])
        self.assertEqual(list(self.workers.iterdir()), [])

    def test_bounds_and_existing_directory(self):
        out = self.base / "invalid"
        invalid = subprocess.run(self.command(out, "-requests", "513"), cwd=ROOT,
                                 env=self.env, capture_output=True, timeout=10)
        self.assertEqual(invalid.returncode, 2)
        self.assertFalse(out.exists())
        out.mkdir(mode=0o700)
        sentinel = out / "report.json"
        sentinel.write_text("preserve existing report")
        existing = subprocess.run(self.command(out), cwd=ROOT, env=self.env,
                                  capture_output=True, timeout=10)
        self.assertEqual(existing.returncode, 1)
        self.assertEqual(sentinel.read_text(), "preserve existing report")
        self.assertEqual(list(self.workers.iterdir()), [])

    def test_private_profiles_suppress_latency_comparisons(self):
        for mode in ("contention", "allocs"):
            with self.subTest(mode=mode):
                out = self.base / (mode + "-profiles-report")
                run = subprocess.run(self.command(out, "-profile", mode, "-protocols", "json", "-concurrency", "4"),
                                     cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                report = json.loads((out / "report.json").read_text())
                self.assertEqual(report["options"]["profile"], mode)
                for row in report["results"]:
                    if row["mode"] == "direct":
                        self.assertNotIn("profiles", row)
                        continue
                    self.assertEqual(len(row["profiles"]), 2)
                    for artifact in row["profiles"]:
                        path = out / artifact["path"]
                        data = path.read_bytes()
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                        self.assertEqual(len(data), artifact["bytes"])
                        self.assertEqual(hashlib.sha256(data).hexdigest(), artifact["sha256"])
                        decoded = gzip.decompress(data)
                        self.assertTrue(decoded)
                        self.assertNotIn(b"must-not-appear-in-benchmark-report", decoded)
                        self.assertNotIn(b"gw_app_", decoded)
                for c in report["comparisons"]:
                    self.assertFalse(c["comparable"])
                    self.assertIsNone(c["completion_p95_difference_ms"])
                self.assertEqual(list(out.rglob("*.partial")), [])
                self.assertEqual(list(self.workers.iterdir()), [])

    def test_interrupt_checkpoints_and_cleans_worker(self):
        out = self.base / "interrupted"
        with subprocess.Popen(self.command(out, "-requests", "128", "-provider-delay-ms", "50"),
                              cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as process:
            deadline = time.monotonic() + 15
            try:
                # Wait for the first child instance to be created; cancellation
                # then exercises cleanup during initialization or in-flight work.
                while not list(self.workers.glob("govweave-load-*")):
                    self.assertIsNone(process.poll(), "runner ended before interruption")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                process.terminate()
                self.assertEqual(process.wait(timeout=15), 1)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["failure"], "interrupted")
        self.assertIn("failed_cell", report)
        self.assertLess(len(report["results"]), report["planned_cells"])
        self.assertEqual(list(self.workers.iterdir()), [])


if __name__ == "__main__":
    if not BINARY.is_file():
        raise SystemExit("Build first: make build-gateway-bench")
    unittest.main()
