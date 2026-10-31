#!/usr/bin/env python3
"""Trial harness failure paths: queue shutdown, task cleanup and safe evidence."""
import asyncio
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("framework_trial", ROOT / "scripts/trial-framework-trace.py")
TRIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRIAL)
from govweave_tracing import TraceContext


class QueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_serialized_context_preserves_fields_without_client_identity(self):
        client = object()
        context = TraceContext.new().after("1" * 16, links=("2" * 16,), retry_of_span_id="3" * 16)
        received = []
        async def worker(actual_client, resource, actual_context):
            received.append((actual_client, resource, actual_context))
            return "done"
        bridge = TRIAL.QueueBridge(client, worker)
        pending = asyncio.create_task(bridge.submit("guide", context))
        await asyncio.sleep(0)
        message, _ = bridge.queue._queue[0]
        self.assertEqual(set(json.loads(message)), {"resource_id", "context"})
        bridge.start()
        try:
            self.assertEqual(await pending, "done")
            self.assertEqual(received, [(client, "guide", context)])
            self.assertIsNot(received[0][2], context)
        finally:
            await bridge.close()

    async def test_close_cancels_full_queue_and_waiting_producer(self):
        async def never_called(*args):
            self.fail("A queue closed before dispatch must not invoke a worker")
        bridge = TRIAL.QueueBridge(object(), never_called)
        tasks = [asyncio.create_task(bridge.submit("guide", TraceContext.new())) for _ in range(9)]
        await asyncio.sleep(0)
        self.assertEqual(bridge.queue.qsize(), 8)
        self.assertEqual(len(bridge.submissions), 9)
        await asyncio.wait_for(bridge.close(), timeout=1)
        self.assertTrue(all(task.cancelled() for task in tasks))
        self.assertTrue(bridge.queue.empty())
        self.assertEqual(bridge.submissions, set())
        with self.assertRaises(TRIAL.CheckFailed):
            await bridge.submit("guide", TraceContext.new())

    async def test_inflight_cancel_closes_worker_and_keeps_consumer_usable(self):
        entered, cleaned = asyncio.Event(), asyncio.Event()
        async def worker(client, resource, context):
            if resource == "second":
                return "done"
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaned.set()
        bridge = TRIAL.QueueBridge(object(), worker)
        bridge.start()
        try:
            task = asyncio.create_task(bridge.submit("first", TraceContext.new()))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())
            self.assertEqual(await bridge.submit("second", TraceContext.new()), "done")
        finally:
            await bridge.close()
        self.assertFalse(bridge.active)

    async def test_failed_workflow_cleans_up_running_siblings(self):
        entered, cleaned = asyncio.Event(), asyncio.Event()
        async def stalled():
            entered.set()
            try:
                await asyncio.Future()
            finally:
                cleaned.set()
        async def failed():
            await entered.wait()
            raise TRIAL.CheckFailed("synthetic_failure")
        with self.assertRaises(TRIAL.CheckFailed):
            await TRIAL.gather_joined([stalled(), failed()])
        self.assertTrue(cleaned.is_set())


class EvidenceTests(unittest.TestCase):
    def report(self):
        return {"cases": [{"id": name, "state": "not_run"} for name in TRIAL.PLAN], "limitations": ["Synthetic test."]}

    def test_partial_failure_does_not_publish_private_evidence(self):
        secret = "synthetic-private-evidence-must-not-be-saved"
        report = self.report()
        report["cases"][0].update(state="passed", evidence={"unexpected_body": secret})
        with self.assertRaises(TRIAL.CheckFailed):
            try:
                raise RuntimeError("synthetic_interruption")
            finally:
                TRIAL.protect_metadata(report, [secret], "")
        self.assertNotIn(secret, json.dumps(report))
        self.assertFalse(report["metadata_privacy_verified"])
        self.assertTrue(all(case["state"] == "unknown" for case in report["cases"]))

    def test_failure_report_retains_planned_denominator_and_private_files(self):
        report = self.report()
        report["cases"][0].update(state="failed", reason="synthetic_failure")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            TRIAL.save_report(path, report)
            saved = json.loads((path / "report.json").read_text())
            self.assertEqual(saved["summary"], {"planned": 9, "passed": 0, "failed": 1, "unknown": 8})
            self.assertEqual(saved["state"], "incomplete_or_failed")
            for name in ("report.json", "report.md"):
                self.assertEqual(stat.S_IMODE((path / name).stat().st_mode), 0o600)

    def test_connect_guard_rejects_non_loopback_addresses(self):
        TRIAL.loopback_address(("127.0.0.1", 8080))
        TRIAL.loopback_address(("::1", 8080, 0, 0))
        for address in (("example.com", 443), ("192.0.2.1", 443), "/tmp/unsupported"):
            with self.subTest(address=address), self.assertRaises(OSError):
                TRIAL.loopback_address(address)


if __name__ == "__main__":
    unittest.main()
