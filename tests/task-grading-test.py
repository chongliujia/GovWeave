#!/usr/bin/env python3
"""Structured grading boundaries; only the development partition is used here."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import task_grading as G


class TaskGradingTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"kind": "hours", "expected": {"start_minutes": 510, "end_minutes": 1050, "zone": "UTC"}}
        self.row = {"status": "completed", "audit_complete": True, "expected_read_returned": True, "task_completed": False, "intervention": False}

    def test_development_partition(self):
        corpus = json.loads((ROOT / "tests/testdata/task-grading-validation-v1.json").read_text())
        for case in corpus["cases"]:
            if case["split"] != "development":
                continue
            with self.subTest(case=case["id"]):
                spec = {"kind": case["kind"], "expected": corpus["expectations"][case["kind"]]}
                self.assertEqual(G.check_fact(spec, case["answer"])["result"], case["expected_result"])

    def test_real_read_and_audit_remain_required(self):
        for change, completed, reason in [({"audit_complete": False}, None, "execution_unknown"), ({"status": "error"}, None, "execution_unknown"), ({"status": "not_run"}, None, "execution_unknown"), ({"status": "blocked"}, False, "gateway_blocked"), ({"expected_read_returned": False}, False, "missing_expected_read")]:
            result = G.assess_task(self.spec, dict(self.row, **change), "08:30-17:30 UTC")
            self.assertIs(result["completed"], completed)
            self.assertEqual(result["diagnosis"], reason)
            self.assertEqual(result["result"], "not_evaluated")

    def test_format_fact_unknown_and_intervention_are_separate(self):
        for answer, completed, diagnosis in [("8:30 AM–5:30 PM UTC", True, "format_equivalent"), ("10:00-18:00 UTC", False, "fact_mismatch"), ("The hours vary.", None, "grading_unknown")]:
            result = G.assess_task(self.spec, self.row, answer)
            self.assertIs(result["completed"], completed)
            self.assertEqual(result["diagnosis"], diagnosis)
        result = G.assess_task(self.spec, dict(self.row, intervention=True), "[REDACTED]")
        self.assertEqual(result["diagnosis"], "intervention_observed")
        self.assertIsNone(result["completed"])

    def test_bounded_and_private_results(self):
        for answer in ("x" * 8193, "\ud800", None):
            self.assertEqual(G.check_fact(self.spec, answer)["result"], "unknown")
        result = G.check_fact(self.spec, "08:30-17:30 UTC")
        self.assertEqual(set(result), {"version", "check", "result", "reason"})
        self.assertNotIn("08:30", json.dumps(result))
        for spec in (None, {}, {"kind": "arbitrary", "expected": {}}, {"kind": "hours", "expected": {"start_minutes": True, "end_minutes": 1050, "zone": "UTC"}}):
            self.assertEqual(G.check_fact(spec, "08:30-17:30 UTC")["result"], "unknown")

    def test_literal_fallback_is_explicit(self):
        result = G.check_fact({"kind": "literal", "expected": {"text": "Topic Label"}}, "Topic Label")
        self.assertEqual((result["check"], result["reason"]), ("literal", "legacy_literal_match"))


if __name__ == "__main__":
    unittest.main()
