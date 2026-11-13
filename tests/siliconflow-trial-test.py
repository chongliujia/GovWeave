#!/usr/bin/env python3
"""Offline safety checks for the opt-in hosted model trial."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("siliconflow_trial", ROOT / "scripts/test-siliconflow-model.py")
TRIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRIAL)
MODEL = "Qwen/Qwen3.8-27B"
KEY = "synthetic-key-not-a-real-credential"


def response(payload):
    return io.BytesIO(json.dumps(payload).encode())


class PreflightTests(unittest.TestCase):
    def test_exact_model_and_bounded_readiness(self):
        opener = Mock()
        opener.open.side_effect = [response({"data": [{"id": MODEL}]}), response({
            "model": MODEL, "choices": [{"message": {"content": "GOVWEAVE_OUTPUT_READY"}}],
        })]
        with patch.object(TRIAL.urllib.request, "build_opener", return_value=opener):
            result = TRIAL.preflight(KEY, MODEL)
        self.assertTrue(result["benign_probe_passed"])
        self.assertEqual(opener.open.call_count, 2)
        request = opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, TRIAL.ENDPOINT + "/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(payload["model"], MODEL)
        self.assertEqual(payload["max_tokens"], 128)
        self.assertIs(payload["enable_thinking"], False)
        self.assertNotIn(KEY, json.dumps(result))

    def test_unknown_model_does_not_fall_back(self):
        opener = Mock()
        opener.open.return_value = response({"data": [{"id": "other-model"}]})
        with patch.object(TRIAL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(RuntimeError, "no replacement selected"):
                TRIAL.preflight(KEY, MODEL)
        self.assertEqual(opener.open.call_count, 1)

    def test_auth_error_does_not_disclose_response(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(TRIAL.ENDPOINT, 401, "unauthorized", {}, response({"secret": KEY}))
        with patch.object(TRIAL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(RuntimeError) as caught:
                TRIAL.preflight(KEY, MODEL)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertIn("HTTP 401", str(caught.exception))
        self.assertEqual(opener.open.call_count, 1)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(TRIAL.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.org"))

    def test_wrong_readiness_content_stops_trial(self):
        opener = Mock()
        opener.open.side_effect = [response({"data": [{"id": MODEL}]}), response({"choices": [{"message": {"content": "no"}}]})]
        with patch.object(TRIAL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(RuntimeError, "benign readiness"):
                TRIAL.preflight(KEY, MODEL)


if __name__ == "__main__":
    unittest.main()
