#!/usr/bin/env python3
"""Failure-boundary tests for the copyable Python reference executor."""

from email.message import Message
import http.client
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "python"))
from govweave_tools import GovernedToolClient, ToolCallError, _NoRedirect

KEY = "gw_app_" + "A" * 43
REQUEST_ID = "req_" + "B" * 22
PRIVATE_TEXT = "retrieved private content"


def envelope():
    return {"request_id": REQUEST_ID, "text": PRIVATE_TEXT, "governance": {
        "policy_version": "read-tool-governance-v1", "ruleset_version": "credentials-v1",
        "tool_id": "tool_" + "C" * 16, "tool_revision": 1, "snapshot_sha256": "a" * 64,
        "action": "read", "authorization": "allowed", "data_sensitivity": "internal",
        "output_mode": "block", "content": {"state": "not_observed", "rule_ids": []},
        "decision": "allow", "reasons": ["resource_grant_allowed", "credential_patterns_not_observed"],
    }}


class Response(io.BytesIO):
    def __init__(self, value, status=200, raw=False):
        super().__init__(value if raw else json.dumps(value).encode())
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        self.headers["X-Request-ID"] = REQUEST_ID


def client():
    result = GovernedToolClient("https://gateway.example", KEY, "support")
    result._opener = Mock()
    return result


class ReferenceClientTests(unittest.TestCase):
    def test_reviewed_instruction_requires_complete_consistent_evidence(self):
        def reviewed():
            value = envelope()
            value["governance"]["reasons"] = ["resource_grant_allowed", "instruction_review_applied"]
            value["governance"]["instruction_policy"] = {
                "version": "tool-instructions-v2", "mode": "block", "state": "observed",
                "rule_ids": ["task_override", "answer_manipulation"], "duration_us": 3, "decision": "allow",
                "review": {"version": "exact-instruction-review-v1", "state": "matched", "exempted_rule_ids": ["task_override", "answer_manipulation"]}}
            return value
        value = reviewed(); c = client(); c._opener.open.return_value = Response(value)
        self.assertEqual(c.invoke("guide").text, PRIVATE_TEXT)
        for field, invalid in [("state", "mismatch"), ("exempted_rule_ids", ["task_override"]), ("exempted_rule_ids", ["task_override", "task_override"]), ("exempted_rule_ids", ["provider-says-safe"]), ("version", "future")]:
            value = reviewed(); value["governance"]["instruction_policy"]["review"][field] = invalid
            c = client(); c._opener.open.return_value = Response(value)
            with self.assertRaises(ToolCallError):
                c.invoke("guide")
        value = reviewed(); value["governance"]["instruction_policy"]["version"] = "tool-instructions-v1"
        c = client(); c._opener.open.return_value = Response(value)
        with self.assertRaises(ToolCallError):
            c.invoke("guide")

    def test_instruction_evidence_cannot_authorize_blocked_or_unknown_text(self):
        for state, rules, decision in [("not_observed", [], "allow"), ("observed", ["task_override"], "observe"), ("observed", ["task_override"], "block"), ("unknown", [], "error")]:
            value = envelope()
            value["governance"]["instruction_policy"] = {"version": "tool-instructions-v1", "mode": "observe" if decision == "observe" else "block", "state": state, "rule_ids": rules, "duration_us": 5, "decision": decision}
            if decision == "observe":
                value["governance"].update(decision="observe", reasons=["resource_grant_allowed", "instruction_patterns_observed"])
            c = client()
            c._opener.open.return_value = Response(value)
            if decision in ("allow", "observe"):
                self.assertEqual(c.invoke("guide").text, PRIVATE_TEXT)
            else:
                with self.assertRaises(ToolCallError):
                    c.invoke("guide")

    def test_unknown_instruction_version_and_forged_rule_fail_closed(self):
        for field, invalid in [("version", "future-version"), ("rule_ids", ["provider-says-safe"]), ("duration_us", True), ("decision", "allow")]:
            value = envelope()
            policy = {"version": "tool-instructions-v1", "mode": "block", "state": "observed", "rule_ids": ["task_override"], "duration_us": 1, "decision": "block"}
            policy[field] = invalid
            value["governance"]["instruction_policy"] = policy
            c = client(); c._opener.open.return_value = Response(value)
            with self.assertRaises(ToolCallError):
                c.invoke("guide")

    def test_valid_result_and_server_bound_identity(self):
        c = client()
        c._opener.open.return_value = Response(envelope())
        result = c.execute({"resource_id": "guide"})
        self.assertEqual(result.text, PRIVATE_TEXT)
        self.assertEqual(result.request_id, REQUEST_ID)
        self.assertNotIn(PRIVATE_TEXT, repr(result))
        self.assertNotIn(KEY, repr(c))
        request = c._opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://gateway.example/v1/tools/support/invoke")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(json.loads(request.data), {"resource_id": "guide"})
        self.assertEqual(c._opener.open.call_count, 1)

    def test_observe_returns_explicit_finding(self):
        c = client()
        value = envelope()
        value["governance"].update(output_mode="observe", decision="observe", content={"state": "observed", "rule_ids": ["api_key"]}, reasons=["resource_grant_allowed", "credential_patterns_observed"])
        c._opener.open.return_value = Response(value)
        self.assertEqual(c.invoke("guide").governance["decision"], "observe")

    def test_invalid_proposals_never_open_http(self):
        c = client()
        for arguments in [None, [], {}, {"resource_id": "guide", "url": "https://provider.example"}, {"resource_id": "guide", "application_id": "spoof"}, {"resource_id": None}, {"resource_id": "../private"}, {"resource_id": "x" * 101}]:
            with self.subTest(arguments=arguments), self.assertRaises(ToolCallError) as caught:
                c.execute(arguments)
            self.assertEqual(caught.exception.code, "invalid_arguments")
            self.assertEqual(caught.exception.request_id, "")
            self.assertEqual(caught.exception.http_status, 0)
        c._opener.open.assert_not_called()

    def test_sensitive_output_observe_and_fail_closed_metadata(self):
        def observed():
            value = envelope()
            value["governance"].update(decision="observe", reasons=["resource_grant_allowed", "content_patterns_observed"], output_policy={
                "id": "sensitive-output", "revision": 1, "detector_version": "sensitive-text-v1",
                "mode": "observe", "result": "observe", "state": "observed", "reason": "patterns_observed",
                "categories": ["email"], "matched_categories": ["email"], "matched_rules": ["email_address"], "check_duration_us": 4,
            })
            return value
        c = client()
        c._opener.open.return_value = Response(observed())
        result = c.invoke("guide")
        self.assertEqual(result.governance["output_policy"]["matched_categories"], ["email"])
        value = observed()
        value["governance"]["output_policy"].update(detector_version="sensitive-text-v2", matched_rules=["normalized_email_address"])
        c._opener.open.return_value = Response(value)
        self.assertEqual(c.invoke("guide").governance["output_policy"]["detector_version"], "sensitive-text-v2")
        for rule in ("formatted_email_address", "base64_email_address", "base64_formatted_email_address", "base64_normalized_email_address"):
            value = observed()
            value["governance"]["output_policy"].update(detector_version="sensitive-text-v3", matched_rules=[rule])
            c._opener.open.return_value = Response(value)
            self.assertEqual(c.invoke("guide").governance["output_policy"]["matched_rules"], [rule])
        for change in [
            {"matched_rules": ["normalized_email_address"]},
            {"detector_version": "sensitive-text-v4"},
            {"matched_rules": ["base64_email_address"]},
            {"detector_version": "sensitive-text-v3", "state": "unknown", "reason": "encoding_limit", "result": "error"},
            {"result": "block", "mode": "block"},
            {"result": "error", "state": "unknown", "reason": "finding_limit"},
            {"matched_categories": ["phone"]},
            {"reason": "untrusted_provider_text"},
            {"revision": True},
            {"matched_rules": []},
            {"raw": PRIVATE_TEXT},
        ]:
            with self.subTest(change=change):
                value = observed()
                value["governance"]["output_policy"].update(change)
                c = client()
                c._opener.open.return_value = Response(value)
                with self.assertRaises(ToolCallError) as caught:
                    c.invoke("guide")
                self.assertEqual(caught.exception.code, "invalid_response")
                self.assertNotIn(PRIVATE_TEXT, str(caught.exception))

    def test_redacted_output_requires_completed_evidence(self):
        def redacted():
            value = envelope()
            value["text"] = "Contact [REDACTED]"
            value["governance"].update(decision="redact", reasons=["resource_grant_allowed", "content_redacted"], output_policy={
                "id": "sensitive-output", "revision": 2, "detector_version": "sensitive-text-v2",
                "mode": "redact", "result": "redacted", "state": "observed", "reason": "patterns_observed",
                "categories": ["email"], "matched_categories": ["email"], "matched_rules": ["normalized_email_address"], "check_duration_us": 4,
                "redaction": {"version": "sensitive-redaction-v1", "scope": "matched_spans", "replacements": 1, "check_duration_us": 8},
            })
            return value
        c = client()
        c._opener.open.return_value = Response(redacted())
        self.assertEqual(c.invoke("guide").text, "Contact [REDACTED]")
        for mutate in [
            lambda v: v["governance"]["output_policy"].pop("redaction"),
            lambda v: v["governance"]["output_policy"].update(result="redact"),
            lambda v: v["governance"]["output_policy"].update(result="error", state="unknown"),
            lambda v: v["governance"]["output_policy"]["redaction"].update(scope="full_output"),
            lambda v: v["governance"]["output_policy"]["redaction"].update(replacements=True),
            lambda v: v["governance"]["output_policy"]["redaction"].update(raw=PRIVATE_TEXT),
            lambda v: v["governance"].update(decision="allow"),
            lambda v: v["governance"].update(content={"state": "observed", "rule_ids": ["api_key"]}),
        ]:
            value = redacted()
            mutate(value)
            c._opener.open.return_value = Response(value)
            with self.assertRaises(ToolCallError) as caught:
                c.invoke("guide")
            self.assertEqual(caught.exception.code, "invalid_response")

    def test_invalid_configuration_and_explicit_http(self):
        for root in ["http://gateway.example", "https://gateway.example/v1", "https://user:pass@gateway.example", "https://@gateway.example", "https://gateway.example?", "https://gateway.example#", "https://gateway.example/\n", "https://gateway.example/\x7f", "https://gateway.example:invalid", "file:///tmp/tool", None]:
            with self.subTest(root=root), self.assertRaises(ToolCallError) as caught:
                GovernedToolClient(root, KEY, "support")
            self.assertEqual(caught.exception.code, "invalid_configuration")
        for key, alias, timeout in [("secret\nheader", "support", 5), (KEY, "../tool", 5), (KEY, "support", float("nan")), (KEY, "support", True), (KEY, "support", 61)]:
            with self.assertRaises(ToolCallError):
                GovernedToolClient("https://gateway.example", key, alias, timeout)
        self.assertIsInstance(GovernedToolClient("http://127.0.0.1:8080", KEY, "support", allow_insecure_http=True), GovernedToolClient)

    def test_gateway_denial_is_sanitized_and_never_retried(self):
        c = client()
        value = envelope()
        del value["text"]
        value["governance"].update(decision="block", authorization="denied", content={"state": "unknown", "rule_ids": []}, reasons=["tool_not_allowed"])
        value["error"] = {"code": "tool_not_allowed", "type": "tool_governance_error", "message": PRIVATE_TEXT + KEY}
        response = Response(value, 403)
        error = urllib.error.HTTPError("https://gateway.example", 403, "private error", response.headers, response)
        c._opener.open.side_effect = error
        with self.assertRaises(ToolCallError) as caught:
            c.invoke("guide")
        self.assertEqual(caught.exception.code, "tool_not_allowed")
        self.assertEqual(caught.exception.http_status, 403)
        self.assertEqual(caught.exception.request_id, REQUEST_ID)
        self.assertNotIn(PRIVATE_TEXT, str(caught.exception))
        self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual(c._opener.open.call_count, 1)
        self.assertTrue(response.closed)

    def test_invalid_governance_cannot_release_text(self):
        mutations = [
            lambda v: v["governance"].update(decision="block"),
            lambda v: v["governance"].update(authorization="denied"),
            lambda v: v["governance"].update(content={"state": "unknown", "rule_ids": []}),
            lambda v: v["governance"].update(content={"state": "observed", "rule_ids": []}),
            lambda v: v["governance"].update(content={"state": "not_observed", "rule_ids": [["api_key"]]}),
            lambda v: v["governance"].update(policy_version="unknown-version"),
            lambda v: v["governance"].update(reasons=[{"raw": PRIVATE_TEXT}]),
            lambda v: v["governance"].update(tool_revision=True),
            lambda v: v["governance"].pop("snapshot_sha256"),
            lambda v: v.update(text="中" * 2731),
            lambda v: v.update(text="\ud800"),
            lambda v: v.update(request_id="private invalid id"),
            lambda v: v.update(unexpected=PRIVATE_TEXT),
            lambda v: v["governance"].update(unexpected=PRIVATE_TEXT),
        ]
        for mutate in mutations:
            value = envelope()
            mutate(value)
            c = client()
            c._opener.open.return_value = Response(value)
            with self.assertRaises(ToolCallError) as caught:
                c.invoke("guide")
            self.assertEqual(caught.exception.code, "invalid_response")
            self.assertNotIn(PRIVATE_TEXT, str(caught.exception))
            self.assertEqual(c._opener.open.call_count, 1)

    def test_response_envelope_bound_and_json_errors(self):
        for body, code in [(b"x" * 65537, "response_limit"), (b'{"x":1,"x":2}', "invalid_response"), (b'{"text":NaN}', "invalid_response"), (b"\xff", "invalid_response"), (b'{} {}', "invalid_response"), (b"[" * 2000, "invalid_response")]:
            c = client()
            response = Response(body, raw=True)
            c._opener.open.return_value = response
            with self.assertRaises(ToolCallError) as caught:
                c.invoke("guide")
            self.assertEqual(caught.exception.code, code)
            self.assertTrue(response.closed)
        c = client()
        response = Response(envelope())
        response.headers.replace_header("X-Request-ID", "req_" + "Z" * 22)
        c._opener.open.return_value = response
        with self.assertRaises(ToolCallError):
            c.invoke("guide")

    def test_transport_failure_and_elapsed_budget_do_not_leak(self):
        for error, code in [(urllib.error.URLError(PRIVATE_TEXT + KEY), "transport_error"), (TimeoutError(PRIVATE_TEXT), "transport_timeout"), (http.client.BadStatusLine(PRIVATE_TEXT + KEY), "transport_error"), (http.client.InvalidURL(PRIVATE_TEXT), "transport_error")]:
            c = client()
            c._opener.open.side_effect = error
            with self.assertRaises(ToolCallError) as caught:
                c.invoke("guide")
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn(PRIVATE_TEXT, str(caught.exception))
            self.assertEqual(c._opener.open.call_count, 1)
        c = client()
        c._opener.open.return_value = Response(envelope())
        with patch("govweave_tools.time.monotonic", side_effect=[0, 6]), self.assertRaises(ToolCallError) as caught:
            c.invoke("guide")
        self.assertEqual(caught.exception.code, "transport_timeout")

    def test_redirect_handler_never_constructs_forwarded_request(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 307, "", {}, "https://elsewhere.example"))


if __name__ == "__main__":
    unittest.main()
