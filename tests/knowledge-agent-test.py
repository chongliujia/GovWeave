#!/usr/bin/env python3
"""Reference Agent boundary tests; no network or external model calls."""
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))
from govweave_agent import KnowledgeAgent
from govweave_tools import ToolCallError, ToolResult

KEY, REQUEST = "gw_app_" + "A" * 43, "req_" + "B" * 22


class Response(io.BytesIO):
    def __init__(self, value, status=200, raw=False):
        super().__init__(value if raw else json.dumps(value).encode())
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        self.headers["X-Request-ID"] = REQUEST


def final(text="private final answer", finish="stop"):
    return {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish}]}


def proposal(args=None, name="read_resource"):
    return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "call_fixture", "type": "function", "function": {"name": name, "arguments": json.dumps(args or {"resource_id": "private-guide"})}}]}, "finish_reason": "tool_calls"}]}


def agent():
    a = KnowledgeAgent("https://gateway.example", KEY, "assistant", "support", {"private-guide": "Owned catalog"}, max_tool_calls=2)
    a.tool._opener = Mock()
    a.tool.execute = Mock(return_value=ToolResult("private retrieved text", REQUEST, {"tool_revision": 1, "authorization": "allowed", "decision": "allow"}))
    return a


class AgentTests(unittest.TestCase):
    def test_moonshot_instant_profile_preserves_execution_boundaries(self):
        a = KnowledgeAgent("https://gateway.example", KEY, "assistant", "support", {"guide": "Catalog"}, request_profile="moonshot-k2.6-instant-v1")
        a.tool._opener = Mock(); a.tool._opener.open.return_value = Response(final())
        self.assertEqual(a.run("test").status, "completed")
        body = json.loads(a.tool._opener.open.call_args.args[0].data)
        self.assertEqual(body["thinking"], {"type": "disabled"})
        self.assertNotIn("temperature", body)
        self.assertEqual(body["max_tokens"], 512)
        self.assertFalse(body["stream"])
        self.assertFalse(body["parallel_tool_calls"])
        with self.assertRaises(ToolCallError):
            KnowledgeAgent("https://gateway.example", KEY, "assistant", "support", {"guide": "Catalog"}, request_profile="unverified-profile")

    def test_full_loop_retains_only_safe_trace(self):
        a = agent()
        a.tool._opener.open.side_effect = [Response(proposal()), Response(final())]
        result = a.run("private user question")
        self.assertEqual(result.status, "completed")
        a.tool.execute.assert_called_once_with({"resource_id": "private-guide"})
        self.assertEqual([event["kind"] for event in result.events], ["model", "tool", "model"])
        requests = a.tool._opener.open.call_args_list
        messages = json.loads(requests[-1].args[0].data)["messages"]
        self.assertEqual(messages[-1]["content"], "private retrieved text")
        for secret in (KEY, "private user question", "private retrieved text", "private final answer", "private-guide"):
            self.assertNotIn(secret, json.dumps(result.metadata()))
            self.assertNotIn(secret, repr(result))
        self.assertIsNone(result.usage)

    def test_denial_is_terminal_without_retry_or_fallback(self):
        for code in ("tool_not_allowed", "tool_instruction_blocked"):
            a = agent()
            a.tool._opener.open.return_value = Response(proposal())
            a.tool.execute.side_effect = ToolCallError(code, REQUEST, 403)
            result = a.run("test")
            self.assertEqual((result.status, result.reason, result.text), ("blocked", code, ""))
            self.assertEqual(a.tool._opener.open.call_count, 1)
            a.tool.execute.assert_called_once()

    def test_proposals_cannot_choose_function_identity_or_endpoint(self):
        invalid = [proposal(name="shell"), proposal({"resource_id": "guide", "url": "https://untrusted.example"}),
                   proposal({"resource_id": "guide", "application_id": "forged"}), proposal({"resource_id": "../secret"})]
        duplicate = proposal()
        duplicate["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"resource_id":"a","resource_id":"b"}'
        invalid.append(duplicate)
        parallel = proposal()
        parallel["choices"][0]["message"]["tool_calls"] *= 2
        invalid.append(parallel)
        for value in invalid:
            with self.subTest(value=value):
                a = agent()
                a.tool._opener.open.return_value = Response(value)
                result = a.run("test")
                self.assertEqual(result.status, "error")
                self.assertEqual(result.text, "")
                a.tool.execute.assert_not_called()

    def test_repeated_proposals_have_bounded_execution(self):
        a = agent()
        a.tool._opener.open.side_effect = [Response(proposal()) for _ in range(3)]
        result = a.run("repeat")
        self.assertEqual((result.status, result.reason), ("limited", "tool_call_limit"))
        self.assertEqual(a.tool.execute.call_count, 2)
        self.assertEqual(a.tool._opener.open.call_count, 3)

    def test_invalid_partial_oversized_and_forged_errors_are_unknown(self):
        responses = [Response(final(finish="length")), Response(final("x" * 8193)), Response(b"x" * 65537, raw=True),
                     Response({"request_id": REQUEST, "error": {"code": "content_output_blocked"}}, status=500)]
        for response in responses:
            a = agent()
            a.tool._opener.open.return_value = response
            result = a.run("test")
            self.assertEqual(result.status, "error")
            self.assertEqual(result.text, "")
            self.assertIsNone(result.usage)
            a.tool.execute.assert_not_called()

    def test_model_failure_is_not_disguised_by_partial_usage(self):
        a = agent()
        value = proposal()
        value["usage"] = {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25}
        a.tool._opener.open.side_effect = [Response(value), TimeoutError("private provider error")]
        result = a.run("test")
        self.assertEqual(result.status, "error")
        self.assertIsNone(result.usage)
        self.assertNotIn("private provider error", json.dumps(result.metadata()))

    def test_metrics_keep_unknowns_and_splits_separate(self):
        spec = importlib.util.spec_from_file_location("agent_evaluation", ROOT / "scripts/eval-knowledge-agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        common = {"split": "evaluation", "mode": "protected", "label": "attack", "status": "error", "task_completed": None,
                  "intervention": False, "events": [], "elapsed_ms": 1}
        rows = [dict(common, attack_success=value) for value in (True, False, None)]
        rows.append(dict(common, split="development", attack_success=True))
        metrics = module.metrics(rows)["evaluation/protected"]
        self.assertEqual((metrics["attack_cases"], metrics["attack_successes"], metrics["attack_unknown"]), (3, 1, 1))
        self.assertEqual(metrics["attack_success_rate_lower"], 1/3)
        self.assertEqual(metrics["attack_success_rate_upper"], 2/3)
        self.assertTrue(metrics["p95_is_maximum"])


if __name__ == "__main__":
    unittest.main()
