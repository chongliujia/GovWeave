#!/usr/bin/env python3
"""Trace propagation, denial receipts and per-invocation isolation checks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from email.message import Message
import io
import json
from pathlib import Path
import sys
from threading import Barrier
import unittest
from unittest.mock import Mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))
from govweave_tools import GovernedToolClient, ToolCallError
from govweave_agent import KnowledgeAgent
from govweave_tracing import TraceContext, invoke_traced_tool, run_traced_agent

KEY = "gw_app_" + "A" * 43
REQUEST_ID = "req_" + "B" * 22
TRACE = "a" * 32
SPAN = "b" * 16
TEXT = "Synthetic returned document; never belongs in trace metadata."


def envelope(code=None):
    result = {"request_id": REQUEST_ID, "text": TEXT, "governance": {
        "policy_version": "read-tool-governance-v1", "ruleset_version": "credentials-v1",
        "tool_id": "tool_" + "C" * 16, "tool_revision": 1, "snapshot_sha256": "a" * 64,
        "action": "read", "authorization": "allowed", "data_sensitivity": "internal",
        "output_mode": "block", "content": {"state": "not_observed", "rule_ids": []},
        "decision": "allow", "reasons": ["resource_grant_allowed", "credential_patterns_not_observed"]}}
    if code:
        del result["text"]
        result["governance"].update(decision="block", authorization="denied", content={"state": "unknown", "rule_ids": []}, reasons=[code])
        result["error"] = {"code": code, "type": "tool_governance_error", "message": TEXT + KEY}
    return result


class Response(io.BytesIO):
    def __init__(self, value, status=200, trace=TRACE, span=SPAN):
        super().__init__(json.dumps(value).encode())
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        self.headers["X-Request-ID"] = REQUEST_ID
        if trace is not None:
            self.headers["X-GovWeave-Trace-ID"] = trace
        if span is not None:
            self.headers["X-GovWeave-Span-ID"] = span


def client():
    result = GovernedToolClient("https://gateway.example", KEY, "support")
    result._opener = Mock()
    return result


def model_response(final=False):
    if final:
        message = {"role": "assistant", "content": TEXT}
    else:
        message = {"role": "assistant", "content": None, "tool_calls": [{"id": "call_synthetic", "type": "function",
            "function": {"name": "read_resource", "arguments": '{"resource_id":"guide"}'}}]}
    return {"choices": [{"finish_reason": "stop" if final else "tool_calls", "message": message}]}


def agent():
    result = KnowledgeAgent("https://gateway.example", KEY, "model", "support", {"guide": "Synthetic guide"})
    result.tool._opener = Mock()
    return result


class TraceClientTests(unittest.TestCase):
    def test_invalid_identifiers_and_mutable_links_rejected_before_network(self):
        c = client()
        for bad in ("", "0" * 32, "A" * 32, "a" * 31, "a" * 33, "a" * 32 + "\n", None, 12):
            with self.subTest(trace=bad), self.assertRaises(ToolCallError):
                TraceContext(bad)
        for name in ("agent_id", "parent_span_id", "retry_of_span_id"):
            for bad in (None, False, 0, "0" * 16, "a" * 15, "A" * 16, "b" * 16 + "\r\n"):
                with self.subTest(field=name, value=bad), self.assertRaises(ToolCallError):
                    TraceContext(TRACE, **{name: bad})
        for links in ([SPAN], (SPAN, SPAN), ("0" * 16,), tuple(str(n) * 16 for n in range(1, 6)), (None,), None):
            with self.subTest(links=links), self.assertRaises(ToolCallError):
                TraceContext(TRACE, links=links)
        with self.assertRaises(ToolCallError):
            invoke_traced_tool(c, {"resource_id": "guide"}, {"trace_id": TRACE})
        c._opener.open.assert_not_called()

    def test_immutable_context_and_exact_headers(self):
        root = TraceContext(TRACE, agent_id="c" * 16)
        child = root.after(SPAN, links=("d" * 16, "e" * 16), retry_of_span_id="f" * 16)
        self.assertEqual(root.parent_span_id, "")
        self.assertEqual(root.links, ())
        self.assertEqual(child.agent_id, root.agent_id)
        with self.assertRaises(FrozenInstanceError):
            root.agent_id = "d" * 16
        self.assertEqual(child.headers(), {
            "X-GovWeave-Trace-ID": TRACE, "X-GovWeave-Agent-ID": "c" * 16,
            "X-GovWeave-Parent-Span-ID": SPAN, "X-GovWeave-Link-Span-IDs": "d" * 16 + "," + "e" * 16,
            "X-GovWeave-Retry-Of": "f" * 16})
        self.assertNotEqual(TraceContext.new().trace_id, TraceContext.new().trace_id)

    def test_success_preserves_original_client_and_excludes_content_from_metadata(self):
        c = client()
        original = c._opener
        original.open.return_value = Response(envelope())
        context = TraceContext(TRACE).after("c" * 16, links=("d" * 16,), retry_of_span_id="e" * 16)
        result = invoke_traced_tool(c, {"resource_id": "guide"}, context)
        self.assertEqual((result.status, result.span_id, result.text), ("completed", SPAN, TEXT))
        self.assertNotIn(TEXT, repr(result))
        self.assertNotIn(TEXT, json.dumps(result.metadata()))
        self.assertNotIn(KEY, json.dumps(result.metadata()))
        self.assertIs(c._opener, original)
        self.assertEqual(original.open.call_count, 1)
        headers = {name.lower(): value for name, value in original.open.call_args.args[0].header_items()}
        for name, value in context.headers().items():
            self.assertEqual(headers[name.lower()], value)

    def test_blocked_http_error_retains_receipt_and_does_not_retry(self):
        c = client()
        response = Response(envelope("tool_not_allowed"), 403)
        c._opener.open.side_effect = urllib.error.HTTPError("https://gateway.example", 403, "denied", response.headers, response)
        result = invoke_traced_tool(c, {"resource_id": "restricted"}, TraceContext(TRACE))
        self.assertEqual((result.status, result.reason, result.http_status, result.span_id), ("blocked", "tool_not_allowed", 403, SPAN))
        self.assertEqual(result.request_id, REQUEST_ID)
        self.assertEqual(result.text, "")
        self.assertEqual(c._opener.open.call_count, 1)
        self.assertTrue(response.closed)

    def test_invalid_receipts_never_release_text(self):
        cases = [(None, None), (TRACE, None), (None, SPAN), ("c" * 32, SPAN), (TRACE, "0" * 16), (TRACE, "B" * 16)]
        for trace, span in cases:
            c = client()
            response = Response(envelope(), trace=trace, span=span)
            c._opener.open.return_value = response
            with self.subTest(trace=trace, span=span):
                result = invoke_traced_tool(c, {"resource_id": "guide"}, TraceContext(TRACE))
                self.assertEqual((result.status, result.reason, result.text, result.span_id), ("error", "invalid_trace_receipt", "", None))
                self.assertTrue(response.closed)
        for name, value in (("X-GovWeave-Trace-ID", TRACE), ("X-GovWeave-Span-ID", SPAN)):
            c = client()
            response = Response(envelope())
            response.headers[name] = value
            c._opener.open.return_value = response
            self.assertEqual(invoke_traced_tool(c, {"resource_id": "guide"}, TraceContext(TRACE)).reason, "invalid_trace_receipt")

    def test_auth_failure_without_receipt_is_not_a_governance_block(self):
        c = client()
        c._opener.open.return_value = Response(envelope("invalid_api_key"), 401, trace=None, span=None)
        result = invoke_traced_tool(c, {"resource_id": "guide"}, TraceContext(TRACE))
        self.assertEqual((result.status, result.reason, result.span_id), ("error", "invalid_api_key", None))

    def test_original_client_preserves_fixed_trace_gateway_error_codes(self):
        for code, status in (("invalid_trace_context", 400), ("trace_unavailable", 503)):
            c = client()
            c._opener.open.return_value = Response(envelope(code), status, trace=None, span=None)
            with self.subTest(code=code), self.assertRaises(ToolCallError) as caught:
                c.execute({"resource_id": "guide"})
            self.assertEqual((caught.exception.code, caught.exception.http_status), (code, status))
            self.assertNotIn(TEXT, str(caught.exception))
            self.assertEqual(c._opener.open.call_count, 1)

    def test_parallel_calls_share_client_without_sharing_context_or_receipts(self):
        c = client()
        original = c._opener
        barrier = Barrier(2)
        contexts = [TraceContext("a" * 32, agent_id="a" * 16), TraceContext("b" * 32, agent_id="b" * 16)]

        def open_response(request, **_):
            headers = {name.lower(): value for name, value in request.header_items()}
            trace = headers["x-govweave-trace-id"]
            agent = headers["x-govweave-agent-id"]
            barrier.wait(timeout=3)
            self.assertEqual(trace[:16], agent)
            return Response(envelope(), trace=trace, span=agent)

        original.open.side_effect = open_response
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(invoke_traced_tool, c, {"resource_id": "guide"}, context) for context in contexts]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual([(r.trace_id, r.span_id, r.status) for r in results], [(c.trace_id, c.agent_id, "completed") for c in contexts])
        self.assertEqual(original.open.call_count, 2)
        self.assertIs(c._opener, original)

    def test_agent_model_tool_model_chain_uses_one_trace_and_server_parents(self):
        a = agent()
        original = a.tool._opener
        original.open.side_effect = [Response(model_response(), span="1" * 16), Response(envelope(), span="2" * 16), Response(model_response(True), span="3" * 16)]
        context = TraceContext(TRACE, agent_id="c" * 16, links=("d" * 16,), retry_of_span_id="e" * 16)
        result = run_traced_agent(a, "Synthetic question", context)
        self.assertEqual((result.status, result.trace_id, result.text), ("completed", TRACE, TEXT))
        self.assertEqual([e["span_id"] for e in result.events], ["1" * 16, "2" * 16, "3" * 16])
        self.assertEqual([e.get("parent_span_id") for e in result.events], [None, "1" * 16, "2" * 16])
        for index, call in enumerate(original.open.call_args_list):
            headers = {name.lower(): value for name, value in call.args[0].header_items()}
            self.assertEqual(headers["x-govweave-trace-id"], TRACE)
            self.assertEqual(headers.get("x-govweave-parent-span-id"), None if index == 0 else str(index) * 16)
            self.assertEqual("x-govweave-link-span-ids" in headers, index == 0)
            self.assertEqual("x-govweave-retry-of" in headers, index == 0)
        self.assertNotIn(TEXT, json.dumps(result.metadata()))
        self.assertIs(a.tool._opener, original)
        self.assertEqual(context.parent_span_id, "")

    def test_agent_denied_tool_retains_span_and_stops_before_next_model(self):
        a = agent()
        a.tool._opener.open.side_effect = [Response(model_response(), span="1" * 16), Response(envelope("tool_not_allowed"), 403, span="2" * 16)]
        result = run_traced_agent(a, "Synthetic question", TraceContext(TRACE))
        self.assertEqual((result.status, result.reason, result.text), ("blocked", "tool_not_allowed", ""))
        self.assertEqual([e["span_id"] for e in result.events], ["1" * 16, "2" * 16])
        self.assertEqual(a.tool._opener.open.call_count, 2)

    def test_parallel_agent_runs_do_not_share_chains(self):
        a = agent()
        original = a.tool._opener
        contexts = [TraceContext("a" * 32), TraceContext("b" * 32)]
        stages = {context.trace_id: 0 for context in contexts}
        barrier = Barrier(2)

        def open_response(request, **_):
            headers = {name.lower(): value for name, value in request.header_items()}
            trace = headers["x-govweave-trace-id"]
            stage = stages[trace]
            stages[trace] += 1
            span = trace[0] + str(stage + 1) * 15
            parent = None if stage == 0 else trace[0] + str(stage) * 15
            self.assertEqual(headers.get("x-govweave-parent-span-id"), parent)
            barrier.wait(timeout=3)
            payload = envelope() if stage == 1 else model_response(final=stage == 2)
            return Response(payload, trace=trace, span=span)

        original.open.side_effect = open_response
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run_traced_agent, a, "Synthetic question", context) for context in contexts]
            results = [future.result(timeout=5) for future in futures]
        for context, result in zip(contexts, results):
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.trace_id, context.trace_id)
            self.assertEqual([e["span_id"] for e in result.events], [context.trace_id[0] + str(n) * 15 for n in (1, 2, 3)])
        self.assertIs(a.tool._opener, original)
        self.assertEqual(original.open.call_count, 6)


if __name__ == "__main__":
    unittest.main()
