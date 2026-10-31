#!/usr/bin/env python3
"""Async transport boundaries: cancellation, unknown outcomes and trace isolation."""

import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))
from govweave_async_tracing import AsyncGovernedToolClient
from govweave_tools import ToolCallError
from govweave_tracing import TraceContext

KEY = "gw_app_" + "A" * 43
REQUEST_ID = "req_" + "B" * 22
TRACE = "a" * 32
SPAN = "b" * 16
TEXT = "Synthetic private tool output; excluded from metadata."


def envelope(code=None):
    value = {"request_id": REQUEST_ID, "text": TEXT, "governance": {
        "policy_version": "read-tool-governance-v1", "ruleset_version": "credentials-v1",
        "tool_id": "tool_" + "C" * 16, "tool_revision": 1, "snapshot_sha256": "a" * 64,
        "action": "read", "authorization": "allowed", "data_sensitivity": "internal",
        "output_mode": "block", "content": {"state": "not_observed", "rule_ids": []},
        "decision": "allow", "reasons": ["resource_grant_allowed", "credential_patterns_not_observed"],
    }}
    if code:
        del value["text"]
        value["governance"].update(authorization="denied", decision="block",
                                   content={"state": "unknown", "rule_ids": []}, reasons=[code])
        value["error"] = {"code": code, "type": "tool_governance_error", "message": TEXT + KEY}
    return value


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks, wait=None):
        self.chunks, self.wait, self.closed = chunks, wait, False
        self.started = asyncio.Event()
        self.yielded = 0

    async def __aiter__(self):
        self.started.set()
        if self.wait is not None:
            await self.wait.wait()
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self):
        self.closed = True


def response(value=None, status=200, trace=TRACE, span=SPAN, headers=None, stream=None):
    fields = [("Content-Type", "application/json"), ("X-Request-ID", REQUEST_ID)]
    if trace is not None:
        fields.append(("X-GovWeave-Trace-ID", trace))
    if span is not None:
        fields.append(("X-GovWeave-Span-ID", span))
    fields.extend(headers or [])
    if stream is None:
        stream = Stream([json.dumps(envelope() if value is None else value).encode()])
    return httpx.Response(status, headers=fields, stream=stream)


class Transport(httpx.MockTransport):
    def __init__(self, handler):
        super().__init__(handler)
        self.closed = False

    async def aclose(self):
        self.closed = True


def client(handler, timeout=5):
    configured = AsyncGovernedToolClient("https://gateway.example", KEY, "support", timeout=timeout)
    transports = []

    def transport():
        value = Transport(handler)
        transports.append(value)
        return value

    configured._make_transport = transport
    return configured, transports


class AsyncTraceClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_uses_explicit_identity_and_metadata_excludes_text(self):
        calls = []
        stream = Stream([json.dumps(envelope()).encode()])

        def handle(request):
            calls.append(request)
            return response(stream=stream)

        c, transports = client(handle)
        context = TraceContext(TRACE, agent_id="c" * 16, parent_span_id="d" * 16,
                               links=("e" * 16,), retry_of_span_id="f" * 16)
        result = await c.invoke("guide", context)
        self.assertEqual((result.status, result.span_id, result.request_id, result.text),
                         ("completed", SPAN, REQUEST_ID, TEXT))
        self.assertNotIn(TEXT, repr(result))
        self.assertNotIn(TEXT, json.dumps(result.metadata()))
        self.assertNotIn(KEY, json.dumps(result.metadata()))
        self.assertEqual(len(calls), 1)
        request = calls[0]
        self.assertEqual(str(request.url), "https://gateway.example/v1/tools/support/invoke")
        self.assertEqual(json.loads(request.content), {"resource_id": "guide"})
        self.assertEqual(request.headers["Authorization"], "Bearer " + KEY)
        self.assertNotIn("Cookie", request.headers)
        for name, value in context.headers().items():
            self.assertEqual(request.headers[name], value)
        self.assertTrue(stream.closed and transports[0].closed)

    async def test_invalid_arguments_and_context_stop_before_network(self):
        calls = []
        c, transports = client(lambda request: calls.append(request))
        for resource in (None, {"resource_id": "guide", "application_id": "spoof"}, "../guide", "a" * 101):
            with self.subTest(resource=resource), self.assertRaises(ToolCallError):
                await c.invoke(resource, TraceContext(TRACE))
        with self.assertRaises(ToolCallError):
            await c.invoke("guide", {"trace_id": TRACE})
        self.assertFalse(calls or transports)

    async def test_denial_preserves_receipt_and_does_not_retry_or_release_body(self):
        calls = []

        def handle(request):
            calls.append(request)
            return response(envelope("tool_not_allowed"), 403)

        c, transports = client(handle)
        result = await c.invoke("restricted", TraceContext(TRACE))
        self.assertEqual((result.status, result.reason, result.http_status, result.span_id),
                         ("blocked", "tool_not_allowed", 403, SPAN))
        self.assertEqual(result.text, "")
        self.assertNotIn(TEXT, json.dumps(result.metadata()))
        self.assertEqual(len(calls), 1)
        self.assertTrue(transports[0].closed)

    async def test_allocation_and_auth_errors_may_precede_span_allocation(self):
        for code, status in (("invalid_api_key", 401), ("invalid_trace_context", 400), ("trace_unavailable", 503)):
            c, _ = client(lambda request: response(envelope(code), status, trace=None, span=None))
            result = await c.invoke("guide", TraceContext(TRACE))
            self.assertEqual((result.reason, result.status, result.span_id), (code, "error", None))

    async def test_invalid_or_duplicate_trace_receipts_never_release_text(self):
        cases = [
            {"trace": None, "span": None}, {"span": None}, {"trace": "c" * 32},
            {"span": "0" * 16}, {"span": "B" * 16},
            {"headers": [("X-GovWeave-Trace-ID", TRACE)]},
            {"headers": [("X-GovWeave-Span-ID", SPAN)]},
        ]
        for fields in cases:
            reply = response(**fields)
            c, transports = client(lambda request: reply)
            result = await c.invoke("guide", TraceContext(TRACE))
            with self.subTest(fields=fields):
                self.assertEqual((result.status, result.reason, result.text, result.span_id),
                                 ("error", "invalid_trace_receipt", "", None))
                self.assertTrue(reply.is_closed and transports[0].closed)

    async def test_timeout_before_headers_keeps_unknown_without_fabricated_span(self):
        calls, terminated = [], asyncio.Event()

        async def handle(request):
            calls.append(request)
            try:
                await asyncio.Event().wait()
            finally:
                terminated.set()

        c, transports = client(handle, timeout=1)
        result = await asyncio.wait_for(c.invoke("guide", TraceContext(TRACE)), timeout=2)
        self.assertEqual((result.status, result.reason, result.span_id, result.request_id),
                         ("unknown", "transport_timeout", None, ""))
        self.assertTrue(terminated.is_set() and transports[0].closed)
        self.assertEqual(len(calls), 1)

    async def test_timeout_after_headers_keeps_real_receipt_but_not_success(self):
        stream = Stream([b"{}"], wait=asyncio.Event())
        c, transports = client(lambda request: response(stream=stream), timeout=1)
        result = await asyncio.wait_for(c.invoke("guide", TraceContext(TRACE)), timeout=2)
        self.assertEqual((result.status, result.reason, result.span_id, result.request_id, result.text),
                         ("unknown", "transport_timeout", SPAN, REQUEST_ID, ""))
        self.assertTrue(stream.closed and transports[0].closed)

    async def test_transport_failure_is_unknown_and_not_retried(self):
        calls = []

        def handle(request):
            calls.append(request)
            raise httpx.ConnectError("untrusted private details " + KEY, request=request)

        c, transports = client(handle)
        result = await c.invoke("guide", TraceContext(TRACE))
        self.assertEqual((result.status, result.reason, result.span_id, result.text),
                         ("unknown", "transport_error", None, ""))
        self.assertEqual(len(calls), 1)
        self.assertTrue(transports[0].closed)
        self.assertNotIn(KEY, json.dumps(result.metadata()))

    async def test_external_cancellation_propagates_and_closes_request_stream(self):
        release = asyncio.Event()
        stream = Stream([json.dumps(envelope()).encode()], wait=release)
        calls = []

        def handle(request):
            calls.append(request)
            return response(stream=stream)

        c, transports = client(handle)
        pending = asyncio.create_task(c.invoke("guide", TraceContext(TRACE)))
        await asyncio.wait_for(stream.started.wait(), timeout=1)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        release.set()
        await asyncio.sleep(0)
        self.assertTrue(pending.cancelled() and stream.closed and transports[0].closed)
        self.assertEqual(stream.yielded, 0)
        self.assertEqual(len(calls), 1)

    async def test_response_and_text_limits_fail_before_release(self):
        stream = Stream([b"x" * 4096] * 18)
        c, _ = client(lambda request: response(stream=stream))
        result = await c.invoke("guide", TraceContext(TRACE))
        self.assertEqual((result.reason, result.text), ("response_limit", ""))
        self.assertEqual(stream.yielded, 17)
        self.assertTrue(stream.closed)
        oversized = envelope()
        oversized["text"] = "x" * 8193
        c, _ = client(lambda request: response(oversized))
        result = await c.invoke("guide", TraceContext(TRACE))
        self.assertEqual((result.reason, result.text), ("invalid_response", ""))

    async def test_duplicate_json_and_inconsistent_governance_fail_closed(self):
        malformed = json.dumps(envelope()).replace('"request_id":', '"request_id":"spoof", "request_id":', 1).encode()
        value = envelope()
        value["governance"]["decision"] = "block"
        for reply in (response(stream=Stream([malformed])), response(value),
                      response(headers=[("X-Request-ID", REQUEST_ID)]),
                      response(headers=[("Content-Encoding", "gzip")])):
            c, _ = client(lambda request: reply)
            result = await c.invoke("guide", TraceContext(TRACE))
            self.assertEqual((result.reason, result.text), ("invalid_response", ""))

    async def test_parallel_calls_share_client_without_context_or_cookie_leaks(self):
        entered, release = 0, asyncio.Event()
        calls = []

        async def handle(request):
            nonlocal entered
            calls.append(request)
            entered += 1
            if entered == 2:
                release.set()
            await release.wait()
            trace = request.headers["X-GovWeave-Trace-ID"]
            self.assertEqual(request.headers["X-GovWeave-Agent-ID"], trace[:16])
            self.assertNotIn("Cookie", request.headers)
            return response(trace=trace, span=trace[:16], headers=[("Set-Cookie", "private=never_forward")])

        c, transports = client(handle)
        contexts = [TraceContext(char * 32, agent_id=char * 16) for char in ("a", "c")]
        results = await asyncio.wait_for(asyncio.gather(*(c.invoke("guide", context) for context in contexts)), timeout=2)
        self.assertEqual([(r.trace_id, r.span_id, r.status) for r in results],
                         [(context.trace_id, context.agent_id, "completed") for context in contexts])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(transports), 2)
        self.assertTrue(all(t.closed for t in transports))

    async def test_no_redirect_proxy_or_transport_retry(self):
        configured = AsyncGovernedToolClient("https://gateway.example", KEY, "support")
        with patch("govweave_async_tracing.httpx.AsyncHTTPTransport") as transport:
            configured._make_transport()
            transport.assert_called_once_with(retries=0, trust_env=False)
        calls = []

        def handle(request):
            calls.append(request)
            return response(status=302, headers=[("Location", "https://provider.example/private")])

        c, _ = client(handle)
        original = httpx.AsyncClient
        with patch("govweave_async_tracing.httpx.AsyncClient", wraps=original) as factory:
            result = await c.invoke("guide", TraceContext(TRACE))
        self.assertFalse(factory.call_args.kwargs["trust_env"])
        self.assertFalse(factory.call_args.kwargs["follow_redirects"])
        self.assertEqual(factory.call_args.kwargs["max_redirects"], 0)
        self.assertEqual(result.status, "error")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
