#!/usr/bin/env python3
"""Run actual optional frameworks against bounded in-memory async clients.

These are orchestration/propagation tests, not gateway HTTP or model-quality
measurements. The integration runner independently tests actual gateway I/O.
"""
import asyncio
from collections import defaultdict
from dataclasses import replace
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))

from pydantic_ai import Agent
from pydantic_ai.models.function import FunctionModel
from langgraph.graph.state import CompiledStateGraph
from govweave_frameworks import build_coordinator, run_worker
from govweave_tools import ToolCallError
from govweave_tracing import TraceContext, TracedToolOutcome


class LocalClient:
    def __init__(self, barrier=None):
        self.calls = []
        self.barrier = barrier

    async def invoke(self, resource, context):
        span = f"{len(self.calls) + 1:016x}"
        self.calls.append((resource, context, span))
        if self.barrier and context.parent_span_id and not context.links:
            await self.barrier.wait()
        else:
            await asyncio.sleep(0)
        status, reason, http = "completed", "tool_returned", 200
        if resource == "denied":
            status, reason, http = "blocked", "tool_not_allowed", 403
        elif resource == "uncertain":
            span, status, reason, http = None, "unknown", "transport_timeout", 0
        elif resource == "bad-receipt":
            span = None
        return TracedToolOutcome(context.trace_id, span, "req_" + "A" * 22,
                                 http, status, reason, "Synthetic document content")


class FrameworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_pydantic_executes_one_tool_and_two_local_model_steps(self):
        client = LocalClient()
        steps = []

        def observed_model(function):
            async def wrapped(messages, info):
                steps.append(len(messages))
                return await function(messages, info)
            return FunctionModel(wrapped)

        with patch("govweave_frameworks.FunctionModel", side_effect=observed_model):
            result = await run_worker(client, "guide", TraceContext("a" * 32))
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(steps), 2)
        self.assertEqual(len(client.calls), 1)
        self.assertNotIn("Synthetic document content", str(result))

    async def test_pydantic_denial_and_unknown_stop_before_second_model_step(self):
        for resource, expected in (("denied", "blocked"), ("uncertain", "unknown"), ("bad-receipt", "unknown")):
            with self.subTest(resource=resource):
                client, steps = LocalClient(), []

                def observed_model(function):
                    async def wrapped(messages, info):
                        steps.append(1)
                        return await function(messages, info)
                    return FunctionModel(wrapped)

                with patch("govweave_frameworks.FunctionModel", side_effect=observed_model):
                    result = await run_worker(client, resource, TraceContext("a" * 32))
                self.assertEqual(result.status, expected)
                self.assertEqual((len(client.calls), len(steps)), (1, 1))

    async def test_worker_cancellation_reaches_awaited_tool(self):
        started, cancelled = asyncio.Event(), asyncio.Event()

        class WaitingClient:
            calls = 0

            async def invoke(self, resource, context):
                self.calls += 1
                started.set()
                try:
                    await asyncio.Future()
                finally:
                    cancelled.set()

        client = WaitingClient()
        task = asyncio.create_task(run_worker(client, "guide", TraceContext("a" * 32)))
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(cancelled.is_set())
        self.assertEqual(client.calls, 1)

    async def test_compiled_langgraph_runs_parallel_branches_and_join(self):
        client = LocalClient(barrier=asyncio.Barrier(2))

        async def delegate(resource, context):
            return await run_worker(client, resource, context)

        graph = build_coordinator(client, delegate)
        self.assertIsInstance(graph.graph, CompiledStateGraph)
        context = TraceContext("a" * 32, agent_id="a" * 16)
        result = await asyncio.wait_for(graph.ainvoke({"context": context, "resource_id": "guide",
                                                      "worker_agent_id": "b" * 16}), 3)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(client.calls), 4)
        calls = {span: cx for _, cx, span in client.calls}
        root = result["root"].span_id
        for name in ("local", "remote"):
            self.assertEqual(calls[result[name].span_id].parent_span_id, root)
        self.assertEqual(calls[result["remote"].span_id].agent_id, "b" * 16)
        self.assertEqual(calls[result["local"].span_id].agent_id, "a" * 16)
        self.assertEqual(calls[result["join"].span_id].links,
                         (result["local"].span_id, result["remote"].span_id))
        self.assertEqual(calls[result["join"].span_id].parent_span_id, root)
        self.assertEqual(context.parent_span_id, "")

    async def test_root_failure_stops_graph_before_handoff(self):
        client = LocalClient()

        async def unexpected_delegate(resource, context):
            self.fail("a refused root must not hand off work")

        result = await build_coordinator(client, unexpected_delegate).ainvoke({
            "context": TraceContext("a" * 32), "resource_id": "denied"})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(client.calls), 1)
        self.assertTrue({"local", "remote", "join"}.isdisjoint(result))

    async def test_remote_failure_keeps_observed_branches_without_join_or_retry(self):
        for resource, expected in (("denied", "blocked"), ("uncertain", "unknown")):
            with self.subTest(resource=resource):
                client = LocalClient()

                async def delegate(resource, context):
                    return await run_worker(client, resource, context)

                result = await build_coordinator(client, delegate).ainvoke({
                    "context": TraceContext("a" * 32), "resource_id": "guide", "worker_resource_id": resource})
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["local"].status, "completed")
                self.assertEqual(result["remote"].status, expected)
                self.assertNotIn("join", result)
                self.assertEqual(len(client.calls), 3)

    async def test_parallel_runs_of_one_graph_keep_context_and_links_separate(self):
        client = LocalClient(barrier=asyncio.Barrier(4))

        async def delegate(resource, context):
            return await run_worker(client, resource, context)

        graph = build_coordinator(client, delegate)
        contexts = [TraceContext(letter * 32, agent_id=letter * 16) for letter in ("a", "b")]
        results = await asyncio.wait_for(asyncio.gather(*[
            graph.ainvoke({"context": context, "resource_id": "guide", "worker_agent_id": "c" * 16})
            for context in contexts]), 3)
        groups = defaultdict(list)
        for _, context, span in client.calls:
            groups[context.trace_id].append((context, span))
        self.assertEqual(len(client.calls), 8)
        for context, result in zip(contexts, results):
            self.assertEqual(result["status"], "completed")
            own = {span for _, span in groups[context.trace_id]}
            self.assertEqual(len(own), 4)
            for call, _ in groups[context.trace_id]:
                self.assertTrue(not call.parent_span_id or call.parent_span_id in own)
                self.assertTrue(set(call.links) <= own)
            self.assertTrue(all(result[name].trace_id == context.trace_id for name in ("root", "local", "remote", "join")))

    async def test_graph_cancellation_cancels_both_active_branches(self):
        entered, cancelled = set(), set()
        both = asyncio.Event()

        class WaitingClient(LocalClient):
            async def invoke(self, resource, context):
                if not context.parent_span_id:
                    return await super().invoke(resource, context)
                entered.add(context.agent_id)
                if len(entered) == 2:
                    both.set()
                try:
                    await asyncio.Future()
                finally:
                    cancelled.add(context.agent_id)

        client = WaitingClient()

        async def delegate(resource, context):
            return await run_worker(client, resource, context)

        task = asyncio.create_task(build_coordinator(client, delegate).ainvoke({
            "context": TraceContext("a" * 32, agent_id="a" * 16), "resource_id": "guide", "worker_agent_id": "b" * 16}))
        await asyncio.wait_for(both.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(cancelled, {"a" * 16, "b" * 16})

    async def test_invalid_input_and_wrong_trace_receipt_fail_without_fallback(self):
        client = LocalClient()

        async def delegate(resource, context):
            outcome = await client.invoke(resource, context)
            return replace(outcome, trace_id="f" * 32)

        graph = build_coordinator(client, delegate)
        for state in ({}, {"context": TraceContext("a" * 32), "resource_id": "guide", "api_key": "not_allowed"},
                      {"context": TraceContext("a" * 32), "resource_id": "guide", "worker_agent_id": "invalid"}):
            with self.subTest(state=state), self.assertRaises(ToolCallError):
                await graph.ainvoke(state)
        self.assertEqual(client.calls, [])
        with self.assertRaisesRegex(ToolCallError, "invalid_trace_receipt"):
            await graph.ainvoke({"context": TraceContext("a" * 32), "resource_id": "guide"})
        self.assertEqual(len(client.calls), 3)

    async def test_optional_telemetry_cannot_be_enabled_by_embedding_defaults(self):
        client = LocalClient()

        async def delegate(resource, context):
            return await run_worker(client, resource, context)

        with patch.dict(os.environ, {"LANGSMITH_TRACING": "true", "LANGCHAIN_TRACING_V2": "true"}), \
                patch.object(Agent, "_instrument_default", True), \
                patch("pydantic_ai.agent.InstrumentationCap.__init__", side_effect=AssertionError("instrumentation enabled")), \
                patch("langsmith.client.Client.__init__", side_effect=AssertionError("telemetry client constructed")):
            result = await build_coordinator(client, delegate).ainvoke({
                "context": TraceContext("a" * 32), "resource_id": "guide"})
        self.assertEqual(result["status"], "completed")


if __name__ == "__main__":
    unittest.main()
