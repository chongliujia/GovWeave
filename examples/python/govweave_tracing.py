"""Opt-in trace propagation for heterogeneous clients; no global mutable context.

Identifiers and graph relationships are caller declarations, not authorization.
This is GovWeave's bounded header contract, not a complete W3C/OTLP client.

Create TraceContext.new() once in a task coordinator. Pass the trace_id across
processes and give each worker its own agent_id. Use returned server span_id
values as parents, links or explicit retry references. The tool-only helper and
run_traced_agent are opt-in: old client entry points remain unchanged.
"""
from copy import copy
from dataclasses import dataclass, field, replace
import re
import secrets
import urllib.error

from govweave_tools import GovernedToolClient, ToolCallError


def _identifier(value, size):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value)) and value != "0" * size


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    agent_id: str = ""
    parent_span_id: str = ""
    links: tuple[str, ...] = ()
    retry_of_span_id: str = ""

    def __post_init__(self):
        if (not _identifier(self.trace_id, 32) or
                any(value != "" and not _identifier(value, 16) for value in (self.agent_id, self.parent_span_id, self.retry_of_span_id)) or
                not isinstance(self.links, tuple) or len(self.links) > 4 or
                any(not _identifier(value, 16) for value in self.links) or len(set(self.links)) != len(self.links)):
            raise ToolCallError("invalid_trace_context")

    @classmethod
    def new(cls):
        return cls(secrets.token_hex(16), agent_id=secrets.token_hex(8))

    def after(self, span_id, *, links=(), retry_of_span_id=""):
        """Create a new context. A retry relation never schedules a request."""
        return replace(self, parent_span_id=span_id, links=links, retry_of_span_id=retry_of_span_id)

    def headers(self):
        values = {"X-GovWeave-Trace-ID": self.trace_id}
        for name, value in (("X-GovWeave-Agent-ID", self.agent_id),
                            ("X-GovWeave-Parent-Span-ID", self.parent_span_id),
                            ("X-GovWeave-Retry-Of", self.retry_of_span_id)):
            if value:
                values[name] = value
        if self.links:
            values["X-GovWeave-Link-Span-IDs"] = ",".join(self.links)
        return values


@dataclass(frozen=True)
class TracedToolOutcome:
    trace_id: str
    span_id: str | None
    request_id: str
    http_status: int
    status: str
    reason: str
    text: str = field(repr=False)

    def metadata(self):
        return {name: getattr(self, name) for name in (
            "trace_id", "span_id", "request_id", "http_status", "status", "reason")}


class _TraceOpener:
    """One invocation owns this mutable receipt; never shared across clients."""
    def __init__(self, opener, context):
        self.opener, self.context, self.span_id = opener, context, None

    def open(self, request, **kwargs):
        for name, value in self.context.headers().items():
            request.add_header(name, value)
        try:
            response = self.opener.open(request, **kwargs)
        except urllib.error.HTTPError as error:
            response = error
        trace_values = response.headers.get_all("X-GovWeave-Trace-ID", [])
        span_values = response.headers.get_all("X-GovWeave-Span-ID", [])
        # Authentication failures have no trustworthy trace attachment. Let the
        # original tool client validate and classify the gateway error.
        absent = not trace_values and not span_values
        valid = len(trace_values) == len(span_values) == 1 and trace_values[0] == self.context.trace_id and _identifier(span_values[0], 16)
        if valid:
            self.span_id = span_values[0]
        elif not (absent and response.status == 401):
            response.close()
            raise ToolCallError("invalid_trace_receipt")
        return response


def invoke_traced_tool(client, arguments, context):
    """Invoke once using an immutable explicit context; never retry or bypass.

    The supplied client and context remain unchanged. Each concurrent call has
    its own opener wrapper and response receipt. Content is returned to the
    application only; metadata() deliberately excludes it.
    """
    if not isinstance(client, GovernedToolClient) or not isinstance(context, TraceContext):
        raise ToolCallError("invalid_trace_context")
    local = copy(client)
    receipt = _TraceOpener(client._opener, context)
    local._opener = receipt
    try:
        result = local.execute(arguments)
        return TracedToolOutcome(context.trace_id, receipt.span_id, result.request_id, 200, "completed", "tool_returned", result.text)
    except ToolCallError as error:
        blocked = error.http_status == 403 and error.code in (
            "tool_not_allowed", "tool_output_blocked", "tool_instruction_blocked", "content_output_blocked")
        return TracedToolOutcome(context.trace_id, receipt.span_id, error.request_id, error.http_status,
                                 "blocked" if blocked else "error", error.code, "")


class _RunTraceOpener:
    """Sequential calls inside one copied KnowledgeAgent run, capped at 16."""
    def __init__(self, opener, context):
        self.opener, self.context, self.receipts = opener, context, []

    def open(self, request, **kwargs):
        if len(self.receipts) >= 16:
            raise ToolCallError("trace_call_limit")
        context = self.context
        receipt = _TraceOpener(self.opener, context)
        self.receipts.append(None)
        response = receipt.open(request, **kwargs)
        if receipt.span_id:
            event = {"trace_id": context.trace_id, "span_id": receipt.span_id}
            if context.parent_span_id:
                event["parent_span_id"] = context.parent_span_id
            self.receipts[-1] = event
            # Links/retry describe the entry call only; subsequent sequential
            # model/tool calls have a parent relation to their predecessor.
            self.context = context.after(receipt.span_id)
        return response


def run_traced_agent(agent, question, context):
    """Opt in a plain KnowledgeAgent to model -> tool -> model propagation.

    The original run(question) and execute(arguments) interfaces stay intact.
    Clone both reference objects so simultaneous runs own separate receipts.
    No framework subclasses are claimed to support this copying contract.
    """
    from govweave_agent import KnowledgeAgent

    if type(agent) is not KnowledgeAgent or not isinstance(context, TraceContext):
        raise ToolCallError("invalid_trace_context")
    local = copy(agent)
    local.tool = copy(agent.tool)
    calls = _RunTraceOpener(agent.tool._opener, context)
    local.tool._opener = calls
    result = local.run(question)
    events = [dict(event) for event in result.events]
    for event, receipt in zip(events, calls.receipts):
        if receipt:
            event.update(receipt)
    return replace(result, trace_id=context.trace_id, events=events)
