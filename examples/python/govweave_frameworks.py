"""Optional, pinned-framework examples with explicit GovWeave context.

LangGraph schedules the coordinator's graph; Pydantic AI executes a real tool
loop using a deterministic local FunctionModel. Only read-tool calls traverse
GovWeave. These examples do not measure model quality or instrument arbitrary
framework internals. No checkpointing, automatic retries, or cloud telemetry.
"""
from dataclasses import replace
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context
from pydantic_ai import Agent
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import UsageLimits

from govweave_tools import ToolCallError, _IDENTIFIER
from govweave_tracing import TraceContext, TracedToolOutcome, _identifier


class _StopToolLoop(Exception):
    """Private terminal signal: a denied/unknown read must not become tool text."""


def _check_input(resource_id, context):
    if not isinstance(context, TraceContext):
        raise ToolCallError("invalid_trace_context")
    if not isinstance(resource_id, str) or not _IDENTIFIER.fullmatch(resource_id):
        raise ToolCallError("invalid_arguments")


def _checked_outcome(outcome, context):
    if not isinstance(outcome, TracedToolOutcome) or outcome.trace_id != context.trace_id:
        raise ToolCallError("invalid_trace_receipt")
    if outcome.status == "completed" and not _identifier(outcome.span_id, 16):
        return replace(outcome, span_id=None, status="unknown", reason="invalid_trace_receipt", text="")
    return outcome


async def run_worker(client, resource_id, context):
    """Execute exactly one read through a per-invocation Pydantic AI agent.

Identity, resource selection and trace metadata are explicit caller inputs,
outside the model's tool arguments. A blocked/error/unknown result stops the
tool loop before a second FunctionModel response. Cancellation propagates to
the actual awaited asynchronous tool invocation; it is never a retry signal.
    """
    _check_input(resource_id, context)
    observed = []
    model_requests = 0

    async def fixed_model(messages, info):
        nonlocal model_requests
        model_requests += 1
        if model_requests == 1:
            return ModelResponse(parts=[ToolCallPart("read_document", {}, tool_call_id="synthetic_read")])
        returned = any(isinstance(part, ToolReturnPart) for message in messages for part in message.parts)
        if model_requests != 2 or not returned or len(observed) != 1 or observed[0].status != "completed":
            raise ToolCallError("framework_contract_error")
        return ModelResponse(parts=[TextPart("The synthetic governed read completed.")])

    agent = Agent(FunctionModel(fixed_model), name="govweave_local_read_worker", retries=0)
    # Per-instance override also defeats an embedding application's
    # Agent.instrument_all(True), without mutating a process-global default.
    agent.instrument = False

    @agent.tool_plain(retries=0)
    async def read_document() -> str:
        """Read the caller-selected resource through the governance gateway."""
        if observed:
            raise ToolCallError("framework_call_limit")
        outcome = _checked_outcome(await client.invoke(resource_id, context), context)
        observed.append(outcome)
        if outcome.status != "completed":
            raise _StopToolLoop("governed_read_stopped")
        return outcome.text

    try:
        await agent.run("Execute the configured synthetic read once.",
                        usage_limits=UsageLimits(request_limit=2, tool_calls_limit=1),
                        infer_name=False)
    except _StopToolLoop:
        pass
    if len(observed) != 1:
        raise ToolCallError("framework_contract_error")
    return observed[0]


class CoordinatorInput(TypedDict, total=False):
    context: TraceContext
    resource_id: str
    worker_resource_id: str
    worker_agent_id: str


class CoordinatorState(CoordinatorInput, total=False):
    root: TracedToolOutcome
    local: TracedToolOutcome
    remote: TracedToolOutcome
    join: TracedToolOutcome
    status: str


def _combined_status(outcomes):
    statuses = {outcome.status for outcome in outcomes}
    if "blocked" in statuses:
        return "blocked"
    if "unknown" in statuses:
        return "unknown"
    if statuses != {"completed"}:
        return "error"
    return "completed"


class _LocalCoordinator:
    def __init__(self, graph):
        self.graph = graph

    async def ainvoke(self, state):
        """Run the compiled graph with local tracing disabled per async context."""
        allowed = {"context", "resource_id", "worker_resource_id", "worker_agent_id"}
        if not isinstance(state, dict) or set(state) - allowed or not {"context", "resource_id"} <= state.keys():
            raise ToolCallError("invalid_arguments")
        _check_input(state["resource_id"], state["context"])
        _check_input(state.get("worker_resource_id", state["resource_id"]), state["context"])
        if "worker_agent_id" in state and not _identifier(state["worker_agent_id"], 16):
            raise ToolCallError("invalid_trace_context")
        # LangSmith environment variables must not turn the example into an
        # external exporter of graph state or returned document content.
        with tracing_context(enabled=False):
            return await self.graph.ainvoke(dict(state), config={"callbacks": [], "recursion_limit": 8})


def build_coordinator(client, delegate):
    """Build root -> parallel local/remote reads -> join on a real StateGraph.

``delegate(resource_id, context)`` is an awaited handoff supplied by the caller,
such as the bounded serialized queue in the integration runner. It must use
its own application client. The same compiled graph may run independent task
contexts concurrently. No intermediate graph state is checkpointed or cached.
    """
    async def root(state):
        context = state["context"]
        outcome = _checked_outcome(await client.invoke(state["resource_id"], context), context)
        return {"root": outcome, "status": outcome.status}

    def next_after_root(state):
        return ["local", "remote"] if state["root"].status == "completed" else END

    async def local(state):
        context = state["context"].after(state["root"].span_id)
        outcome = _checked_outcome(await client.invoke(state["resource_id"], context), context)
        return {"local": outcome}

    async def remote(state):
        context = state["context"].after(state["root"].span_id)
        if "worker_agent_id" in state:
            context = replace(context, agent_id=state["worker_agent_id"])
        outcome = _checked_outcome(await delegate(state.get("worker_resource_id", state["resource_id"]), context), context)
        return {"remote": outcome}

    async def join(state):
        status = _combined_status([state["local"], state["remote"]])
        if status != "completed":
            return {"status": status}
        context = state["context"].after(state["root"].span_id,
                                         links=(state["local"].span_id, state["remote"].span_id))
        outcome = _checked_outcome(await client.invoke(state["resource_id"], context), context)
        return {"join": outcome, "status": outcome.status}

    graph = StateGraph(CoordinatorState, input_schema=CoordinatorInput)
    graph.add_node("root", root)
    graph.add_node("local", local)
    graph.add_node("remote", remote)
    graph.add_node("join", join)
    graph.add_edge(START, "root")
    graph.add_conditional_edges("root", next_after_root, ["local", "remote", END])
    graph.add_edge(["local", "remote"], "join")
    graph.add_edge("join", END)
    return _LocalCoordinator(graph.compile(checkpointer=False))
