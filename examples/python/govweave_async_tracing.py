"""Optional HTTPX/asyncio tracing client for async Agent framework adapters.

Each invocation owns its HTTP transport and immutable explicit trace context.
No retries, redirects, environment proxies, shared cookies or background worker
threads are used. Cancellation propagates to the awaiting caller. It does not
prove that the remote read never started or that completed effects rolled back.
"""

import asyncio
import json

import httpx

from govweave_tools import (
    GovernedToolClient, ToolCallError, _IDENTIFIER, _MAX_RESPONSE, _REQUEST_ID,
    _parse_tool_response,
)
from govweave_tracing import TraceContext, TracedToolOutcome, _identifier


class AsyncGovernedToolClient:
    def __init__(self, root_url, api_key, alias, timeout=5, allow_insecure_http=False):
        # Keep configuration validation identical to the standard-library
        # client; constructing it performs no network I/O.
        configured = GovernedToolClient(root_url, api_key, alias, timeout, allow_insecure_http)
        self._endpoint = configured._endpoint
        self._key = configured._key
        self._timeout = configured._timeout

    def _make_transport(self):
        return httpx.AsyncHTTPTransport(retries=0, trust_env=False)

    async def invoke(self, resource_id, context):
        """Perform one governed read. Return metadata and approved text only.

        Transport failures are unknown outcomes, not evidence of rejection or
        safe non-execution. External CancelledError is deliberately not caught.
        Callers decide whether to make a distinct, explicitly linked retry.
        """
        if not isinstance(context, TraceContext):
            raise ToolCallError("invalid_trace_context")
        if not isinstance(resource_id, str) or not _IDENTIFIER.fullmatch(resource_id):
            raise ToolCallError("invalid_arguments")
        payload = json.dumps({"resource_id": resource_id}, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": "Bearer " + self._key,
            "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity", **context.headers(),
        }
        span_id, request_id, status = None, "", 0
        try:
            async with asyncio.timeout(self._timeout):
                async with httpx.AsyncClient(
                    transport=self._make_transport(), trust_env=False,
                    follow_redirects=False, max_redirects=0, timeout=self._timeout,
                ) as client:
                    async with client.stream("POST", self._endpoint, content=payload, headers=headers) as response:
                        status = response.status_code
                        trace_values = response.headers.get_list("X-GovWeave-Trace-ID")
                        span_values = response.headers.get_list("X-GovWeave-Span-ID")
                        absent = not trace_values and not span_values
                        if (len(trace_values) == len(span_values) == 1 and
                                trace_values[0] == context.trace_id and _identifier(span_values[0], 16)):
                            span_id = span_values[0]
                        elif not (absent and status in (400, 401, 503)):
                            raise ToolCallError("invalid_trace_receipt", http_status=status)
                        ids = response.headers.get_list("X-Request-ID")
                        if len(ids) == 1 and _REQUEST_ID.fullmatch(ids[0]):
                            request_id = ids[0]
                        else:
                            raise ToolCallError("invalid_response", http_status=status)
                        content_types = response.headers.get_list("Content-Type")
                        if (len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json" or
                                response.headers.get("Content-Encoding", "identity").lower() != "identity"):
                            raise ToolCallError("invalid_response", http_status=status)
                        data = bytearray()
                        async for chunk in response.aiter_raw(chunk_size=4096):
                            if len(data) + len(chunk) > _MAX_RESPONSE:
                                raise ToolCallError("response_limit", http_status=status)
                            data.extend(chunk)
                        result = _parse_tool_response(data, status, request_id)
                        # A successful traced call requires an actual receipt.
                        if span_id is None:
                            raise ToolCallError("invalid_trace_receipt", http_status=status)
            return TracedToolOutcome(context.trace_id, span_id, result.request_id, status,
                                     "completed", "tool_returned", result.text)
        except (TimeoutError, httpx.TimeoutException):
            return TracedToolOutcome(context.trace_id, span_id, request_id, status,
                                     "unknown", "transport_timeout", "")
        except (httpx.TransportError, OSError):
            return TracedToolOutcome(context.trace_id, span_id, request_id, status,
                                     "unknown", "transport_error", "")
        except ToolCallError as error:
            # Trace allocation/authentication errors can legitimately precede
            # a receipt. All other responses without one remain untrusted.
            if span_id is None and error.code not in (
                    "invalid_api_key", "invalid_trace_context", "trace_unavailable", "invalid_trace_receipt"):
                error = ToolCallError("invalid_trace_receipt", http_status=status)
            blocked = error.http_status == 403 and error.code in (
                "tool_not_allowed", "tool_output_blocked", "tool_instruction_blocked", "content_output_blocked")
            return TracedToolOutcome(context.trace_id, span_id, error.request_id or request_id,
                                     error.http_status or status, "blocked" if blocked else "error", error.code, "")
