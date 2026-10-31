#!/usr/bin/env python3
"""Bounded LangGraph/Pydantic AI trace trial with local, deterministic services.

Install the optional pinned requirements in a separate virtual environment.
No cloud model, customer data, persistent queue or framework telemetry is used.
"""
import argparse
import asyncio
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/python"))
# These flags affect this local test process, not the user's persisted settings.
os.environ.update(LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false",
                  OTEL_SDK_DISABLED="true", LOGFIRE_SEND_TO_LOGFIRE="false", PYDANTIC_AI_NO_BANNER="1")
SPEC = importlib.util.spec_from_file_location("framework_trace_fixture", ROOT / "scripts/demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)

PLAN = ("framework_handoff", "concurrent_task_isolation", "gateway_timeout_retry",
        "client_timeout_missing_receipt", "cancel_before_dispatch", "cancel_after_dispatch",
        "unresolved_reference", "governance_denial", "query_scope_revocation")
FIXTURE_TEXT = "Synthetic framework trial document."
SOURCES = ("scripts/trial-framework-trace.py", "examples/python/govweave_frameworks.py",
           "examples/python/govweave_async_tracing.py", "examples/python/govweave_tracing.py",
           "examples/python/govweave_tools.py", "examples/python/framework-trace-requirements.txt")


class CheckFailed(Exception):
    pass


def check(condition, code):
    if not condition:
        raise CheckFailed(code)


def loopback_address(address):
    if not isinstance(address, tuple) or len(address) < 2:
        raise OSError("external_network_disabled")
    try:
        allowed = ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        raise OSError("external_network_disabled")


class Fixture(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.lock = threading.Lock()
        self.counts = Counter()
        self.header_errors = 0
        self.entered = {name: threading.Event() for name in ("flaky-guide", "client-wait-guide", "cancel-guide")}
        self.release = {name: threading.Event() for name in self.entered}
        super().__init__(("127.0.0.1", 0), FixtureHandler)

    def state(self):
        with self.lock:
            return sum(self.counts.values()), self.header_errors

    def count(self, resource):
        with self.lock:
            return self.counts[resource]

    def server_close(self):
        for event in self.release.values():
            event.set()
        super().server_close()


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            self.connection.settimeout(3)
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/read" or not 0 < size <= 4096 or self.headers.get("Transfer-Encoding"):
                raise ValueError()
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict) or set(body) != {"resource_id"}:
                raise ValueError()
            resource = body["resource_id"]
            if resource not in ("public-guide", "restricted-guide", "credential-guide", *self.server.entered):
                raise ValueError()
            valid = (self.headers.get("Authorization") == "Bearer " + TOOLS.PROVIDER_KEY
                     and not any(name.lower().startswith("x-govweave-") and name.lower() != "x-govweave-request-id" for name in self.headers)
                     and self.headers.get("Cookie") is None and self.headers.get("Origin") is None)
            with self.server.lock:
                self.server.counts[resource] += 1
                number = self.server.counts[resource]
                self.server.header_errors += int(not valid)
            if not valid:
                raise ValueError()
            if resource in self.server.entered and (resource != "flaky-guide" or number == 1):
                self.server.entered[resource].set()
                self.server.release[resource].wait(timeout=8)
            data = json.dumps({"text": FIXTURE_TEXT}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (OSError, ValueError, TypeError):
            # Broken pipes are expected when a client deadline closes the path.
            self.close_connection = True


class QueueBridge:
    """In-process bounded JSON handoff; application B's key never enters messages."""
    def __init__(self, client, run_worker):
        self.client, self.run_worker = client, run_worker
        self.queue = asyncio.Queue(maxsize=8)
        self.active, self.workers = {}, []
        self.submissions = set()
        self.closed = False

    def start(self):
        if not self.workers:
            self.workers = [asyncio.create_task(self._consume()) for _ in range(4)]

    async def submit(self, resource_id, context):
        if self.closed:
            raise CheckFailed("bridge_closed")
        message = json.dumps({"resource_id": resource_id, "context": asdict(context)}).encode()
        check(len(message) <= 1024, "handoff_message_limit")
        future = asyncio.get_running_loop().create_future()
        submission = asyncio.current_task()
        self.submissions.add(submission)
        try:
            await self.queue.put((message, future))
            return await future
        except asyncio.CancelledError:
            future.cancel()
            running = self.active.get(future)
            if running is not None:
                running.cancel()
                await asyncio.gather(running, return_exceptions=True)
            raise
        finally:
            self.submissions.discard(submission)

    async def _consume(self):
        from govweave_tracing import TraceContext
        while True:
            message, future = await self.queue.get()
            try:
                if future.cancelled():
                    continue
                data = json.loads(message)
                fields = data["context"]
                fields["links"] = tuple(fields["links"])
                context = TraceContext(**fields)
                task = asyncio.create_task(self.run_worker(self.client, data["resource_id"], context))
                self.active[future] = task
                try:
                    result = await task
                except asyncio.CancelledError:
                    future.cancel()
                    if asyncio.current_task().cancelling():
                        raise
                except Exception:
                    if not future.done():
                        future.set_exception(CheckFailed("worker_failed"))
                else:
                    if not future.done():
                        future.set_result(result)
            finally:
                self.active.pop(future, None)
                self.queue.task_done()

    async def close(self):
        self.closed = True
        submissions = [task for task in self.submissions if task is not asyncio.current_task()]
        for task in submissions:
            task.cancel()
        await asyncio.gather(*submissions, return_exceptions=True)
        for task in self.workers:
            task.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        while not self.queue.empty():
            _, future = self.queue.get_nowait()
            future.cancel()
            self.queue.task_done()


async def gather_joined(coroutines):
    """A failed test run must not leave sibling workflows in the next case."""
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]
    try:
        return await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def protect_metadata(report, private_values, audit):
    serialized = json.dumps(report)
    if any(value in serialized or value in audit for value in private_values):
        for case in report["cases"]:
            case.pop("evidence", None)
            case.update(state="unknown", reason="privacy_check_failed_evidence_withheld")
        report["metadata_privacy_verified"] = False
        raise CheckFailed("private_content_in_metadata")
    report["metadata_privacy_verified"] = True


async def wait_entered(fixture, resource):
    deadline = time.monotonic() + 4
    while not fixture.entered[resource].is_set():
        check(time.monotonic() < deadline, "upstream_barrier_timeout")
        await asyncio.sleep(0.01)


def combined_view(session, trace_id, applications, expected=200):
    query = urllib.parse.urlencode([("application_id", app["id"]) for app in applications])
    result, _ = session.request("/api/v1/traces/" + trace_id + "?" + query, expected=expected)
    return result


async def terminal_view(session, trace_id, apps, expected_records):
    deadline = time.monotonic() + 5
    while True:
        view = combined_view(session, trace_id, apps)
        if len(view["records"]) == expected_records and all(r["phase"] == "finished" for r in view["records"]):
            return view
        check(time.monotonic() < deadline, "terminal_audit_timeout")
        await asyncio.sleep(0.02)


def configure(session):
    snapshot, _ = session.request("/api/v1/gateway")
    issued, _ = session.request("/api/v1/applications", {
        "revision": snapshot["revision"], "name": "Pydantic AI trial worker", "allowed_connections": []})
    app_b, key_b = issued["application"], issued["api_key"]
    tool = session.tool
    resources = [{"resource_id": resource, "sensitivity": "public", "allowed_applications": [session.application["id"], app_b["id"]]}
                 for resource in ("public-guide", "flaky-guide", "client-wait-guide", "cancel-guide")]
    resources += [{"resource_id": "restricted-guide", "sensitivity": "restricted", "allowed_applications": []}]
    session.request("/api/v1/tools/" + tool["id"], {
        "revision": tool["revision"], "name": "Framework trial read service", "alias": "support-docs",
        "endpoint": f"http://127.0.0.1:{session.provider.server_port}/read", "enabled": True,
        "allow_insecure_http": True, "timeout_seconds": 2, "output_mode": "block", "resources": resources}, method="PUT")
    return app_b, key_b


async def exercise(session, app_b, key_b, report):
    from govweave_async_tracing import AsyncGovernedToolClient
    from govweave_frameworks import build_coordinator, run_worker
    from govweave_tracing import TraceContext

    apps = [session.application, app_b]
    client_a = AsyncGovernedToolClient(session.origin, session.key, "support-docs", allow_insecure_http=True)
    client_b = AsyncGovernedToolClient(session.origin, key_b, "support-docs", allow_insecure_http=True)
    bridge = QueueBridge(client_b, run_worker)
    bridge.start()
    graph = build_coordinator(client_a, bridge.submit)
    normal = []

    async def workflow():
        context = TraceContext.new()
        state = await graph.ainvoke({"context": context, "resource_id": "public-guide", "worker_agent_id": secrets.token_hex(8)})
        check(state["status"] == "completed", "framework_workflow_not_completed")
        calls = [state[name] for name in ("root", "local", "remote", "join")]
        check(all(call.trace_id == context.trace_id and call.status == "completed" and call.span_id for call in calls), "framework_receipt_mismatch")
        check(len({call.span_id for call in calls}) == 4, "framework_span_reused")
        view = await terminal_view(session, context.trace_id, apps, 4)
        check({r["request_id"] for r in view["records"]} == {c.request_id for c in calls}, "framework_audit_receipt_mismatch")
        check(all(e["resolution"] == "observed" for e in view["edges"]), "handoff_reference_missing")
        counts = Counter(e["relation"] for e in view["edges"])
        check(counts == {"parent": 3, "link": 2}, "parallel_join_relationship_mismatch")
        check(view["task_completion"] == "not_determined", "task_completion_overclaim")
        normal.append((context, view))
        return {"trace_id": context.trace_id, "calls": [call.metadata() for call in calls], "view": view}

    async def framework_handoff():
        before = session.provider.state()[0]
        result = await workflow()
        check(session.provider.state()[0] - before == 4, "hidden_framework_retry")
        return result

    async def concurrent_task_isolation():
        before = session.provider.state()[0]
        results = await gather_joined(workflow() for _ in range(3))
        spans = [record["trace"]["span_id"] for result in results for record in result["view"]["records"]]
        check(len(set(spans)) == 12 and len({result["trace_id"] for result in results}) == 3, "concurrent_context_leak")
        for result in results:
            check(all(record["trace"]["trace_id"] == result["trace_id"] for record in result["view"]["records"]), "cross_task_audit_leak")
        check(session.provider.state()[0] - before == 12, "concurrent_hidden_retry")
        return {"concurrent_tasks": 3, "runs": results}

    async def gateway_timeout_retry():
        context = TraceContext.new()
        first = await bridge.submit("flaky-guide", context)
        try:
            check(first.http_status == 504 and first.reason == "upstream_timeout" and first.span_id, "gateway_timeout_not_observed")
        finally:
            session.provider.release["flaky-guide"].set()
        retried = await bridge.submit("flaky-guide", context.after(first.span_id, retry_of_span_id=first.span_id))
        check(retried.status == "completed" and retried.span_id != first.span_id, "explicit_retry_failed")
        view = await terminal_view(session, context.trace_id, apps, 2)
        check(session.provider.count("flaky-guide") == 2, "hidden_timeout_retry")
        check(any(e["relation"] == "retry_of" and e["target_span_id"] == first.span_id and e["resolution"] == "observed" for e in view["edges"]), "retry_link_missing")
        check(view["records"][0]["error_code"] == "upstream_timeout" and view["records"][0]["upstream_attempted"], "timeout_overwritten_or_called_block")
        return {"first": first.metadata(), "explicit_retry": retried.metadata(), "view": view}

    async def client_timeout_missing_receipt():
        context = TraceContext.new()
        timed = AsyncGovernedToolClient(session.origin, key_b, "support-docs", timeout=1, allow_insecure_http=True)
        pending = asyncio.create_task(run_worker(timed, "client-wait-guide", context))
        try:
            await wait_entered(session.provider, "client-wait-guide")
            result = await pending
            check(result.status == "unknown" and result.span_id is None and result.reason == "transport_timeout", "timeout_invented_receipt")
            view = await terminal_view(session, context.trace_id, apps, 1)
            record = view["records"][0]
            check(record["upstream_attempted"] and record["outcome"] == "cancelled" and record["error_code"] == "client_cancelled", "client_timeout_audit_mismatch")
            check(session.provider.count("client-wait-guide") == 1, "client_timeout_retried")
            return {"client": result.metadata(), "gateway_evidence_reconciled_later": True, "view": view, "rollback_claimed": False}
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            session.provider.release["client-wait-guide"].set()

    async def cancel_before_dispatch():
        context = TraceContext.new()
        queued = QueueBridge(client_b, run_worker)
        before = session.provider.state()[0]
        pending = asyncio.create_task(queued.submit("public-guide", context))
        try:
            await asyncio.sleep(0)
            check(queued.queue.qsize() == 1, "not_queued_before_cancel")
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            queued.start()
            await asyncio.wait_for(queued.queue.join(), timeout=1)
            check(pending.cancelled() and session.provider.state()[0] == before, "queued_cancel_still_executed")
            combined_view(session, context.trace_id, apps, expected=404)
            return {"trace_id": context.trace_id, "executor_state": "cancelled_before_dispatch", "gateway_records": 0,
                    "span_id": None, "gateway_can_infer_unsent_step": False}
        finally:
            await queued.close()

    async def cancel_after_dispatch():
        context = TraceContext.new()
        pending = asyncio.create_task(bridge.submit("cancel-guide", context))
        try:
            await wait_entered(session.provider, "cancel-guide")
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            check(pending.cancelled(), "inflight_cancel_not_propagated")
            view = await terminal_view(session, context.trace_id, apps, 1)
            record = view["records"][0]
            check(record["outcome"] == "cancelled" and record["error_code"] == "client_cancelled" and record["upstream_attempted"], "cancel_audit_mismatch")
            check(session.provider.count("cancel-guide") == 1, "cancelled_worker_retried")
            return {"executor_state": "cancelled_after_upstream_entry", "client_receipt": "absent",
                    "gateway_evidence_reconciled_later": True, "rollback_claimed": False, "view": view}
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            session.provider.release["cancel-guide"].set()

    async def unresolved_reference():
        missing = secrets.token_hex(8)
        context = TraceContext.new().after(missing)
        result = await bridge.submit("public-guide", context)
        check(result.status == "completed", "missing_reference_request_failed")
        view = await terminal_view(session, context.trace_id, apps, 1)
        check(view["summary"]["unresolved_references"] == 1 and view["edges"][0]["resolution"] == "unresolved", "missing_reference_invented")
        check(view["task_completion"] == "not_determined" and view["history_may_be_truncated"], "missing_reference_task_overclaim")
        return {"declared_predecessor_observation": "unknown", "view": view}

    async def governance_denial():
        context = TraceContext.new()
        before = session.provider.state()[0]
        result = await bridge.submit("restricted-guide", context)
        check(result.status == "blocked" and result.http_status == 403 and result.reason == "tool_not_allowed", "denial_not_terminal")
        view = await terminal_view(session, context.trace_id, apps, 1)
        check(not view["records"][0]["upstream_attempted"] and session.provider.state()[0] == before, "denial_bypassed_or_retried")
        return {"client": result.metadata(), "view": view, "direct_provider_fallback": False}

    async def query_scope_revocation():
        check(bool(normal), "no_completed_task_for_scope_check")
        context, combined = normal[0]
        path = "/v1/traces/" + context.trace_id
        view_a, _ = session.request(path, public=True, key=session.key)
        view_b, _ = session.request(path, public=True, key=key_b)
        check(len(view_a["records"]) == 3 and len(view_b["records"]) == 1, "application_trace_scope_mismatch")
        for view, app in ((view_a, apps[0]), (view_b, apps[1])):
            check(all(record["application_id"] == app["id"] for record in view["records"]), "cross_application_trace_leak")
        check(view_a["summary"]["unresolved_references"] == 1, "application_resolved_invisible_worker")
        session.request(path + "?application_id=" + app_b["id"], public=True, key=session.key, expected=400)
        session.request("/api/v1/traces/" + context.trace_id, public=True, key=key_b, expected=401)
        session.request("/api/v1/applications/" + app_b["id"] + "/revoke", {"revision": app_b["revision"]})
        session.request(path, public=True, key=key_b, expected=401)
        return {"application_views": [view_a, view_b], "admin_record_count": len(combined["records"]), "revoked_key_rejected": True}

    functions = (framework_handoff, concurrent_task_isolation, gateway_timeout_retry,
                 client_timeout_missing_receipt, cancel_before_dispatch, cancel_after_dispatch,
                 unresolved_reference, governance_denial, query_scope_revocation)
    try:
        for case, function in zip(report["cases"], functions):
            case["state"] = "running"
            try:
                async with asyncio.timeout(20):
                    case["evidence"] = await function()
                case["state"] = "passed"
            except CheckFailed as error:
                case.update(state="failed", reason=str(error))
            except Exception:
                case.update(state="failed", reason="case_execution_error")
            print(case["id"] + ": " + case["state"], flush=True)
        report["fixture"] = {"upstream_requests_observed": session.provider.state()[0], "unexpected_headers": session.provider.state()[1]}
        check(report["fixture"]["unexpected_headers"] == 0, "caller_headers_forwarded")
    finally:
        await bridge.close()


def save_report(folder, report):
    states = Counter(case["state"] for case in report["cases"])
    report["summary"] = {"planned": len(PLAN), "passed": states["passed"], "failed": states["failed"],
                         "unknown": sum(count for state, count in states.items() if state not in ("passed", "failed"))}
    report["state"] = "passed" if states["passed"] == len(PLAN) and not report.get("fatal_reason") else "incomplete_or_failed"
    lines = ["# Real framework trace integration trial", "", "Actual LangGraph orchestration and Pydantic AI tool execution with deterministic local model decisions.", "",
             "| Scenario | Result |", "| --- | --- |"]
    lines += [f"| {case['id']} | {case['state']} |" for case in report["cases"]]
    lines += ["", f"Planned: {len(PLAN)}; passed: {report['summary']['passed']}; failed: {report['summary']['failed']}; unknown: {report['summary']['unknown']}.", "",
              "## Evidence limits", ""] + ["- " + value for value in report["limitations"]]
    lines += ["", "[Metadata evidence](report.json)", ""]
    for name, value in (("report.json", json.dumps(report, indent=2) + "\n"), ("report.md", "\n".join(lines))):
        with os.fdopen(os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write(value)


def main(args):
    folder = (args.output_dir or ROOT / "dist/framework-trace" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))).resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema_version": 1, "trial_id": "framework-trace-v1", "created_at": datetime.now(timezone.utc).isoformat(),
              "python_version": platform.python_version(), "cases": [{"id": name, "state": "not_run"} for name in PLAN],
              "framework_versions": {}, "automatic_retries": False, "external_network": "disabled_in_python_trial_process",
              "limitations": [
                  "Actual LangGraph and Pydantic AI packages execute; FunctionModel supplies fixed local decisions, not a real language model.",
                  "The serialized asynchronous queue is in-process, not a distributed broker, durable queue or cross-machine test.",
                  "The gateway observes tool HTTP calls; framework model decisions, queue operations and unsent steps are not gateway spans.",
                  "Cancellation closes client HTTP but cannot undo an upstream read that already started; lost receipts remain unknown to the caller.",
                  "Administrator queries reconcile later evidence separately from client receipts; relationships remain caller declarations.",
                  "Coverage is bounded gateway calls only; success does not establish full task completeness, framework-wide compatibility, production load, detector accuracy or legal compliance.",
              ]}
    try:
        report["framework_versions"] = {name: importlib.metadata.version(name) for name in ("langgraph", "pydantic-ai-slim", "httpx")}
        report["source_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
        report["binary_sha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        connect, connect_ex = socket.socket.connect, socket.socket.connect_ex
        def local_connect(sock, address):
            loopback_address(address)
            return connect(sock, address)
        def local_connect_ex(sock, address):
            loopback_address(address)
            return connect_ex(sock, address)
        with patch.object(socket.socket, "connect", local_connect), patch.object(socket.socket, "connect_ex", local_connect_ex):
            with TOOLS.ToolSession(args.binary.resolve(), provider_factory=Fixture) as session:
                private_values = [session.key, TOOLS.PROVIDER_KEY, FIXTURE_TEXT, TOOLS.CALLER_HEADER]
                try:
                    app_b, key_b = configure(session)
                    private_values.append(key_b)
                    asyncio.run(exercise(session, app_b, key_b, report))
                finally:
                    # Scan even if a case, final assertion or user interruption
                    # aborts the run. Cleanup never publishes unsafe evidence.
                    try:
                        audit = (session.directory / "calls.jsonl").read_text()
                    except OSError:
                        for case in report["cases"]:
                            case.pop("evidence", None)
                            case.update(state="unknown", reason="audit_privacy_not_verified")
                        raise CheckFailed("audit_privacy_not_verified") from None
                    protect_metadata(report, private_values, audit)
    except KeyboardInterrupt:
        report["fatal_reason"] = "interrupted"
    except CheckFailed as error:
        # These codes are only fixed assertions defined in this file.
        report["fatal_reason"] = str(error)
    except importlib.metadata.PackageNotFoundError:
        report["fatal_reason"] = "optional_framework_dependencies_missing"
    except Exception:
        report["fatal_reason"] = "trial_setup_or_execution_error"
    save_report(folder, report)
    print("Private framework trace report: " + str(folder / "report.json"))
    return 0 if report["state"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    parser.add_argument("--output-dir", type=Path)
    raise SystemExit(main(parser.parse_args()))
