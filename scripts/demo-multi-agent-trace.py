#!/usr/bin/env python3
"""Demonstrate explicit Python/Node task context and application-isolated queries.

Run `make build`, then `python3 scripts/demo-multi-agent-trace.py`. Requires Node
only for the synthetic second worker; uses no external model or credentials.
The temporary gateway and fixture are cleaned up, leaving a metadata report.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"examples/python"))
from govweave_tools import GovernedToolClient, ToolCallError
from govweave_tracing import TraceContext, invoke_traced_tool

SPEC = importlib.util.spec_from_file_location("multi_agent_environment", ROOT/"scripts/demo-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


def clean_environment(key):
    values = {k: v for k,v in os.environ.items() if k in ("PATH","LANG","LC_ALL","LC_CTYPE","TMPDIR","SYSTEMROOT")}
    values["GOVWEAVE_API_KEY"] = key
    return values


def worker():
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError("configuration limit")
    config = json.loads(raw)
    context = TraceContext(config["trace_id"], agent_id=config["agent_id"], parent_span_id=config["parent_span_id"])
    client = GovernedToolClient(config["root"], os.environ.get("GOVWEAVE_API_KEY", ""), config["alias"], allow_insecure_http=True)
    result = invoke_traced_tool(client, {"resource_id": config["resource_id"]}, context)
    print(json.dumps(result.metadata()))
    return 0 if result.status == "completed" else 1


def metadata_call(client, resource, context, expected):
    result = invoke_traced_tool(client, {"resource_id": resource}, context)
    TOOLS.require(result.status == expected and result.span_id, "unexpected governed call outcome")
    return result.metadata()


def run(args):
    TOOLS.require(args.binary.is_file(), "build the gateway before running the example")
    node = shutil.which("node")
    TOOLS.require(node is not None, "Node is required only for this cross-runtime example")
    with TOOLS.ToolSession(args.binary.resolve()) as session:
        snapshot, _ = session.request("/api/v1/gateway")
        application, _ = session.request("/api/v1/applications", {"revision": snapshot["revision"], "name": "Synthetic Node worker", "allowed_connections": []})
        app_a, key_a = session.application, session.key
        app_b, key_b = application["application"], application["api_key"]
        client_a = GovernedToolClient(session.origin, key_a, "support-docs", allow_insecure_http=True)
        client_b = GovernedToolClient(session.origin, key_b, "support-docs", allow_insecure_http=True)
        coordinator = TraceContext.new()
        root = metadata_call(client_a, "public-guide", coordinator, "completed")
        configs = [
            {"root":session.origin+"/","alias":"support-docs","trace_id":coordinator.trace_id,"agent_id":secrets.token_hex(8),"parent_span_id":root["span_id"],"resource_id":resource}
            for resource in ("public-guide", "restricted-guide")]
        processes = []
        try:
            # Both workers are started before either is awaited. Context travels
            # through explicit process input, never an ambient shared global.
            for command, config, key in (([sys.executable,str(Path(__file__).resolve()),"--worker"],configs[0],key_a),
                ([node,str(ROOT/"examples/python/multi_agent_trace_worker.cjs")],configs[1],key_b)):
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_environment(key))
                processes.append(process)
                process.stdin.write(json.dumps(config).encode()); process.stdin.close(); process.stdin = None
            branches = []
            for process in processes:
                output, error = process.communicate(timeout=15)
                TOOLS.require(process.returncode == 0 and len(output) <= 8192 and not error, "worker did not complete")
                branches.append(json.loads(output))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.communicate(timeout=5)
        TOOLS.require(branches[0]["status"] == "completed" and branches[1]["status"] == "blocked", "unexpected branch outcomes")
        joined = metadata_call(client_a,"public-guide",coordinator.after(root["span_id"],links=tuple(b["span_id"] for b in branches)),"completed")
        retry_context = TraceContext(coordinator.trace_id,agent_id=configs[1]["agent_id"],parent_span_id=root["span_id"],retry_of_span_id=branches[1]["span_id"])
        retried = metadata_call(client_b,"restricted-guide",retry_context,"blocked")
        calls = [root,*branches,joined,retried]
        TOOLS.require(len({c["span_id"] for c in calls}) == 5, "retry or branch reused a gateway span")
        path = "/v1/traces/"+coordinator.trace_id
        view_a, _ = session.request(path,public=True,key=key_a)
        view_b, _ = session.request(path,public=True,key=key_b)
        query = urllib.parse.urlencode([("application_id",app_a["id"]),("application_id",app_b["id"])])
        combined, _ = session.request("/api/v1/traces/"+coordinator.trace_id+"?"+query)
        expected_a = {root["request_id"],branches[0]["request_id"],joined["request_id"]}
        expected_b = {branches[1]["request_id"],retried["request_id"]}
        for view, ids, apps in ((view_a,expected_a,{app_a["id"]}),(view_b,expected_b,{app_b["id"]}),(combined,expected_a|expected_b,{app_a["id"],app_b["id"]})):
            TOOLS.require({r["request_id"] for r in view["records"]} == ids, "trace query mixed applications or omitted a call")
            TOOLS.require({r["application_id"] for r in view["records"]} == apps, "trace identity mismatch")
            TOOLS.require(view["coverage"] == "gateway_calls_only" and view["task_completion"] == "not_determined" and view["history_may_be_truncated"] is True, "trace overclaims task coverage")
        TOOLS.require(any(e["relation"]=="link" and e["resolution"]=="unresolved" for e in view_a["edges"]), "private view resolved another application's span")
        TOOLS.require(all(e["resolution"]=="observed" for e in combined["edges"]), "explicit joined graph did not resolve visible references")
        TOOLS.require(any(e["relation"]=="retry_of" for e in combined["edges"]), "retry relation missing")
        session.request(path+"?application_id="+app_b["id"],public=True,key=key_a,expected=400)
        session.request("/api/v1/traces/"+coordinator.trace_id,expected=400)
        session.request("/api/v1/traces/"+coordinator.trace_id+"?"+query,public=True,key=key_a,expected=401)
        session.request("/api/v1/applications/"+app_b["id"]+"/revoke",{"revision":app_b["revision"]})
        session.request(path,public=True,key=key_b,expected=401)
        TOOLS.require(session.provider.state() == (3,0), "blocked calls reached the fixture or caller headers escaped")
        report = {"schema_version":1,"id":"multi-agent-trace-demo-v1","created_at":datetime.now(timezone.utc).isoformat(),"state":"completed",
            "runtimes":["python","node"],"trace_id":coordinator.trace_id,"checks":{"distinct_gateway_spans":5,"parallel_workers":2,"observed_tool_calls":5,"upstream_reads":3,
                "denied_before_execution":2,"application_a_records":3,"application_b_records":2,"admin_combined_records":5,"cross_application_queries_denied":True,"revoked_query_denied":True},
            "calls":calls,"application_views":[view_a,view_b],"admin_view":combined,
            "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ("examples/python/govweave_tracing.py","examples/python/govweave_tools.py","examples/python/multi_agent_trace_worker.cjs","scripts/demo-multi-agent-trace.py")},
            "binary_sha256":hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "limitations":["Synthetic local Python/Node workers, not framework adapters, independent customer traffic or a multi-instance deployment.",
                "Workers are launched concurrently; graph links are caller declarations, not proof of causal dependence or task correctness.",
                "Only gateway-observed calls are shown. Bounded retention and uninstrumented work prevent full-task completeness claims.",
                "Application queries expose only their own fragment; the administrator explicitly selects applications for a combined view.",
                "The explicit retry remains unauthorized. Trace context never changes grants and never schedules automatic retries.",
                "No model request is made. This demonstrates control/trace integration, not model safety or semantic detection accuracy."]}
        serialized=json.dumps(report,indent=2)
        for secret in (key_a,key_b,TOOLS.PROVIDER_KEY,TOOLS.NORMAL_TEXT,TOOLS.FIXTURE_CREDENTIAL,TOOLS.CALLER_HEADER):
            TOOLS.require(secret not in serialized,"private content retained in trace demo report")
    folder=(args.output_dir or ROOT/"dist/multi-agent-trace"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(3))).resolve()
    folder.mkdir(parents=True,mode=0o700,exist_ok=False)
    markdown=["# Heterogeneous multi-Agent trace demonstration","", "Two separate Python/Node worker processes used the same task context with different application keys.","",
        "- Five distinct gateway spans: coordinator, two parallel branches, join and explicit retry.",
        "- Three authorized reads completed; two unauthorized calls were blocked before upstream execution.",
        "- Application views contain three and two records respectively; explicit administrator aggregation contains all five.",
        "- The Python application's link to the Node span stays unresolved in its private view; it resolves in the selected administrator view.",
        "- Cross-application filters, application-key access to the admin route and revoked-key queries were denied.","","## Limits",""]+["- "+s for s in report["limitations"]]+["","[Metadata report](report.json)",""]
    for name,data in (("report.json",serialized+"\n"),("report.md","\n".join(markdown))):
        with os.fdopen(os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as target:target.write(data)
    print("Multi-runtime trace checks passed. Private report:",folder/"report.json")
    return 0


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,default=ROOT/"bin/govweave")
    parser.add_argument("--output-dir",type=Path)
    parser.add_argument("--worker",action="store_true",help=argparse.SUPPRESS)
    args=parser.parse_args()
    try:
        raise SystemExit(worker() if args.worker else run(args))
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired,ToolCallError,TOOLS.DemoError):
        print("Multi-Agent trace demo could not complete. Check the local binary, Node runtime and output path.",file=sys.stderr)
        raise SystemExit(1)
