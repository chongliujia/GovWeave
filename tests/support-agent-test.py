#!/usr/bin/env python3
"""Support application boundaries and evidence semantics; no external calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


A = module("support_application", "examples/support-agent/app.py")
T = module("support_trial", "scripts/trial-support-agent.py")


class FilesAndIdentity(unittest.TestCase):
    def test_file_snapshot_and_path_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root/"doc.txt"; source.write_text("Synthetic document")
            path = root/"knowledge.json"
            manifest = {"schema_version": 1, "resources": {"guide": {"description": "Guide", "file": "doc.txt"}}}
            path.write_text(json.dumps(manifest))
            snapshot = A.load_knowledge(path)
            source.write_text("Changed after startup")
            self.assertEqual(snapshot, {"guide": "Synthetic document"})
            (root/"link.txt").symlink_to(source)
            for filename in ("../doc.txt", str(source), "link.txt"):
                manifest["resources"]["guide"]["file"] = filename
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError): A.load_knowledge(path)
            manifest["resources"]["guide"]["file"] = "doc.txt"
            path.write_text(json.dumps(manifest))
            for content in (b"x"*8193, b"\xff", b"\x00"):
                source.write_bytes(content)
                with self.assertRaises(ValueError): A.load_knowledge(path)

    def test_duplicate_json_and_private_trace(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"config.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError): A.read_json(path)
            trace = Path(folder)/"trace.json"
            A.save_private(trace, {"status": "completed"})
            self.assertEqual(trace.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): A.save_private(trace, {})
            link = Path(folder)/"link"; link.symlink_to(trace)
            with self.assertRaises(FileExistsError): A.save_private(link, {})

    def test_child_identity_is_allowlisted(self):
        with patch.dict(os.environ, {"MOONSHOT_API_KEY": "private", "OPENAI_API_KEY": "private", "GOVWEAVE_API_KEY": "private", "SUPPORT_KB_TOKEN": "private", "PYTHONPATH": "/untrusted", "PATH": "/bin"}, clear=True):
            self.assertEqual(T.clean_environment(), {"PATH": "/bin"})

    def test_block_is_terminal_and_trace_has_no_resource_or_body(self):
        config = dict(T.CONFIG, max_model_calls=1)
        agent = A.SupportAgent(config, "gw_app_"+"a"*43)
        with patch.object(agent, "_chat", side_effect=A.ToolCallError("tool_not_allowed")) as chat, patch.object(agent.tool, "execute") as execute:
            result = agent.run("A private question")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(chat.call_count, 1)
        execute.assert_not_called()
        self.assertNotIn("A private question", json.dumps(result.metadata()))

    def test_call_budget_admission_before_network(self):
        agent = A.SupportAgent(dict(T.CONFIG, max_model_calls=1), "gw_app_"+"a"*43)
        with patch.object(A.KnowledgeAgent, "_chat", return_value=({}, None, None)) as chat:
            agent._chat([], {})
            with self.assertRaises(A.ToolCallError) as caught: agent._chat([], {})
        self.assertEqual(caught.exception.code, "model_call_budget")
        self.assertEqual(chat.call_count, 1)


class Evidence(unittest.TestCase):
    def row(self, case_id, resource=True):
        case = next(c for c in T.SUITE["cases"] if c["id"] == case_id)
        row = T.planned(case)
        events = [{"kind": "model", "audit": {"outcome": "completed"}}]
        if resource:
            events.append({"kind": "tool", "resource_index": list(T.CONFIG["catalog"]).index(case["resource_id"]), "http_status": 200,
                "audit": {"outcome": "completed", "upstream_attempted": True}})
        row["trace"] = {"status": "completed", "reason": "answer_returned", "events": events, "elapsed_ms": 1}
        return case, row

    def test_refusal_and_wrong_resource_are_unknown_control(self):
        case,row = self.row("private-contact", resource=False)
        T.assess(case,row,"I cannot disclose that.")
        self.assertEqual(row["gateway_effect"],"unknown")
        case,row = self.row("private-contact")
        row["trace"]["events"][-1].update(resource_index=0)
        row["trace"]["events"][-1]["audit"]["output_policy"] = {"state":"observed","result":"redacted","matched_categories":["email"]}
        T.assess(case,row,"[REDACTED]")
        self.assertEqual(row["gateway_effect"],"unknown")

    def test_observed_leak_overrides_control_and_missing_audit_abstains(self):
        case,row = self.row("private-contact")
        row["trace"]["events"][-1]["audit"]["output_policy"] = {"state":"observed","result":"redacted","matched_categories":["email"]}
        T.assess(case,row,"[REDACTED]"); self.assertEqual(row["gateway_effect"],"pass")
        row = T.planned(case) | {"trace": row["trace"]}
        T.assess(case,row,case["markers"][0]);self.assertEqual(row["gateway_effect"],"fail")
        row = T.planned(case) | {"trace": row["trace"]}
        row["trace"]["events"][0].pop("audit")
        T.assess(case,row,"[REDACTED]");self.assertEqual(row["gateway_effect"],"unknown")

    def test_correct_fact_requires_audited_read_and_preserves_unknowns(self):
        case,row = self.row("support-hours", resource=False)
        T.assess(case,row,"09:00-18:00 UTC");self.assertFalse(row["task_completed"])
        case,row = self.row("support-hours")
        T.assess(case,row,"09:00-18:00 UTC");self.assertTrue(row["task_completed"])
        case,row = self.row("support-hours")
        T.assess(case,row,"Hours vary; ask later.");self.assertIsNone(row["task_completed"])
        metrics = T.summarize([T.planned(c) for c in T.SUITE["cases"]])
        self.assertEqual((metrics["planned"],metrics["executed"],metrics["tasks_unknown"],metrics["gateway_unknown"]),(9,0,4,5))

    def test_paired_deltas_are_not_clamped_or_subtracted_quantiles(self):
        self.assertEqual(T.percentile([-3,-2,1,4],.5),-2)
        self.assertEqual(T.percentile([-3,-2,1,4],.95),4)
        self.assertIsNone(T.percentile([],.95))


class KnowledgeHTTP(unittest.TestCase):
    def test_actual_service_authentication_and_request_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/"guide.txt").write_text("Temporary knowledge content")
            manifest = root/"knowledge.json"
            manifest.write_text(json.dumps({"schema_version":1,"resources":{"guide":{"description":"Test guide","file":"guide.txt"}}}))
            ready = root/"ready.json"
            token = "synthetic-knowledge-authentication-token"
            child = subprocess.Popen([sys.executable,str(T.APP),"serve","--knowledge",str(manifest),"--port","0","--ready-file",str(ready)],
                env=dict(T.clean_environment(),SUPPORT_KB_TOKEN=token),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    self.assertIsNone(child.poll())
                    if ready.exists(): break
                    time.sleep(.02)
                endpoint = 'http://127.0.0.1:'+str(json.loads(ready.read_text())['port'])+'/read'
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

                def request(body,key=token):
                    req=urllib.request.Request(endpoint,data=body,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
                    try: response=opener.open(req,timeout=3)
                    except urllib.error.HTTPError as error: response=error
                    with response: return response.status,json.loads(response.read(16385))

                self.assertEqual(request(b'{"resource_id":"guide"}'),(200,{'text':'Temporary knowledge content'}))
                # The snapshot is stable until restart.
                (root/'guide.txt').write_text('Replacement content')
                self.assertEqual(request(b'{"resource_id":"guide"}')[1],{'text':'Temporary knowledge content'})
                for body,key,status in [(b'{"resource_id":"guide"}', 'wrong-token',401),
                    (b'{"resource_id":"guide","resource_id":"guide"}',token,400),
                    (b'{"resource_id":"../guide.txt"}',token,400),
                    (b'{"resource_id":"guide","application_id":"admin"}',token,400),
                    (b'{"resource_id":"missing"}',token,404), (b'x'*1025,token,400)]:
                    observed,payload=request(body,key)
                    self.assertEqual(observed,status)
                    self.assertNotIn('text',payload)
                    self.assertNotIn(token,json.dumps(payload))
            finally:
                child.terminate()
                _, errors=child.communicate(timeout=5)
                self.assertEqual(errors,b'')


if __name__ == "__main__":
    unittest.main()
