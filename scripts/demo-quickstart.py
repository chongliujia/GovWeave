#!/usr/bin/env python3
"""Try three gateway controls locally, without a provider account or model download."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quickstart_sensitive", ROOT / "scripts/demo-sensitive.py")
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)
require = DEMO.require


def exercise(session):
    output_policy = session.policy("redact")
    input_policy, _ = session.request("/api/v1/policies/credential-egress")
    input_policy, _ = session.request("/api/v1/policies/credential-egress", {
        "revision": input_policy["revision"], "mode": "block", "rules": ["private_key", "api_key"],
        "application_ids": [session.application["id"]], "connection_ids": [],
    }, method="PUT")
    capture, _ = session.request("/api/v1/evidence/config")
    session.request("/api/v1/evidence/config", {
        **capture, "mode": "full", "application_ids": [session.application["id"]],
    }, method="PUT")
    stages = []
    for name, wanted_status, wanted_text in (
        ("harmless", 200, DEMO.TEXTS["harmless"]),
        ("email", 200, "Synthetic email: [REDACTED]"),
        ("credential", 403, None),
    ):
        before = session.provider.calls
        status, result, request_id, _ = session.request_result("/v1/chat/completions", {
            "model": DEMO.ALIAS, "messages": [{"role": "user", "content": DEMO.PROMPTS[name]}],
            "stream": False, "max_tokens": 128, "thinking": {"type": "disabled"},
        }, public=True)
        require(status == wanted_status, name + ": unexpected HTTP status")
        require(isinstance(request_id, str) and request_id.startswith("req_"), "missing request ID")
        require(session.provider.calls - before == (name != "credential"), "unexpected upstream call")
        if wanted_text is not None:
            require(result["choices"][0]["message"]["content"] == wanted_text, name + ": unexpected output")
        else:
            require(result.get("error", {}).get("code") == "policy_blocked", "input was not blocked by policy")
            require(DEMO.TEXTS["credential"] not in json.dumps(result), "blocked response exposed input")
        stages.append({"scenario": name, "http_status": status, "request_id": request_id})
    audit, _ = session.request("/api/v1/requests?limit=100")
    records = {item["request_id"]: item for item in audit["records"]}
    require(len(records) == 3, "expected exactly three independent request records")
    for stage in stages:
        name = stage["scenario"]
        record = records.get(stage["request_id"], {})
        require(record.get("phase") == "finished", "missing finished audit record")
        require(record.get("http_status") == stage["http_status"], "audit HTTP status mismatch")
        require(record.get("upstream_attempted") == (name != "credential"), "audit upstream mismatch")
        if name != "credential":
            policy = record.get("output_policy", {})
            require(policy.get("result") == ("redacted" if name == "email" else "allow"), "output decision mismatch")
            require(policy.get("revision") == output_policy["revision"], "output revision mismatch")
            require(policy.get("detector_version") == "sensitive-text-v1", "detector mismatch")
        else:
            policy = record.get("content_policy", {})
            require(policy.get("result") == "block", "input block decision missing")
            require(policy.get("revision") == input_policy["revision"], "input revision mismatch")
            require(policy.get("matched_rules"), "missing input policy match")
        evidence_id = "ev_" + stage["request_id"][4:]
        detail, _ = session.request(f"/api/v1/evidence/{evidence_id}?application_id={session.application['id']}")
        require(detail.get("audit_committed") is True, "evidence not linked to committed audit")
        require(detail.get("delivery_state") == ("withheld" if name == "credential" else "release_prepared"), "evidence delivery mismatch")
        stage.update(upstream_attempted=name != "credential", evidence_id=evidence_id, audit_verified=True)
    require(session.provider.calls == 2 and session.provider.invalid_requests == 0, "fixture call budget mismatch")
    excluded = [session.key, session.provider_key, *DEMO.TEXTS.values(), *DEMO.PROMPTS.values()]
    audit_text = (session.directory / "calls.jsonl").read_text()
    require(all(value not in audit_text and value not in json.dumps(audit) for value in excluded), "plaintext in ordinary audit")
    return {
        "schema_version": 1, "result": "passed", "synthetic_data": True,
        "target_kind": "local_scripted_model", "upstream_attempts": 2,
        "input_policy_revision": input_policy["revision"], "output_policy_revision": output_policy["revision"],
        "detector_version": "sensitive-text-v1", "stages": stages,
        "scope": "Three synthetic non-streaming integration cases; not a model-safety benchmark or legal assessment.",
    }


def capture_walkthrough(session, summary, output):
    # Development-only rendering dependencies; never needed for the default trial.
    try:
        from PIL import Image
    except ImportError:
        raise DEMO.DemoError("capture needs Pillow; see docs/demo/README.md") from None
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    jar = next(handler.cookiejar for handler in session.admin.handlers if isinstance(handler, urllib.request.HTTPCookieProcessor))
    payload = {
        "origin": session.origin, "application_id": session.application["id"], "stages": summary["stages"],
        "cookies": [{"name": cookie.name, "value": cookie.value, "url": session.origin, "httpOnly": True} for cookie in jar],
    }
    # The disposable session cookie travels only over stdin, never argv or disk.
    subprocess.run(["node", str(ROOT / "scripts/capture-quickstart.cjs"), str(output)],
                   input=json.dumps(payload), text=True, check=True, timeout=150, cwd=ROOT)
    for language in ("en", "zh-CN"):
        paths = sorted(output.glob(f"{language}-[0-9][0-9].png"))
        require(len(paths) == 6, "capture did not produce all six scenes")
        frames = []
        for path in paths:
            with Image.open(path) as frame:
                frames.append(frame.convert("RGB").quantize(colors=192))
        frames[0].save(output / f"quickstart-{language}.gif", save_all=True, append_images=frames[1:],
                       duration=[10000] * 6, loop=0, optimize=False, disposal=2)


def main(args):
    zh = args.lang == "zh-CN"
    try:
        require(args.binary.resolve().is_file(), "binary not found; run make build first")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        output = (args.output_dir or ROOT / "dist/quickstart" / stamp).resolve()
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        print("GovWeave 本机试用 · 合成数据 · 无需模型账号" if zh else "GovWeave local trial · synthetic data · no model account", flush=True)
        with DEMO.SensitiveSession(args.binary.resolve()) as session:
            summary = exercise(session)
            if args.capture_dir:
                capture_walkthrough(session, summary, args.capture_dir.resolve())
        require(not session.directory.exists(), "temporary state cleanup did not complete")
        summary["temporary_configuration_removed"] = True
        DEMO.TOOLS.save_json(output / "summary.json", summary)
        lines = (
            ["1/3 普通回答：HTTP 200，原样返回。", "2/3 合成邮箱：HTTP 200，返回 Synthetic email: [REDACTED]。",
             "3/3 输入含合成凭证：HTTP 403，在访问上游前阻断。", "已核对 3 条终态审计及关联证据；本机模型收到 2 次请求。",
             "临时网关、凭证和正文证据已清理。", "这三例验证接入与控制流程，不代表通用安全或法律合规结论。"]
            if zh else
            ["1/3 Normal answer: HTTP 200, unchanged.", "2/3 Synthetic email: HTTP 200, returned Synthetic email: [REDACTED].",
             "3/3 Synthetic credential in input: HTTP 403, blocked before upstream access.",
             "Verified 3 finished audit records and linked evidence; 2 local model requests.",
             "Temporary gateway, credentials and captured content removed.",
             "These three cases verify integration and controls, not general safety or legal compliance."]
        )
        print("\n".join(lines))
        print(("私有元数据摘要：" if zh else "Private metadata summary: ") + str(output / "summary.json"))
        return 0
    except KeyboardInterrupt:
        print("试用已中断，临时服务已关闭。" if zh else "Trial interrupted; temporary services stopped.")
        return 130
    except DEMO.DemoError as error:
        print(("试用未通过：" if zh else "Trial failed: ") + str(error))
        return 1
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, subprocess.SubprocessError):
        print("试用未完成：检查本机端口权限、二进制及可选录制依赖；未输出私有响应。" if zh else
              "Trial incomplete: check local port access, binary and optional capture dependencies; private responses omitted.")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/govweave")
    parser.add_argument("--lang", choices=["en", "zh-CN"], default="en")
    parser.add_argument("--output-dir", type=Path, help="New private metadata directory")
    parser.add_argument("--capture-dir", type=Path, help="New directory for synthetic walkthrough frames/GIFs (developer dependencies required)")
    raise SystemExit(main(parser.parse_args()))
