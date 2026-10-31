#!/usr/bin/env python3
"""Independent support application and file-backed read service; Python stdlib only."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from govweave_agent import KnowledgeAgent, REQUEST_PROFILES
from govweave_tools import ToolCallError, _object, _constant

VERSION = "support-agent-v1"
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def bounded_file(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("invalid file")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file limit")
    return data


def read_json(path):
    return json.loads(bounded_file(path, 16384).decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)


def save_private(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as target:
        json.dump(value, target, ensure_ascii=False, indent=2)
        target.write("\n")


def credential(name):
    value = os.environ.get(name, "")
    if not 16 <= len(value) <= 4096 or any(not 33 <= ord(c) <= 126 for c in value):
        raise ValueError("invalid credential")
    return value


def load_knowledge(path):
    manifest = read_json(path)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "resources"} or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("invalid manifest")
    resources = manifest["resources"]
    if not isinstance(resources, dict) or not 1 <= len(resources) <= 16:
        raise ValueError("invalid resources")
    texts = {}
    root = path.parent.resolve()
    for key, entry in resources.items():
        if not IDENTIFIER.fullmatch(key) or not isinstance(entry, dict) or set(entry) != {"description", "file"} or not isinstance(entry["description"], str) or len(entry["description"].encode()) > 300 or not isinstance(entry["file"], str):
            raise ValueError("invalid resource")
        relative = Path(entry["file"])
        if relative.is_absolute() or not relative.parts or any(part in ("..", ".") for part in relative.parts):
            raise ValueError("invalid resource path")
        target = root / relative
        if any((root.joinpath(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise ValueError("symlink resource")
        text = bounded_file(target, 8192).decode("utf-8")
        if not text or "\ufffd" in text or "\x00" in text:
            raise ValueError("invalid resource text")
        texts[key] = text
    # Files are snapshotted once. Requests select IDs, never paths or URLs.
    return texts


class ReadHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def respond(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, TimeoutError):
            pass

    def do_POST(self):
        if self.path != "/read":
            return self.respond(404, {"error": "not_found"})
        auth = self.headers.get_all("Authorization", [])
        if len(auth) != 1 or not secrets.compare_digest(auth[0].encode(), ("Bearer " + self.server.key).encode()):
            return self.respond(401, {"error": "unauthorized"})
        try:
            sizes = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(sizes) != 1 or not sizes[0].isascii() or not sizes[0].isdigit() or len(sizes[0]) > 4:
                raise ValueError()
            size = int(sizes[0])
            if not 1 <= size <= 1024 or self.headers.get_content_type() != "application/json":
                raise ValueError()
            body = json.loads(self.rfile.read(size).decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
            if not isinstance(body, dict) or set(body) != {"resource_id"} or not isinstance(body["resource_id"], str) or not IDENTIFIER.fullmatch(body["resource_id"]):
                raise ValueError()
        except (OSError, ValueError, UnicodeError, RecursionError):
            return self.respond(400, {"error": "invalid_request"})
        text = self.server.texts.get(body["resource_id"])
        if text is None:
            return self.respond(404, {"error": "resource_not_found"})
        self.respond(200, {"text": text})


def serve(args):
    texts, key = load_knowledge(args.knowledge), credential("SUPPORT_KB_TOKEN")
    # Loopback-only reference service. Remote deployments need an authenticated
    # TLS service; application resource grants remain at the gateway.
    with HTTPServer(("127.0.0.1", args.port), ReadHandler) as server:
        server.texts, server.key = texts, key
        if args.ready_file:
            save_private(args.ready_file, {"port": server.server_port, "version": VERSION})
        print("Knowledge service ready on loopback port " + str(server.server_port), flush=True)
        server.serve_forever(poll_interval=0.1)


def load_config(path):
    config = read_json(path)
    fields = {"schema_version", "gateway_root", "model_alias", "tool_alias", "request_profile", "allow_insecure_http", "timeout_seconds", "max_model_calls", "min_model_interval_seconds", "catalog"}
    if not isinstance(config, dict) or set(config) != fields or type(config["schema_version"]) is not int or config["schema_version"] != 1 or type(config["allow_insecure_http"]) is not bool:
        raise ValueError("invalid configuration")
    for field, low, high in (("timeout_seconds", 1, 60), ("max_model_calls", 1, 6), ("min_model_interval_seconds", 0, 60)):
        if type(config[field]) is not int or not low <= config[field] <= high:
            raise ValueError("invalid limit")
    if config["request_profile"] not in REQUEST_PROFILES:
        raise ValueError("unsupported profile")
    return config


class SupportAgent(KnowledgeAgent):
    def __init__(self, config, key):
        super().__init__(config["gateway_root"], key, config["model_alias"], config["tool_alias"], config["catalog"],
                         timeout=config["timeout_seconds"], max_tool_calls=2,
                         allow_insecure_http=config["allow_insecure_http"], request_profile=config["request_profile"])
        self.remaining, self.interval, self.next_call = config["max_model_calls"], config["min_model_interval_seconds"], 0
        self.read_indices = []
        execute = self.tool.execute
        identifiers = list(config["catalog"])

        def tracked(arguments):
            resource = arguments.get("resource_id")
            self.read_indices.append(identifiers.index(resource) if resource in identifiers else None)
            return execute(arguments)

        self.tool.execute = tracked

    def _chat(self, messages, event):
        if self.remaining == 0:
            raise ToolCallError("model_call_budget")
        wait = max(0, self.next_call - time.monotonic())
        if wait:
            time.sleep(wait)
        event["pacing_wait_ms"] = round(wait * 1000, 3)
        self.next_call = time.monotonic() + self.interval
        self.remaining -= 1
        return super()._chat(messages, event)


def answer(args):
    config = load_config(args.config)
    key = credential("GOVWEAVE_API_KEY")
    question = sys.stdin.buffer.read(4097).decode("utf-8").strip()
    if not question or len(question.encode()) > 4096:
        raise ValueError("invalid question")
    agent = SupportAgent(config, key)
    result = agent.run(question)
    metadata = result.metadata()
    metadata.update(application_version=VERSION, configuration_sha256=hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                    model_calls_reserved=config["max_model_calls"] - agent.remaining)
    for event, index in zip((e for e in metadata["events"] if e["kind"] == "tool"), agent.read_indices):
        event["resource_index"] = index
    if args.trace:
        save_private(args.trace, metadata)
    if args.json:
        # This is the application's answer channel, not an audit export. The
        # trial consumes it in memory and never writes the answer into reports.
        print(json.dumps({"answer": result.text, "trace": metadata}, ensure_ascii=False))
    elif result.status == "completed":
        print(result.text)
    else:
        print("Agent stopped: " + result.reason)
    return 0 if result.status == "completed" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backend = commands.add_parser("serve", help="Serve snapshotted knowledge files on loopback.")
    backend.add_argument("--knowledge", type=Path, default=Path(__file__).with_name("knowledge.json"))
    backend.add_argument("--port", type=int, default=8091)
    backend.add_argument("--ready-file", type=Path)
    client = commands.add_parser("answer", help="Read a question from stdin; use only the configured gateway.")
    client.add_argument("--config", required=True, type=Path)
    client.add_argument("--trace", type=Path)
    client.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                raise ValueError()
            serve(args)
            return 0
        return answer(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, ToolCallError):
        print("Support application could not run. Check its configuration, credentials and local paths.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
