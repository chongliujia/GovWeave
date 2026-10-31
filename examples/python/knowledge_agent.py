#!/usr/bin/env python3
"""Run the bounded reference Agent against an already configured GovWeave instance."""
import argparse
import json
import os
from pathlib import Path

from govweave_agent import KnowledgeAgent
from govweave_tools import ToolCallError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Authorized GovWeave model alias.")
    parser.add_argument("--tool", required=True, help="Configured read-tool alias.")
    parser.add_argument("--catalog", required=True, type=Path, help="Application-owned resource ID to description JSON object.")
    parser.add_argument("--question", required=True)
    parser.add_argument("--trace", type=Path, help="Write a new private metadata-only trace file; never overwrite.")
    parser.add_argument("--allow-insecure-http", action="store_true", help="Explicit local HTTP opt-in.")
    args = parser.parse_args()
    try:
        if args.catalog.stat().st_size > 8192:
            raise ToolCallError("invalid_configuration")
        catalog = json.loads(args.catalog.read_text())
        agent = KnowledgeAgent(os.environ.get("GOVWEAVE_ROOT", ""), os.environ.get("GOVWEAVE_API_KEY", ""),
                               args.model, args.tool, catalog, allow_insecure_http=args.allow_insecure_http)
        result = agent.run(args.question)
        if args.trace:
            # An existing trace or symlink is never followed or replaced.
            fd = os.open(args.trace, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as target:
                json.dump(result.metadata(), target, indent=2)
                target.write("\n")
        if result.status == "completed":
            print(result.text)
            return 0
        print("Agent stopped: " + result.reason)
        return 2
    except (ToolCallError, OSError, ValueError, UnicodeError):
        print("Agent could not run. Check the configured application, model, tool, catalog and trace path.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
