#!/usr/bin/env python3
"""Read a resource through GovWeave using backend-owned configuration."""

import argparse
import json
import os

from govweave_tools import GovernedToolClient, ToolCallError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resource_id")
    parser.add_argument("--allow-insecure-http", action="store_true", help="Explicitly permit a trusted unencrypted gateway")
    parser.add_argument("--show-text", action="store_true", help="Print the retrieved text; default output is decision metadata only")
    args = parser.parse_args()
    try:
        client = GovernedToolClient(os.environ.get("GOVWEAVE_ROOT", ""), os.environ.get("GOVWEAVE_API_KEY", ""),
                                    os.environ.get("GOVWEAVE_TOOL_ALIAS", ""), allow_insecure_http=args.allow_insecure_http)
        result = client.execute({"resource_id": args.resource_id})
        output = {"request_id": result.request_id, "governance": result.governance}
        if args.show_text:
            output["text"] = result.text
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except ToolCallError as error:
        print(json.dumps({"error": error.code, "request_id": error.request_id, "http_status": error.http_status}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
