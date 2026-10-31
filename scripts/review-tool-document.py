#!/usr/bin/env python3
"""Create metadata for an operator-reviewed document. Does not judge safety or save to a server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def make_review(path, detector, rules):
    supported = {"task_override", "authority_spoof", "role_delimiter"}
    if detector == "tool-instructions-v2":
        supported.add("answer_manipulation")
    if detector not in ("tool-instructions-v1", "tool-instructions-v2") or not 1 <= len(rules) <= 4 or len(set(rules)) != len(rules) or not set(rules) <= supported:
        raise ValueError("invalid review settings")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("not a regular document")
        data = source.read(8193)
    if len(data) > 8192 or "\ufffd" in data.decode("utf-8"):
        raise ValueError("unsupported document")
    return {"version": "exact-instruction-review-v1", "detector_version": detector,
            "content_sha256": hashlib.sha256(data).hexdigest(), "rule_ids": sorted(rules)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, type=Path, help="Already-reviewed UTF-8 text, byte-exact including line endings; maximum 8192 bytes.")
    parser.add_argument("--detector", required=True, choices=("tool-instructions-v1", "tool-instructions-v2"))
    parser.add_argument("--rule", required=True, action="append", help="Explicit rule to exempt for this document; repeat for multiple rules.")
    args = parser.parse_args()
    try:
        print(json.dumps(make_review(args.file, args.detector, args.rule), indent=2))
    except (OSError, ValueError, UnicodeError):
        print("Review metadata could not be created. Check the document, size, UTF-8 encoding, detector and rule selection.", file=sys.stderr)
        raise SystemExit(1)
