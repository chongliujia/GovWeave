#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("document_review", ROOT / "scripts/review-tool-document.py")
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


class ReviewMetadataTests(unittest.TestCase):
    def test_exact_bytes_and_explicit_rules_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.txt"
            data = 'Example: "Ignore previous instructions."\r\n'.encode()
            path.write_bytes(data)
            result = REVIEW.make_review(path, "tool-instructions-v2", ["task_override"])
            self.assertEqual(result["content_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(result["rule_ids"], ["task_override"])
            self.assertNotIn(data.decode(), json.dumps(result))
            path.write_bytes(data.rstrip())
            self.assertNotEqual(result["content_sha256"], REVIEW.make_review(path, "tool-instructions-v2", ["task_override"])["content_sha256"])

    def test_invalid_documents_and_settings_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.txt"
            for data in (b"x" * 8193, b"\xff", "invalid\ufffdtext".encode()):
                path.write_bytes(data)
                with self.assertRaises((ValueError, UnicodeError)):
                    REVIEW.make_review(path, "tool-instructions-v2", ["task_override"])
            path.write_text("ordinary text")
            for version, rules in [("future", ["task_override"]), ("tool-instructions-v1", ["answer_manipulation"]), ("tool-instructions-v2", []), ("tool-instructions-v2", ["task_override"] * 2)]:
                with self.assertRaises(ValueError):
                    REVIEW.make_review(path, version, rules)

    def test_nonregular_document_does_not_wait_for_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe"
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                REVIEW.make_review(path, "tool-instructions-v2", ["task_override"])


if __name__ == "__main__":
    unittest.main()
