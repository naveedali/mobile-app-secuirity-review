import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / (
    "skills/mobile-security-review/scripts/check_canary.py"
)
MARKER = b"MSR_CANARY_4dd557ce29c12da05cc44f73f562572c"


class CanaryTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.root = Path(workspace.name)
        self.marker_file = self.write("canary.txt", MARKER + b"\r\n")

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def run_checker(self, *captures):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--canary-file", self.marker_file, *captures],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_match_across_read_boundary_redacts_marker_and_payload(self):
        prefix = b"test payload" + b"x" * (65536 - len(b"test payload") - 4)
        log = self.write(MARKER.decode() + ".txt", prefix + MARKER + b"\n")
        storage = self.write("storage.db", b"\0\xff" + MARKER)
        result = self.run_checker("--logcat", log, "--storage", storage)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(MARKER.decode(), result.stdout)
        self.assertNotIn("test payload", result.stdout)
        reports = json.loads(result.stdout)["inputs"]
        self.assertEqual([report["first_byte_offset"] for report in reports], [len(prefix), 2])

    def test_clean_capture_requires_exact_bytes(self):
        log = self.write("clean.txt", MARKER.lower() + b"\n")
        storage = self.write("empty.db", b"")
        result = self.run_checker("--logcat", log, "--storage", storage)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [entry["status"] for entry in json.loads(result.stdout)["inputs"]],
            ["no-match", "no-match"],
        )

    def test_incomplete_takes_priority_and_preserves_match(self):
        storage = self.write("snapshot.db", MARKER)
        log = self.write("empty-log.txt", b"")
        result = self.run_checker(
            "--logcat", log, "--storage", storage, "--storage", self.root / "missing"
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["completion"], "incomplete")
        self.assertEqual(
            [entry["status"] for entry in report["inputs"]],
            ["incomplete", "match", "incomplete"],
        )

    def test_rejects_invalid_canary_without_echoing_it(self):
        self.marker_file.write_bytes(b"unstructured-example-secret")
        result = self.run_checker("--storage", self.marker_file)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("unstructured-example-secret", result.stdout + result.stderr)

    def test_canary_file_cannot_be_scanned_as_evidence(self):
        alias = self.root / "alias.txt"
        alias.symlink_to(self.marker_file)
        result = self.run_checker("--storage", alias)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["inputs"][0]["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
