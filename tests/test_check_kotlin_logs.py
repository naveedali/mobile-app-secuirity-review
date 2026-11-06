import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / (
    "skills/mobile-security-review/scripts/check_kotlin_logs.py"
)


class KotlinLogTests(unittest.TestCase):
    def run_checker(self, source, *additional_files):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Example.kt"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path), *additional_files],
                capture_output=True, text=True, check=False,
            )
        return result, json.loads(result.stdout)

    def test_direct_calls_and_templates_report_call_lines(self):
        result, report = self.run_checker('''import android.util.Log
fun example() {
    Log.d(TAG, accessToken)
    android.util.Log.w(
        tag(1, 2),
        "private fixture: ${refresh_token}",
        error
    )
    Log.i(TAG, """raw $password""")
}
''')
        self.assertEqual(result.returncode, 1)
        self.assertEqual([item["line"] for item in report["findings"]], [3, 4, 9])
        self.assertNotIn("private fixture", result.stdout)
        self.assertTrue(all(item["rule_id"] == "MSR007" for item in report["findings"]))

    def test_comments_literals_and_redaction_do_not_trigger(self):
        result, report = self.run_checker(r'''import android.util.Log
fun example() {
    // Log.d(TAG, accessToken)
    /* outer /* nested */ Log.d(TAG, accessToken) */
    val example = """Log.d(TAG, accessToken)"""
    Log.d(TAG, "password redacted")
    Log.d(TAG, "\$accessToken")
    Log.d(TAG, redact(accessToken))
    Log.d(TAG, accessTokenCount)
    Log.d(TAG, "value: ${if (flag) "safe" else "redacted"}")
    custom.Log.d(TAG, accessToken)
}
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["findings"], [])

    def test_unrelated_or_aliased_import_does_not_activate_log(self):
        for statement in ("import my.logger.Log", "import android.util.Log as AndroidLog"):
            with self.subTest(statement=statement):
                result, report = self.run_checker(statement + "\nfun f() { Log.d(TAG, password) }")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(report["findings"], [])

    def test_incomplete_input_takes_precedence_over_finding(self):
        result, report = self.run_checker(
            'fun f() { android.util.Log.d(TAG, password) }', "missing.kt",
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["completion"], "incomplete")
        self.assertEqual(len(report["findings"]), 1)

    def test_unterminated_comment_is_incomplete(self):
        result, report = self.run_checker("/* unfinished")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["completion"], "incomplete")


if __name__ == "__main__":
    unittest.main()
