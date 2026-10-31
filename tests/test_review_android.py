import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/mobile-security-review/scripts/review_android.py'
spec = importlib.util.spec_from_file_location('review_android', SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def xml(self, name, text):
        path = self.root / name
        path.write_text(text, encoding='utf-8')
        return str(path)

    def manifest(self, attrs='', children=''):
        return self.xml('AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application ' + attrs + '>' + children + '</application></manifest>')

    def ids(self, report):
        return [f['rule_id'] for f in report['findings']]

    def test_synthetic_fixture_detects_all_six_rules(self):
        report = review.inspect([str(ROOT / 'tests/fixtures/AndroidManifest.xml')], [str(ROOT / 'tests/fixtures/network_security_config.xml')], 'release')
        self.assertEqual(self.ids(report), ['MSR001', 'MSR002', 'MSR003', 'MSR004', 'MSR005', 'MSR006'])
        self.assertEqual(report['completion'], 'completed-limited-checks')

    def test_absent_attributes_are_not_assumed_vulnerable(self):
        report = review.inspect([self.manifest()], [])
        self.assertEqual(report['findings'], [])
        self.assertTrue(report['limitations'])

    def test_explicit_false_values(self):
        report = review.inspect([self.manifest('android:debuggable="false" android:testOnly="false" android:usesCleartextTraffic="false"', '<service android:exported="false"/>')], [])
        self.assertEqual(report['findings'], [])

    def test_debug_context_changes_severity(self):
        path = self.manifest('android:debuggable="true"')
        self.assertEqual(review.inspect([path], [], 'source')['findings'][0]['severity'], 'low')
        self.assertEqual(review.inspect([path], [], 'release')['findings'][0]['severity'], 'high')

    def test_manifest_cleartext_not_flagged_with_network_config(self):
        manifest = self.manifest('android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network"')
        config = self.xml('network.xml', '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>')
        report = review.inspect([manifest], [config])
        self.assertNotIn('MSR003', self.ids(report))
        self.assertEqual(report['errors'], [])

    def test_missing_network_resource_is_incomplete(self):
        report = review.inspect([self.manifest('android:networkSecurityConfig="@xml/network"')], [])
        self.assertEqual(report['completion'], 'incomplete')

    def test_debug_user_ca_excluded(self):
        config = self.xml('network.xml', '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>')
        self.assertEqual(review.inspect([self.manifest()], [config])['findings'], [])

    def test_nested_domain_cleartext_is_observed(self):
        config = self.xml('network.xml', '<network-security-config><domain-config cleartextTrafficPermitted="false"><domain-config cleartextTrafficPermitted="true"><domain>example.test</domain></domain-config></domain-config></network-security-config>')
        report = review.inspect([self.manifest()], [config])
        self.assertEqual(self.ids(report), ['MSR005'])
        self.assertIn('/domain-config[1]/domain-config[1]', report['findings'][0]['location'])

    def test_permission_protected_export_is_review_candidate(self):
        path = self.manifest('android:permission="org.example.GUARD"', '<activity android:name=".Entry" android:exported="true"/>')
        finding = review.inspect([path], [])['findings'][0]
        self.assertEqual(finding['status'], 'needs-review')
        self.assertIn('org.example.GUARD', finding['evidence'])

    def test_malformed_missing_wrong_root_and_no_application(self):
        for name, text in [('broken.xml', '<manifest'), ('wrong.xml', '<resources/>'), ('missing-app.xml', '<manifest/>')]:
            with self.subTest(name=name):
                report = review.inspect([self.xml(name, text)], [])
                self.assertEqual(report['completion'], 'incomplete')
        self.assertEqual(review.inspect([str(self.root / 'absent.xml')], [])['completion'], 'incomplete')

    def test_unresolved_boolean_and_placeholder(self):
        for attr in ['android:debuggable="@bool/debug"', 'android:debuggable="${debugFlag}"']:
            self.assertEqual(review.inspect([self.manifest(attr)], [])['completion'], 'incomplete')

    def test_rejects_entities_and_non_utf8(self):
        path = self.xml('entity.xml', '<!DOCTYPE manifest [<!ENTITY flag "true">]><manifest/>')
        self.assertIn('DTD/entity', review.inspect([path], [])['errors'][0]['message'])
        Path(path).write_bytes('<manifest/>'.encode('utf-16'))
        self.assertEqual(review.inspect([path], [])['completion'], 'incomplete')

    def test_duplicate_inputs_do_not_duplicate_findings(self):
        path = self.manifest('android:debuggable="true"')
        self.assertEqual(len(review.inspect([path, path], [])['findings']), 1)

    def test_markdown_escapes_html_evidence(self):
        path = self.manifest('', '<activity android:exported="true" android:name="&lt;script&gt;"/>')
        text = review.markdown(review.inspect([path], []))
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)

    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_ci_threshold_and_json(self):
        path = self.manifest('android:debuggable="true"')
        result = self.cli('--manifest', path, '--build-context', 'release', '--format', 'json', '--fail-on', 'high')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['summary']['high'], 1)
        self.assertEqual(self.cli('--manifest', path, '--fail-on', 'high').returncode, 0)

    def test_input_failure_overrides_threshold(self):
        path = self.manifest('android:debuggable="true" android:networkSecurityConfig="@xml/missing"')
        self.assertEqual(self.cli('--manifest', path, '--build-context', 'release', '--fail-on', 'high').returncode, 2)

    def test_cannot_overwrite_input(self):
        path = self.manifest()
        original = Path(path).read_text()
        self.assertEqual(self.cli('--manifest', path, '--output', path).returncode, 2)
        self.assertEqual(Path(path).read_text(), original)

    def test_report_written_to_output(self):
        path = self.manifest()
        output = self.root / 'report.json'
        result = self.cli('--manifest', path, '--format', 'json', '--output', str(output))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(json.loads(output.read_text())['completion'], 'completed-limited-checks')


if __name__ == '__main__':
    unittest.main()
