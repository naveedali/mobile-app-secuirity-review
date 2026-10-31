#!/usr/bin/env python3
"""Inspect explicitly supplied Android XML; never execute an inspected project."""
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ANDROID = '{http://schemas.android.com/apk/res/android}'
LEVEL = {'low': 1, 'medium': 2, 'high': 3}
RULES = {
    'MSR001': ('high', 'Debugging explicitly enabled', 'Disable debugging in the release variant and verify the packaged manifest.'),
    'MSR002': ('low', 'Test-only application', 'Verify this is the intended artifact; produce a non-test release for distribution.'),
    'MSR003': ('medium', 'Manifest explicitly permits cleartext traffic', 'Require HTTPS; review target SDK, supported devices, and actual network clients.'),
    'MSR004': ('low', 'Exported component requires access review', 'Verify callers, input validation, authentication, and intended public behavior. Exported does not itself mean vulnerable.'),
    'MSR005': ('medium', 'Network configuration explicitly permits cleartext', 'Remove unnecessary exceptions and test affected hosts with the actual client.'),
    'MSR006': ('low', 'User-installed certificate authorities trusted outside debug overrides', 'Confirm this trust is intentional for the selected variant and threat model.'),
}


def inspect(manifests, network_configs, context='unknown'):
    report = {
        'schema_version': '1.0', 'tool_version': '0.1.0', 'build_context': context,
        'inputs': [], 'findings': [], 'errors': [],
        'limitations': [
            'Static XML observations only; no runtime testing or exploit verification.',
            'Build context is supplied by the caller, not independently verified.',
            'Source manifests may differ from merged and packaged release artifacts.',
            'No Gradle resource/variant resolution, manifest merging, or target/device default evaluation.',
            'Supplied network configurations are inspected independently; manifest linkage is not verified.',
            'No source data-flow, secrets, backup contents, authentication, dependencies, or backend assessment.',
        ],
    }

    def add(rule, path, location, evidence, confidence='high'):
        severity, title, remediation = RULES[rule]
        # Debug configurations are observations, not release vulnerabilities.
        if context != 'release' and rule == 'MSR001':
            severity = 'low'
        report['findings'].append({
            'rule_id': rule, 'severity': severity, 'confidence': confidence,
            'status': 'needs-review' if rule == 'MSR004' else 'configuration-observed',
            'title': title, 'path': str(path), 'location': location,
            'evidence': evidence, 'remediation': remediation,
        })

    def load(path, kind, expected):
        path = Path(path)
        report['inputs'].append({'path': str(path), 'kind': kind})
        try:
            with path.open('rb') as handle:
                data = handle.read(5_000_001)
            if len(data) > 5_000_000:
                raise ValueError('XML exceeds the 5 MB input limit')
            data = data.decode('utf-8-sig')
            if '<!DOCTYPE' in data.upper() or '<!ENTITY' in data.upper():
                raise ValueError('DTD/entity declarations are unsupported')
            root = ET.fromstring(data)
            if root.tag != expected:
                raise ValueError('Expected root element ' + expected)
            # Never silently treat unresolved manifest placeholders as concrete values.
            if '${' in data or any(str(v).startswith(('@', '?')) for e in root.iter()
                                    for k, v in e.attrib.items()
                                    if k in {ANDROID + 'debuggable', ANDROID + 'testOnly',
                                             ANDROID + 'exported', ANDROID + 'usesCleartextTraffic',
                                             'cleartextTrafficPermitted'}):
                report['errors'].append({'path': str(path), 'message': 'Unresolved placeholders or boolean resources; provide resolved XML.'})
            return root
        except (OSError, ET.ParseError, ValueError, UnicodeError) as error:
            report['errors'].append({'path': str(path), 'message': str(error)})
            return None

    for path in dict.fromkeys(manifests):
        root = load(path, 'manifest', 'manifest')
        if root is None:
            continue
        app = root.find('application')
        if app is None:
            report['errors'].append({'path': str(path), 'message': 'Missing application element'})
            continue
        for attr, rule in [('debuggable', 'MSR001'), ('testOnly', 'MSR002')]:
            if app.get(ANDROID + attr) == 'true':
                add(rule, path, '/manifest/application', 'android:' + attr + '=true')
        if app.get(ANDROID + 'networkSecurityConfig'):
            report['limitations'].append(str(path) + ': networkSecurityConfig declared; usesCleartextTraffic is not evaluated because Android 7+ ignores it when a network configuration is present. Inspect the resolved resource and supported older devices.')
            if not network_configs:
                report['errors'].append({'path': str(path), 'message': 'Referenced network security resource not supplied; use --network-config with the resolved variant resource.'})
        elif app.get(ANDROID + 'usesCleartextTraffic') == 'true':
            add('MSR003', path, '/manifest/application', 'android:usesCleartextTraffic=true')
        for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            for i, component in enumerate(app.findall(tag), 1):
                if component.get(ANDROID + 'exported') == 'true':
                    # Inspect all explicit exports: permissions can be weak or custom.
                    permission = component.get(ANDROID + 'permission', app.get(ANDROID + 'permission', '(none declared)'))
                    name = component.get(ANDROID + 'name', '(unnamed)')
                    add('MSR004', path, '/manifest/application/' + tag + '[' + str(i) + ']',
                        'component=' + name + '; exported=true; permission=' + permission)

    for path in dict.fromkeys(network_configs):
        root = load(path, 'network-config', 'network-security-config')
        if root is None:
            continue

        def walk(element, location, debug=False):
            debug = debug or element.tag == 'debug-overrides'
            if not debug:
                if element.tag in ('base-config', 'domain-config') and element.get('cleartextTrafficPermitted') == 'true':
                    add('MSR005', path, location, 'cleartextTrafficPermitted=true')
                if element.tag == 'certificates' and element.get('src') == 'user':
                    add('MSR006', path, location, 'certificates src=user')
            counts = {}
            for child in element:
                counts[child.tag] = counts.get(child.tag, 0) + 1
                walk(child, location + '/' + child.tag + '[' + str(counts[child.tag]) + ']', debug)
        walk(root, '/network-security-config')
    report['completion'] = 'incomplete' if report['errors'] else 'completed-limited-checks'
    report['summary'] = {level: sum(f['severity'] == level for f in report['findings']) for level in LEVEL}
    return report


def markdown(report):
    # Escape inspected text so evidence cannot become active Markdown/HTML.
    def esc(value):
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('`', '&#96;').replace('[', '&#91;').replace(']', '&#93;').replace('\n', ' ')
    lines = ['# Mobile Security Review', '', 'Completion: ' + report['completion'],
             'Build context (caller supplied): ' + report['build_context'], '',
             'No findings means no observations from these limited checks; it does not establish app security.', '', '## Inputs', '']
    lines += ['- ' + esc(i['path']) + ' (' + i['kind'] + ')' for i in report['inputs']]
    lines += ['', '## Findings', '']
    if not report['findings']:
        lines.append('No findings from the implemented checks.')
    for f in report['findings']:
        lines += ['### ' + f['rule_id'] + ' — ' + f['title'], '',
                  '- Severity: ' + f['severity'] + '; confidence in observation: ' + f['confidence'] + '; status: ' + f['status'],
                  '- File: ' + esc(f['path']), '- XML location: ' + esc(f['location']),
                  '- Evidence: ' + esc(f['evidence']), '- Next step: ' + f['remediation'], '']
    lines += ['## Input errors / incomplete coverage', '']
    lines += ['- ' + esc(e['path']) + ': ' + esc(e['message']) for e in report['errors']] or ['None recorded.']
    lines += ['', '## Limitations', '']
    lines += ['- ' + esc(item) for item in report['limitations']]
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', action='append', required=True, help='Plain-text manifest; repeat for multiple inputs')
    parser.add_argument('--network-config', action='append', default=[], help='Resolved plain-text network XML; repeat as needed')
    parser.add_argument('--build-context', choices=['source', 'release', 'unknown'], default='unknown')
    parser.add_argument('--format', choices=['json', 'markdown'], default='markdown')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fail-on', choices=['none', 'low', 'medium', 'high'], default='none')
    args = parser.parse_args(argv)
    report = inspect(args.manifest, args.network_config, args.build_context)
    output = json.dumps(report, indent=2) + '\n' if args.format == 'json' else markdown(report)
    if args.output:
        # Prevent accidental replacement of an inspected input file.
        if args.output.resolve() in {Path(p).resolve() for p in args.manifest + args.network_config}:
            parser.error('--output must differ from input files')
        try:
            args.output.write_text(output, encoding='utf-8')
        except OSError as error:
            print('Cannot write report: ' + str(error), file=sys.stderr)
            return 2
    else:
        print(output, end='')
    if report['errors']:
        return 2
    if args.fail_on != 'none' and any(LEVEL[f['severity']] >= LEVEL[args.fail_on] for f in report['findings']):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
