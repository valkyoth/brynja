"""Finite hosted compiler-checker selections; no discovery or native execution.

The adjacent maintained data lists exact commands and imported helper closures.
Commands keep their existing individual unittest selections, not the full suite.
"""
import json
from pathlib import Path
from verification_cargo_bindings import fixture_inputs
from verification_assessment_bindings import ENV
from verification_miri_bindings import REJECT

DATA = Path(__file__).with_name('verification_hosted_selections.json')


def build(rows):
    definitions = json.loads(DATA.read_text())
    groups = {'hosted-python': {'tools': [{'program': 'python3'},
        {'program': 'c++filt'}, {'program': 'llvm-cxxfilt', 'optional': True}]}}
    checks = []
    for family, definition in definitions.items():
        fixture = 'hmac-hosted-cleanup' if family == 'hmac' else 'legacy-hmac-hosted-cleanup'
        known = {tuple(s['command']): s for s in definition['selections']}
        script = next(iter(known))[1]
        key = 'hosted-' + family
        # These suites copy/edit literal manifests. Their original fixture and
        # relevant copied manifests must not use semantic-only normalization.
        packages = (['brynja-crypto-cpu-std', 'brynja-mac-hmac'] if family == 'hmac'
                    else ['brynja-legacy-hmac-std', 'brynja-legacy-hmac'])
        groups[key] = {'paths': [*definition['helpers'],
            'assurance/' + fixture + '/Cargo.toml', 'assurance/' + fixture + '/Cargo.lock',
            *['crates/' + p + '/Cargo.toml' for p in packages]],
            'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
                                   'workspace.package.license', 'workspace.package.repository', 'workspace.lints']}}
        source = fixture_inputs(groups, fixture, key + '-source')
        for row in rows:
            if row['phase'] != 'repository' or row['command'][:2] != ['python3', script]:
                continue
            spec = known.get(tuple(row['command']))
            if not spec or spec['id'] != row['id'] or row.get('environment') or row.get('stdin'):
                raise ValueError('unreviewed hosted selection: ' + row['id'])
            tools = key + '-' + row['id']
            groups[tools] = {'tools': [{'program': p, 'toolchain': c}
                                      for c in spec['compilers'] for p in ('cargo', 'rustc')]}
            count = len(row['command']) - 2
            summary = f'\nRan {count} ' + ('test' if count == 1 else 'tests') + ' in '
            checks.append(dict(component=family, id=row['id'], name=row['label'], category='repository',
                command=row['command'], cwd='.', inputs=['hosted-python', key, tools, *source],
                environment=ENV, reject_environment=REJECT, platform='linux-x86_64',
                success={'contains': [summary], 'unique_lines': ['OK']},
                timeout_seconds=3600, log_bytes=16777216,
                establishes='Existing selected hosted compiler-checker regressions; original cross-target artifact profiles and mutations, not native execution or whole-worker/kernel/register erasure. Missing compilers/demanglers or target support fail closed.'))
    return dict(schema=1, groups=groups, checks=checks)
