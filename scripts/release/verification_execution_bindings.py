"""Default execution acceptance wrappers, not native collection campaigns.

Original policy inventories are inputs to these wrappers only. Export reads
declarations, never imports a checker or executes its commands.
"""
import json
from pathlib import Path
import tomllib
from verification_assessment_bindings import ENV
from verification_cargo_bindings import source_inputs
from verification_miri_bindings import REJECT
from verification_package_bindings import PACKAGES, SHA2_HELPERS, SHA3_HELPERS

ROOT = Path(__file__).resolve().parents[2]


def definitions():
    result = {}
    for family, mode, marker in [
        ('md5', 'cpu', 'MD5 batch/SIMD source, packaged APIs and production rejection: PASS; admission NONE'),
        ('md5', 'execution', 'MD5 ordinary operational selection: PASS; public-only; native qualification separate'),
        ('md5', 'hardened', 'Hardened MD5 development acceptance: PASS; native evidence/retest separate'),
        ('sha1', 'cpu', 'SHA-1 CPU candidate surface and ordinary-build rejection: PASS; native admission: NONE'),
        ('sha1', 'hardened', 'Hardened legacy SHA-1 execution: PASS; seven owned regions; native qualification is separate'),
    ]:
        source = 'verification_hardened_inputs.json' if mode == 'hardened' else 'verification_legacy_policy_inputs.json'
        key = family if mode == 'hardened' else family + '-' + mode
        paths = json.loads((Path(__file__).with_name(source)).read_text())[key]['paths']
        title = 'MD5' if family == 'md5' else 'SHA-1'
        markers = [marker]
        # SHA-1 CPU invokes the packager twice; a duplicated scoped marker is
        # expected there, so require it by content rather than uniqueness.
        contains = [f'Scoped {title} packaged negatives: 13; compiled regressions: 18 rejected']
        fixtures = [family + '-public-api']
        if mode == 'cpu':
            fixtures += [family + '-cpu-public-api']
            markers += [f'{title} evidence isolation: {8 if family == "md5" else 7} release-mode combinations and external cfg(test) consumer reject execution']
        if family == 'md5' and mode in ('execution', 'hardened'):
            fixtures += ['md5-' + ('hardened-execution' if mode == 'hardened' else mode)]
        if family == 'md5' and mode == 'hardened':
            markers += ['Packaged hardened MD5 cleanup: 5 compiled whole-region/Drop mutants rejected']
            paths += json.loads(Path(__file__).with_name('verification_codegen_inputs.json').read_text())[
                'scripts/md5/check-md5-hardened-codegen.py']
        if family == 'sha1' and mode == 'hardened':
            markers += ['Hardened SHA-1 CI: two-architecture driver model, 10 orchestration negatives, 2 missing-flags compiled rejections passed',
                'Hardened SHA-1 sanitizer: 8 ambient/runtime cases passed; 4 enforcement mutants rejected',
                'Independent hardened SHA-1 oracle: 1135 bit messages, public and secret destinations',
                'Packaged hardened ownership/classification negatives: 38 rejected',
                'Hardened output/quarantine/padding compiled mutants: 10 rejected',
                'Scoped execution compiled lifecycle/cleanup mutants: 24 rejected',
                'Compiled source-owner and scratch cleanup removals: 10 rejected']
        result[('python3', f'scripts/{family}/check-{family}-{mode}.py')] = dict(
            paths=paths, patterns=[], fixtures=fixtures,
            packages=PACKAGES | {'brynja-legacy-' + family, 'brynja-legacy-' + family + '-std'},
            versions=['1.99.1', '1.98.1'] if mode == 'hardened' else ['1.99.1'],
            compiler='1.99.1', markers=markers, contains=contains, clippy=mode != 'cpu',
            visible_tests=True)

    for family, stem in [('sha2', 'sha2-hardened-execution'), ('sha3', 'keccak-hardened')]:
        review = f'security/{stem}-reviewed.json'
        # This is the inventory read by the original checker, not a new
        # approval or evidence freshness requirement for other components.
        paths = [review, *json.loads((ROOT / review).read_text())['sha256']]
        paths += SHA2_HELPERS if family == 'sha2' else SHA3_HELPERS
        policy = f'scripts/{family}/' + ('sha2_hardened_execution_policy.py' if family == 'sha2' else 'keccak_hardened_policy.py')
        paths += [policy]
        patterns = [f'scripts/{family}/*{stem}*.py']
        fixtures = ['general-sha512-t', 'sha2-hardened-execution'] if family == 'sha2' else ['sha3-execution']
        markers = (['Twelve packaged ownership/classification bypasses rejected',
            '22 compiled hardened algorithm/lifecycle regressions rejected',
            'Ten live owned regions observed on Drop; twenty compiled clearing mutants rejected',
            'Four compiled buffer-bound/reset mutants rejected in debug/release',
            'Complete packaged hardened SHA-2 execution: PASS'] if family == 'sha2' else [
            'Hardened Keccak packaged ownership rejects 54 bypasses',
            'Packaged hardened Keccak public API: PASS'])
        base = dict(paths=paths, patterns=patterns, fixtures=fixtures, packages=set(PACKAGES),
            compiler='1.99.1' if family == 'sha2' else '1.98.1',
            versions=['1.99.1'] if family == 'sha2' else ['1.98.1'],
            markers=markers, contains=[], clippy=family == 'sha2', visible_tests=False)
        result[('python3', f'scripts/{family}/check-{stem}.py')] = base
        if family == 'sha3':
            result[('python3', 'scripts/sha3/test-keccak-hardened.py', '--compiled')] = dict(base,
                markers=['Hardened Keccak semantic policy rejects 30 regressions',
                    'Hardened Keccak rejects 22 compiled debug/release region-removal mutants',
                    'Hardened Keccak rejects eight compiled debug/release exact-layout mutants'])
        else:
            result[('python3', 'scripts/sha2/test-sha2-hardened-execution.py')] = dict(base,
                versions=[], clippy=False, packages=set(), fixtures=[],
                paths=[*paths, 'scripts/sha2/sha2_execution_faults.py',
                    'crates/brynja-crypto-cpu/src', 'crates/brynja-hash-sha2/src',
                    'assurance/sha2-hardened-execution/src',
                    *['crates/' + p + '/Cargo.toml' for p in sorted(PACKAGES)]],
                markers=['Hardened execution region/gate policy rejects 30 regressions',
                    'Native gate shell: strict success, reviewed reuse, both-fail and plan-fail paths pass',
                    'Native gate rejects eight semantic bypasses independently of hash checks',
                    'SHA-2 compiler identity rejects neighboring Keccak and wrong-owner matches',
                    'Dedicated SHA512 driver rejects seven exit/coverage/route regressions and five timeouts, including post-PASS shutdown',
                    'Dedicated SHA512 sanitizer overrides hostile ambient disable/exit settings',
                    'Dedicated SHA512 packager rejects both missing optional dependency manifests',
                    'SDE installer: four execution cases, seven policy and three explicit-only workflow regressions PASS'])
    for kind in ('hosted', 'static'):
        review = f'security/{kind}-cpu-execution-reviewed.json'
        compiler = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        markers = (['Ten packaged raw-state/block classification bypasses rejected',
            'Packaged hosted HMAC: debug/release selection passed; owner escape, policy forgery/substitution and feature absence rejected',
            'Hosted authority rejects 14 compiled lifecycle/selection regressions'] if kind == 'hosted' else [
            'Static reachability documentation rejects 28 semantic regressions',
            'Static authority package, public vectors, quarantine and 7 compiled regressions: PASS'])
        result[('python3', f'scripts/cpu/check-{kind}-execution.py')] = dict(
            paths=[review, *json.loads((ROOT / review).read_text())['sha256']], patterns=[],
            fixtures=[kind + '-cpu-execution'], packages=set(PACKAGES) if kind == 'hosted' else
                {'brynja-core', 'brynja-crypto-cpu'}, compiler=compiler, versions=[compiler],
            clippy=True, visible_tests=False, markers=markers, contains=[])
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'execution-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv in {('python3', script, '--policy-only') for script in (
                'scripts/sha2/check-sha2-hardened-execution.py',
                'scripts/cpu/check-static-execution.py', 'scripts/cpu/check-hosted-execution.py')}:
            # Already retained as a manual historical gate diagnostic.
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed execution acceptance selector: ' + row['id'])
        spec = known[argv]
        key = 'execution-' + row['id']
        paths = [argv[1], 'rust-toolchain.toml', *spec['paths']]
        paths += ['crates/' + p for p in sorted(spec['packages'])]
        paths += ['assurance/' + p for p in spec['fixtures']]
        tools = [dict(program=p, toolchain=v) for v in spec['versions'] for p in ('cargo', 'rustc')]
        if spec['versions']:
            tools.append(dict(program='rustdoc', toolchain=spec['compiler']))
            if spec['clippy']:
                tools.append(dict(program='clippy-driver', toolchain=spec['compiler']))
        groups[key] = dict(paths=sorted(set(paths)), patterns=spec['patterns'],
            tools=tools,
            toml={'Cargo.toml': ['workspace.package', 'workspace.resolver', 'workspace.lints',
                'workspace.members', 'workspace.exclude', 'profile', 'patch', 'replace']})
        if not spec['versions']:
            groups[key]['tools'] = [{'program': 'bash'}]
            groups[key]['toml']['Cargo.toml'] = ['workspace.dependencies.' + p for p in sorted(PACKAGES)]
        inputs = ['execution-python', key]
        inputs += source_inputs(groups, key + '-source', spec['packages'], 'Cargo.lock')
        success = dict(contains=spec['markers'] + spec['contains'], unique_lines=spec['markers'])
        if spec['visible_tests']:
            success.update(minimum_tests=1, allow_ignored=True)
        establishes = ('Existing source-policy, fake gate-shell branches and mocked SDE/sanitizer driver '
            'regressions; no compiler, cryptography, sanitizer or emulator execution.' if not spec['versions'] else
            'Existing default execution acceptance and/or packaged ownership/cleanup mutations. '
            'Preferred routes may use the available host or remain portable; no required native capture, '
            'QEMU, Miri or sanitizer campaign is selected.')
        if '--compiled' in argv:
            establishes += ' Keccak layout mutants also cross-compile AArch64, without executing it.'
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs,
            environment=dict(ENV, RUSTUP_TOOLCHAIN=spec['compiler']), reject_environment=REJECT,
            platform='linux-x86_64', timeout_seconds=3600, log_bytes=16777216, success=success,
            establishes=establishes + ' Historical review/gate inputs belong to this wrapper only, '
                'not previous implementation results. Missing targets or stale original policies can fail this '
                'explicit check; a runnable binding is not a recorded pass.'))
    return dict(schema=1, groups=groups, checks=checks)
