#!/usr/bin/env python3
"""Negative policy fixtures for secret-bearing SHA-2 execution."""
import sha2_hardened_execution_policy as policy
import importlib.util
from pathlib import Path
import re
import os
import shutil
import subprocess
import x86_sha512_regressions
import x86_sha512_ci


def namespace_regressions():
    spec = importlib.util.spec_from_file_location('codegen', Path(__file__).with_name('check-sha2-hardened-execution-codegen.py'))
    codegen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codegen)
    prefix = 'fn hardened_execution::<impl at crates/brynja-crypto-cpu/src/hardened_execution/mod.rs:175:1: 175:32>::drop(_1: &mut '
    for name in ('Operation', 'hardened_execution::Operation'):
        header = prefix + name + "<'_, '_>) -> () {"
        assert re.search(codegen.OPERATION, header)
        assert not re.search(codegen.OPERATION, header.replace('hardened_execution::<impl', 'hardened_execution::keccak::<impl'))
        assert not re.search(codegen.OPERATION, header.replace('/mod.rs:', '/keccak.rs:'))
        assert not re.search(codegen.OPERATION, header.replace('&mut ' + name, '&mut WrongOperation'))
    assert re.search(codegen.SCRATCH_WIPE, '_symbol7Scratch4wipe')
    assert not re.search(codegen.SCRATCH_WIPE, '_symbol13KeccakScratch4wipe')
    print('SHA-2 compiler identity rejects neighboring Keccak and wrong-owner matches')


def native_gate_regressions():
    original = policy.read(policy.ROOT, 'scripts/tag_gate.sh')
    policy.native_gate(original)
    exact = 'python3 scripts/sha2/check-sha2-hardened-native-evidence.py'
    reuse = 'python3 scripts/release/native_sha2_carry_forward.py'
    plan = 'python3 scripts/release/run-verification.py plan --check'
    mutations = [original.replace(exact, 'true'), original.replace(reuse, 'true'),
                 original.replace(reuse, reuse + ' || true'),
                 original.replace(plan, plan + ' || true'),
                 original.replace(plan, '# omitted'),
                 original.replace('if ' + exact, 'if ! ' + exact),
                 original.replace('set -euo pipefail', 'set -uo pipefail'),
                 original.replace(policy.NATIVE_GATE, policy.NATIVE_GATE + '\n' + policy.NATIVE_GATE)]
    for changed in mutations:
        try:
            policy.native_gate(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('native gate bypass escaped semantic check')
    # Exercise actual shell branching, independently of source-review hashes.
    bash = shutil.which('bash')
    if bash is not None:
        gate = policy.NATIVE_GATE.split('verify() {')[0]
        fake = '''python3() {
    case "$*" in
        *'plan --check') echo PLAN; return "$PLAN" ;;
        *check-sha2-hardened-native-evidence.py) echo EXACT; return "$EXACT" ;;
        *native_sha2_carry_forward.py) echo REUSE; return "$REUSE" ;;
        *) return 99 ;;
    esac
}
set -euo pipefail
'''
        for values, expected, code in (
                ((0, 0, 7), ['PLAN', 'EXACT', 'REACHED'], 0),
                ((0, 7, 0), ['PLAN', 'EXACT', 'REUSE', 'REACHED'], 0),
                ((0, 7, 9), ['PLAN', 'EXACT', 'REUSE'], 9),
                ((8, 0, 0), ['PLAN'], 8)):
            result = subprocess.run([bash, '-c', fake + gate + 'echo REACHED\n'],
                env={**os.environ, **dict(zip(('PLAN', 'EXACT', 'REUSE'), map(str, values)))},
                capture_output=True, text=True, timeout=10)
            assert result.returncode == code, result.stderr
            assert result.stdout.splitlines() == expected, result.stdout
        print('Native gate shell: strict success, reviewed reuse, both-fail and plan-fail paths pass')
    print('Native gate rejects eight semantic bypasses independently of hash checks')

if __name__ == '__main__':
    policy.validate()
    policy.regressions()
    native_gate_regressions()
    namespace_regressions()
    x86_sha512_regressions.regressions()
    x86_sha512_ci.regressions()
