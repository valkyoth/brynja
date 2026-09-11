#!/usr/bin/env python3
"""Negative policy fixtures for secret-bearing SHA-2 execution."""
import sha2_hardened_execution_policy as policy
import importlib.util
from pathlib import Path
import re


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

if __name__ == '__main__':
    policy.validate()
    policy.regressions()
    namespace_regressions()
