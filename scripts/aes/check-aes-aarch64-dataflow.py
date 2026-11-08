#!/usr/bin/env python3
"""AArch64 compile-only helper review; no native timing or final-link claim."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_arm_flow', HERE / 'check-aes-dataflow.py')
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)
spec = importlib.util.spec_from_file_location('aes_arm_machine', HERE / 'aes_aarch64_review.py')
machine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(machine)
spec = importlib.util.spec_from_file_location('aes_arm_helpers', HERE / 'aes_aarch64_helpers.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
spec = importlib.util.spec_from_file_location('aes_arm_rounds', HERE / 'aes_aarch64_rounds.py')
rounds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rounds)
spec = importlib.util.spec_from_file_location('aes_arm_wrappers', HERE / 'aes_aarch64_wrappers.py')
wrappers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrappers)
spec = importlib.util.spec_from_file_location('aes_arm_core', HERE / 'aes_aarch64_core.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
spec = importlib.util.spec_from_file_location('aes_arm_public', HERE / 'aes_aarch64_public.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
spec = importlib.util.spec_from_file_location('aes_arm_constructors', HERE / 'aes_aarch64_constructors.py')
constructors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(constructors)
spec = importlib.util.spec_from_file_location('aes_arm_callers', HERE / 'aes_aarch64_callers.py')
callers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(callers)
TARGET = 'aarch64-unknown-linux-gnu'
MARKER = 'AES AArch64 dataflow: 4 compile-only configurations; 11 LLVM helpers; eleven assembly helpers, six secret wrappers, six public boundaries, six constructors, twelve secret entry points and seven matched core bodies reviewed; not native or final-linked qualification'
REJECT = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC', 'RUSTDOC',
          'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN',
          'PYTHONOPTIMIZE', 'PYTHONPATH')


def negative_controls(assembly, selected, compiler, panic):
    callees = {item[0]: role for role, item in selected.items()}
    count = 0
    for role, (_, args, body) in selected.items():
        argument = re.findall(r'\b(?:ptr|i\d+)\b[^%]*?(' + flow.VAR + r')(?=, |$)', args)[0]
        load = '' if role == 'inverse' else f'  %audit_byte = load i8, ptr {argument}, align 1\n'
        value = argument if role == 'inverse' else '%audit_byte'
        insertion = (load + f'  %audit_condition = icmp eq i8 {value}, 0\n'
                     '  br i1 %audit_condition, label %audit_done, label %audit_done\naudit_done:\n')
        start, rest = body.split('\n', 1)
        try:
            flow.check_body(role, args, start + '\n' + insertion + rest, callees)
        except ValueError as error:
            flow.require('secret-dependent branch' in str(error), 'mutation failed for unrelated reason: ' + str(error))
        else:
            raise ValueError('AArch64 secret-branch mutation accepted: ' + role)
        count += 1
    symbol = selected['inverse'][0]
    for instruction in ('b.eq .Lother', 'bl other', 'br x0', 'udiv w0, w0, w1',
                        'ldr w0, [x0]', 'ldr w0, [sp, x0]', 'mov sp, x0',
                        'lsl w0, w0, w1', 'csel x0, xzr, x0, gt', '.word 0',
                        'str w0, [sp, #8]', 'mov w8, #27'):
        # Last case is individually admitted arithmetic, but must still break
        # the reviewed instruction-stream fingerprint. No automatic rebasing.
        start = assembly.index(symbol + ':\n')
        save = re.search(r'^\s*str\s+x27, \[sp, #-80\]!\s*$', assembly[start:], re.M)
        flow.require(save is not None, 'missing inverse frame for mutation')
        point = start + save.end()
        changed = assembly[:point] + '\n\t' + instruction + assembly[point:]
        try:
            machine.check(changed, symbol, compiler, panic)
        except ValueError as error:
            expected = 'instruction stream changed' if instruction == 'mov w8, #27' else 'unreviewed instruction'
            flow.require(expected in str(error), 'machine mutation failed for unrelated reason: ' + str(error))
        else:
            raise ValueError('AArch64 machine mutation accepted: ' + instruction)
        count += 1
    flow.require(count == 23, 'AArch64 mutation population changed')
    return count


def collect_core(directory, env, compiler, panic, callees):
    flow.verifier.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release', '--lib',
                       '-p', 'brynja-core', '--target', TARGET, '--', '--emit=llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('ll', 's'):
        paths = list((directory / 'target' / TARGET / 'release/deps').glob('brynja_core-*.' + extension))
        flow.require(len(paths) == 1, 'missing/ambiguous AArch64 core artifact')
        artifacts[extension] = paths[0].read_text()
        print(f'AES AArch64 core artifact: {compiler} {panic} {extension} sha256={hashlib.sha256(paths[0].read_bytes()).hexdigest()}', flush=True)
    definitions, aliases = flow.graph.definitions_and_aliases(artifacts['ll'])
    selected = core.select(artifacts['ll'], definitions, aliases, callees)
    zeroizer = definitions[selected['zeroize']][1]
    print('AES AArch64 zeroizer LLVM: ' + core.check_llvm(zeroizer, compiler), flush=True)
    rejected = core.llvm_mutations(zeroizer, compiler)
    for role in core.ROLES:
        lines = machine.body(artifacts['s'], selected[role])
        args = (lines, selected, role, compiler, panic)
        print(json.dumps(core.check(*args)), flush=True)
        rejected += core.mutations(*args)
    flow.require(rejected == 107, 'AArch64 core mutation population changed')
    return rejected


def collect(directory, compiler, panic):
    env = flow.verifier.environment(directory)
    env.update(CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_PROFILE_RELEASE_LTO='fat',
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', RUSTUP_AUTO_INSTALL='0')
    print(flow.verifier.run(['rustc', '+' + compiler, '-vV'], env).strip(), flush=True)
    flow.verifier.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release', '--lib',
                       '-p', 'brynja-crypto', '--no-default-features', '--features', 'hazmat-aes-block',
                       '--target', TARGET, '--', '--emit=llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('ll', 's'):
        paths = list((directory / 'target' / TARGET / 'release/deps').glob('brynja_crypto-*.' + extension))
        flow.require(len(paths) == 1, 'missing/ambiguous AArch64 artifact')
        artifacts[extension] = paths[0].read_text()
        print(f'AES AArch64 artifact: {compiler} {panic} {extension} sha256={hashlib.sha256(paths[0].read_bytes()).hexdigest()}', flush=True)
    selected = flow.check_ir(artifacts['ll'], TARGET)
    count = machine.check(artifacts['s'], selected['inverse'][0], compiler, panic)
    rejected = negative_controls(artifacts['s'], selected, compiler, panic)
    for role in helpers.ROLES:
        lines = machine.body(artifacts['s'], selected[role][0])
        args = (lines, selected['inverse'][0], role, compiler, panic)
        print(json.dumps(helpers.check(*args)), flush=True)
        rejected += helpers.mutations(*args)
    callees = rounds.bind(selected, artifacts['ll'], flow.CLEAR)
    for role in rounds.ROLES:
        lines = machine.body(artifacts['s'], selected[role][0])
        args = (lines, callees, role, compiler, panic)
        print(json.dumps(rounds.check(*args)), flush=True)
        rejected += rounds.mutations(*args)
    definitions, aliases = flow.graph.definitions_and_aliases(artifacts['ll'])
    owners, callees = wrappers.select(definitions, aliases, artifacts['ll'], selected, panic, flow.CLEAR)
    for role in wrappers.ROLES:
        lines = machine.body(artifacts['s'], owners[role])
        args = (lines, callees, role, compiler, panic)
        print(json.dumps(wrappers.check(*args)), flush=True)
        rejected += wrappers.mutations(*args)
    rejected += collect_core(directory, env, compiler, panic, callees)
    for role, symbol in public.select(definitions, aliases).items():
        lines = machine.body(artifacts['s'], symbol)
        args = (lines, callees, role, compiler, panic)
        print('AES AArch64 public boundary: ' + json.dumps(public.check(*args)), flush=True)
        rejected += public.mutations(*args)
    for role, symbol in constructors.select(definitions, aliases).items():
        lines = machine.body(artifacts['s'], symbol)
        args = (lines, callees, role, compiler, panic)
        print('AES AArch64 constructor: ' + json.dumps(constructors.check(*args)), flush=True)
        rejected += constructors.mutations(*args)
    for role, symbol in callers.select(definitions, aliases).items():
        lines = machine.body(artifacts['s'], symbol)
        args = (lines, callees, role, compiler, panic)
        print('AES AArch64 secret entry point: ' + json.dumps(callers.check(*args)), flush=True)
        rejected += callers.mutations(*args)
    flow.require(rejected == 804, 'AArch64 mutation population changed')
    print(f'AES AArch64 configuration: PASS; {compiler}; {panic}; 11 LLVM helpers; {count} inverse instructions; ten additional assembly helpers; six secret wrappers; six public boundaries; six constructors; twelve secret entry points; seven matched core bodies; 804 rejected mutations', flush=True)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for name in REJECT:
        flow.require(name not in os.environ, 'remove ambient ' + name)
    for compiler in ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with flow.verifier.cargo_environment.private_directory(flow.ROOT) as temporary:
                collect(Path(temporary), compiler, panic)
    print(MARKER, flush=True)


if __name__ == '__main__':
    main()
