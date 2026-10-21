#!/usr/bin/env python3
"""Inspect hosted HMAC capture/factory placement and lifecycle, not whole-worker erasure."""
import argparse
import json
from pathlib import Path
import re

import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_contracts as contracts
import hmac_hosted_capture as capture
import hmac_hosted_capture_types as capture_types
import hmac_hosted_placement as placement
import hmac_hosted_authority as authority
import hmac_hosted_keyed as keyed
import hmac_hosted_storage as storage
import hmac_hosted_scalar as scalar
import hmac_hosted_compiled as compiled_worker
import hmac_hosted_output as output
import hmac_hosted_input as input_flow
import hmac_hosted_checkpoints as checkpoints
import hmac_hosted_checkpoint_callees as checkpoint_callees
import hmac_hosted_transaction as transaction
import hmac_hosted_guard_paths as guard_paths
import hmac_hosted_buffers as buffers
import hmac_hosted_callee_admission as callee_admission
import hmac_hosted_constructor as constructor
import hmac_hosted_consumers as consumers
import hmac_hosted_loans as loans
import hmac_hosted_loan_creation as loan_creation
import hmac_hosted_verify as public_verify
import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / 'assurance/hmac-hosted-cleanup/Cargo.toml'
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')
FEATURES = {'x86_64-unknown-linux-gnu': '+sha,+sha512,+avx2',
            'aarch64-unknown-linux-gnu': '+neon,+sha2,+sha3,+aes',
            'aarch64-apple-darwin': '+neon,+sha2,+sha3,+aes'}
PACKAGES = {'brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std',
            'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-hmac',
            'brynja-hmac-hosted-cleanup-fixture'}


def graph(metadata):
    packages, nodes = metadata['packages'], metadata['resolve']['nodes']
    common.require(len(packages) == len(nodes) == len(PACKAGES)
                   and {row['name'] for row in packages} == PACKAGES
                   and len({row['id'] for row in packages}) == len(PACKAGES)
                   and {row['id'] for row in packages} == {row['id'] for row in nodes},
                   'hosted fixture dependency population changed')
    common.require(all(row['source'] is None for row in packages), 'nonlocal hosted fixture dependency')
    hosted = next(row for row in packages if row['name'] == 'brynja-crypto-cpu-std')
    selected = next(row['features'] for row in nodes if row['id'] == hosted['id'])
    common.require({'strict-hmac-acceleration', 'macos-resident-hmac-acceleration'} <= set(selected),
                   'missing hosted fixture features')
    common.require(all('runtime-execution' not in row['features'] for row in nodes),
                   'runtime feature contaminates hosted static fixture')


def artifact_profile(llvm, target, compiler):
    common.require(compiler in ('1.90.0', '1.99.1')
                   and re.findall(r'!"rustc version ([\d.]+) ', llvm) == [compiler],
                   'hosted emitted compiler identity changed')
    expected = ('arm64-apple-macosx11.0.0' if target == 'aarch64-apple-darwin' else target)
    common.require(target in TARGETS and re.findall(r'^target triple = "([^"]+)"$', llvm, re.M) == [expected],
                   'hosted emitted target identity changed')


def validate(llvm, target, compiler='1.99.1', panic='unwind'):
    artifact_profile(llvm, target, compiler)
    common.require(panic in ('abort', 'unwind'), 'unreviewed hosted panic profile')
    contracts.validate()
    capture_types.validate()
    definitions, aliases = common.definitions_and_aliases(llvm)
    types = constructor.construct.iterator.array_types(llvm, 'static')
    symbols = {name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)}
    names = lifecycle.demangle(symbols)
    owner, resource = lifecycle.profile(target)
    checked, workers = set(), set()
    for identity in common.IDENTITIES:
        algorithm = ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                     else 'brynja_mac_hmac::algorithms::' + ('Sha' + identity[3:]))
        for operation in lifecycle.OPERATIONS:
            entry = 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + operation
            candidates = [name for name in (*definitions, *aliases) if names[name] == entry]
            common.require(len(candidates) == 1, 'missing/ambiguous hosted consumer ' + entry)
            _, body = common.resolve(candidates[0], definitions, aliases)
            calls = [call for line in body.splitlines() if (call := syntax.call(line))]
            session = 'compiled::CompiledSession' if operation.startswith('compiled_') else 'Session'
            expected = '<' + owner + '::' + session + '<' + algorithm + '>>::execute'
            selected = [symbol for symbol, _ in calls if names.get(symbol) == expected]
            common.require(len(selected) == 1, 'host consumer does not call exact typed executor: ' + entry)
            executor = selected[0]
            if executor not in checked:
                arguments, host = common.resolve(executor, definitions, aliases)
                record = capture.check(arguments, host, names, target, operation.startswith('compiled_'))
                worker = lifecycle.check_host(host, names, definitions, target)
                host_result = transaction.check(record, operation.startswith('compiled_'), compiler)
                guard_paths.check(host_result)
                # Bind the exact closure type, not merely any thread::enter symbol.
                closure = expected + '::{closure#0}'
                common.require(names[worker] in (resource + '::thread::enter::<' + closure + '>',
                                                resource + '::thread::enter<' + closure + '>'),
                               'host callback belongs to another session')
                placement.check(*common.resolve(worker, definitions, aliases), names, algorithm,
                                operation.startswith('compiled_'))
                if operation.startswith('compiled_'):
                    authority.check(common.resolve(worker, definitions, aliases)[1], names, compiler)
                model = keyed.check(common.resolve(worker, definitions, aliases)[1], names, compiler,
                                    identity, operation.startswith('compiled_'))
                if operation.startswith('compiled_'):
                    constructor.check(model, identity, definitions, aliases, compiler, panic, types)
                else:
                    constructor.scalar(model, identity, definitions, aliases, panic)
                checkpoints.preflight(model, common.resolve(worker, definitions, aliases)[0], target, compiler)
                storage.check(model, identity)
                if not operation.startswith('compiled_'):
                    scalar.check(model, identity, definitions, aliases, panic)
                    consumers.scalar(model, identity, definitions, aliases, panic)
                else:
                    compiled_worker.check(model, identity, definitions, aliases, compiler, panic)
                    consumers.compiled(model, identity, definitions, aliases, compiler, panic)
                output_model = output.check(model, common.resolve(worker, definitions, aliases)[0], panic)
                flow = input_flow.check(model, common.resolve(worker, definitions, aliases)[0], compiler)
                checkpoints.check(model, flow, output_model, target, compiler)
                workers.add(worker)
                checked.add(executor)
    common.require(len(checked) == len(workers) == 24, 'hosted scalar/compiled graph collapsed or incomplete')
    loan_creation.validate(definitions, aliases, names, target, compiler)
    loans.validate(definitions, aliases, names, target, compiler, panic)
    public_verify.validate(definitions, aliases, names, target, compiler)
    return definitions, aliases, names, checked


def emit_callees(directory, compiler, target, panic, fixture=FIXTURE):
    env = verifier.environment(directory)
    if target == 'aarch64-apple-darwin':
        env['MACOSX_DEPLOYMENT_TARGET'] = '11.0'
    env['CARGO_PROFILE_RELEASE_PANIC'] = panic
    env['RUSTFLAGS'] = '-C symbol-mangling-version=v0 -C target-feature=' + FEATURES[target]
    verifier.run(['cargo', '+' + compiler, 'rustc', '--manifest-path', str(fixture), '--locked', '--offline',
        '--release', '--lib', '--target', target, '-p', 'brynja-crypto-cpu-std', '--', '--emit=llvm-ir'], env)
    paths = list((directory / 'target' / target / 'release/deps').glob('brynja_crypto_cpu_std-*.ll'))
    common.require(len(paths) == 1, 'missing/ambiguous hosted checkpoint callee artifact')
    llvm = paths[0].read_text()
    artifact_profile(llvm, target, compiler)
    return llvm


def emit(directory, compiler, target, panic, fixture=FIXTURE):
    common.require(compiler in ('1.90.0', '1.99.1') and target in TARGETS
                   and panic in ('abort', 'unwind'), 'unreviewed hosted compiler profile')
    env = verifier.environment(directory)
    if target == 'aarch64-apple-darwin':
        env['MACOSX_DEPLOYMENT_TARGET'] = '11.0'
    env['CARGO_PROFILE_RELEASE_PANIC'] = panic
    # Stable v0 retains concrete generic identities on both reviewed compilers.
    env['RUSTFLAGS'] = '-C symbol-mangling-version=v0 -C target-feature=' + FEATURES[target]
    metadata = json.loads(verifier.run(['cargo', '+' + compiler, 'metadata', '--manifest-path', str(fixture),
        '--locked', '--offline', '--format-version', '1', '--filter-platform', target], env))
    graph(metadata)
    # These non-generic callees are outlined into the dependency rather than
    # the fixture. Inspect their actual emitted bodies, including aliases.
    callee_llvm = emit_callees(directory, compiler, target, panic, fixture)
    checkpoint_callees.validate(callee_llvm, target, compiler)
    buffers.validate(callee_llvm, target)
    loans.resources.validate(callee_llvm, target)
    verifier.run(['cargo', '+' + compiler, 'rustc', '--manifest-path', str(fixture), '--locked', '--offline',
        '--release', '--lib', '--target', target, '--', '--emit=mir,llvm-ir,asm'], env)
    artifacts = []
    for suffix in ('mir', 'll', 's'):
        paths = list((directory / 'target' / target / 'release/deps').glob(
            'brynja_hmac_hosted_cleanup_fixture-*.' + suffix))
        common.require(len(paths) == 1, 'missing/ambiguous hosted artifact')
        artifacts.append(paths[0].read_text())
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', action='append')
    parser.add_argument('--target', choices=TARGETS, default=TARGETS[0])
    args = parser.parse_args()
    for compiler in args.toolchain or ['1.90.0', '1.99.1']:
        for panic in ('abort', 'unwind'):
            contracts.validate()
            with verifier.cargo_environment.private_directory(ROOT) as directory:
                _, llvm, _ = emit(Path(directory), compiler, args.target, panic)
                validate(llvm, args.target, compiler, panic)
            print(f'HMAC hosted capture/admission/storage/input/output/checkpoints/transaction/cleanup-dispatch: PASS; {compiler}; {args.target}; panic={panic}; '
                  '48 host consumers, 48 loan probes, 24 executors; full hosted qualification pending', flush=True)


if __name__ == '__main__':
    main()
