#!/usr/bin/env python3
"""Bounded wide AES scratch dispatch; not output correctness or frame erasure."""
import argparse
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('aes_operation', Path(__file__).with_name('check-aes-operation-cleanup.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
graph, scratch, verifier = base.graph, base.scratch, base.verifier
require = base.require
MARKER = 'AES wide operation cleanup complete: 4 configurations; delegated core clearing; not whole-frame erasure or timing qualification'
WIDTHS = {192: 208, 256: 240}
METHODS = {'public': ('Key', 'encrypt_block_public'), 'secret': ('Key', 'transform'),
           'encrypt': ('Key', 'encrypt_block'), 'decrypt': ('Key', 'decrypt_block'),
           'key-clear': ('Key', 'clear'), 'cached-new': ('ExpandedKey', 'new'),
           'cached-public': ('ExpandedKey', 'encrypt_block_public'),
           'cached-encrypt': ('ExpandedKey', 'encrypt_block'),
           'cached-decrypt': ('ExpandedKey', 'decrypt_block'),
           'cached-clear': ('ExpandedKey', 'clear')}


def roles(bits):
    size = WIDTHS[bits]
    return {'public': {'schedule': (size, 1), 'state': (16, 1)},
            'secret': {'schedule': (size, 1)}, 'shared-secret': {'state': (16, 1)},
            'expand': {'word': (4, 1)}, 'rounds': {'previous': (16, 4)},
            'cached-new': {'schedule': (size, 1)}, 'cached-public': {'state': (16, 1)}}


def calls(body):
    return re.findall(r'\b(?:call|invoke)\b[^\n]*@(\w+)\(', body)


def select(llvm, bits):
    require('target triple = "x86_64-unknown-linux-gnu"' in llvm, 'wrong target')
    definitions, aliases = graph.definitions_and_aliases(llvm)
    selected = {}
    for role, (kind, method) in METHODS.items():
        owner = f'Aes{bits}{kind}'
        suffix = str(len(owner)) + owner + str(len(method)) + method
        names = [n for n in (*definitions, *aliases) if '13brynja_crypto3aes4wide' in n
                 and re.search(suffix + r'(?:17h[0-9a-f]+E)?$', n)]
        require(len(names) == 1, 'missing/ambiguous wide method: ' + role)
        selected[role] = (names[0], *graph.resolve(names[0], definitions, aliases))
    # Resolve monomorphizations from actual public consumers, never from a
    # first-matching generic symbol. Require the concrete schedule ABI too.
    for role, caller, path in (('expand', 'public', '8portable4wide6expand'),
                               ('rounds', 'public', '8portable4wide9transform'),
                               ('shared-secret', 'secret', '3aes4wide6secret')):
        names = [n for n in set(calls(selected[caller][2])) if path in n]
        require(len(names) == 1, 'missing/ambiguous wide helper: ' + role)
        selected[role] = (names[0], *graph.resolve(names[0], definitions, aliases))
        require(re.search(r'\bdereferenceable\(' + str(WIDTHS[bits]) + r'\) %schedule\b',
                          selected[role][1]), 'wrong monomorphized schedule ABI: ' + role)
    edges = {'encrypt': ('secret',), 'decrypt': ('secret',),
             'public': ('expand', 'rounds'), 'secret': ('expand', 'shared-secret'),
             'shared-secret': ('rounds',), 'cached-new': ('expand',),
             'cached-public': ('rounds',), 'cached-encrypt': ('shared-secret',),
             'cached-decrypt': ('shared-secret',)}
    for caller, callees in edges.items():
        for callee in callees:
            require(selected[callee][0] in calls(selected[caller][2]),
                    'missing wide call edge: ' + caller + '/' + callee)
    for role in ('cached-public', 'cached-encrypt', 'cached-decrypt', 'shared-secret'):
        require(not any('4wide6expand' in n for n in calls(selected[role][2])),
                'cached operation re-expands schedule')
    return selected


def owners(body, bits, role):
    selected = {}
    for name, (size, count) in roles(bits)[role].items():
        matches = re.findall(r'(%' + name + r'(?:\.[-\w]+)*) = alloca \[' + str(size) + r' x i8\],', body)
        require(len(matches) == count, 'wide scratch population changed: ' + role + '/' + name)
        selected.update({pointer: size for pointer in matches})
    return selected


def check_body(arguments, body, bits, role):
    selected = owners(body, bits, role)
    operation = f'aes{bits}-{role}'
    scratch.SCRATCH[operation] = {re.escape(name[1:]): size for name, size in selected.items()}
    argument_guards = ()
    if role in ('secret', 'cached-new', 'shared-secret'):
        require('%initialization' not in body, 'ambiguous wide output guard')
        if role == 'shared-secret':
            # Safe Rust + noalias caller argument keeps this output descriptor
            # disjoint from the local state allocation. This exemption is only
            # for its exact typed Drop, not writes or arbitrary external calls.
            require(re.search(r'(?:^|, )ptr (?=[^%]*\bnoalias\b)[^%]*dereferenceable\(24\) %destination(?:,|$)', arguments),
                    'outlined output descriptor ABI changed')
            require(not re.search(r'%destination\s*=', body), 'outlined output argument redefined')
            argument_guards = ('%initialization',)
        else:
            require(len(re.findall(r'%destination = alloca \[24 x i8\],', body)) == 1,
                    'wide output guard storage changed')
        body = re.sub(r'%destination\b', '%initialization', body)
    scratch.check(body, operation, argument_guards=argument_guards)


def check(llvm, panic):
    require(panic in ('abort', 'unwind'), 'unknown panic profile')
    result = {}
    for bits in WIDTHS:
        selected = select(llvm, bits)
        for role in roles(bits):
            _, arguments, body = selected[role]
            if role in ('public', 'secret', 'shared-secret', 'cached-new', 'cached-public'):
                require(('landingpad ' in body) == (panic == 'unwind'), 'wide panic profile changed')
            check_body(arguments, body, bits, role)
        for role in ('key-clear', 'cached-clear'):
            base.check_clear(*selected[role][1:])
        result[bits] = selected
    return result


def negative_controls(selected):
    rejected = 0
    for bits, methods in selected.items():
        for role in roles(bits):
            _, arguments, body = methods[role]
            for pointer, size in owners(body, bits, role).items():
                clear = r'([^\n]*clear_owned_region[^\n]*?)' + re.escape(pointer) + r', i64(?: noundef)? ' + str(size) + r'\)'
                mutants = [
                    re.sub(clear, lambda m: m[1] + pointer + ', i64 ' + str(size - 1) + ')', body),
                    re.sub(clear, lambda m: m[1] + 'null, i64 ' + str(size) + ')', body),
                    re.sub(clear, lambda m: m[0].replace('clear_owned_region', 'other_owned_region'), body),
                    re.sub(r'([^\n]*@llvm.lifetime.start.p0\([^\n]*' + re.escape(pointer) + r'\)[^\n]*\n)',
                           r'\1  ret void\n', body),
                    re.sub(clear + r'[^\n]*\n', lambda m: m[0] + '  store i8 1, ptr ' + pointer + ', align 1\n', body),
                ]
                for mutant in mutants:
                    require(mutant != body, 'vacuous wide scratch mutation')
                    try:
                        check_body(arguments, mutant, bits, role)
                    except ValueError:
                        rejected += 1
                        continue
                    raise ValueError('accepted wide scratch mutation: ' + role + '/' + pointer)
        for role in ('key-clear', 'cached-clear'):
            _, arguments, body = methods[role]
            pointer, length = [arg.split()[-1] for arg in arguments.split(', ')]
            for mutant in (body.replace(pointer, 'null'), body.replace(length, '0'),
                           body.replace('OwnedSecretRegion', 'OtherSecretRegion'),
                           'start:\n  ret void\n', body.replace('  ret void', '  store i8 1, ptr null\n  ret void')):
                require(mutant != body, 'vacuous wide explicit-clear mutation')
                try:
                    base.check_clear(arguments, mutant)
                except ValueError:
                    rejected += 1
                    continue
                raise ValueError('accepted wide explicit-clear mutation')
    return rejected


def collect(directory, compiler, panic):
    env = verifier.environment(directory)
    env.update(CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_PROFILE_RELEASE_LTO='fat',
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
    verifier.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release', '--lib',
                  '-p', 'brynja-crypto', '--no-default-features', '--features', 'hazmat-aes-block',
                  '--target', 'x86_64-unknown-linux-gnu', '--', '--emit=mir,llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('mir', 'll', 's'):
        paths = list((directory / 'target/x86_64-unknown-linux-gnu/release/deps').glob('brynja_crypto-*.' + extension))
        require(len(paths) == 1, 'missing/ambiguous wide compiler artifact')
        artifacts[extension] = paths[0].read_text()
    selected = check(artifacts['ll'], panic)
    count = negative_controls(selected)
    require(count == 130, 'wide mutation population changed')
    require('clear_owned_region' in artifacts['s'], 'wide assembly clearing absent')
    for bits, methods in selected.items():
        for symbol, _, _ in methods.values():
            require(symbol in artifacts['s'], 'wide assembly method absent')
        for kind in ('Key', 'ExpandedKey'):
            require(f'Aes{bits}{kind}' in artifacts['mir'], 'wide MIR owner absent')
    print(f'AES wide operation cleanup: PASS; Rust {compiler}; x86_64; panic={panic}; '
          f'14 scratch bodies; 4 explicit clears; {count} rejected IR mutations', flush=True)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for compiler in ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with verifier.cargo_environment.private_directory(verifier.ROOT) as temporary:
                collect(Path(temporary), compiler, panic)
    print(MARKER)


if __name__ == '__main__':
    main()
