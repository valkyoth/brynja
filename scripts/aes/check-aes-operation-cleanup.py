#!/usr/bin/env python3
"""Bounded AES scratch and explicit-clear dispatch; not physical erasure/timing."""
import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_engine_codegen as graph
import hmac_engine_scratch as scratch
import hmac_verifiers as verifier

ROOT = verifier.ROOT
MARKER = 'AES operation cleanup complete: 4 configurations; delegated core clearing; not whole-frame erasure or timing qualification'
ROLES = {'public': {'schedule': (176, 1), 'state': (16, 1)},
         'secret': {'schedule': (176, 1), 'state': (16, 1)},
         'expand': {'word': (4, 1)}, 'rounds': {'previous': (16, 4)},
         'cached-new': {'schedule': (176, 1)},
         'cached-public': {'state': (16, 1)}, 'cached-secret': {'state': (16, 1)}}
METHODS = {'public': ('Aes128Key', 'encrypt_block_public'),
           'secret': ('Aes128Key', 'transform'),
           'encrypt': ('Aes128Key', 'encrypt_block'),
           'decrypt': ('Aes128Key', 'decrypt_block'),
           'key-clear': ('Aes128Key', 'clear'),
           'block-clear': ('SecretBlock', 'clear'),
           'expand': ('portable', 'expand'), 'rounds': ('portable', 'transform'),
           'cached-new': ('Aes128ExpandedKey', 'new'),
           'cached-public': ('Aes128ExpandedKey', 'encrypt_block_public'),
           'cached-secret': ('Aes128ExpandedKey', 'transform'),
           'cached-encrypt': ('Aes128ExpandedKey', 'encrypt_block'),
           'cached-decrypt': ('Aes128ExpandedKey', 'decrypt_block'),
           'cached-clear': ('Aes128ExpandedKey', 'clear')}


def require(condition, message):
    if not condition:
        raise ValueError('AES operation cleanup: ' + message)


def select(llvm):
    require('target triple = "x86_64-unknown-linux-gnu"' in llvm, 'wrong target')
    definitions, aliases = graph.definitions_and_aliases(llvm)
    selected = {}
    for role, (owner, method) in METHODS.items():
        suffix = str(len(owner)) + owner + str(len(method)) + method
        names = [name for name in (*definitions, *aliases)
                 if '13brynja_crypto3aes' in name and re.search(suffix + r'(?:17h[0-9a-f]+E)?$', name)]
        require(len(names) == 1, 'missing/ambiguous production method: ' + role)
        selected[role] = (names[0], *graph.resolve(names[0], definitions, aliases))
    # Require the actual public consumers to reach the reviewed implementation.
    for caller, callees in {'encrypt': ('secret',), 'decrypt': ('secret',),
                            'secret': ('expand', 'rounds'), 'public': ('expand', 'rounds'),
                            'cached-new': ('expand',), 'cached-encrypt': ('cached-secret',),
                            'cached-decrypt': ('cached-secret',), 'cached-secret': ('rounds',),
                            'cached-public': ('rounds',)}.items():
        for callee in callees:
            require(re.search(r'\b(?:call|invoke)\b[^\n]*@' + re.escape(selected[callee][0]) + r'\(',
                              selected[caller][2]), 'missing production call edge: ' + caller + '/' + callee)
    for caller in ('cached-secret', 'cached-public'):
        require(not re.search(r'\b(?:call|invoke)\b[^\n]*@' + re.escape(selected['expand'][0]) + r'\(',
                              selected[caller][2]), 'cached operation re-expands schedule')
    return selected


def check_clear(arguments, body):
    # Deliberately only accept the observed direct, two-word forwarding body.
    # Any inlining or new control flow needs a new reviewed model, not a waiver.
    args = arguments.split(', ')
    require(len(args) == 2 and args[0].startswith('ptr ') and args[1].startswith('i64 '), 'clear ABI changed')
    pointer, length = [arg.split()[-1] for arg in args]
    blocks = graph.blocks(body)
    require(list(blocks) == ['start'] and len(blocks['start']) == 2, 'clear is not direct delegation')
    call, end = blocks['start']
    callee = (r'(?:_RNvMs\w*_NtCs\w+_11brynja_core13secret_memoryNt\w+_17OwnedSecretRegion5clear|'
              r'_ZN11brynja_core13secret_memory17OwnedSecretRegion5clear17h[0-9a-f]+E)')
    require(re.fullmatch(r'(?:tail )?call void @' + callee + r'\(ptr [^,\n]*' + re.escape(pointer)
                         + r', i64 ' + re.escape(length) + r'\)(?: #\d+)?', call), 'clear pointer/extent/callee changed')
    require(end == 'ret void', 'clear exit changed')


def owners(body, role):
    selected = {}
    for name, (size, count) in ROLES[role].items():
        matches = re.findall(r'(%' + name + r'(?:\.[-\w]+)*) = alloca \[' + str(size) + r' x i8\],', body)
        require(len(matches) == count, 'scratch population changed: ' + role + '/' + name)
        selected.update({name: size for name in matches})
    return selected


def check_body(body, role):
    selected = owners(body, role)
    # Each inlined ShiftRows copy gets its own lifetime state, including loops.
    operation = 'aes-' + role
    scratch.SCRATCH[operation] = {re.escape(name[1:]): size for name, size in selected.items()}
    if role in ('secret', 'cached-secret', 'cached-new'):
        require(len(re.findall(r'%destination = alloca \[24 x i8\],', body)) == 1,
                'output guard storage changed')
        require('%initialization' not in body, 'ambiguous output guard')
        # The shared checker models this distinct caller-output descriptor under
        # the name initialization. This is a spelling normalization only.
        body = re.sub(r'%destination\b', '%initialization', body)
    scratch.check(body, operation)


def check(llvm, panic):
    require(panic in ('abort', 'unwind'), 'unknown panic profile')
    selected = select(llvm)
    for role in ROLES:
        body = selected[role][2]
        # Expansion/round helpers may be proven nounwind even with panic=unwind.
        if role in ('public', 'secret', 'cached-public', 'cached-secret', 'cached-new'):
            require(('landingpad ' in body) == (panic == 'unwind'), 'operation panic profile changed')
        check_body(body, role)
    for role in ('key-clear', 'block-clear', 'cached-clear'):
        check_clear(*selected[role][1:])
    return selected


def negative_controls(selected):
    rejected = 0
    for role in ROLES:
        body = selected[role][2]
        for pointer, size in owners(body, role).items():
            clear = r'([^\n]*clear_owned_region[^\n]*?)' + re.escape(pointer) + r', i64(?: noundef)? ' + str(size) + r'\)'
            mutants = {
                'short extent': re.sub(clear, lambda m: m[1] + pointer + ', i64 ' + str(size - 1) + ')', body),
                'wrong pointer': re.sub(clear, lambda m: m[1] + 'null, i64 ' + str(size) + ')', body),
                'wrong callee': re.sub(clear, lambda m: m[0].replace('clear_owned_region', 'other_owned_region'), body),
                'early return': re.sub(r'([^\n]*@llvm.lifetime.start.p0\([^\n]*' + re.escape(pointer)
                                       + r'\)[^\n]*\n)', r'\1  ret void\n', body),
                'write after clear': re.sub(clear + r'[^\n]*\n', lambda m: m[0] +
                                           '  store i8 1, ptr ' + pointer + ', align 1\n', body),
            }
            for name, mutant in mutants.items():
                require(mutant != body, 'vacuous scratch mutation: ' + name)
                try:
                    check_body(mutant, role)
                except ValueError:
                    rejected += 1
                    continue
                raise ValueError('accepted scratch mutation: ' + role + '/' + pointer + '/' + name)
    for role in ('key-clear', 'block-clear', 'cached-clear'):
        _, args, body = selected[role]
        pointer, length = [arg.split()[-1] for arg in args.split(', ')]
        for mutant in (body.replace(pointer, 'null'), body.replace(length, '0'),
                       body.replace('OwnedSecretRegion', 'OtherSecretRegion'),
                       'start:\n  ret void\n', body.replace('  ret void', '  store i8 1, ptr null\n  ret void')):
            require(mutant != body, 'vacuous explicit-clear mutation')
            try:
                check_clear(args, mutant)
            except ValueError:
                rejected += 1
                continue
            raise ValueError('accepted explicit-clear mutation: ' + role)
    return rejected


def collect(directory, compiler, panic):
    env = verifier.environment(directory)
    env.update(CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_PROFILE_RELEASE_LTO='fat',
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
    verifier.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release', '--lib',
                  '-p', 'brynja-crypto', '--no-default-features', '--features', 'hazmat-aes-block', '--target', 'x86_64-unknown-linux-gnu',
                  '--', '--emit=mir,llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('mir', 'll', 's'):
        paths = list((directory / 'target/x86_64-unknown-linux-gnu/release/deps').glob('brynja_crypto-*.' + extension))
        require(len(paths) == 1, 'missing/ambiguous compiler artifact')
        artifacts[extension] = paths[0].read_text()
    selected = check(artifacts['ll'], panic)
    count = negative_controls(selected)
    require('clear_owned_region' in artifacts['s'], 'assembly core clearing absent')
    for role, (symbol, _, _) in selected.items():
        require(symbol in artifacts['s'], 'assembly method absent: ' + role)
    require('Aes128Key' in artifacts['mir'] and 'SecretBlock' in artifacts['mir'], 'MIR owner identities absent')
    print(f'AES operation cleanup: PASS; Rust {compiler}; x86_64; panic={panic}; '
          f'7 scratch bodies; 3 explicit clears; {count} rejected IR mutations', flush=True)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for compiler in ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                collect(Path(temporary), compiler, panic)
    print(MARKER)


if __name__ == '__main__':
    main()
