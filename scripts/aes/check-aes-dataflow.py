#!/usr/bin/env python3
"""Bounded AES LLVM dataflow and scalar inverse assembly review, not CT proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_engine_codegen as graph
import hmac_verifiers as verifier
sys.path.insert(0, str(Path(__file__).resolve().parent))
import aes_machine_review as machine

ROOT = verifier.ROOT
MARKER = 'AES dataflow review: 4 configurations; 11 LLVM and assembly helpers; not whole-program constant-time qualification'
VAR = r'%[-\w.]+'
SHAPES = {'substitute': ('ptr', 'i1'), 'mix': ('ptr', 'i1'),
          'expand': ('ptr', 'i64', 'ptr'), 'add_key': ('ptr', 'ptr', 'i64'),
          'transform': ('ptr', 'ptr', 'i1'), 'inverse': ('i8',)}
BASE_ROLES = set(SHAPES)
SHAPES.update({'expand192': SHAPES['expand'], 'expand256': SHAPES['expand'],
               'transform192': SHAPES['transform'], 'transform256': SHAPES['transform'],
               'wide_add_key': ('ptr', 'ptr', 'i64', 'i64')})
EDGES = {'inverse': set(), 'mix': set(), 'add_key': set(),
         'substitute': {'inverse'}, 'expand': {'inverse'},
         'transform': {'substitute', 'mix', 'add_key'},
         'expand192': {'inverse'}, 'expand256': {'inverse'}, 'wide_add_key': set(),
         'transform192': {'substitute', 'mix', 'wide_add_key'},
         'transform256': {'substitute', 'mix', 'wide_add_key'}}
CLEAR = r'(?:_RNvNt\w+_11brynja_core13secret_memory18clear_owned_region|_ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E)'


def require(condition, message):
    if not condition:
        raise ValueError('AES dataflow: ' + message)


def variables(expression):
    return set(re.findall(VAR, expression))


def select(llvm, target='x86_64-unknown-linux-gnu'):
    require(target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu')
            and re.findall(r'^target triple = "([^"]+)"$', llvm, re.M) == [target], 'wrong target')
    definitions, aliases = graph.definitions_and_aliases(llvm)
    require(not any('13brynja_crypto3aes8portable' in name for name in aliases), 'portable aliases require review')
    result = {}
    for role in sorted(BASE_ROLES):
        suffix = ('5field' if role == 'inverse' else '') + str(len(role)) + role
        names = [name for name in definitions if re.search(
            r'13brynja_crypto3aes8portable' + suffix + r'(?:17h[0-9a-f]+E)?$', name)]
        require(len(names) == 1, 'missing/ambiguous helper: ' + role)
        result[role] = (names[0], *definitions[names[0]])
    for bits, extent in ((192, 208), (256, 240)):
        # Follow each concrete public consumer, not the first generic match.
        owner = f'Aes{bits}Key'
        names = [name for name in definitions if '13brynja_crypto3aes4wide' in name
                 and re.search(str(len(owner)) + owner + r'20encrypt_block_public(?:17h[0-9a-f]+E)?$', name)]
        require(len(names) == 1, 'missing/ambiguous public wide consumer')
        calls = set(re.findall(r'\b(?:call|invoke)\b[^\n]*@(\w+)\(', definitions[names[0]][1]))
        for helper in ('expand', 'transform'):
            names = [name for name in calls if '8portable4wide' + str(len(helper)) + helper in name]
            require(len(names) == 1 and names[0] in definitions, 'missing/ambiguous wide helper')
            item = (names[0], *definitions[names[0]])
            require(re.search(r'\bdereferenceable\(' + str(extent) + r'\) %schedule(?:,|$)', item[1]),
                    'wrong wide schedule ABI')
            result[helper + str(bits)] = item
    names = [name for name in definitions if re.search(
        r'13brynja_crypto3aes8portable4wide7add_key(?:17h[0-9a-f]+E)?$', name)]
    require(len(names) == 1, 'missing/ambiguous wide add-key')
    result['wide_add_key'] = (names[0], *definitions[names[0]])
    # Do not silently accept an unreviewed additional portable helper.
    require({name for name in definitions if '13brynja_crypto3aes8portable' in name}
            == {item[0] for item in result.values()}, 'portable helper population changed')
    return result


def check_body(role, arguments, body, callees):
    """Conservative SSA taint: every load is secret, even scratch/public loads.

    Pointer addresses, lengths, direction and round number are public arguments;
    the field inverse byte is secret. Pointer *contents* are never declassified.
    All branches must be public, so secret implicit control flows are rejected.
    Public status-return summaries are checked on the callee bodies separately.
    This deliberately supports only the observed scalar LLVM subset, not LLVM
    in general. Unknown syntax/instructions/calls require a new model review.
    """
    args = re.findall(r'\b(ptr|i\d+)\b[^%]*?(' + VAR + r')(?=, |$)', arguments)
    require(tuple(kind for kind, _ in args) == SHAPES[role], 'helper ABI changed: ' + role)
    known = {name for _, name in args}
    secret = set(known) if role == 'inverse' else set()
    deps, sinks, edges = {}, [], set()
    # LLVM prints switch cases on separate lines. Fold only this exact grammar;
    # labels/case constants are not data operands, but the selector is a sink.
    body = re.sub(r'switch i64 ([^\n]+) \[\n((?:\s*i64 -?\d+, label %[-\w.]+\n)+)\s*\]',
                  lambda match: 'switch i64 ' + match[1] + ' [ ' + ' '.join(match[2].split()) + ' ]', body)
    lines = [line for block in graph.blocks(body).values() for line in block]
    require(lines, 'empty helper')
    for original in lines:
        # Debug/alias/range metadata cannot contribute executable SSA operands.
        line = re.split(r', ![\w.]+ ', original, maxsplit=1)[0]
        match = re.match(r'(' + VAR + r') = (.*)', line)
        target, expression = match.groups() if match else (None, line)
        if target:
            require(target not in known, 'duplicate SSA definition')
            known.add(target)
        op = expression.split()[0]
        uses = variables(expression)
        if op == 'phi':
            incoming = re.findall(r'\[\s*([^,]+),\s*' + VAR + r'\s*\]', expression)
            require(incoming and len(incoming) == expression.count('['), 'unmodeled phi')
            uses = variables(' '.join(incoming))
        if op in ('and', 'or', 'xor', 'add', 'shl', 'icmp', 'select', 'phi'):
            require(target is not None and '@' not in expression and '<' not in expression,
                    'unmodeled scalar operation')
            deps[target] = uses
            if op == 'shl':
                sinks.append(('shift count', variables(expression.rsplit(',', 1)[1])))
        elif op == 'alloca':
            require(target and re.fullmatch(r'alloca \[\d+ x i8\], align \d+', expression), 'unmodeled allocation')
            deps[target] = set()
        elif op == 'urem':
            # AES-192 schedule periodicity only. Do not admit secret division
            # or silently generalize the model to arbitrary divisors.
            require(target and re.fullmatch(r'urem i(?:8|64) ' + VAR + r', 24', expression),
                    'unmodeled remainder')
            deps[target] = uses
            sinks.append(('remainder operands', uses))
        elif op == 'trunc':
            require(target and re.fullmatch(r'trunc(?: nuw)? i64 ' + VAR + r' to i8', expression),
                    'unmodeled truncation')
            deps[target] = uses
        elif op == 'getelementptr':
            require(target and re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr ' + VAR
                                           + r', i64 (?:' + VAR + r'|-?\d+)', expression), 'unmodeled address')
            deps[target] = uses
            sinks.append(('address', uses))
        elif op in ('load', 'store'):
            require(re.match(r'(?:load i\d+|store i\d+ (?:' + VAR + r'|-?\d+)), ptr ' + VAR + r', align \d+$', expression),
                    'unmodeled memory access')
            pointer = re.search(r', ptr (' + VAR + ')', expression)[1]
            sinks.append(('memory address', {pointer}))
            if op == 'load':
                require(target is not None, 'load without result')
                secret.add(target)
                deps[target] = set()
            else:
                require(target is None, 'store with result')
        elif op == 'br':
            require(target is None, 'branch with result')
            branch = re.fullmatch(r'br i1 (' + VAR + r'|true|false), label ' + VAR + r', label ' + VAR, expression)
            require(branch or re.fullmatch(r'br label ' + VAR, expression), 'unmodeled branch')
            uses = variables(branch[1]) if branch else set()
            sinks.append(('branch', uses))
        elif op == 'switch':
            switch = re.fullmatch(r'switch i64 (' + VAR + r'), label ' + VAR
                                  + r' \[ ((?:i64 -?\d+, label ' + VAR + r'\s*)+)\]', expression)
            require(target is None and switch is not None, 'unmodeled switch')
            cases = re.findall(r'i64 (-?\d+),', switch[2])
            require(len(cases) == len(set(cases)), 'duplicate switch case')
            uses = {switch[1]}
            sinks.append(('switch selector', uses))
        elif op == 'ret':
            require(target is None and re.fullmatch(r'ret (?:void|i(?:1|8) (?:' + VAR + r'|true|false|\d+))', expression),
                    'unmodeled return')
            if role != 'inverse':
                sinks.append(('status return', uses))
        elif op in ('call', 'tail'):
            call = re.fullmatch(r'(?:tail )?call [^@\n]*@([-\w.]+)\((.*)\)(?: #\d+)?', expression)
            require(call is not None, 'indirect/unknown call syntax: ' + expression)
            name, operands = call.groups()
            uses = variables(operands)
            if name in callees:
                callee = callees[name]
                edges.add(callee)
                if callee == 'inverse':
                    require(target is not None, 'missing inverse result')
                    secret.add(target)
                else:
                    sinks.append(('helper arguments', uses))
                if target:
                    deps[target] = set()
            elif name == 'llvm.fshl.i8':
                require(target is not None, 'missing rotate result')
                deps[target] = uses
                sinks.append(('rotate count', variables(operands.rsplit(',', 1)[1])))
            elif name == 'llvm.usub.sat.i64':
                # AArch64 wide_add_key lowers its remaining public slice length
                # to max(length - round_offset, 0). Admit only this exact scalar
                # operation with public operands, never secret saturation.
                require(role == 'wide_add_key' and target is not None
                        and re.fullmatch(r'(?:tail )?call i64 @llvm\.usub\.sat\.i64\(i64 '
                                         + VAR + r', i64 ' + VAR + r'\)(?: #\d+)?', expression),
                        'unmodeled saturating subtraction')
                deps[target] = uses
                sinks.append(('saturating length operands', uses))
            elif (name in ('llvm.memcpy.p0.p0.i64', 'llvm.memmove.p0.p0.i64',
                           'llvm.lifetime.start.p0', 'llvm.lifetime.end.p0',
                           'llvm.experimental.noalias.scope.decl') or re.fullmatch(CLEAR, name)):
                sinks.append(('intrinsic/clear arguments', uses))
                if target:
                    # Clearing status is outside this model; never let it steer
                    # a branch or address. These inspected helpers ignore it.
                    secret.add(target)
                    deps[target] = set()
            else:
                raise ValueError('AES dataflow: unmodeled call: ' + name)
        else:
            raise ValueError('AES dataflow: unmodeled instruction: ' + op)
        # Predecessor/block names were removed for phi/br above.
        sinks.append(('defined operands', uses))
    for label, uses in sinks:
        require(uses <= known, 'undefined SSA operand in ' + label)
    # Fixed point handles public induction cycles and loop-carried secret bytes.
    while True:
        grown = secret | {name for name, uses in deps.items() if uses & secret}
        if grown == secret:
            break
        secret = grown
    for label, uses in sinks:
        if label != 'defined operands':
            require(not uses & secret, 'secret-dependent ' + label + ': ' + role)
    return edges


def check_ir(llvm, target='x86_64-unknown-linux-gnu'):
    selected = select(llvm, target)
    callees = {item[0]: role for role, item in selected.items()}
    edges = {role: check_body(role, args, body, callees) for role, (_, args, body) in selected.items()}
    require(edges == EDGES, 'portable call graph changed')
    return selected


def check_inverse_assembly(assembly, symbol):
    found = re.findall(r'^' + re.escape(symbol) + r':\n(.*?)^\s*\.size\s+' + re.escape(symbol) + r',',
                       assembly, re.M | re.S)
    require(len(found) == 1, 'missing/ambiguous inverse assembly')
    instructions = []
    allowed = {'addb', 'addl', 'addq', 'andb', 'cmovnsl', 'leal', 'movb', 'movl', 'movq',
               'movzbl', 'negb', 'popq', 'pushq', 'retq', 'sarb', 'shlb', 'subq', 'testb', 'xorb', 'xorl'}
    for line in found[0].splitlines():
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith('.cfi_') or re.fullmatch(r'\.L[-\w.]+:', line):
            continue
        opcode, *rest = line.split(None, 1)
        require(opcode in allowed, 'unreviewed inverse machine opcode: ' + opcode)
        operands = re.split(r',\s*(?![^()]*\))', rest[0]) if rest else []
        require(len(operands) == (0 if opcode == 'retq' else 1 if opcode in ('pushq', 'popq', 'negb') else 2),
                'machine operand count changed')
        for index, operand in enumerate(operands):
            if opcode == 'leal' and index == 0:
                require(re.fullmatch(r'\((?:%\w+)?,%\w+(?:,[1248])?\)', operand), 'unmodeled LEA arithmetic')
            else:
                require(re.fullmatch(r'(?:%\w+|\$-?\d+|-?\d*\(%rsp\))', operand), 'non-fixed-stack memory access')
        if operands:
            require(not re.fullmatch(r'%(?:rsp|esp|sp|spl)', operands[-1])
                    or (opcode in ('addq', 'subq') and operands[-1] == '%rsp'
                        and re.fullmatch(r'\$\d+', operands[0])), 'nonconstant stack pointer write')
            if opcode in ('shlb', 'sarb'):
                require(operands[0].startswith('$'), 'variable machine shift')
            if opcode in ('pushq', 'popq'):
                require(re.fullmatch(r'%(?:rbp|rbx|r1[2-5])', operands[0]), 'unmodeled stack operation')
        instructions.append(opcode)
    require(len(instructions) > 100 and instructions.count('retq') == 1 and instructions[-1] == 'retq',
            'inverse machine body truncated/changed')
    return len(instructions)


def collect(directory, compiler, panic):
    env = verifier.environment(directory)
    env.update(CARGO_PROFILE_RELEASE_PANIC=panic, CARGO_PROFILE_RELEASE_LTO='fat',
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', RUSTUP_AUTO_INSTALL='0')
    verifier.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release', '--lib',
                  '-p', 'brynja-crypto', '--no-default-features', '--features', 'hazmat-aes-block', '--target', 'x86_64-unknown-linux-gnu',
                  '--', '--emit=llvm-ir,asm'], env)
    artifacts = {}
    for extension in ('ll', 's'):
        paths = list((directory / 'target/x86_64-unknown-linux-gnu/release/deps').glob('brynja_crypto-*.' + extension))
        require(len(paths) == 1, 'missing/ambiguous compiler artifact')
        artifacts[extension] = paths[0].read_text()
        print(f'AES dataflow artifact: {compiler} {panic} {extension} sha256={hashlib.sha256(paths[0].read_bytes()).hexdigest()}')
    selected = check_ir(artifacts['ll'])
    count = check_inverse_assembly(artifacts['s'], selected['inverse'][0])
    machine.check(artifacts['s'], selected, compiler, panic, json.loads(machine.POLICY.read_text()))
    print(f'AES machine review: PASS; Rust {compiler}; panic={panic}; 11 reviewed instruction streams')
    print(f'AES dataflow: PASS; Rust {compiler}; panic={panic}; 11 helpers; {count} inverse machine instructions')


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for compiler in ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                collect(Path(temporary), compiler, panic)
    print(MARKER)


if __name__ == '__main__':
    main()
