"""Ordinary legacy secret output loans; no caller-copy/fatal-erasure claim.

Safe Rust exclusive borrowing and valid caller slices are premises. The pinned
resident wrapper provides a stable slice; its hypothetical recoverable unwind
edges are tested conservatively. Batch loans have a separate representation.
"""
import itertools
import re

import legacy_hmac_engine_codegen as shared

flow = shared.load('hmac_hosted_loan_flow')
resources = shared.load('hmac_hosted_loan_resources')
syntax, require = flow.syntax, shared.require
METHODS = ('output_expose', 'output_declassify', 'output_clear')


def formals(arguments, kinds):
    args = syntax.parameters(arguments)
    require(len(args) == len(kinds) and all(arg.startswith(kind + ' ') and re.search(flow.V + '$', arg)
                                          for arg, kind in zip(args, kinds)),
            'legacy loan formal types changed')
    return args, [arg.split()[-1] for arg in args]


def creation(arguments, body, names, target, compiler, identity, executor):
    require(identity in ('sha1', 'md5', 'sha1_compiled'), 'ordinary legacy loan identity changed')
    args, params = formals(arguments, ('ptr', 'ptr', 'ptr', 'ptr'))
    require('sret([16 x i8])' in args[0] and 'dereferenceable(16)' in args[0]
            and 'dereferenceable(' + ('256' if identity.endswith('compiled') else '240') + ')' in args[1]
            and 'dereferenceable(56)' in args[2], 'legacy compute Result/session/request extent')
    ok = 255 if compiler == '1.99.1' else 10
    resources_count = 14 if target == 'aarch64-apple-darwin' else 13
    cases = [(ok, 2)] + [(tag, payload) for tag in range(10)
                        for payload in {0: range(resources_count), 7: range(8)}.get(tag, (None,))]
    visited = set()
    for category, payload in cases:
        output, calls = {}, []
        encoded = category | payload << 8 if payload is not None else flow.expressions.Unknown(category, 255)
        initial = dict(zip(params, (('result', 0), ('session', 0), ('request', 0), ('cancel', 0))))

        def call(symbol, operands, value):
            require(names.get(symbol) == executor and len(operands) == 5 and not calls
                    and value(operands[0]) == ('session', 0) and value(operands[1]) == ('request', 0)
                    and value(operands[2]) is None and isinstance(value(operands[3]), flow.expressions.Unknown)
                    and value(operands[4]) == ('cancel', 0), 'legacy compute executor/arguments changed')
            calls.append('execute')
            return 'return', encoded

        def store(address, kind, value):
            require(calls and address[0] == 'result', 'legacy loan writes before execution/outside result')
            offset = address[1]
            require((offset, kind) in ((0, 'i8'), (1, 'i8'), (2, 'i8'), (1, 'i16'), (8, 'ptr')),
                    'legacy loan Result field/width changed')
            slots = (1, 2) if kind == 'i16' else (offset,)
            require(not any(slot in output for slot in slots), 'legacy loan overwrites initialized field')
            if kind == 'i16':
                number, known = flow.expressions.parts(value)
                require(type(number) is int, 'legacy error payload not integer')
                output[1] = flow.expressions.Unknown(number & 255, known & 255)
                output[2] = flow.expressions.Unknown((number >> 8) & 255, (known >> 8) & 255)
            else:
                output[offset] = value

        outcome, result, reached = flow.run(body, initial, {}, call, store)
        require(outcome == 'return' and result is None and len(calls) == 1, 'legacy compute loan exit changed')
        if category == ok:
            require(output == {0: 0, 8: ('session', 184)}, 'legacy compute returns wrong output loan')
        else:
            require(set(output) == {0, 1, 2} and output[0] == 1
                    and flow.expressions.integer(output[1], 8) == category, 'legacy failed compute admitted loan/changed error')
            if payload is not None:
                require(flow.expressions.integer(output[2], 8) == payload, 'legacy loan error payload changed')
        visited |= reached
    require(visited == set(flow.common.blocks(body)), 'unreviewed legacy loan creation path')
    return len(cases)


def method(arguments, body, names, target, compiler, panic, identity, operation):
    require(identity in ('sha1', 'md5', 'sha1_compiled') and operation in METHODS, 'unknown legacy output method')
    apple, borrowed = target == 'aarch64-apple-darwin', operation == 'output_expose'
    args, params = formals(arguments, ('ptr', 'ptr', 'i64') if operation == 'output_declassify' else ('ptr',))
    require('dereferenceable(' + ('8' if borrowed else '56') + ')' in args[0], 'legacy loan extent changed')
    clear = ('<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear' if apple
             else '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear')
    access = '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::as_bytes'
    lengths = range(10, (16 if identity == 'md5' else 20) + 1)
    cases = [(n, delta, 0) for n, delta in itertools.product(lengths, (-1, 0, 1)
             if operation == 'output_declassify' else (0,))]
    if apple and operation == 'output_declassify' and panic == 'unwind':
        cases += [(n, 0, fault) for n, fault in itertools.product(lengths, (1, 2))]
    visited = set()
    for used, delta, fault in cases:
        events, accesses = [], 0
        initial = {params[0]: ('loan', 0) if borrowed else ('storage', 0)}
        if len(params) == 3:
            initial.update({params[1]: ('public', 0), params[2]: used + delta})
        memory = {('loan', 0): ('storage', 0), **resources.fields(apple, used=used)}

        def call(symbol, operands, value):
            nonlocal accesses
            name = names.get(symbol, symbol)
            require('clear' not in events, 'legacy loan call after clearing')
            if name == access:
                require(apple and operation in ('output_expose', 'output_declassify') and len(operands) == 1
                        and value(operands[0]) == ('storage', 0), 'legacy loan slice storage changed')
                accesses += 1
                return ('unwind', None) if fault == accesses else ('return', (('bytes', 0), used))
            if name == clear:
                require(not borrowed and len(operands) == 1 and value(operands[0]) == ('storage', 0),
                        'legacy loan clears wrong storage')
                events.append('clear')
                return 'return', None
            require(symbol == 'llvm.memcpy.p0.p0.i64' and operation == 'output_declassify' and len(operands) == 4,
                    'unreviewed legacy loan call')
            require(not events and delta == 0 and not (fault and accesses >= fault)
                    and value(operands[0]) == ('public', 0) and value(operands[1]) == ('bytes', 0)
                    and value(operands[2]) == used and value(operands[3]) == 0, 'legacy loan copy provenance/width/order')
            events.append('copy')
            return 'return', None

        def load(address, kind):
            require(not events and {('loan', 0): 'ptr', **resources.field_types(apple)}.get(address) == kind,
                    'legacy loan field type or load after copy/clear')

        outcome, result, reached = flow.run(body, initial, memory, call, load=load)
        if fault:
            require(outcome == 'unwind' and accesses == fault and events == ['clear'], 'legacy loan unwind lost clearing')
        elif borrowed:
            require(outcome == 'return' and result == (('bytes', 0), used) and not events, 'legacy loan exposed wrong span')
        elif operation == 'output_clear':
            require(outcome == 'return' and result is None and events == ['clear'], 'legacy loan drop did not clear')
        else:
            ok = 255 if compiler == '1.99.1' else 10
            require(outcome == 'return' and isinstance(result, tuple) and len(result) == 2
                    and flow.expressions.integer(result[0], 8) == (ok if delta == 0 else 5)
                    and events == (['copy', 'clear'] if delta == 0 else ['clear']), 'legacy loan declassification outcome')
        visited |= reached
    return visited, len(cases)


def validate(population, target, compiler, panic):
    definitions, aliases, names = population
    count = 0
    for identity in ('sha1', 'md5', 'sha1_compiled'):
        for operation in METHODS:
            wanted = 'brynja_legacy_hmac_hosted_cleanup::' + identity + '::' + operation
            selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
            require(len(selected) == 1, 'missing/ambiguous legacy output probe: ' + wanted)
            method(*flow.common.resolve(selected[0], definitions, aliases), names, target, compiler, panic, identity, operation)
            count += 1
    require(count == 9, 'legacy ordinary output method population changed')
