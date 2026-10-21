"""Concrete public Output methods: borrowed span, explicit copy and consuming clear.

Resource access/clearing helpers are checked separately from their actual
dependency emissions. Safe Rust exclusive loans and caller-buffer validity
remain premises; no caller-copy or fatal-path erasure is claimed.
"""
import itertools
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_loan_flow as flow
import hmac_hosted_loan_resources as resources

require = common.require
METHODS = ('output_bits', 'output_expose', 'output_declassify', 'output_clear')


def formals(arguments, expected):
    actual = syntax.parameters(arguments)
    require(len(actual) == len(expected) and all(re.fullmatch(kind + r' [^%]*' + re.escape(name), arg)
            for arg, (kind, name) in zip(actual, expected)), 'loan formal binding changed')


def check(arguments, body, names, target, compiler, panic, method):
    require(method in METHODS and compiler in ('1.90.0', '1.99.1') and panic in ('abort', 'unwind'),
            'unknown loan profile')
    apple = target == 'aarch64-apple-darwin'
    clear, access = resources.names_for(target)
    borrowed = method in ('output_bits', 'output_expose')
    expected = [('ptr', '%output')] if borrowed else [('ptr', '%output.0'), ('i64', '%output.1')]
    if method == 'output_declassify':
        expected += [('ptr', '%destination.0'), ('i64', '%destination.1')]
    formals(arguments, expected)
    require('dereferenceable(' + ('16' if borrowed else '56') + ')' in syntax.parameters(arguments)[0],
            'loan storage/borrow extent changed')
    cases = list(itertools.product((17, 31, 64), (-1, 0, 1))) if method == 'output_declassify' else [(17, 0), (63, 0)]
    cases = [(length, delta, 0) for length, delta in cases]
    if apple and method == 'output_declassify' and panic == 'unwind':
        cases += [(17, 0, 1), (17, 0, 2)]
    visited = set()
    for used, delta, fault in cases:
        events, accesses = [], 0
        bits = 'selected-bits'  # Opaque: a fixed numeric substitute cannot pass.
        initial = {'%output': ('loan', 0), '%output.0': ('storage', 0), '%output.1': bits,
                   '%destination.0': ('public', 0), '%destination.1': used + delta}
        memory = {**resources.fields(apple, used=used), ('loan', 0): ('storage', 0), ('loan', 8): bits}

        def call(symbol, args, value):
            nonlocal accesses
            name = names.get(symbol, symbol)
            require('clear' not in events, 'loan call after clearing')
            if name == access:
                require(apple and method in ('output_expose', 'output_declassify') and len(args) == 1
                        and value(args[0]) == ('storage', 0), 'loan access storage changed')
                accesses += 1
                return ('unwind', None) if fault == accesses else ('return', (('bytes', 0), used))
            if name == clear:
                require(method in ('output_clear', 'output_declassify') and len(args) == 1
                        and value(args[0]) == ('storage', 0), 'loan clear storage changed')
                events.append('clear')
                return 'return', None
            require(symbol == 'llvm.memcpy.p0.p0.i64' and method == 'output_declassify' and len(args) == 4,
                    'unknown loan callee')
            require(not events and delta == 0 and not (fault and accesses >= fault)
                    and value(args[0]) == ('public', 0) and value(args[1]) == ('bytes', 0)
                    and value(args[2]) == used and value(args[3]) == 0,
                    'loan declassification pointer/extent/order changed')
            events.append('copy')
            return 'return', None

        def load(address, kind):
            require(not events, 'loan load after output copy/clear')
            types = {**resources.field_types(apple), ('loan', 0): 'ptr', ('loan', 8): 'i64'}
            require(types.get(address) == kind, 'loan field type changed')

        outcome, result, reached = flow.run(body, initial, memory, call, load=load)
        if fault:
            require(accesses == fault and outcome == 'unwind' and events == ['clear'],
                    'loan conservative unwind cleanup changed')
        elif method == 'output_bits':
            require(outcome == 'return' and result == bits and not events, 'loan width field changed')
        elif method == 'output_expose':
            require(outcome == 'return' and result == (('bytes', 0), used) and not events,
                    'loan exposed storage/span changed')
        elif method == 'output_clear':
            require(outcome == 'return' and result is None and events == ['clear'], 'loan drop lost clear')
        else:
            require(outcome == 'return' and isinstance(result, tuple) and len(result) == 2,
                    'loan declassification Result shape changed')
            ok = 255 if compiler == '1.99.1' else 11
            require(flow.expressions.integer(result[0], 8) == (ok if delta == 0 else 5)
                    and events == (['copy', 'clear'] if delta == 0 else ['clear']),
                    'loan declassification Result/cleanup changed')
        visited |= reached
    return visited


def validate(definitions, aliases, names, target, compiler, panic):
    count = 0
    for identity in common.IDENTITIES:
        for method in METHODS:
            expected = 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method
            selected = [symbol for symbol in (*definitions, *aliases) if names[symbol] == expected]
            require(len(selected) == 1, 'missing/ambiguous public loan probe: ' + expected)
            check(*common.resolve(selected[0], definitions, aliases), names, target, compiler, panic, method)
            count += 1
    require(count == 48, 'public loan population changed')
