"""Public batch loan views, consumption and moves in actual emitted code.

Safe exclusive Rust loans, valid caller destinations and the source-bound
mapping/copy callees are premises. No fatal-abort or caller-copy erasure claim.
All activity masks and admitted widths are exercised; malformed widths/storage
are additional bounds diagnostics, not states admitted by public constructors.
"""
import itertools
import re
from functools import lru_cache

import legacy_hmac_hosted_loans as loans
import legacy_hmac_hosted_batch_flow as flow
import legacy_hmac_hosted_md5_tag_copy as copy

require, syntax = loans.require, flow.syntax
ACCESS = '<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::as_bytes'


def clear_name(apple):
    return ('<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear' if apple else
            '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear')


def expose(arguments, body, names, target):
    return _expose(arguments, body, tuple(sorted(names.items())), target)


@lru_cache(maxsize=16)
def _expose(arguments, body, symbol_names, target):
    # Other mutation tests repeatedly inspect this same projection. Bind all
    # arguments, body bytes, resolved symbols and platform; never cache failures.
    # Source/callee premises still run at each outer validation entry.
    names = dict(symbol_names)
    args, params = loans.formals(arguments, ('ptr', 'i64'))
    require('dereferenceable(24)' in args[0], 'batch view loan extent changed')
    apple = target == 'aarch64-apple-darwin'
    cases = [(mask, lane, width, 128) for mask, lane, width in
             itertools.product(range(256), (*range(9), 15, 2**64 - 1), range(10, 17))]
    cases += [(255, lane, width, used) for lane, width, used in
              itertools.product(range(8), (0, 17, 2**64 - 1), (0, 127, 128))]
    # Fast witnesses precede the exhaustive domain so broken artifacts reject
    # promptly without reducing the successful check's population.
    cases = [(255, 7, 16, 128), (0, 0, 10, 128), (255, 8, 10, 128),
             (255, 7, 2**64 - 1, 128), (255, 7, 16, 127)] + cases
    visited = set()
    for mask, lane, width, used in cases:
        selected = lane < 8 and bool(mask & (1 << lane))
        present = selected and lane * 16 + width <= min(used, 2**64 - 1)
        memory = {('loan', i): (mask >> i) & 1 for i in range(8)}
        memory.update({('loan', 8): ('storage', 0), ('loan', 16): width,
                       **loans.resources.fields(apple, used=used)})
        types = {('loan', i): 'i8' for i in range(8)}
        types.update({('loan', 8): 'ptr', ('loan', 16): 'i64', **loans.resources.field_types(apple)})
        accesses = []

        def call(symbol, operands, value):
            require(apple and selected and names.get(symbol) == ACCESS and not accesses and len(operands) == 1
                    and value(operands[0]) == ('storage', 0), 'batch view uses unreviewed/wrong storage call')
            accesses.append('access')
            return 'return', (('bytes', 0), used)

        def load(address, kind):
            require(types.get(address) == kind, 'batch view field type changed')
            require(address == ('loan', lane) if address[0] == 'loan' and address[1] < 8 else selected,
                    'batch view reads another lane or inactive storage')

        outcome, result, reached = flow.run(body, {params[0]: ('loan', 0), params[1]: lane}, memory, call, load=load)
        require(outcome == 'return' and isinstance(result, tuple) and len(result) == 2,
                'batch view return shape changed')
        require(result == (('bytes', lane * 16), width) if present else result[0] is None,
                'batch view exposed wrong lane/span or admitted invalid lane')
        visited |= reached
    require(visited == set(flow.common.blocks(body)), 'batch view has unreviewed paths')
    return frozenset(visited), len(cases)


def consume(arguments, body, names, target, compiler, panic, drop=False):
    args, params = loans.formals(arguments, ('ptr',) if drop else ('ptr', 'ptr'))
    require('dereferenceable(24)' in args[0] and (drop or 'dereferenceable(128)' in args[1]),
            'batch consumption extent changed')
    apple = target == 'aarch64-apple-darwin'
    copy_ok, ok = (255, 255) if compiler == '1.99.1' else (4, 10)
    cases = [(copy_ok, None)] if drop else [(result, None) for result in (copy_ok, 0, 1, 2, 3)]
    if not drop and panic == 'unwind':
        cases += [(copy_ok, failure) for failure in (('access', 'copy') if apple else ('copy',))]
    visited = set()
    for status, failure in cases:
        events = []
        initial = {params[0]: ('loan', 0)}
        if not drop:
            initial[params[1]] = ('public', 0)
        memory = {('loan', 8): ('storage', 0), **loans.resources.fields(apple, used=128)}

        def call(symbol, operands, value):
            name = names.get(symbol, symbol)
            require('clear' not in events, 'batch loan call after clearing')
            if name == ACCESS:
                require(apple and not drop and not events and len(operands) == 1
                        and value(operands[0]) == ('storage', 0), 'batch loan accesses wrong owner')
                events.append('access')
                return ('unwind', None) if failure == 'access' else ('return', (('bytes', 0), 128))
            if name == clear_name(apple):
                require(len(operands) == 1 and value(operands[0]) == ('storage', 0), 'batch loan clears wrong owner')
                events.append('clear')
                return 'return', None
            require(not drop and name == copy.COPY and events == (['access'] if apple else [])
                    and len(operands) == 4 and [value(arg) for arg in operands]
                    == [('public', 0), 128, ('bytes', 0), 128], 'batch declassification copy provenance/extent/order')
            events.append('copy')
            return ('unwind', None) if failure == 'copy' else ('return', status)

        def load(address, kind):
            require(not events and {('loan', 8): 'ptr', **loans.resources.field_types(apple)}.get(address) == kind,
                    'batch loan field type or read after consumption')

        outcome, result, reached = flow.run(body, initial, memory, call, load=load)
        expected = ([] if drop else (['access'] if apple else []) + ([] if failure == 'access' else ['copy'])) + ['clear']
        require(events == expected, 'batch loan must clear exactly once after copying/error')
        if failure:
            require(outcome == 'unwind', 'batch loan recovers from copy/access unwind')
        elif drop:
            require(outcome == 'return' and result is None, 'batch Drop return changed')
        else:
            require(outcome == 'return' and isinstance(result, tuple) and len(result) == 2
                    and flow.expressions.integer(result[0], 8) == (ok if status == copy_ok else 8),
                    'batch declassification result changed')
        visited |= reached
    # Clearing is source-bound as nonthrowing; double-panic fatal cleanup is
    # deliberately outside this normal-return/recoverable-unwind claim.
    graph = flow.common.blocks(body)
    for label in set(graph) - visited:
        lines = graph[label]
        call = syntax.call(lines[2]) if len(lines) == 4 else None
        require(len(lines) == 4 and re.fullmatch(flow.V + r' = landingpad \{ ptr, i32 \}', lines[0])
                and lines[1] == 'filter [0 x ptr] zeroinitializer' and call and call[1] == ['']
                and names.get(call[0]) == 'core::panicking::panic_in_cleanup' and lines[3] == 'unreachable',
                'batch consumption has unreviewed path outside nonthrowing-clear premise: ' + repr(lines)
                + ' callee=' + str(names.get(call[0]) if call else None))
    return visited, len(cases)


def selected(population, wanted):
    definitions, aliases, names = population
    symbols = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
    require(len(symbols) == 1, 'batch loan probe/callee missing or ambiguous: ' + wanted)
    return flow.common.resolve(symbols[0], definitions, aliases)


def forward(arguments, body, names, wanted, operation):
    kinds = ('ptr', 'i64') if operation == 'expose' else ('ptr', 'ptr')
    args, params = loans.formals(arguments, kinds)
    require('dereferenceable(24)' in args[0], 'batch loan forwarding extent changed')
    calls = []
    # Symbolic lane: a forwarding wrapper cannot replace it with a constant.
    sentinels = [('loan', 0), ('lane-value', 0) if operation == 'expose' else ('public', 0)]
    returned = (('bytes', 80), 13) if operation == 'expose' else (8, flow.expressions.Unknown())

    def call(symbol, operands, value):
        require(not calls and names.get(symbol) == wanted and len(operands) == 2
                and [value(arg) for arg in operands] == sentinels, 'batch output forwarding lost provenance')
        calls.append(symbol)
        return 'return', returned

    outcome, result, visited = flow.run(body, dict(zip(params, sentinels)), {}, call)
    require(outcome == 'return' and result == returned and len(calls) == 1
            and visited == set(flow.common.blocks(body)), 'batch output forwarding changed result/paths')


def moved_drop(arguments, body, names, wanted):
    args, params = loans.formals(arguments, ('ptr',))
    require('dereferenceable(24)' in args[0], 'batch drop move extent changed')
    graph = flow.common.blocks(body)
    require(len(graph) == 1, 'batch drop move control flow changed')
    lines = next(iter(graph.values()))
    require(len(lines) == 6, 'batch drop move instruction population changed')
    allocation = re.fullmatch('(' + flow.V + r') = alloca \[24 x i8\], align 8', lines[0])
    require(allocation, 'batch drop local owner extent changed')
    local = allocation[1]
    for index, intrinsic in ((1, 'start'), (4, 'end')):
        call = syntax.call(lines[index])
        require(call and call[0] == 'llvm.lifetime.' + intrinsic + '.p0'
                and [arg.split()[-1] for arg in call[1]] in ([local], ['24', local]), 'batch drop move lifetime changed')
    call = syntax.call(lines[2])
    require(call and call[0] == 'llvm.memcpy.p0.p0.i64'
            and len(call[1]) == 4 and call[1][2:] == ['i64 24', 'i1 false']
            and [arg.split()[-1] for arg in call[1]] == [local, params[0], '24', 'false'],
            'batch drop must move whole original owner')
    call = syntax.call(lines[3])
    require(call and names.get(call[0]) == wanted and len(call[1]) == 1
            and syntax.operand(call[1][0]) == local and lines[5] == 'ret void', 'batch drop move omits/misroutes destruction')


def validate(fixture, leaf, target, compiler, panic):
    owner = 'macos_resident' if target == 'aarch64-apple-darwin' else 'strict_execution'
    base = 'brynja_legacy_hmac_std::' + owner + '::md5_compiled::types::Md5BatchOutput'
    drop_name = '<' + base + ' as core::ops::drop::Drop>::drop'
    rows = []
    probes = {operation: selected(fixture, 'brynja_legacy_hmac_hosted_cleanup::md5_compiled::output_' + operation)
              for operation in ('expose', 'declassify', 'clear')}
    for operation, (args, body) in probes.items():
        if operation == 'clear':
            moved_drop(args, body, fixture[2], drop_name)
            args, body = selected(leaf, drop_name)
            population = leaf
        else:
            wanted = '<' + base + '>::' + operation
            outlined = any(names == wanted for symbol, names in fixture[2].items() if '@' + symbol in body)
            if outlined:
                forward(args, body, fixture[2], wanted, operation)
                args, body = selected(leaf, wanted)
                population = leaf
            else:
                population = fixture
        checker = (lambda text: expose(args, text, population[2], target)) if operation == 'expose' else (
            lambda text: consume(args, text, population[2], target, compiler, panic, operation == 'clear'))
        reached, count = checker(body)
        rows.append((operation, args, body, population[2], reached, count))
    return rows
