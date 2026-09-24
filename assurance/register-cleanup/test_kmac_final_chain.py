#!/usr/bin/env python3
"""Regressions for same-row constructor/reader/final-tail composition."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_final_chain as check
from test_kmac_verify_comparisons import rejects


def selected(case):
    definitions = check.comparison.definitions(case.sha3)
    finals = check.adapter.final_symbols(case.sha3)
    construct = check.rejection.forwarding.constructor(case.sha3)
    trace = check.rejection.forwarding.inspect(case.caller, finals, construct)
    label, index, *_ = trace.adapter_details
    name, _ = check.adapter.routes.guard.call(trace.graph[label][index])
    public = check.resolve(case.sha3, definitions, name, 'void (ptr, ptr, i1, ptr)')
    wipes = {name for name in check.adapter.routes.early.state_symbols(case.sha3)
             if 'HardenedFips202Owner' in name and '4wipe' in name}
    _, _, borrowed = check.reader.inspect(public, definitions, wipes)
    squeeze = [name for name in definitions if '@' + name + '(' in definitions[borrowed]
               and ('14squeeze_secret' in name or '25squeeze_final_bits_secret' in name)]
    assert len(squeeze) == 2
    fill = [name for name in definitions if '12fill_staging' in name
            and any('@' + name + '(' in definitions[caller] for caller in squeeze)]
    assert len(fill) == 1
    owner = check.resolve(case.sha3, definitions, sorted(wipes)[0], 'void (ptr)')
    yield 'sha3', definitions[construct]
    yield 'sha3', public
    yield 'sha3', check.resolve(case.sha3, definitions, case.bulk, 'void (ptr, ptr, ptr, i64)')
    yield 'sha3', definitions[borrowed]
    for name in (*squeeze, *fill):
        yield 'sha3', definitions[name]
    yield 'sha3', owner
    for token in ('26SecretRegionInitialization5begin', 'SecretRegionInitialization5write',
                  'SecretRegionInitialization6finish', '18copy_secret_region', '22apply_secret_byte_mask'):
        bodies = [body for name, body in check.comparison.definitions(case.core).items() if token in name]
        assert len(bodies) == 1, token
        yield 'core', bodies[0]
    yield 'core', check.dropping.select(case.core)[1]


def mutations(case):
    # Keep each dependency's symbol/ABI and every caller unchanged. A call-name
    # allowlist alone would accept these; the actual dependency checks must not.
    for field, body in selected(case):
        changed = body.replace('start:\n', 'start:\n  call void @unreviewed_effect()\n', 1)
        assert changed != body
        yield 'same-symbol altered ' + check.symbol(body), replace(case, **{field: getattr(case, field).replace(body, changed, 1)})
    for token in ('25squeeze_final_bits_secret', 'Fips202Output3new'):
        line = next(line for line in case.caller.splitlines() if token in line and ('call ' in line or 'invoke ' in line))
        name = re.search(check.comparison.SYMBOL, line)[1]
        yield 'unbound adapter callee', replace(case, caller=case.caller.replace(line, line.replace(name, 'unreviewed_callee'), 1))
    yield 'wrong feature result layout', replace(case, mode='accelerated' if case.mode == 'portable' else 'portable')
    yield 'wrong compiler result layout', replace(case, compiler='1.98.1' if case.compiler == '1.90.0' else '1.90.0')
    yield 'wrong assembly architecture', replace(case, arm=not case.arm)
    yield 'missing emitted byte-mask cleanup', replace(case, core_assembly=case.core_assembly.replace('BRYNJA_MASK_ERASE', 'MISSING_MASK_ERASE'))
    writer = check.tail.ownership.writing.select(case.core)
    line = next(line for line in writer.splitlines() if 'tail call fastcc void @' in line)
    callee = re.search(check.comparison.SYMBOL, line)[1]
    changed = writer.replace(line, line.replace(callee, callee + '_unbound'), 1)
    yield 'token-matching but unbound output copy', replace(case, core=case.core.replace(writer, changed, 1))
    yield 'missing bulk entry', replace(case, bulk='missing_bulk_reader')


def bulk_mutations(body):
    graph, _, _ = check.adapter.routes.transfer.finish.graph_info(body)
    call = graph['start'][0]
    name, args = check.adapter.routes.guard.call(call)
    for index, value in enumerate(('ptr noalias %destination.0', 'ptr noalias %destination.0',
                                   'ptr noalias %self', 'i64 noundef 0',
                                   'i1 noundef zeroext true', 'i8 7')):
        yield 'bulk argument substitution', body.replace(call, call.replace(args[index], value, 1), 1)
    yield 'wrong borrowed specialization', body.replace(call, call.replace(name, 'unbound_borrowed'), 1)
    yield 'omitted borrowed call', body.replace(call, '', 1)
    yield 'duplicated borrowed call', body.replace(call, call + '\n  ' + call, 1)
    yield 'payload access', body.replace(call, '%leak = load i8, ptr %destination.0\n  ' + call, 1)
    yield 'lost input exclusivity', body.replace('ptr noalias ', 'ptr ', 1)
    yield 'missing return', body.replace('ret void', 'unreachable', 1)


def main(record):
    counts, controls, bulk_counts = [], 0, []
    before = check.comparison.capture.sources()
    for case in check.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, thorough=False), case, mutations(case)))
        definitions = check.comparison.definitions(case.sha3)
        bulk = check.resolve(case.sha3, definitions, case.bulk, 'void (ptr, ptr, ptr, i64)')
        graph, _, _ = check.adapter.routes.transfer.finish.graph_info(bulk)
        borrowed, _ = check.adapter.routes.guard.call(graph['start'][0])
        bulk_counts.append(rejects(lambda value: check.bulk_bridge(value, borrowed), bulk, bulk_mutations(bulk)))
        # Full composition must continue to tolerate harmless formatting on
        # both sides of the package boundary; mutation checks are not hashes.
        for field in ('caller', 'sha3', 'core'):
            original = getattr(case, field)
            changed = original.replace('start:\n', 'start:\n; harmless chain comment\n')
            assert original != changed
            check.inspect(replace(case, **{field: changed}), thorough=False)
            controls += 1
    assert counts == [22] * 16 and controls == 48 and bulk_counts == [12] * 16, (counts, controls, bulk_counts)
    assert before == check.comparison.capture.sources()
    print(f'Final-chain composition rejects {sum(counts)} dependency/body/layout regressions; {controls} controls PASS')
    print(f'Bulk-reader forwarding rejects {sum(bulk_counts)} argument, effect, binding and control-flow regressions PASS')
    print('Actual retained callees checked without compiler/runtime execution; production and release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
