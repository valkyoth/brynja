#!/usr/bin/env python3
"""Accelerated reader argument, cleanup and dependency regression mutations."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_accelerated_readers as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def bodies(case):
    borrowed, wipe, clear, drop = check.inspect(case)
    definitions = check.comparison.definitions(case.sha3)
    return [check.chain.resolve(case.sha3, definitions, case.bulk, 'void (ptr, ptr, ptr, i64)'),
            check.chain.resolve(case.sha3, definitions, case.final, 'void (ptr, ptr, ptr, i64, i8)'),
            definitions[wipe], definitions[drop]], borrowed


def mutations(function, borrowed):
    graph, _, _ = check.adapter.routes.transfer.finish.graph_info(function)
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            yield 'missing boundary operation', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if ' = getelementptr ' in line:
                offset = re.search(r'i64 (\d+)$', line)
                assert offset
                changes.append(('wrong owned field', line[:offset.start(1)] + str(int(offset[1]) + 1)))
            if line.startswith('store '):
                changes.append(('wrong lifecycle value', re.sub(r'(store i(?:8|64) )([01])', lambda m: m[1] + str(1 - int(m[2])), line)))
            if ' call ' in ' ' + line or ' invoke ' in ' ' + line:
                name, args = check.adapter.routes.guard.call(line)
                if not name.startswith('llvm.'):
                    changes.append(('unbound cleanup/reader callee', line.replace(name, 'unreviewed_callee')))
                if name == borrowed:
                    for i in range(6):
                        if i < 3:
                            changed = args[i].replace(check.comparison.pointer(args[i]), '%foreign')
                        elif i == 3:
                            changed = 'i64 noundef 0'
                        elif i == 4:
                            changed = args[i].replace('true', 'FALSE').replace('false', 'true').replace('FALSE', 'false')
                        else:
                            changed = 'i8 0'
                        changes.append(('substituted original reader argument', line.replace(args[i], changed, 1)))
                if '18clear_owned_region' in name:
                    changes.append(('shortened cleanup extent', line.replace(args[1], 'i64 noundef 1')))
            if line.startswith('resume '):
                changes += [('wrong resumed exception', 'resume { ptr, i32 } %foreign'), ('swallowed exception', 'ret void')]
            for reason, changed in changes:
                assert changed != line, reason
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
    yield 'extra payload read', function.replace('start:\n', 'start:\n  %secret = load i8, ptr %foreign\n', 1)


def dependency_mutants(case, selected):
    for body in selected:
        yield 'missing actual dependency', replace(case, sha3=case.sha3.replace(body, '', 1))
    yield 'wrong assembly architecture', replace(case, arm=not case.arm)
    yield 'missing core volatile erase', replace(case, core=case.core.replace('store volatile i8 0,', 'store i8 0,'))
    definitions = check.comparison.definitions(case.sha3)
    name = check.staging.unique(definitions, 'accelerated', '8Borrowed6secret')
    body = definitions[name]
    for old, new in (('define internal fastcc void @', 'define internal void @'),
                     ('dereferenceable(24)', 'dereferenceable(32)')):
        yield 'incompatible actual borrowed ABI', replace(case, sha3=case.sha3.replace(body, body.replace(old, new, 1), 1))


def main(record):
    before = check.comparison.capture.sources()
    counts, bindings, controls = [], 0, 0
    for case in check.cases(record):
        selected, borrowed = bodies(case)
        count = 0
        for body in selected:
            inspect = lambda value: check.inspect(replace(case, sha3=case.sha3.replace(body, value, 1)))
            count += rejects(inspect, body, mutations(body, borrowed))
            graph, _, _ = check.adapter.routes.transfer.finish.graph_info(body)
            locals_ = {m[1] for lines in graph.values() for line in lines if (m := re.match('(' + check.SSA + ') = ', line))}
            for changed in (
                    body.replace('start:\n', 'start:\n; harmless accelerated-reader comment\n', 1),
                    re.sub(check.SSA, lambda m: '%reader_' + m[0][1:] if m[0] in locals_ else m[0], body)):
                assert changed != body
                inspect(changed)
                controls += 1
        counts.append(count)
        bindings += rejects(check.inspect, case, dependency_mutants(case, selected))
    assert counts == [103] * 8 and controls == 64 and bindings == 64, (counts, controls, bindings)
    assert before == check.comparison.capture.sources()
    print(f'Accelerated reader boundaries reject {sum(counts)} LLVM and {bindings} dependency regressions; {controls} controls PASS; per-path={counts}')
    print('Subprocess execution forbidden; production artifacts and release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
