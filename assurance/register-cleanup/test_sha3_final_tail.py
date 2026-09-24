#!/usr/bin/env python3
"""Final-bit admission, mask, dependency and error-route regression mutations."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_final_tail as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels):
    for label, lines in trace.graph.items():
        for index, line in enumerate(lines):
            yield 'missing final-tail operation', replace_block(function, label, lines[:index] + lines[index + 1:])
            changes = []
            if line.startswith('i8 8, label '):
                changes.append(('wrong full-byte switch case', line.replace('i8 8,', 'i8 7,')))
            if 'llvm.usub.sat.i64' in line:
                changes.append(('incorrect complete-byte count', line.replace('i64 1)', 'i64 2)')))
            if 'getelementptr ' in line:
                changes.append(('wrong owner field', re.sub(r'i64 \d+$', 'i64 32', line)))
            if ' = load i64,' in line:
                changes.append(('truncated counter load', line.replace('load i64,', 'load i8,')))
            if ' = shl ' in line:
                changes.append(('wrong counter significance', re.sub(r', \d+$', ', 0', line)))
            if ' = or ' in line:
                changes.append(('lost counter fragment', re.sub(r', ' + check.SSA + '$', ', 0', line)))
            if ' = add nuw nsw i128 ' in line:
                changes.append(('lost complete-byte admission count', re.sub(r'i128 ' + check.SSA + ',', 'i128 0,', line)))
            if ' = icmp ' in line:
                changes.append(('incorrect predicate', line.replace('icmp eq', 'icmp ne').replace('icmp ugt', 'icmp ult').replace('icmp samesign ult', 'icmp samesign ugt')))
            if 'extractvalue { i128, i1 }' in line:
                changes.append(('wrong overflow tuple field', line.replace(', 1', ', 0')))
            if ' = xor i128 ' in line:
                changes.append(('wrong available counter capacity', line.replace(', -1', ', 0')))
            if ' = lshr i8 %valid, 3' in line:
                changes.append(('incorrect bit/byte conversion', line.replace(', 3', ', 2')))
            if 'llvm.usub.sat.i8' in line:
                changes.append(('wrong mask shift base', line.replace('i8 8,', 'i8 7,')))
            if ' = lshr i8 -1,' in line:
                changes.append(('mask reversed direction', line.replace('lshr', 'shl')))
            if ' = select i1 ' in line and ', i8 0, i8 ' in line:
                changes.append(('full-byte mode adds a byte', line.replace(', i8 0,', ', i8 1,')))
            if 'tail call void @' in line and '22apply_secret_byte_mask' in line:
                name, args = check.ownership.adapter.routes.guard.call(line)
                changes += [('unbound byte mask', line.replace(name, 'unreviewed_mask')),
                            ('mask other owner byte', line.replace(check.comparison.pointer(args[0]), '%self')),
                            ('mask sets secret output bits', line.replace('i8 noundef 0)', 'i8 noundef 1)'))]
            if '12fill_staging' in line:
                changes += [('empty tail fill', line.replace('i64 noundef 1)', 'i64 noundef 0)')),
                            ('foreign fill owner', line.replace(' %self,', ' %initialization,'))]
            if '14squeeze_secret' in line:
                name, args = check.ownership.adapter.routes.guard.call(line)
                changes.append(('wrong bulk length', line.replace(args[2], 'i64 noundef %output_bytes')))
            if line.startswith('br i1 '):
                flag, yes, no = check.ownership.adapter.shape.branch(trace, label)
                changes.append(('inverted final-tail branch', f'br i1 {flag}, label %{no}, label %{yes}'))
            for reason, changed in changes:
                yield reason, replace_block(function, label, lines[:index] + [changed] + lines[index + 1:])
    returning = labels[-1]
    lines = trace.graph[returning]
    for parent in (labels[1], labels[2], labels[3], labels[4], labels[5]):
        changed = re.sub(r'\[ [^,]+, %' + re.escape(parent) + r' \]', '[ 1, %' + parent + ' ]', lines[0])
        yield 'wrong final result on actual predecessor', replace_block(function, returning, [changed, lines[1]])


def dependency_mutants(core, assembly, arm):
    definitions = check.comparison.definitions(core)
    wrapper = next(body for name, body in definitions.items() if '22apply_secret_byte_mask' in name)
    primitive = next(name for name in definitions if 'secret_memory_mask9mask_byte' in name)
    call = next(line for line in wrapper.splitlines() if 'tail call ' in line)
    for reason, value in (
        ('missing mask wrapper', core.replace(wrapper, '')),
        ('missing mask primitive', core.replace(definitions[primitive], '')),
        ('missing mask call', core.replace(wrapper, wrapper.replace(call, ''))),
        ('wrong keep mask', core.replace(wrapper, wrapper.replace(call, call.replace('%keep', '%set')))),
        ('wrong set mask', core.replace(wrapper, wrapper.replace(call, call.replace('%set', '%keep')))),
        ('wrong byte pointer', core.replace(wrapper, wrapper.replace(call, call.replace('%byte', '%foreign')))),
        ('lost byte exclusivity', core.replace(wrapper, wrapper.replace('ptr noalias ', 'ptr ', 1))),
    ):
        yield reason, (value, assembly, arm)
    yield 'wrong assembly identity', (core, assembly.replace(primitive + ':', 'other_mask:'), arm)
    yield 'lost mask erasure', (core, assembly.replace('BRYNJA_MASK_ERASE', 'MISSING_MASK_ERASE'), arm)
    yield 'wrong mask architecture', (core, assembly, not arm)


def main(record):
    # Independent byte arithmetic for the structurally matched mask sequence;
    # this is not execution of the emitted assembly or a runtime oracle rerun.
    for valid in range(1, 8):
        for byte in range(256):
            assert (byte & (255 >> (8 - valid))) | 0 == byte % (1 << valid)
    counts = []
    bindings = controls = 0
    for case, core, assembly, arm in check.cases(record):
        function, *args = case
        trace, labels, _ = check.inspect(*case)
        inspect = lambda value: check.inspect(value, *args, thorough=False)
        counts.append(rejects(inspect, function, mutations(function, trace, labels)))
        bindings += rejects(lambda value: check.dependency(*value), (core, assembly, arm), dependency_mutants(core, assembly, arm))
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%tail_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless final-tail comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
    assert counts == [136] * 8 + [137] * 8 and bindings == 160 and controls == 48, (counts, bindings, controls)
    print(f'Final-bit tails reject {sum(counts)} LLVM and {bindings} mask-dependency regressions; {controls} controls PASS; counts={counts}')
    print('All 1792 byte/partial-width mathematical mask checks PASS (not machine execution)')
    print('Subprocess execution forbidden; no compiler/runtime rerun or release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
