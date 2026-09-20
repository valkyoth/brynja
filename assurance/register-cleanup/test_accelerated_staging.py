#!/usr/bin/env python3
"""Alter retained accelerated staging/guard LLVM; never compile or run Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_accelerated_staging as check
from test_kmac_verify_comparisons import rejects


def producer_mutants(function):
    lines = function.splitlines()
    calls = {}
    for kind, token in (('read', '6Engine4read'), ('write', 'Initialization5write')):
        line = next(line for line in lines if 'invoke ' in line and token in line)
        args = check.invocation(line)[1]
        calls[kind] = line, args
    read, read_args = calls['read']
    write, write_args = calls['write']
    stage = check.comparison.pointer(read_args[1])
    stage_address = next(line for line in lines if stage + ' = getelementptr' in line)
    count = re.search(check.SSA + '$', read_args[2])[0]
    guard = next(line for line in lines if 'invoke ' in line and 'Operation' in line
                 and not line.lstrip().startswith(';'))
    success_clear = next(line for line in lines if 'invoke ' in line and '18clear_owned_region' in line)
    for label, old, new in (
        ('wrong engine owner', read, read.replace('%self.0.val', '%_0')),
        ('wrong read destination', read, read.replace(stage, '%_0')),
        ('wrong read count', read, read.replace(count, '0')),
        ('wrong write stage', write, write.replace(stage, '%_0')),
        ('wrong write count', write, write.replace(count, '0')),
        ('wrong staging address', stage_address, stage_address.replace('i64 864', 'i64 863')),
        ('guard marked complete during unwind', guard, guard.replace('i8 0', 'i8 1')),
        ('wrong guard owner', guard, guard.replace('%self.0.val', '%_0')),
        ('missing success clear', success_clear, ''),
        ('short success clear', success_clear, success_clear.replace('i64 noundef 168', 'i64 noundef 167')),
        ('wrong success clear address', success_clear, success_clear.replace(stage, '%_0')),
    ):
        yield label, function.replace(old, new, 1)
    for invocation, _ in calls.values():
        result = re.search('(' + check.SSA + ') = invoke', invocation)[1]
        test = next(line for line in lines if 'icmp eq i8 ' + result + ',' in line)
        yield 'inverted result check', function.replace(test, test.replace('icmp eq', 'icmp ne'), 1)
        index = lines.index(invocation)
        continuation = lines[index + 1]
        normal, unwind = check.edges(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', continuation.strip()))
        yield 'unwind skips destruction', function.replace(continuation, '          to label %' + normal + ' unwind label %bb7', 1)
        predicate = re.search('(' + check.SSA + ') =', test)[1]
        branch = next(line for line in lines if 'br i1 ' + predicate + ',' in line)
        yield 'result bypasses cleanup', function.replace(branch, '  br label %bb7', 1)
    # Mutate each error-path clear, including the predecessor-selected domain clear.
    # Skip the first early-begin-error block, which is outside this inspector's scope.
    selected = function[function.index('\nbb1.i.i.i:'):]
    for token in ('6Memory4wipe', '18clear_owned_region'):
        for line in selected.splitlines():
            if 'call ' not in line or token not in line:
                continue
            yield 'missing error cleanup call', function.replace(line, '', 1)
            yield 'unreviewed error cleanup callee', function.replace(line, line.replace(token, 'unreviewed_cleanup'), 1)
    for old, new in (
        ('[ 1056, %bb1.i.i.i ]', '[ 864, %bb1.i.i.i ]'),
        ('[ 2, %bb1.i.i.i ]', '[ 168, %bb1.i.i.i ]'),
        ('ptr %self.0.val, i64 624', 'ptr %self.0.val, i64 625'),
    ):
        # Change all occurrences so the later (tested) cleanup cannot stay intact.
        yield 'wrong error cleanup region', function.replace(old, new)
    for line in lines:
        if 'invoke void' in line and 'SecretRegionInitialization' in line and '4drop' in line:
            yield 'missing initialization destruction', function.replace(line, '', 1)
        if line.strip().startswith('store i64 2, ptr %_0'):
            # Several blocks have the same instruction: replace all to cover the selected error path.
            yield 'error downgraded to success', function.replace('store i64 2, ptr %_0', 'store i64 0, ptr %_0')
            break


def guard_mutants(function):
    lines = function.splitlines()
    for line in lines:
        if 'call ' in line and ('18clear_owned_region' in line or '6Memory4wipe' in line):
            yield 'missing guard cleanup', function.replace(line, '', 1)
            yield 'wrong guard cleanup callee', function.replace(line, line.replace('18clear_owned_region', '18unreviewed_cleanup').replace('6Memory4wipe', '6Memory4fake'), 1)
    for old, new in (
        ('ptr %_1.0.val, i64 624', 'ptr %_1.0.val, i64 625'),
        ('ptr %_1.0.val, i64 864', 'ptr %_1.0.val, i64 865'),
        ('i64 noundef 168', 'i64 noundef 1'),
        ('[ 1056, %bb1.i ]', '[ 864, %bb1.i ]'),
        ('[ 2, %bb1.i ]', '[ 1, %bb1.i ]'),
        ('[ 168, %start ]', '[ 1, %start ]'),
        ('ret void', 'br label %start'),
    ):
        yield 'guard width/address/control regression', function.replace(old, new, 1)
    branch = next(line for line in lines if line.strip().startswith('br i1'))
    yield 'guard bypass', function.replace(branch, '  ret void', 1)


def main(record):
    totals = []
    for sha3, core, compiler in check.cases(record):
        definitions = check.comparison.definitions(sha3)
        producer = definitions[check.unique(definitions, 'accelerated', '8Borrowed6secret')]
        guard = next(body for name, body in definitions.items() if 'Operation' in name and 'xof' in name
                     and ('drop_in_place' in name or 'drop_glue' in name))
        count = rejects(lambda body: check.inspect(sha3.replace(producer, body, 1), core, compiler), producer, producer_mutants(producer))
        count += rejects(lambda body: check.inspect(sha3.replace(guard, body, 1), core, compiler), guard, guard_mutants(guard))
        totals.append(count)
    if totals != [41] * 4:
        raise AssertionError(f'incomplete accelerated mutation matrix: {totals}')
    print('Accelerated staging rejects 164 retained-LLVM producer/guard regressions across four optimized configurations')
    print('Subprocess execution forbidden; no compiled fault campaign, production edit or release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
