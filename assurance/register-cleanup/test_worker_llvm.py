#!/usr/bin/env python3
"""Mutate actual emitted worker bodies; no Rust builds or native executions."""
import argparse
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import check_worker_llvm as check


def rendered(original, graph):
    return original.splitlines()[0] + '\n' + '\n'.join(
        label + ':\n' + '\n'.join('  ' + line for line in lines)
        for label, lines in graph.items()) + '\n}'


def rejects(body, available, label):
    try:
        check.inspect(body, available)
    except ValueError:
        return
    raise AssertionError('worker mutant survived: ' + label)


def campaign(original, available):
    graph = check.blocks(original)
    entry = next(label for label, lines in graph.items() for line in lines
                 if (op := check.operation(line)) and (
                     'LeafWorkspace' in op[0] and 'execute' in op[0]
                     or 'brynja_hash_parallel' in op[0] and 'execute_into' in op[0]))
    normal, unwind = check.successors(graph[entry])[0]
    owner = '%workspace.i' if '%workspace.i = alloca' in original else '%workspace'
    count = 0

    def mutation(label, block, instructions, replace=False):
        nonlocal count
        changed = deepcopy(graph)
        changed[block] = instructions if replace else instructions + changed[block]
        rejects(rendered(original, changed), available, label)
        count += 1

    for label, instruction in (
        ('payload read', f'%leak = load i8, ptr {owner}, align 1'),
        ('payload write', f'store i8 7, ptr {owner}, align 1'),
        ('escaped owner pointer', f'store ptr {owner}, ptr %escaped, align 8'),
        ('aggregate copy', f'call void @llvm.memcpy.p0.p0.i64(ptr %escaped, ptr {owner}, i64 1088, i1 false)'),
        ('unknown callee', f'call void @unreviewed(ptr {owner})'),
        ('indirect callee', f'call void %unreviewed(ptr {owner})'),
        ('integer pointer escape', f'%address = ptrtoint ptr {owner} to i64'),
        ('alias through phi', f'%leak = phi ptr [ {owner}, %{entry} ]'),
        ('lifetime before cleanup', f'call void @llvm.lifetime.end.p0(ptr {owner})'),
    ):
        mutation(label, normal, [instruction])
    for label, block, terminator in (
        ('success bypass', normal, 'ret void'),
        ('unwind bypass', unwind, 'resume { ptr, i32 } undef'),
        ('post-execution cycle', normal, 'br label %' + normal),
        ('dangling successor', normal, 'br label %missing'),
    ):
        mutation(label, block, [terminator], replace=True)
    # A derived pointer is not a license to inspect or publish workspace data.
    if '5772 x i8' in original:
        mutation('subfield payload read', normal, [
            f'%derived = getelementptr inbounds i8, ptr {owner}, i64 512',
            '%leak = load i8, ptr %derived, align 1',
        ])
    execution = check.operation(graph[entry][-2])[0]
    rejects(original, available - {execution}, 'missing execution definition')
    count += 1
    cleanup = next(op[0] for lines in graph.values() for line in lines
                   if (op := check.operation(line)) and check.drop_kind(op[0]) is not None)
    rejects(original, available - {cleanup}, 'missing cleanup definition')
    count += 1
    # Wrong execution argument provenance must fail before CFG traversal.
    changed = deepcopy(graph)
    changed[entry][-2] = changed[entry][-2].replace(owner, '%copied_owner')
    rejects(rendered(original, changed), available, 'copied execution workspace')
    count += 1
    for role in ('execution', 'cleanup'):
        changed = deepcopy(graph)
        block, index = next((label, i) for label, lines in changed.items()
                            for i, line in enumerate(lines)
                            if (op := check.operation(line)) and (
                                op[0] == execution if role == 'execution' else op[0] == cleanup))
        # The original pointer identity alone is not enough: byval would give
        # the callee a copied aggregate instead of the caller's owner.
        name, arguments = check.operation(changed[block][index])
        position = (3 if '5772 x i8' in original else 1) if role == 'execution' else 0
        before = arguments[position]
        after = before.replace('ptr ', 'ptr byval([1088 x i8]) ', 1)
        changed[block][index] = changed[block][index].replace(before, after, 1)
        rejects(rendered(original, changed), available, role + ' by-value ABI')
        count += 1
    # Normalization can change whitespace/comments without disabling inspection.
    check.inspect(rendered(original, graph).replace('\n  ', '\n    '), available)
    return count


def main(record):
    total = controls = 0
    with patch('subprocess.run', side_effect=AssertionError('must not rebuild')):
        for _, _, body, available in check.cases(record):
            total += campaign(body, available)
            controls += 1
    check.require(controls == 48, 'complete emitted worker mutation matrix')
    print(f'Actual worker LLVM: {total} regressions rejected; {controls} normalization controls pass')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
