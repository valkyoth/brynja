#!/usr/bin/env python3
"""Retained debug accessor mutation controls; no compiler/runtime execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_output_accessors as check


def rejected(functions, name, changed):
    if changed == functions[name]:
        raise AssertionError('missing accessor mutation')
    mutant = dict(functions)
    if changed is None:
        del mutant[name]
    else:
        mutant[name] = changed
    try:
        check.inspect(mutant)
    except ValueError:
        return 1
    raise AssertionError('accessor mutant accepted: ' + name)


def main(record):
    count, targeted = 0, 0
    for functions in check.cases(record):
        check.inspect(functions)
        selected = check.closure(functions)
        for name, body in selected.items():
            for injected in (
                '%probe = load i8, ptr %unknown, align 1',
                '%probe = load i64, ptr %unknown, align 8',
                'store i64 0, ptr %unknown, align 8',
                '%probe = call i64 @unreviewed()',
                'call void @llvm.memcpy.p0.p0.i64(ptr %unknown, ptr %unknown, i64 1, i1 false)',
            ):
                count += rejected(functions, name, body.replace('start:\n', 'start:\n  ' + injected + '\n', 1))
            count += rejected(functions, name, None)
        by_role = {check.role(name): name for name in selected}
        name = by_role['deref']
        body = selected[name]
        load = re.search('(' + check.SSA + r') = load ptr, ptr %self, align 8[^\n]*', body)
        targeted += rejected(functions, name, body.replace(load[0], load[0] + '\n  %payload = load i64, ptr ' + load[1] + ', align 8', 1))
        name = by_role['as_ref']
        body = selected[name]
        targeted += rejected(functions, name, body.replace('ptr %self, i64 8', 'ptr %self, i64 16'))
        name = by_role['as_deref']
        body = selected[name]
        store = re.search(r'store ptr %self, ptr (%self\d+), align 8[^\n]*', body)
        targeted += rejected(functions, name, body.replace(store[0], store[0] + '\n  store i64 1, ptr ' + store[1] + ', align 8', 1))
        load = re.search('(' + check.SSA + r') = load ptr, ptr %self, align 8[^\n]*', body)
        targeted += rejected(functions, name, body.replace(store[0], store[0] + '\n  store ptr ' + load[1] + ', ptr ' + store[1] + ', align 8', 1))
    if count != 336 or targeted != 32:
        raise AssertionError(f'incomplete accessor campaign: {count}/{targeted}')
    print('Debug accessor closure rejects 336 memory/call/missing-definition and 32 payload/offset/alias regressions')
    print('LLVM-text mutations only; subprocess execution forbidden; production and release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('must not rerun compiler or runtime')):
        main(parser.parse_args().record.resolve())
