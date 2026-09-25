#!/usr/bin/env python3
"""Retained scoped KMAC input-byte borrow and actual xor primitive inspection."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_verify_comparisons as comparison
import check_secret_xor as xor
import debug_write_model as model
import check_kmac_guard_paths as guard

require = comparison.require


def inspect(function, core, assembly, arm):
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    require('9push_bits' in header and comparison.pointer(params[-2]) == '%byte'
            and re.fullmatch(r'i8 (?:noundef )?%valid', params[-1]), 'borrowed input-byte ABI')
    graph = model.blocks(function)
    slots = {m[1] for lines in graph.values() for line in lines
             if (m := re.fullmatch(r'(%[-.$\w]+) = alloca \[8 x i8\], align 8', line))}
    uses, primitive = [], None
    for lines in graph.values():
        for line in lines:
            if not re.search(r'%byte(?![-.$\w])', line):
                continue
            spill = re.fullmatch(r'store ptr %byte, ptr (%[-.$\w]+), align 8', line)
            if spill:
                require(spill[1] in slots, 'only pointer identity may be saved in a local debug slot')
                # The saved address is debug-only, not a route to an unchecked
                # payload load or secondary consumer.
                accesses = [other for block in graph.values() for other in block
                            if re.search(re.escape(spill[1]) + r'(?![-.$\w])', other)]
                require(len(accesses) == 2, 'saved input pointer is never read or exported')
                uses.append('debug-pointer')
                continue
            require('call ' in line and 'secret_memory20xor_secret_byte_bits' in line,
                    'input byte cannot be loaded, copied, returned, aliased or sent to an unreviewed consumer')
            name, args = guard.call(line)
            require(len(args) == 5 and comparison.pointer(args[1]) == '%byte' and
                    'byval' not in line and re.search(r'\bi1 @', line), 'xor borrows input and returns only status')
            require(primitive is None, 'one input-byte xor site')
            primitive = name
            uses.append('xor')
    require(uses in (['xor'], ['debug-pointer', 'xor']), 'complete nonvacuous byte-use inventory')
    definitions = comparison.definitions(core)
    require(primitive in definitions, 'same-row defined core xor wrapper')
    body = definitions[primitive]
    require('%source' in body.splitlines()[0] or '%input' in body.splitlines()[0], 'borrowed core xor source')
    xor.inspect(assembly, arm)
    return len(uses)


def cases(record):
    for row, kmac, core, assembly in comparison.cases(record):
        selected = [body for body in comparison.definitions(kmac).values()
                    if all(token in body.splitlines()[0] for token in ('SecretPacker', '9push_bits', '%byte'))]
        require(len(selected) == (7 if row['mode'] == 'accelerated' else 4), 'complete emitted shared packer inventory')
        for body in selected:
            yield body, core, assembly, row['target'].startswith('aarch64')


def main(record):
    before = comparison.capture.sources()
    counts = [inspect(*case) for case in cases(record)]
    require(len(counts) == 88 and before == comparison.capture.sources(), 'complete unchanged packer matrix')
    print('KMAC partial-byte input: 88 debug/release shared packers retain borrowed bytes; actual xor assembly PASS')
    print('This checks the input-byte route, not every packer helper or whole-call register/spill erasure.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
