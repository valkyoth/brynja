#!/usr/bin/env python3
"""Whole verifier with actual suffix/bit-packer control flow and cleanup."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_whole as whole
from debug_kmac_packing import PackingModel, closure, model, require


def expected(machine, size, valid, bits, fault):
    p = model.Pointer
    encoded = machine.encoded
    pending = p(machine.frame.region, machine.frame.offset + 8)
    width = max(1, (bits.bit_length() + 7) // 8) + 1
    events = []
    used = 0
    if fault and fault[:2] == ('absorb', 1) and size is not None:
        require(encoded is None, 'failed message absorption precedes suffix encoding')
        return [('absorb', p('message'), size - int(valid not in (0, 8)))], [(8, 1), (9, 1), (0, 8)] * 3
    if size is not None:
        if valid in (0, 8):
            events.append(('absorb', p('message'), size))
        else:
            events += [('absorb', p('message'), size - 1), ('xor', p('message', size - 1), 0, valid, 0)]
            used = valid
    if used:
        for index in range(width):
            source = p(encoded.region, encoded.offset + index)
            events += [('xor', source, 0, 8 - used, used), ('absorb', pending, 1),
                       ('xor', source, 8 - used, used, 0)]
    else:
        events.append(('absorb', encoded, width))
    wipes = [(8, 1), (9, 1), (0, 8)]
    count, trace = 0, []
    for event in events:
        trace.append(event)
        if event[0] == 'absorb':
            count += 1
            if fault and fault[:2] == ('absorb', count):
                break
            if event[1] == pending:
                wipes += [(8, 1), (9, 1)]
    if fault:
        require(count == fault[1], 'injected absorption actually reached')
    return trace, wipes + [(8, 1), (9, 1), (0, 8)] * 2


def scenarios(errors, fast=False):
    messages = [(None, 0), (0, 0)] + [(size, valid) for size in ((1, 33) if fast else (1, 33, 168, 4097))
                                     for valid in ((3, 8) if fast else range(1, 9))]
    for size, valid in messages:
        for length in ((130,) if fast else (0, 1, 65, 130)):
            yield size, valid, length, None
    for call in (1, 4):
        for error in ((0, 'unwind') if fast else (*range(errors), 'unwind')):
            yield 33, 3, 130, ('absorb', call, error)


def inspect(function, definitions, names, text, fast=False):
    linked = closure(function, definitions, names, text)
    suffix = next(name for name in linked[1] if '13append_suffix' in name)
    codes = re.findall(r'icmp eq i8 %[-.$\w]+, (7|20|-1)\b', definitions[suffix])
    require(codes and len(set(codes)) == 1, 'bound unit-result success')
    errors = 20 if re.search(r'store i8 18,', function) else 7
    total = absorbs = fragments = unwinds = 0
    for size, valid, length, fault in scenarios(errors, fast):
        class Configured(PackingModel):
            def __init__(self, *args):
                super().__init__(*args)
                self.success_code = int(codes[0]) & 255
                self.packing_fault = fault
                if size is not None:
                    self.allocate('message', size, payload=True)
                    self.message = [(0, 8, model.Pointer('message')), (8, 8, size),
                                    (16, 8, (size - 1) * 8 + valid if size else 0), (24, 1, valid)]
        output_valid = 3 if length else 0
        with patch.object(whole, 'WholeModel', Configured):
            m, result, _ = whole.run(function, definitions, names, text,
                (length, output_valid, True, True, False, None, None, None),
                ('unused', 0) if fault and fault[2] == 'unwind' else None, linked)
        bits = (length - 1) * 8 + output_valid if length else 0
        trace, wipes = expected(m, size, valid, bits, fault)
        value = ('unwind' if fault[2] == 'unwind' else (1, fault[2])) if fault else (0, 1)
        require(result == value and m.packing_events == trace and m.framing_clears == wipes,
                'exact original message/suffix packing, returned error/unwind and framing cleanup')
        regions = whole.destruction.ACCELERATED if m.accelerated else whole.destruction.PORTABLE
        require([x for x in m.trace if x[0] == 'engine'] == [('engine', *x) for x in regions]
                and [x for x in m.trace if x[0] == 'metadata'] == [('metadata', *x) for x in whole.destruction.METADATA],
                'full verifier destroys original state and metadata through actual caller destructors')
        require(not m.output_live and len(m.pairs) == (0 if fault else length), 'complete comparison or early failure without output')
        total += 1
        absorbs += sum(event[0] == 'absorb' for event in trace)
        fragments += sum(event[0] == 'xor' for event in trace)
        unwinds += int(result == 'unwind')
    return total, absorbs, fragments, unwinds


def main(record):
    before = whole.comparison.capture.sources()
    results = []
    for case in whole.retained.cases(record):
        results.append(inspect(*case))
        print(f'Whole KMAC packing: {len(results)}/24 paths; {results[-1]} PASS', flush=True)
    require(len(results) == 24 and before == whole.comparison.capture.sources(), 'complete unchanged packing matrix')
    totals = tuple(sum(row[i] for row in results) for i in range(4))
    require(totals == (4064, 12464, 18528, 48), 'nonvacuous complete packing coverage')
    print('Totals: ' + repr(totals))
    print('Absorb/encoding/state-finalization payload contracts remain explicit; no general spill-erasure claim.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
