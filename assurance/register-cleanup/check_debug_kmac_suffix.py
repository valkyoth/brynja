#!/usr/bin/env python3
"""Whole verifier plus actual suffix frame, state take and cleanup control flow."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_kmac_whole as whole
from debug_kmac_suffix import SuffixModel, closure, model, require


def inspect(function, definitions, names, text, fast=False):
    linked = closure(function, definitions, names, text)
    suffix = next(name for name in linked[1] if '13append_suffix' in name)
    codes = re.findall(r'icmp eq i8 %[-.$\w]+, (7|20|-1)\b', definitions[suffix])
    require(codes and len(set(codes)) == 1, 'actual suffix unit-result success discriminator')
    success = int(codes[0]) & 255
    errors = 20 if re.search(r'store i8 18,', function) else 7
    count = comparisons = unwinds = 0
    for message_bits in (None, 0, 1, 7, 8):
        faults = [None] + [(role, error) for role in ('push_encoded', 'state_finish') + (('push_message',) if message_bits is not None else ())
                          for error in ((0, 'unwind') if fast else (*range(errors), 'unwind'))]
        for fault in faults:
            class Configured(SuffixModel):
                def __init__(self, *args):
                    super().__init__(*args)
                    self.success_code, self.suffix_fault = success, fault
                    if message_bits is not None:
                        size = 0 if message_bits == 0 else 33
                        self.allocate('message', size, payload=True)
                        self.message = [(0, 8, model.Pointer('message')), (8, 8, size),
                                        (16, 8, (size - 1) * 8 + message_bits if size else 0), (24, 1, message_bits)]
            with patch.object(whole, 'WholeModel', Configured):
                # A selected suffix unwind is caught by actual suffix/finish/
                # caller landingpads, not by a synthetic caller fragment.
                m, result, _ = whole.run(function, definitions, names, text,
                    (130, 3, True, True, False, None, None, None),
                    ('unused', 0) if fault and fault[1] == 'unwind' else None, linked)
            if fault:
                expected = 'unwind' if fault[1] == 'unwind' else (1, fault[1])
            else:
                expected = (0, 1)
            require(result == expected and not m.output_live, 'exact composed suffix error/unwind/result and no leaked output owner')
            require(m.framing_clears == [(8, 1), (9, 1), (0, 8)] * 3,
                    'initial packer wipe and both real frame destructors request all original fields')
            engine = whole.destruction.ACCELERATED if m.accelerated else whole.destruction.PORTABLE
            require([x for x in m.trace if x[0] == 'engine'] == [('engine', *item) for item in engine],
                    'taken or untaken state always cleaned once through the correct owner')
            require([x for x in m.trace if x[0] == 'metadata'] == [('metadata', *item) for item in whole.destruction.METADATA],
                    'metadata cleared once after suffix success/error/unwind')
            if not fault:
                require(m.suffix_events == (['message'] if message_bits is not None else []) + ['encode', 'append', 'consume']
                        and len(m.pairs) == 130 and m.outputs == [64, 64, 1, 1],
                        'ordered message/suffix/state transfer and complete downstream comparison')
            count += 1
            comparisons += len(m.pairs)
            unwinds += int(result == 'unwind')
    return count, comparisons, unwinds


def main(record):
    before = whole.comparison.capture.sources()
    results = []
    for case in whole.retained.cases(record):
        results.append(inspect(*case))
        print(f'Whole verifier/suffix: {len(results)}/24 paths; {results[-1]} PASS', flush=True)
    require(len(results) == 24 and before == whole.comparison.capture.sources(), 'unchanged complete suffix matrix')
    print('Totals: ' + repr(tuple(sum(row[i] for row in results) for i in range(3))))
    print('Packing/encoding/backend payload and primitive contracts are explicit; no whole-call physical-erasure claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
