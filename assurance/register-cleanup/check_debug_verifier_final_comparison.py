#!/usr/bin/env python3
"""Retained consuming-final result, missing-output and final-byte caller paths."""
import argparse
from pathlib import Path
from unittest.mock import patch

from check_debug_verifier_comparison import cases, comparison
from debug_verifier_final_comparison import FinalModel, extract, model, require


def inspect(function, definitions, errors):
    allocations, result, roles, functions, _ = extract(function, definitions)
    count = pairs = 0
    for base in (0, 32):
        for tail in (0, 1, 63, 255):
            for length, error in [(0, None), (1, None)] + [(1, n) for n in range(errors)]:
                machine = FinalModel(functions, roles, base, length, tail)
                slots = {name: machine.allocate('slot:' + name, size) for name, size in allocations.items()}
                machine.allocate('metadata', base + 66, payload=True)
                machine.allocate('candidate', base + tail + 1, payload=True)
                machine.allocate('empty', 0, payload=True)
                p = model.Pointer
                machine.store(slots['%cleanup'], 8, p('metadata', base))
                fields = ([(0, 8, 2), (8, 1, error)] if error is not None else
                          [(0, 8, 1), (8, 8, p('metadata', base)), (16, 8, 1)] if length else [(0, 8, 0)])
                for offset, size, value in fields:
                    machine.store(p(slots[result].region, offset), size, value)
                returned = machine.run('fragment', list(slots.values()) + [p('candidate', base + tail)])
                # Retained KmacError::State layout differs with enabled backends.
                # Keep this oracle independent of the caller's ok_or argument.
                failure = error if error is not None else (5 if errors == 7 else 17) if not length else None
                require(returned == int(failure is not None) and len(machine.pairs) == int(failure is None),
                        'exact final comparison count and fragment outcome')
                if failure is not None:
                    require(machine.boundaries == [('boundary_error', failure)], 'exact onward error byte')
                else:
                    require(machine.boundaries == [('boundary_drop', machine.exposures[0])], 'original successful output Drop boundary')
                require(len(machine.exposures) == len(machine.first_calls) == int(error is None),
                        'reader errors never expose; successful empty output is rejected by actual Option/Result helpers')
                count += 1
                pairs += int(failure is None)
    return count, pairs


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in cases(record)]
    counts = len(results), sum(n for n, _ in results), sum(n for _, n in results)
    require(counts == (24, 3392, 192) and before == comparison.capture.sources(), 'complete unchanged final comparison matrix')
    print(f'Debug verifier final comparison: {counts[0]} fragments; {counts[1]} cases; {counts[2]} final byte-pair handoffs PASS')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Reader/exposure/iterator/first/comparison contracts remain explicit; no whole-verifier, unwind or F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
