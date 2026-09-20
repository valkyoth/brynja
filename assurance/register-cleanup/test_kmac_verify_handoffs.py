#!/usr/bin/env python3
"""Mutate retained verification MIR to test cleanup diagnostics, without builds."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_verify_handoffs as check


def rejects(inspect, original, mutant):
    if original == mutant:
        raise AssertionError('missing MIR mutation')
    try:
        inspect(mutant)
    except ValueError:
        return
    raise AssertionError('verification cleanup mutation accepted')


def main(record):
    paths = forwarders = fields = 0
    for verify, drop, wipe in check.functions(record):
        check.verification(verify)
        check.guard_drop(drop)
        check.metadata_wipe(wipe)
        guard, blocks, calls = check.operations(verify)
        exits = [label for label, block in blocks.items() if re.search(r'\breturn;', block)]
        if len(exits) != 1:
            raise AssertionError('unique verification return expected')
        rejects(check.verification, verify, verify.replace(f'debug cleanup => {guard};', 'debug cleanup => _999;'))
        rejects(check.verification, verify, re.sub(r'(?m)^(\s*)' + guard + r' = (copy|move) ', r'\1_999 = \2 ', verify))
        paths += 2
        for label, _, call in calls:
            block = blocks[label]
            for changed in (
                block.replace(call[1], 'unreviewed_operation('),
                block.replace(call[4], re.sub(r'return: bb\d+', 'return: ' + exits[0], call[4])),
                block.replace(call[4], re.sub(r'unwind: bb\d+', 'unwind continue', call[4])),
            ):
                rejects(check.verification, verify, verify.replace(block, changed, 1))
                paths += 1
        for label, block in blocks.items():
            if f'drop({guard})' not in block:
                continue
            changed = block.replace(f'drop({guard})', 'drop(_1)')
            rejects(check.verification, verify, verify.replace(block, changed, 1))
            paths += 1
        # A conditional early return must not be mistaken for the cleaned path.
        label, _, call = calls[0]
        next_label = call[3]
        block = blocks[next_label]
        changed = f'\n        switchInt(const true) -> [0: {exits[0]}, otherwise: {next_label}];\n    }}\n'
        rejects(check.verification, verify, verify.replace(block, changed, 1))
        paths += 1
        # Self-loop-only behavior cannot be silently reported as a tested exit.
        changed = f'\n        goto -> {next_label};\n    }}\n'
        # The call's normal path diverges; unwind still exits. Termination is
        # deliberately outside the claim, so this is an explicit positive control.
        check.verification(verify.replace(block, changed, 1))

        for mutant in (
            drop.replace('Metadata::wipe(', 'Metadata::wrong('),
            drop.replace('((*_1).0:', '((*_1).1:'),
            drop.replace('bb0: {', 'bb0: {\n        goto -> bb1;'),
        ):
            rejects(check.guard_drop, drop, mutant)
            forwarders += 1
        for field in range(3):
            rejects(check.metadata_wipe, wipe, wipe.replace(f'((*_1).{field}:', f'((*_1).9:'))
            rejects(check.metadata_wipe, wipe, re.sub(r'\(\(\*_1\)\.' + str(field) + r': \[u8; \d+\]',
                                                    f'((*_1).{field}: [u8; 0]', wipe))
            fields += 2
        for block in check.mir.basic_blocks(wipe).values():
            if 'clear_owned_region(' not in block:
                continue
            changed = block.replace('clear_owned_region(', 'wrong_clear(')
            rejects(check.metadata_wipe, wipe, wipe.replace(block, changed, 1))
            fields += 1
    if (paths, forwarders, fields) != (172, 24, 72):
        raise AssertionError(f'incomplete MIR regressions: {paths}, {forwarders}, {fields}')
    print(f'KMAC verification rejects {paths} call/return/unwind, {forwarders} guard-forwarding and {fields} metadata-field/callee MIR mutants')
    print('Divergence explicitly outside the claim; no subprocess execution, compiled mutants or machine-code proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('retained MIR inspection must not run tools')):
        main(parser.parse_args().record)
