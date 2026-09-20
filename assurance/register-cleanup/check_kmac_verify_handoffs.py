#!/usr/bin/env python3
"""Development MIR check of scoped KMAC verification cleanup, not erasure proof."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import check_recorded_boundaries as recorded
import check_worker_handoffs as handoffs
from batch_cleanup_flow import linear_fields

mir = handoffs.mir
require = handoffs.require
PREFIX = 'fn hardened_in_place::core_state::<impl'


def guard_drop(function):
    blocks = mir.basic_blocks(function)
    require(set(blocks) == {'bb0', 'bb1'}, 'exact guard forwarding blocks')
    code = re.sub(r'\s+', '', blocks['bb0']).rstrip('}')
    pattern = (r'(?P<loan>_\d+)=(?:deref_copy|(?:no_retag)?copy)\(\(\*_1\)\.0:'
               r'&muthardened_in_place::core_state::Metadata\);'
               r'_\d+=Metadata::wipe\((?:move|copy)(?P=loan)\)'
               r'->\[return:bb1,unwindcontinue\];')
    require(re.fullmatch(pattern, code), 'guard must forward its own borrowed metadata')
    require(re.sub(r'\s+', '', blocks['bb1']).rstrip('}') == 'return;', 'guard return')


def metadata_wipe(function):
    fields = re.findall(r'&mut \(\(\*_1\)\.(\d+): \[u8; (\d+)\]\);', function)
    require(fields == [('0', '1'), ('1', '64'), ('2', '1')], 'complete metadata region widths')
    linear_fields(function, [(str(i), '[u8]', 'clear_owned_region(') for i in range(3)],
                  'unwind', 'Metadata')


def operations(function):
    guard = re.findall(r'debug cleanup => (_\d+);', function)
    require(len(guard) == 1, 'unique verification cleanup guard')
    guard = guard[0]
    require(re.search(r'let (?:mut )?' + guard +
                      r": hardened_in_place::core_state::Guard<'_>;", function), 'typed cleanup guard')
    blocks = mir.basic_blocks(function)
    calls = []
    for label, block in blocks.items():
        call = mir.call_definition(block)
        if call is None:
            continue
        target = call[1]
        kind = None
        if target in ('accumulate_secret_byte_difference(', 'secret_difference_is_zero('):
            kind = target
        elif target.endswith('backend::Reader>::secret('):
            kind = 'secret'
        elif target.endswith('backend::Reader>::final_secret('):
            kind = 'final_secret'
        if kind:
            calls.append((label, kind, call))
    require(Counter(kind for _, kind, _ in calls) == {
        'accumulate_secret_byte_difference(': 2, 'secret_difference_is_zero(': 1,
        'secret': 1, 'final_secret': 1}, 'complete verification-operation inventory')
    return guard, blocks, calls


def verification(function):
    """Every modeled exit after guard initialization/selected calls invokes Drop.

    Loops converge over (block, drop-invoked) states; termination is not proved.
    Drop invocation is not successful/non-unwinding cleanup or callee proof.
    """
    guard, blocks, calls = operations(function)
    initializers = [label for label, block in blocks.items()
                    if re.search(r'(?m)^\s*' + guard + r' = (?:copy|move) ', block)]
    require(len(initializers) == 1, 'unique live metadata-guard initialization')
    starts = [[(initializers[0], False)]]
    for _, _, call in calls:
        require(re.fullmatch(r'return: bb\d+, unwind: bb\d+', call[4]),
                'verification operation must retain normal and cleanup edges')
        starts.append([(edge, False) for edge in re.findall(r'\bbb\d+\b', call[4])])
    for todo in starts:
        seen, exits = set(), 0
        while todo:
            label, invoked = todo.pop()
            if (label, invoked) in seen:
                continue
            seen.add((label, invoked))
            require(label in blocks, 'dangling verification successor')
            block = blocks[label]
            drops = re.findall(r'\bdrop\(' + guard + r'\)', block)
            require(len(drops) <= 1 and not (invoked and drops), 'repeated guard Drop')
            invoked = invoked or bool(drops)
            edges = re.findall(r'\bbb\d+\b', block)
            exit_path = bool(re.search(r'\b(?:return|resume)\s*;|unwind continue', block))
            impossible = block.strip().rstrip('}').strip() == 'unreachable;'
            abort_path = 'unwind terminate(cleanup)' in block
            require(edges or exit_path or impossible or abort_path, 'unknown verification terminator')
            if exit_path:
                require(invoked, 'verification exit bypasses metadata guard: ' + label)
                exits += 1
            todo.extend((edge, invoked) for edge in edges)
        require(exits > 0, 'no modeled lifecycle exit')


def functions(record):
    handoffs.checked_functions(record, batch=True)
    for row in json.loads(record.read_text())['records']:
        paths = [record.parent / key for key in row['artifacts']
                 if Path(key).name.startswith('brynja_mac_kmac-') and key.endswith('.mir')]
        require(len(paths) == 1, 'unique actual KMAC MIR artifact')
        text = paths[0].read_text()
        yield (mir.exact_function(text, (PREFIX, '>::verify(')),
               mir.exact_function(text, (PREFIX, ">::drop(_1: &mut Guard<'_>)")),
               mir.exact_function(text, (PREFIX, '>::wipe(_1: &mut Metadata)')))


def main(record):
    before = recorded.audit.sources()
    count = 0
    for verify, drop, wipe in functions(record):
        verification(verify)
        guard_drop(drop)
        metadata_wipe(wipe)
        count += 1
    require(count == 8 and before == recorded.audit.sources(), 'incomplete or changing verification inputs')
    print('Scoped KMAC verification MIR: 8 initialized guards and 40 operation sites retain Drop on modeled return/unwind')
    print('Eight guard forwarders and three-field metadata clear sequences: PASS')
    print('Observation record SHA-256: ' + recorded.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(recorded.inspector_sources(), sort_keys=True))
    print('Generic MIR only: no monomorphized machine-code, register/spill, termination or non-unwinding cleanup proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
