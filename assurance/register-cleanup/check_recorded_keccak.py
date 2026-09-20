#!/usr/bin/env python3
"""Inspect retained actual Keccak kernels; development only, no builds or gates."""
import argparse
import ast
import json
from pathlib import Path
import re
from unittest.mock import patch

import check as x86
import check_arm as aarch64
import check_recorded_boundaries as recorded
from batch_cleanup_flow import assembly_function

require = recorded.handoffs.require


def constants():
    # This independent oracle is already in the retained source closure.
    path = recorded.audit.ROOT / 'scripts/sha3/check-sha3-bit-differential.py'
    assignments = [node.value for node in ast.parse(path.read_text()).body
                   if isinstance(node, ast.Assign) and any(
                       isinstance(target, ast.Name) and target.id == 'ROUND_CONSTANTS'
                       for target in node.targets)]
    require(len(assignments) == 1, 'unique oracle constant table')
    values = ast.literal_eval(assignments[0])
    require(len(values) == 24, 'complete Keccak constant table')
    return b''.join(value.to_bytes(8, 'little') for value in values)


def public_table(text, label):
    name = re.escape(label)
    pattern = (r'(?m)^\s*\.section\s+\.rodata\.' + name + r',"a",@progbits\n'
               r'\s*\.p2align\s+3, 0x0\n' + name + r':\n'
               r'\s*\.ascii\s+("[^\n]*")\n\s*\.size\s+' + name + r', 192\n')
    matches = re.findall(pattern, text)
    require(len(matches) == 1 and len(re.findall('(?m)^' + name + ':$', text)) == 1,
            'unique read-only 192-byte Keccak table')
    require(ast.literal_eval('b' + matches[0]) == constants(), 'Keccak table bytes')


def kernel_body(text, arm, batch):
    tokens = ('brynja_crypto_cpu', 'keccak_hardened_batch',
              '3arm' if arm else '3x86', '6secret7permute') if batch else (
                  'brynja_crypto_cpu', 'aarch64_sha3_keccak' if arm else 'x86_avx2_keccak',
                  '6secret7permute')
    return assembly_function(text, tokens)


def inspect(text, arm, batch):
    body = kernel_body(text, arm, batch)
    body = re.sub(r'(?m)^\s*#+\s*BRYNJA_', '# BRYNJA_', body)
    body = re.sub(r'(?m)^\s*//\s*BRYNJA_', '// BRYNJA_', body)
    marker = ('// ' if arm else '# ') + 'BRYNJA_SECRET_BEGIN'
    require(body.count(marker) == 1, 'unique kernel beginning')
    before, rest = body.split(marker)
    # Release LLVM substitutes the one public constant pointer. Accept only
    # address formation, never a load, and only before the opaque secret block.
    if arm:
        pattern = (r'(?m)^\s*adrp\s+x8, (\.Lalloc_[a-f0-9]+)\n'
                   r'\s*add\s+x8, x8, :lo12:\1\n')
    else:
        register = 'rsi' if batch else 'r9'
        pattern = r'(?m)^\s*leaq\s+(\.Lalloc_[a-f0-9]+)\(%rip\), %' + register + r'\n'
    matches = list(re.finditer(pattern, before))
    require(len(matches) <= 1, 'ambiguous public table address')
    if matches:
        public_table(text, matches[0][1])
        before = before[:matches[0].start()] + before[matches[0].end():]
    body = before + marker + rest
    if arm:
        # The prototype has no literal-pool loads. In a whole crate, ldr can
        # instead name a label without brackets; do not mistake that for the
        # stack-only ldr operations accepted by the prototype checker.
        ends = rest.split('// BRYNJA_SECRET_END')
        require(len(ends) == 2, 'unique kernel end')
        after = re.split(r'(?m)^\s*ret\s*$', ends[1])[0]
        for line in (before + '\n' + after).splitlines():
            if re.match(r'\s*ldr\b', line):
                require('[' in line, 'literal memory load outside the opaque boundary')
        with patch.object(aarch64, 'GP', (4, 5, 6) if batch else (4, 5, 6, 7, 9)), \
                patch.object(aarch64, 'VECTOR', tuple(range(4))), \
                patch.object(aarch64, 'SHA256', False):
            aarch64.asm_check(body, keccak=not batch, batch512=batch, keccak_batch=batch)
    else:
        with patch.object(x86, 'REGISTERS', ('eax', 'ecx', 'edx') if batch else ('eax', 'ecx', 'edx', 'r8d')), \
                patch.object(x86, 'SHA256', False):
            x86.asm_check(body, keccak=not batch, batch512=batch, keccak_batch=batch)


def cases(record):
    recorded.handoffs.checked_functions(record, batch=True)
    for row in json.loads(record.read_text())['records']:
        paths = [record.parent / key for key in row['artifacts']
                 if Path(key).name.startswith('brynja_crypto_cpu-') and key.endswith('.s')]
        require(len(paths) == 1, 'unique actual CPU crate assembly')
        for batch in (False, True):
            yield paths[0].read_text(), row['target'].startswith('aarch64'), batch


def main(record):
    before = recorded.audit.sources()
    count = 0
    for text, arm, batch in cases(record):
        inspect(text, arm, batch)
        count += 1
    require(count == 16 and before == recorded.audit.sources(), 'incomplete or changing inputs')
    print('Actual single/multibuffer Keccak assembly boundaries: 16 PASS')
    print('Observation record SHA-256: ' + recorded.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(recorded.inspector_sources(), sort_keys=True))
    print('Development only: no build, runtime, native-platform or whole-caller qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record)
