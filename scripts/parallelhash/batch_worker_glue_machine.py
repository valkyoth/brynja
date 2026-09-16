"""Closed normal-return Storage drop-glue sequences through deallocation.

For a valid immutable Vec header: clear original base/live length; test capacity;
free original base with size=capacity*256 and alignment=1 iff capacity != 0.
Matched epilogues restore the saved registers/frame before return or tail-call.
This assumes reviewed non-unwinding clear/deallocator and callee ABI contracts.
It does not interpret CFI/LSDA, execute exception tails, prove allocator internals
or establish that arbitrary callers supplied a valid Vec. Inlined glue is separate.
"""
import re

import batch_worker_drop_glue as glue
from batch_cleanup_flow import require


def template(clear, free, arm, apple, panic):
    entries = glue.entry_templates(clear)
    if not arm:
        abort = panic == 'abort'
        owner = '%r14' if abort else '%r15'
        restore = ['addq $8, %rsp', 'popq %rbx', 'popq %r14'] if abort else [
            'popq %rbx', 'popq %r14', 'popq %r15']
        suffix = [f'movq ({owner}), %rsi', 'testq %rsi, %rsi', 'je ZERO',
                  'shlq $8, %rsi', 'movl $1, %edx', 'movq %rbx, %rdi',
                  *restore, f'jmpq *{free}@GOTPCREL(%rip)', 'ZERO:', *restore, 'retq']
        return entries[int(abort)] + suffix
    if apple:
        entry = entries[4]
        restore = ['ldp x29, x30, [sp, #16]', 'ldp x20, x19, [sp], #32']
    else:
        entry = entries[3 if panic == 'abort' else 2]
        restore = ['ldp x20, x19, [sp, #16]', 'ldp x29, x30, [sp], #32']
    free = '_' + free if apple else free
    work = ['lsl x1, x8, #8', 'mov x0, x19', 'mov w2, #1', *restore]
    if not apple and panic == 'abort':
        work = ['mov x0, x19', restore[0], 'lsl x1, x8, #8', 'mov w2, #1', restore[1]]
    return entry + ['ldr x8, [x20]', 'cbz x8, ZERO', *work, 'b ' + free,
                    'ZERO:', *restore, 'ret']


def parse(body):
    code, labels, raw_lines = [], {}, []
    for index, raw in enumerate(body.splitlines()):
        line = ' '.join(raw.split('//', 1)[0].split())
        require(';' not in line, 'no hidden glue machine instructions')
        if line == '.cfi_endproc' or line.startswith(('.section ', '.globl ', '.type ')):
            break
        if not line or line.startswith(('.cfi_', '.size ')) or re.fullmatch(r'\.p2align \d+(?:, 0x[0-9a-f]+)?', line):
            continue
        if re.fullmatch(r'\.?L(?:BB[\w]+|tmp\d+|func_(?:begin|end)\d+):', line):
            require(line[:-1] not in labels, 'unique glue machine label')
            labels[line[:-1]] = len(code)
            continue
        code.append(line)
        raw_lines.append(index)
    return code, labels, raw_lines


def inspect(body, clear, free, arm, apple, panic):
    require(panic in ('abort', 'unwind') and (not apple or arm), 'reviewed glue machine profile/target')
    require(re.fullmatch(glue.DEALLOC, free), 'reviewed Rust deallocator identity')
    code, labels, raw = parse(body)
    pattern = template(clear, free, arm, apple, panic)
    zero = pattern.index('ZERO:')
    expected = pattern[:zero] + pattern[zero + 1:]
    branch = next(i for i, line in enumerate(expected) if 'ZERO' in line)
    prefix = 'cbz x8, ' if arm else 'je '
    require(len(code) >= len(expected) and code[branch].startswith(prefix), 'complete normal drop-glue paths')
    target = code[branch].removeprefix(prefix)
    require(labels.get(target) == zero, 'capacity-zero branch reaches exact returning epilogue')
    expected[branch] = expected[branch].replace('ZERO', target)
    require(code[:len(expected)] == expected, 'normal machine glue must clear then free original allocation with exact ABI')
    # Both normal paths end inside the matched prefix. Only the separately
    # scoped exception tail can remain after this returning epilogue.
    return len(expected), raw


def check(row, panic):
    result = glue.check(row, panic)
    if result is None:
        return None
    llvm, body, clear = result
    frees = set(re.findall('@(' + glue.DEALLOC + r')\(', llvm))
    require(len(frees) == 1, 'one LLVM-bound deallocator identity')
    triple = re.search(r'^target triple = "([\w.-]+)"$', row['ll'], re.M)
    require(triple and triple[1] in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                                    'arm64-apple-macosx11.0.0'), 'reviewed glue machine target')
    args = body, clear, frees.pop(), not triple[1].startswith('x86'), 'apple' in triple[1], panic
    return args, inspect(*args)


def mutations(row, panic):
    result = check(row, panic)
    if result is None:
        return 0
    args, (extent, raw) = result
    body, clear, free, arm, apple, _ = args
    prefix = next(i for i, line in enumerate(parse(body)[0]) if line.startswith(('callq ', 'bl '))) + 1
    lines, count = body.splitlines(keepends=True), 0
    for pc in range(prefix, extent):
        index = raw[pc]
        for replacement in ('', 'bl _wrong' if arm else 'callq _wrong'):
            changed = ''.join(lines[:index] + [replacement + '\n'] + lines[index + 1:])
            glue.assembly_check(changed, clear)  # Old entry-only check must still pass.
            try:
                inspect(changed, clear, free, arm, apple, panic)
            except ValueError:
                count += 1
            else:
                raise AssertionError('post-clear machine glue mutation survived')
    return count
