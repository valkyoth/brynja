"""Qualify retained Storage drop glue, not fully inlined coordinator cleanup.

LLVM: symbolic original Vec fields, clear-before-deallocation on normal and
exceptional exits. Assembly: exact entry-to-clear argument handoff only; no
claim about machine unwind tables. Valid Vec layout and external ABI contracts
are assumptions. Positive capacity and arbitrary valid live length are symbols,
not sampled integers; allocated-but-empty Vecs are included in that abstraction.
"""
import re

import batch_worker_arguments as arguments
from batch_cleanup_flow import require, assembly_function

VALUE = r'%[\w.]+'
LABEL = r'(?:[\w.]+|"[^"\n]+")'
DEALLOC = r'_RNvCs[\w]+_7___rustc14___rust_dealloc'


def extract(row, panic):
    bodies = [body for body in re.findall(r'^define [\s\S]*?^}', row['ll'], re.M)
              if ('drop_in_place' in body.splitlines()[0] and
                  'execution..batch..worker..Storage' in body.splitlines()[0]) or
              ('drop_glue' in body.splitlines()[0] and
               '9execution5batch6worker7Storage' in body.splitlines()[0])]
    require(len(bodies) <= 1, 'unique retained Storage drop glue')
    if not bodies:
        require(panic == 'abort' and '4Drop4drop' in arguments.functions(row)[0],
                'only reviewed v0-mangled abort output may inline all Storage drop glue')
        return None
    body = bodies[0]
    symbol = re.search(r'@("[^"\n]+"|[\w]+)\(', body.splitlines()[0])[1].strip('"')
    return body, assembly_function(row['s'], (symbol,)), arguments.functions(row)[2]


def parse(body):
    blocks, current = {}, None
    for raw in body.splitlines()[1:]:
        line = raw.split(';', 1)[0].strip().split(', !', 1)[0]
        if not line or line == '}':
            continue
        label = re.fullmatch('(' + LABEL + r'):', line)
        if label:
            current = label[1]
            require(current not in blocks, 'unique glue block')
            blocks[current] = []
        else:
            require(current is not None, 'glue instruction in block')
            blocks[current].append(line)
    require('start' in blocks, 'glue entry block')
    for lines in blocks.values():
        for index, line in enumerate(lines):
            if line.startswith('invoke '):
                require(index == len(lines) - 2 and lines[index + 1].startswith('to label '),
                        'invoke terminates its glue block')
            if line.startswith('to label '):
                require(index > 0 and lines[index - 1].startswith('invoke '), 'paired invoke successors')
            if ' = landingpad ' in line:
                require(index == 0 and len(lines) > 1 and lines[1] == 'cleanup', 'complete landing pad')
            if line == 'cleanup':
                require(index == 1 and ' = landingpad ' in lines[0], 'paired landing-pad cleanup')
    return blocks


def llvm_check(body, clear, panic):
    owner = re.fullmatch(r'define internal fastcc void @(?:"[^"\n]+"|[\w]+)\(ptr '
                        r'(?:(?:noalias|nocapture|nofree|noundef|nonnull|readonly|align 8|captures\(none\)) )+'
                        r'dereferenceable\(24\) (' + VALUE + r')\) unnamed_addr #\d+'
                        r'(?: personality ptr @rust_eh_personality)? \{', body.splitlines()[0])
    require(owner is not None, 'valid Storage argument to drop glue')
    blocks, visited = parse(body), set()
    definitions = [match[1] for lines in blocks.values() for line in lines
                   if (match := re.match('(' + VALUE + r') = ', line))]
    require(len(set(definitions)) == len(definitions) and owner[1] not in definitions,
            'unique SSA definitions without rewriting owner input')
    for allocated in (False, True):
        for throws in ((False, True) if panic == 'unwind' else (False,)):
            env = {owner[1]: ('owner', 0)}
            capacity = ('capacity',) if allocated else 0
            length = ('length',) if allocated else 0
            field = {0: capacity, 8: ('base',), 16: length}
            block, clears, frees, unwinding = 'start', 0, 0, False
            def value(token):
                require(token in env or token.isdigit(), 'defined glue SSA operand')
                return env[token] if token in env else int(token)
            for _ in range(32):
                require(block in blocks, 'existing glue successor')
                visited.add(block)
                lines, successor, ended = blocks[block], None, False
                for line in lines:
                    require(not ended, 'no instruction after glue terminator')
                    assignment = re.fullmatch('(' + VALUE + r') = (.*)', line)
                    dest, op = assignment.groups() if assignment else (None, line)
                    if re.fullmatch(r'(?:tail )?call void @llvm.experimental.noalias.scope.decl\(metadata !\d+\)', op):
                        require(dest is None, 'void alias metadata')
                        continue
                    gep = re.fullmatch(r'getelementptr inbounds(?: nuw)? i8, ptr (' + VALUE + r'), i64 (8|16)', op)
                    load = re.fullmatch(r'load (ptr|i64), ptr (' + VALUE + r'), align 8', op)
                    cmp = re.fullmatch(r'icmp eq i64 (' + VALUE + r'), 0', op)
                    shift = re.fullmatch(r'shl nuw i64 (' + VALUE + r'), 8', op)
                    call = re.fullmatch(r'(?:tail call|invoke) fastcc void @' + re.escape(clear) +
                                       r'\(ptr nonnull (' + VALUE + r'), i64 (' + VALUE + r')\)(?: #\d+)?', op)
                    free = re.fullmatch(r'tail call void @' + DEALLOC + r'\(ptr noundef nonnull (' + VALUE +
                                        r'), i64 noundef (' + VALUE + r'), i64 noundef '
                                        r'range\(i64 1, -9223372036854775807\) 1\)(?: #\d+)?', op)
                    if gep:
                        require(dest and value(gep[1]) == ('owner', 0), 'field from original owner')
                        env[dest] = ('owner', int(gep[2]))
                    elif load:
                        pointer = value(load[2])
                        require(dest and isinstance(pointer, tuple) and len(pointer) == 2 and pointer[0] == 'owner'
                                and pointer[1] in field, 'load from original Vec field')
                        require(load[1] == ('ptr' if pointer[1] == 8 else 'i64'), 'full field load width')
                        env[dest] = field[pointer[1]]
                    elif cmp:
                        require(dest and value(cmp[1]) == capacity, 'capacity-only branch')
                        env[dest] = not allocated
                    elif shift:
                        require(dest and value(shift[1]) == capacity, 'full allocation size')
                        env[dest] = ('allocation_size',)
                    elif call:
                        require(dest is None and clears == frees == 0 and
                                value(call[1]) == ('base',) and value(call[2]) == length,
                                'original full live storage cleared exactly once before deallocation')
                        require(op.startswith('invoke') == (panic == 'unwind'), 'profile-correct clear edge')
                        clears += 1
                    elif free:
                        require(dest is None and clears == 1 and frees == 0 and allocated and
                                value(free[1]) == ('base',) and value(free[2]) == ('allocation_size',),
                                'original allocation freed once only after clearing')
                        frees += 1
                    elif op == 'landingpad { ptr, i32 }':
                        require(dest and unwinding, 'exception only on unwind edge')
                        env[dest] = ('exception',)
                    elif op == 'cleanup':
                        require(dest is None and unwinding, 'cleanup only after landing pad')
                    elif op == 'ret void' or op.startswith('resume '):
                        resume = re.fullmatch(r'resume \{ ptr, i32 \} (' + VALUE + ')', op)
                        require((op == 'ret void' or resume is not None) and
                                dest is None and clears == 1 and frees == int(allocated) and
                                (bool(resume) == unwinding) and
                                (resume is None or value(resume[1]) == ('exception',)), 'complete glue exit')
                        ended = True
                    else:
                        invoke = re.fullmatch(r'to label %(' + LABEL + r') unwind label %(' + LABEL + ')', op)
                        branch = re.fullmatch(r'br i1 (' + VALUE + r'), label %(' + LABEL + r'), label %(' + LABEL + ')', op)
                        jump = re.fullmatch(r'br label %(' + LABEL + ')', op)
                        require(dest is None, 'known glue instruction: ' + op)
                        if invoke:
                            require(clears == 1 and panic == 'unwind', 'clear invoke before successors')
                            successor, unwinding = invoke[2] if throws else invoke[1], throws
                        elif branch:
                            require(type(value(branch[1])) is bool, 'known glue condition')
                            successor = branch[2] if value(branch[1]) else branch[3]
                        elif jump:
                            successor = jump[1]
                        else:
                            raise ValueError('unknown glue instruction: ' + op)
                        ended = True
                require(ended, 'terminated glue block')
                if successor is None:
                    break
                block = successor
            else:
                raise ValueError('unbounded glue traversal')
    require(visited == set(blocks), 'all glue blocks exercised')


def entry_templates(clear):
    x86 = ['pushq %r15', 'pushq %r14', 'pushq %rbx', 'movq %rdi, %r15',
           'movq 8(%rdi), %rbx', 'movq 16(%rdi), %rsi', 'movq %rbx, %rdi', 'callq ' + clear]
    abort = ['pushq %r14', 'pushq %rbx', 'pushq %rax', 'movq %rdi, %r14'] + x86[4:]
    linux = ['stp x29, x30, [sp, #-32]!', 'stp x20, x19, [sp, #16]', 'mov x29, sp',
             'ldp x19, x1, [x0, #8]', 'mov x20, x0', 'mov x0, x19', 'bl ' + clear]
    linux_abort = linux[:2] + linux[3:5] + linux[2:3] + linux[5:]
    apple = ['stp x20, x19, [sp, #-32]!', 'stp x29, x30, [sp, #16]', 'add x29, sp, #16',
             'mov x20, x0', 'ldp x19, x1, [x0, #8]', 'mov x0, x19', 'bl _' + clear]
    return x86, abort, linux, linux_abort, apple


def assembly_check(body, clear):
    # Match the straight-line entry prefix before its first call. Everything
    # after that call (including LSDA and deallocation) remains LLVM-only here.
    code = []
    for raw in body.splitlines():
        line = raw.strip()
        require(';' not in line, 'no hidden instruction in glue prefix or CFI metadata')
        if (not line or (line.startswith('.cfi_') and line != '.cfi_endproc') or
                re.fullmatch(r'\.?L(?:func_begin|tmp)\d+:', line)):
            continue
        code.append(' '.join(line.split()))
        if line.startswith(('callq', 'bl\t', 'bl ')):
            break
    require(code in entry_templates(clear), 'exact glue entry-to-clear machine arguments')


def check(row, panic):
    result = extract(row, panic)
    if result is not None:
        llvm, assembly, clear = result
        llvm_check(llvm, clear, panic)
        assembly_check(assembly, clear)
    return result


def mutations(row, panic):
    result = check(row, panic)
    if result is None:
        return 0
    llvm, assembly, clear = result
    count = 0
    for original, inspector, edits in (
        (llvm, lambda body: llvm_check(body, clear, panic), (
            ('i64 8\n', 'i64 0\n'), ('i64 16\n', 'i64 8\n'),
            ('load i64', 'load i32'), ('icmp eq', 'icmp ne'),
            (', 8\n', ', 7\n'), ('i64 %self.val1.i)', 'i64 1)'),
            ('ptr nonnull %self.val.i,', 'ptr nonnull %_1,'),
            ('___rust_dealloc', '___wrong_dealloc'),
            ('ret void', 'store i8 1, ptr %_1\nret void'),
            ('ret void', 'resume invalid'), (clear, clear + '_wrong'),
            ('resume { ptr, i32 }', 'ret void ;'),
        )),
        (assembly, lambda body: assembly_check(body, clear), (
            ('8(%rdi)', '0(%rdi)'), ('16(%rdi)', '8(%rdi)'),
            ('%rbx, %rdi', '%rsi, %rdi'), ('movq', 'movl'),
            ('[x0, #8]', '[x0, #0]'), ('x19, x1', 'x19, x2'),
            ('x0, x19', 'x0, x1'), ('ldp', 'ldr'), (clear, clear + '_wrong'),
        )),
    ):
        for before, after in edits:
            if before not in original:
                continue
            try:
                inspector(original.replace(before, after))
            except ValueError:
                count += 1
                continue
            raise AssertionError('worker glue mutation survived: ' + before)
    require(count == (17 if panic == 'unwind' else 16), 'non-vacuous glue artifact mutants')
    return count
