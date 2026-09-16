"""Closed-grammar MIR checks for whole-field, straight-line batch destruction.

This is an artifact inspector, not a general MIR verifier. Unknown instructions,
projections, branch paths and partial slices fail closed. External clear methods'
non-panicking contracts remain required for unwind builds.
"""
import re

import mir_cleanup_flow as flow


def require(condition, message):
    if not condition:
        raise ValueError('batch cleanup evidence: ' + message)


def compact(value):
    return re.sub(r'\s+', '', value)


def linear_fields(function, expected, panic, owner):
    blocks = flow.basic_blocks(function)
    current, seen, observed = 'bb0', set(), []
    aliases = {'_1': ('self', compact(owner))}
    while current not in seen:
        require(current in blocks, 'missing successor')
        seen.add(current)
        block = blocks[current]
        call = flow.call_definition(block)
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line == '}' or line.startswith(('StorageLive(', 'StorageDead(')):
                continue
            if line == 'return;':
                require(call is None and observed == expected and seen == set(blocks),
                        'all mandatory fields and no alternate blocks')
                require(compact(block) == 'return;}}' or
                        compact(re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', block)) == 'return;}}',
                        'unmodeled terminal instructions')
                return
            if ' -> [' in line:
                continue
            field = re.fullmatch(r'(_\d+) = (?:&mut|(?:no_retag )?copy) \(\(\*_1\)\.(\d+): (.+)\);', line)
            cast = re.fullmatch(r'(_\d+) = (?:copy|move) (_\d+) as &mut (.+) \(PointerCoercion\(Unsize, Implicit\)\);', line)
            if field:
                aliases[field[1]] = (field[2], compact(field[3]))
            elif cast:
                require(cast[2] in aliases, 'unknown slice origin')
                origin, source_type = aliases[cast[2]]
                target_type = compact(cast[3])
                array = re.fullmatch(r'\[(.+);\d+\]', source_type)
                require(array and target_type == '[' + array[1] + ']', 'whole-array unsizing only')
                aliases[cast[1]] = (origin, target_type)
            else:
                raise ValueError('unreviewed cleanup instruction: ' + line)
        require(call is not None, 'missing straight-line call')
        destination, target, arguments, successor, edges = call
        argument = re.fullmatch(r'(?:move|copy) (_\d+)', arguments)
        require(argument and argument[1] in aliases, 'exact single owned argument')
        origin, kind = aliases[argument[1]]
        flatten = re.fullmatch(r'slice::<impl (.+)>::as_flattened_mut\(', target)
        if flatten:
            require(compact(flatten[1]) == kind and re.fullmatch(r'\[\[u8;\d+\]\]', kind),
                    'flatten must preserve a whole byte array slice')
            aliases[destination] = (origin, '[u8]')
        else:
            if target == 'clear_owned_region(':
                require(kind == '[u8]', 'clear must receive whole bytes')
            observed.append((origin, kind, target))
            aliases.pop(destination, None)
        require(edges == f'return: {successor}, unwind ' + ('unreachable' if panic == 'abort' else 'continue'),
                'unexpected unwind or branch edge')
        require(successor is not None, 'missing return edge')
        current = successor
    raise ValueError('cyclic straight-line cleanup')


def entry_cleanup(function, target, owner, panic):
    """A guard clears its exact workspace in bb0, before any completion branch."""
    block = flow.basic_blocks(function)['bb0']
    clean = re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', block)
    clean = compact(clean)
    pattern = (r'(?P<loan>_\d+)=(?:no_retag)?(?:copy|move)\(\(\*_1\)\.1:&mut' +
               re.escape(compact(owner)) + r'\);_\d+=' + re.escape(compact(target)) +
               r'(?:move|copy)(?P=loan)\)->\[return:bb\d+,unwind' +
               ('unreachable' if panic == 'abort' else 'continue') + r'\];\}')
    require(re.fullmatch(pattern, clean), 'guard must clear its exact workspace at entry')


def llvm_function(text, tokens):
    functions = re.findall(r'^define [^\n]*\{.*?^}', text, re.M | re.S)
    found = [body for body in functions if all(token in body.splitlines()[0] for token in tokens)]
    require(len(found) == 1, 'unique LLVM identity: ' + repr(tokens))
    return found[0]


def assembly_function(text, tokens):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = []
    for index, match in enumerate(labels):
        if all(token in match[1] for token in tokens):
            end = labels[index + 1].start() if index + 1 < len(labels) else len(text)
            found.append(text[match.end():end])
    require(len(found) == 1, 'unique assembly identity: ' + repr(tokens))
    return found[0]


def assembly_calls(body):
    """Resolve direct calls and x86 GOT-loaded callee-saved function registers."""
    aliases, calls, terminal = {}, [], False
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith(('.', '#', '//')) or line.endswith(':'):
            continue
        instruction = re.fullmatch(r'([a-z][a-z0-9.]*)\s*(.*)', line)
        require(instruction is not None, 'unrecognized assembly instruction')
        operation, arguments = instruction.groups()
        require(not terminal, 'instructions after a terminal branch/return')
        require(not re.fullmatch(r'j(?!mp)[a-z]+|b\..+|cbn?z|tbn?z', operation),
                'branch can bypass assembly cleanup')
        if operation in ('call', 'callq', 'jmp', 'jmpq', 'bl', 'b'):
            indirect = re.fullmatch(r'\*(%[a-z0-9]+)', arguments)
            if indirect:
                require(indirect[1] in aliases, 'unresolved indirect cleanup call')
                calls.append(aliases[indirect[1]])
            else:
                require(re.match(r'\*?_+(?:R|ZN)', arguments), 'non-Rust cleanup call or jump')
                calls.append(arguments)
            terminal = operation in ('jmp', 'jmpq', 'b')
            continue
        require(operation in ('movq', 'movl', 'movabsq', 'leaq', 'addq', 'subq', 'pushq', 'popq',
                              'retq', 'ret', 'add', 'sub', 'mov', 'stp', 'ldp', 'str', 'ldr'),
                'unreviewed non-call assembly instruction: ' + operation)
        if operation in ('ret', 'retq'):
            terminal = True
        destination = re.search(r'(%[a-z0-9]+)$', arguments)
        if destination and operation != 'pushq':
            register = destination[1]
            register = re.sub(r'^(%r1[2-5])[dwb]$', r'\1', register)
            register = {'%ebx': '%rbx', '%bx': '%rbx', '%bl': '%rbx', '%bh': '%rbx',
                        '%ebp': '%rbp', '%bp': '%rbp', '%bpl': '%rbp'}.get(register, register)
            aliases.pop(register, None)
        load = re.fullmatch(r'(_+(?:R|ZN)[^\s,]+)@GOTPCREL\(%rip\), (%(?:rbx|rbp|r1[2-5]))', arguments)
        if operation == 'movq' and load:
            aliases[load[2]] = load[1]
    return calls
