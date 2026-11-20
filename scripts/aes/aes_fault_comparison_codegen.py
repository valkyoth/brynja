"""Exact bounded leaf observations; not caller, timing or fault qualification."""
import hashlib
import re

PREFIX = 'brynja_core::fault_comparison_workbench::opaque::'


def lines(text):
    return [line.strip() for line in text.strip().splitlines()]


X86_PREFIX = lines('''push %rbx
mov %rcx,%r11
mov %rdx,%rbx''')
X86_END = lines('''mov %r9b,(%rdi)
mov %r10b,0x1(%rdi)
xor %eax,%eax
xor %ecx,%ecx
xor %edx,%edx
xor %r8d,%r8d
xor %r9d,%r9d
xor %r10d,%r10d
pop %rbx
ret''')
ARM_END = lines('''strb w7,[x0]
strb w8,[x0,#0x1]
mov x4,xzr
mov x5,xzr
mov x6,xzr
mov x7,xzr
mov x8,xzr
cmp xzr,xzr
ret''')
EXPECTED = {
    ('x86_64', 'forward'): X86_PREFIX + lines('''xor %ecx,%ecx
xor %r9d,%r9d
xor %r10d,%r10d
movzbl (%rsi,%rcx,1),%eax
movzbl (%rbx,%rcx,1),%edx
xor %al,%dl
or %dl,%r9b
movzbl (%r11,%rcx,1),%r8d
xor %al,%r8b
or %r8b,%r10b
inc %ecx
cmp $0x10,%ecx
jb @6''') + X86_END,
    ('x86_64', 'reverse'): X86_PREFIX + lines('''mov $0x10,%ecx
mov $0xff,%r9d
mov $0xff,%r10d
dec %ecx
movzbl (%rsi,%rcx,1),%eax
not %al
movzbl (%rbx,%rcx,1),%edx
xor %al,%dl
and %dl,%r9b
movzbl (%r11,%rcx,1),%r8d
xor %al,%r8b
and %r8b,%r10b
test %ecx,%ecx
jne @6''') + X86_END,
    ('aarch64', 'forward'): lines('''mov x4,xzr
mov x7,xzr
mov x8,xzr
ldrb w5,[x1,x4]
ldrb w6,[x2,x4]
eor w6,w6,w5
orr w7,w7,w6
ldrb w6,[x3,x4]
eor w6,w6,w5
orr w8,w8,w6
add x4,x4,#0x1
cmp x4,#0x10
b.lo @3''') + ARM_END,
    ('aarch64', 'reverse'): lines('''mov x4,#0x10
mov w7,#0xff
mov w8,#0xff
sub x4,x4,#0x1
ldrb w5,[x1,x4]
mvn w5,w5
ldrb w6,[x2,x4]
eor w6,w6,w5
and w7,w7,w6
ldrb w6,[x3,x4]
eor w6,w6,w5
and w8,w8,w6
cbnz x4,@3''') + ARM_END,
}


def inspect(text, arch):
    if arch not in ('x86_64', 'aarch64'):
        raise ValueError('unsupported observation target')
    header = re.compile(r'^\s*([0-9a-fA-F]+) <(.+)>:\s*$')
    bodies, starts, selected = {}, {}, None
    for line in text.splitlines():
        match = header.fullmatch(line)
        if match:
            # Legacy Rust demangling retains a 16-hex hash on some toolchains.
            # Strip only that exact suffix; duplicates still fail below.
            name = re.sub(r'::h[0-9a-f]{16}$', '', match[2])
            selected = name[len(PREFIX):] if name in (PREFIX+'forward', PREFIX+'reverse') else None
            if selected:
                if selected in bodies:
                    raise ValueError('duplicate comparison symbol')
                bodies[selected] = []
                starts[selected] = int(match[1], 16)
        elif selected and line.strip():
            instruction = re.fullmatch(r'\s*([0-9a-fA-F]+):\s+(.+?)\s*', line)
            if not instruction:
                raise ValueError('unparsed selected instruction')
            operation = instruction[2].split('//', 1)[0].strip()
            operation = re.sub(r'\s+', ' ', operation).replace(', ', ',')
            bodies[selected].append((int(instruction[1], 16), operation))
    if set(bodies) != {'forward', 'reverse'} or len(set(starts.values())) != 2:
        raise ValueError('missing or aliased comparison leaves')
    result = {}
    for role, body in bodies.items():
        # GNU x86 objdump prints alignment traps after RET; no other tail allowed.
        while arch == 'x86_64' and body and body[-1][1] == 'int3':
            body.pop()
        addresses = [address for address, _ in body]
        if not addresses or addresses[0] != starts[role] or addresses != sorted(set(addresses)):
            raise ValueError('invalid instruction addresses')
        normalized = []
        for _, operation in body:
            branch = re.fullmatch(r'(jb|jne|b\.lo|cbnz x4,)\s*(?:0x)?([0-9a-fA-F]+)(?: <[^>]+>)?', operation)
            if branch:
                target = int(branch[2], 16)
                if target not in addresses:
                    raise ValueError('branch outside selected leaf')
                space = '' if branch[1].endswith(',') else ' '
                operation = branch[1] + space + '@' + str(addresses.index(target))
            normalized.append(operation)
        if normalized != EXPECTED[arch, role]:
            raise ValueError('unreviewed comparison leaf: ' + role)
        result[role] = dict(instructions=len(normalized),
                            sha256=hashlib.sha256(('\n'.join(normalized)+'\n').encode()).hexdigest())
    return result
