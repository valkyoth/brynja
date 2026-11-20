"""Exact x86-64 capture call-chain mapping; NOT complete D3/C1 qualification.

These narrow patterns describe one reviewed compiler shape, not a general
disassembler or symbolic execution engine. Any changed shape stays unmapped.
"""
import hashlib
import json
import re

SYMBOLS = {
    "capture": "brynja_crypto::aes::fault_integrity::capture::pair",
    "wrapper": "brynja_core::secret_memory::copy_secret_region",
    "copy": "brynja_core::secret_memory_transfer::copy_bytes",
}


def lines(text):
    return text.strip().splitlines()


EXPECTED = {
    # Entry: source rdi/rsi, first rdx/rcx, second r8/r9. After equal-length
    # admission, r14 retains the source pointer, rbx its length, r15 second.
    # Each wrapper call receives a distinct destination and the SAME source.
    "capture": lines("""push %rbp
push %r15
push %r14
push %rbx
push %rax
xor %rsi,%rcx
xor %rsi,%r9
mov $0x1,%bpl
or %rcx,%r9
jne @26
mov %rsi,%rbx
mov %rdi,%r14
mov %r8,%r15
mov %rdx,%rdi
mov %r14,%rdx
mov %rsi,%rcx
call @wrapper
cmp $0xff,%al
jne @26
mov %r15,%rdi
mov %rbx,%rsi
mov %r14,%rdx
mov %rbx,%rcx
call @wrapper
cmp $0xff,%al
setne %bpl
mov %ebp,%eax
add $0x8,%rsp
pop %rbx
pop %r14
pop %r15
pop %rbp
ret"""),
    # Wrapper receives destination rdi/rsi and source rdx/rcx. It forwards
    # destination rdi, source rsi, length rdx to the opaque C-ABI copy leaf.
    "wrapper": lines("""mov $0x2,%al
cmp %rcx,%rsi
jne @10
push %rax
mov %rsi,%r8
mov %rdx,%rsi
mov %r8,%rdx
call @copy
mov $0xff,%al
add $0x8,%rsp
ret"""),
    "copy": lines("""mov %rdx,%r8
xor %ecx,%ecx
mov %r8,%rdx
cmp $0x8,%rdx
jb @11
mov (%rsi,%rcx,1),%rax
mov %rax,(%rdi,%rcx,1)
add $0x8,%rcx
sub $0x8,%rdx
cmp $0x8,%rdx
jae @5
test %rdx,%rdx
je @18
movzbl (%rsi,%rcx,1),%eax
mov %al,(%rdi,%rcx,1)
inc %rcx
dec %rdx
jne @13
xor %eax,%eax
xor %ecx,%ecx
xor %edx,%edx
ret"""),
}
EVENTS = {
    "capture": {"entry": 0, "first_call": 16, "after_first_call": 17,
                "second_call": 23, "after_second_call": 24, "return": 32},
    "wrapper": {"entry": 0, "copy_call": 7, "after_copy_call": 8, "return": 10},
    "copy": {"entry": 0, "word_load": 5, "word_store": 6,
             "byte_load": 13, "byte_store": 14, "return": 21},
}

# A second observed shape retains the source in r15, second destination in r14,
# and uses a different Result niche. The wrapper and caller must agree: never
# accept a loose mix of register/return variants or assume Rust has a fixed ABI.
ALTERNATE_CAPTURE = lines("""push %rbp
push %r15
push %r14
push %rbx
push %rax
xor %rsi,%rcx
xor %rsi,%r9
mov $0x1,%bpl
or %rcx,%r9
jne @26
mov %r8,%r14
mov %rsi,%rbx
mov %rdi,%r15
mov %rdx,%rdi
mov %r15,%rdx
mov %rsi,%rcx
call @wrapper
cmp $0x4,%al
jne @26
mov %r14,%rdi
mov %rbx,%rsi
mov %r15,%rdx
mov %rbx,%rcx
call @wrapper
cmp $0x4,%al
setne %bpl
mov %ebp,%eax
add $0x8,%rsp
pop %rbx
pop %r14
pop %r15
pop %rbp
ret""")
PATTERNS = {
    "source-r14-result-ff": EXPECTED,
    "source-r15-result-04": {
        "capture": ALTERNATE_CAPTURE,
        "wrapper": [op.replace("mov $0xff,%al", "mov $0x4,%al") for op in EXPECTED["wrapper"]],
        "copy": EXPECTED["copy"],
    },
}


def canonical(name):
    return re.sub(r"::h[0-9a-f]{16}$", "", name)


def inspect(dump):
    reverse = {name: role for role, name in SYMBOLS.items()}
    bodies, names, starts = {}, {}, {}
    selected = None
    for line in dump.splitlines():
        header = re.fullmatch(r"\s*([0-9a-fA-F]+) <(.+)>:\s*", line)
        if header:
            selected = reverse.get(canonical(header[2]))
            if selected:
                if selected in bodies:
                    raise ValueError("duplicate capture-chain symbol")
                bodies[selected] = []
                starts[selected] = int(header[1], 16)
                names[selected] = header[2]
        elif selected and line.strip():
            instruction = re.fullmatch(r"\s*([0-9a-fA-F]+):\s+(.+?)\s*", line)
            if not instruction:
                raise ValueError("unparsed capture-chain instruction")
            op = re.sub(r"\s+", " ", instruction[2]).replace(", ", ",")
            bodies[selected].append((int(instruction[1], 16), op))
    if set(bodies) != set(SYMBOLS) or len(set(starts.values())) != len(SYMBOLS):
        raise ValueError("missing or aliased capture-chain symbols")
    result, used_addresses, candidates = {}, set(), set(PATTERNS)
    for role, body in bodies.items():
        while body and body[-1][1] == "int3":
            body.pop()
        addresses = [address for address, _ in body]
        if (not addresses or addresses[0] != starts[role]
                or addresses != sorted(set(addresses)) or used_addresses.intersection(addresses)):
            raise ValueError("invalid capture-chain addresses")
        used_addresses.update(addresses)
        normalized = []
        for _, op in body:
            branch = re.fullmatch(r"(jne|je|jb|jae) ([0-9a-fA-F]+) <(.+)>", op)
            call = re.fullmatch(r"call ([0-9a-fA-F]+) <(.+)>", op)
            if branch:
                target = int(branch[2], 16)
                if target not in addresses:
                    raise ValueError("nonlocal or misaligned capture-chain branch")
                op = branch[1] + " @" + str(addresses.index(target))
            elif call:
                target = reverse.get(canonical(call[2]))
                if target is None or int(call[1], 16) != starts[target]:
                    raise ValueError("unresolved capture-chain call")
                op = "call @" + target
            normalized.append(op)
        candidates = {candidate for candidate in candidates if normalized == PATTERNS[candidate][role]}
        if not candidates:
            raise ValueError("unreviewed capture-chain instruction shape: " + role)
        result[role] = {
            "symbol": names[role], "elf_address": starts[role],
            "events": {event: addresses[index] - starts[role] for event, index in EVENTS[role].items()},
            "normalized_sha256": hashlib.sha256(json.dumps(normalized).encode()).hexdigest(),
        }
    if len(candidates) != 1:
        raise ValueError("ambiguous capture-chain pattern")
    for function in result.values():
        function["shape"] = next(iter(candidates))
    return result
