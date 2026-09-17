"""Per-register, region, lane and SHA-256 recurrence negative controls."""


def specification(arch):
    if arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        gp = ('eax', 'ecx', 'edx')
        erase = [f'"xor {r}, {r}",' for r in gp]
        erase += [f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        poison = [f'"mov {r}, -1",' for r in gp]
        poison += [f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        algorithm = (
            ('"mov [{scratch} + rcx], rax",\n            "add rcx, 8",\n            "cmp rcx, 2304",',
             '"add rcx, 8",\n            "cmp rcx, 2304",'),
            ('"mov [{scratch} + rcx], rax",\n            "add rcx, 8",\n            "cmp rcx, 2752",',
             '"add rcx, 8",\n            "cmp rcx, 2752",'),
            ('"vpaddd ymm1, ymm1, [{scratch} + rcx - 512]",',
             '"vpaddd ymm1, ymm1, [{scratch} + rcx - 480]",'),
            ('"vpsrld ymm1, ymm0, 7",', '"vpsrld ymm1, ymm0, 8",'),
            ('"vpand ymm0, ymm0, ymm1",', '"vpxor ymm0, ymm0, ymm1",'),
            ('"vpaddd ymm0, ymm0, [{scratch} + rcx]",',
             '"vpaddd ymm0, ymm0, [{scratch} + rcx]",\n"vpshufd ymm0, ymm0, 0",'),
        )
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        gp = (4, 5, 6)
        erase = [f'"mov x{i}, xzr",' for i in gp]
        erase += [f'"movi v{i}.16b, #0",' for i in range(4)]
        poison = [f'"mov x{i}, #-1",' for i in gp]
        poison += [f'"movi v{i}.16b, #255",' for i in range(4)]
        algorithm = (
            ('"str xzr, [{scratch}, x4]",\n            "add x4, x4, #8",\n            "cmp x4, #2304",',
             '"add x4, x4, #8",\n            "cmp x4, #2304",'),
            ('"str xzr, [{scratch}, x4]",\n            "add x4, x4, #8",\n            "cmp x4, #2752",',
             '"add x4, x4, #8",\n            "cmp x4, #2752",'),
            ('"add x6, x6, #288",', '"add x6, x6, #256",'),
            ('"ushr v1.4s, v0.4s, #7",', '"ushr v1.4s, v0.4s, #8",'),
            ('"and v0.16b, v0.16b, v1.16b",', '"eor v0.16b, v0.16b, v1.16b",'),
            ('"ldr q1, [x6]",', '"ldr q1, [x6, #32]",'),
            ('"stp q0, q3, [x6]",', '"stp q0, q0, [x6]",'),
        )
    return marker, erase, poison, algorithm
