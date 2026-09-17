"""Per-register, region, lane and SHA-512 recurrence negative controls."""


def specification(arch):
    if arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        gp = ('eax', 'ecx', 'edx')
        erase = [f'"xor {r}, {r}",' for r in gp]
        erase += [f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        poison = [f'"mov {r}, -1",' for r in gp]
        poison += [f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        algorithm = (
            ('"mov [{scratch} + rcx], rax",\n            "add rcx, 8",\n            "cmp rcx, 2816",',
             '"add rcx, 8",\n            "cmp rcx, 2816",'),
            ('"mov [{scratch} + rcx], rax",\n            "add rcx, 8",\n            "cmp rcx, 3264",',
             '"add rcx, 8",\n            "cmp rcx, 3264",'),
            ('"vpaddq ymm1, ymm1, [{scratch} + rcx - 512]",',
             '"vpaddq ymm1, ymm1, [{scratch} + rcx - 480]",'),
            ('"vpsrlq ymm1, ymm0, 1",', '"vpsrlq ymm1, ymm0, 2",'),
            ('"vpand ymm0, ymm0, ymm1",', '"vpxor ymm0, ymm0, ymm1",'),
            ('"vpaddq ymm0, ymm0, [{scratch} + rcx]",',
             '"vpaddq ymm0, ymm0, [{scratch} + rcx]",\n"vpshufd ymm0, ymm0, 0",'),
        )
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        gp = (4, 5, 6)
        erase = [f'"mov x{i}, xzr",' for i in gp]
        erase += [f'"movi v{i}.16b, #0",' for i in range(4)]
        poison = [f'"mov x{i}, #-1",' for i in gp]
        poison += [f'"movi v{i}.16b, #255",' for i in range(4)]
        algorithm = (
            ('"str xzr, [{scratch}, x4]",\n            "add x4, x4, #8",\n            "cmp x4, #2816",',
             '"add x4, x4, #8",\n            "cmp x4, #2816",'),
            ('"str xzr, [{scratch}, x4]",\n            "add x4, x4, #8",\n            "cmp x4, #3264",',
             '"add x4, x4, #8",\n            "cmp x4, #3264",'),
            ('"add x6, x6, #288",', '"add x6, x6, #256",'),
            ('"ushr v1.2d, v0.2d, #1",', '"ushr v1.2d, v0.2d, #2",'),
            ('"and v0.16b, v0.16b, v1.16b",', '"eor v0.16b, v0.16b, v1.16b",'),
            ('"ldr q1, [x6]",', '"ldr q1, [x6, #32]",'),
            ('"stp q0, q3, [x6]",', '"stp q0, q0, [x6]",'),
        )
    return marker, erase, poison, algorithm
