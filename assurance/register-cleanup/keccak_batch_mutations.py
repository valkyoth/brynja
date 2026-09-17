"""Runtime mutants: register erasure, every scratch region, rounds and isolation."""


def specification(arch):
    if arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        gp = ('eax', 'ecx', 'edx')
        erase = [f'"xor {r}, {r}",' for r in gp]
        erase += [f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        poison = [f'"mov {r}, -1",' for r in gp]
        poison += [f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        algorithm = [
            ('"mov ecx, 800",', '"mov ecx, 960",'),
            ('"mov ecx, 800",', '"mov ecx, 1120",'),
            ('"vmovdqu [{scratch} + rcx], ymm0",', ''),
            ('"vpsllq ymm1, ymm0, 62",', '"vpsllq ymm1, ymm0, 61",'),
            ('"vmovdqu [{scratch} + 1760], ymm0",', '"vmovdqu [{scratch} + 1728], ymm0",'),
            ('"vpandn ymm0, ymm0, [{scratch} + rcx + 1184]",',
             '"vpand ymm0, ymm0, [{scratch} + rcx + 1184]",'),
            ('"vpxor ymm0, ymm0, [{scratch}]",', ''),
            ('"vpxor ymm0, ymm0, [{scratch} + rcx + 640]",', ''),
            ('"cmp rax, 192",', '"cmp rax, 184",'),
            ('"vmovdqu [{scratch}], ymm0",',
             '"vpermq ymm0, ymm0, 0x39",\n"vmovdqu [{scratch}], ymm0",'),
        ]
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        gp = (4, 5, 6)
        erase = [f'"mov x{i}, xzr",' for i in gp]
        erase += [f'"movi v{i}.16b, #0",' for i in range(4)]
        poison = [f'"mov x{i}, #-1",' for i in gp]
        poison += [f'"movi v{i}.16b, #255",' for i in range(4)]
        algorithm = [
            ('"mov x5, #800",', '"mov x5, #960",'),
            ('"mov x5, #800",', '"mov x5, #1120",'),
            ('"cmp x5, #1920",', '"cmp x5, #1904",'),
            ('"mov x5, #16",', '"mov x5, #48",'),
            ('"shl v1.2d, v0.2d, #62",', '"shl v1.2d, v0.2d, #61",'),
            ('"str q0, [{scratch}, #1760]",', '"str q0, [{scratch}, #1728]",'),
            ('"ld1r {{v0.2d}}, [x6]",', '"movi v0.16b, #0",'),
            ('"ldr q1, [x6, #640]",', '"ldr q1, [x6, #480]",'),
            ('"cmp x4, #192",', '"cmp x4, #184",'),
            ('"str q0, [{scratch}]",',
             '"ext v0.16b, v0.16b, v0.16b, #8",\n"str q0, [{scratch}]",'),
        ]
    return marker, erase, poison, algorithm
