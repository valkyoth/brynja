"""Explicit scalar primitive reuse across the two saved SIMD images.

Only named ABI substitutions are accepted. No arbitrary feature stripping,
reference renaming, inferred range removal or blanket helper reuse is allowed.
Caller alias/lifetime and positive zeroizer-length obligations remain separate.
"""
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_batch_reuse as prior
import windows_enclave_sha2_simd_kernel as kernel

FEATURES = '+cx16,+sse,+sse2,+sse3,+sahf'
SIMD_FEATURES = FEATURES + (',+avx,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3'
    ',+avx,+avx2,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3')
BOUND = 1 << 63


def substitute(text, old, new):
    s.require(text.count(old) == 1, 'unique explicit primitive ABI substitution')
    return text.replace(old, new)


def abi(before, current, role):
    s.require(role in ('compress', 'wipe', 'copy', 'bytes', 'zero'), 'named primitive role')
    expected = substitute(before, f'"target-features"="{FEATURES}"', f'"target-features"="{SIMD_FEATURES}"')
    if role in ('copy', 'bytes'):
        argument = '%1' if role == 'copy' else '%2'
        expected = substitute(expected, f'range(i64 0, 256) {argument}',
                              f'range(i64 0, -9223372036854775808) {argument}')
    if role == 'zero':
        expected = substitute(expected, 'range(i64 0, -9223372036854775808) %1',
                              'range(i64 1, -9223372036854775808) %1')
    s.require(current == expected, 'only explicitly reviewed primitive ABI changes')


def transfer_geometry(length):
    s.require(type(length) is int and 0 <= length < BOUND, 'copy ABI byte count')
    words, tail = divmod(length, 8)
    return dict(word_iterations=words, byte_iterations=tail,
                word_end=words * 8, tail_end=words * 8 + tail,
                last_word=None if not words else (words - 1) * 8,
                last_byte=None if not tail else length - 1)


def zero_geometry(length):
    s.require(type(length) is int and 0 < length < BOUND, 'positive zeroizer ABI count')
    tail = length % 8
    return dict(prefix=(0, tail), word_iterations=length // 8, word_start=tail,
                word_end=length, last_word=None if length < 8 else length - 8)


def zeroizer(bodies):
    expected = ['movq %rdx, %r8', 'movq %rcx, %rax', 'andq $7, %r8', 'je .B3',
        'movq %rcx, %rax', '.p2align 4', '.B2:', 'movb $0, (%rax)', 'incq %rax',
        'decq %r8', 'jne .B2', '.B3:', 'cmpq $8, %rdx', 'jb .B6', 'addq %rdx, %rcx',
        '.p2align 4', '.B5:', 'movb $0, (%rax)']
    expected += [f'movb $0, {i}(%rax)' for i in range(1, 8)]
    expected += ['addq $8, %rax', 'cmpq %rcx, %rax', 'jne .B5', '.B6:', 'retq']
    s.require(s.lines(bodies[s.ZERO])[2:] == expected, 'complete positive-length zeroizer')
    return dict(function=s.ZERO, instructions=len(expected), no_calls=True,
                stores='byte prefix then eight individual byte stores per iteration',
                positive_length_caller_precondition=True, all_callers_checked=False)


def names(functions, lane):
    s.require(lane in ('simd256', 'simd512'), 'known SIMD primitive family')
    return {role: s.one(functions, regex) for role, regex in (
        ('compress', r'hardened10compress' + ('32' if lane == 'simd256' else '64') + r'6native6scalar$'),
        ('wipe', r'HardenedSha2Owner4wipe$'), ('copy', r'secret_memory18copy_secret_region$'),
        ('bytes', r'secret_memory_transfer10copy_bytes$'))}


def helpers(functions, previous, ir, old_ir, lane, constants):
    selected = names(functions, lane); matched = {}
    new_table = kernel.CONSTANTS[lane]
    old_table = prior.scalar.shapes.ROUND32 if lane == 'simd256' else prior.scalar.shapes.ROUND64
    raw = kernel.round_constants(lane)
    s.require(new_table in constants and constants[new_table]['bytes'] == len(raw) and
              constants[new_table]['sha256'] == prior.digest(raw), 'current linked scalar round table')
    s.require(prior.scalar.CONSTANTS[old_table] == (len(raw), prior.digest(raw)),
              'independent constants equal reproduced scalar table')
    for role, name in selected.items():
        s.require(name in previous, 'explicitly reused primitive present in earlier review')
        code, refs, kind = functions[name]; old_code, old_refs, old_kind = previous[name]
        s.require(code == old_code and kind == old_kind, 'complete reused primitive bytes and extent kind')
        expected = old_refs
        if role == 'compress':
            offset = 14 if lane == 'simd256' else 17
            s.require(old_refs == [dict(offset=offset, symbol=old_table, trailing=0, addend=0)],
                      'sole original compression round-table relocation')
            expected = [dict(offset=offset, symbol=new_table, trailing=0, addend=0)]
        s.require(refs == expected, 'exact primitive references with one reviewed table rename')
        before, current = prior.reuse.abi(old_ir, name), prior.reuse.abi(ir, name)
        abi(before, current, role)
        matched[role] = dict(function=name, bytes=len(code), sha256=prior.digest(code),
            abi_sha256=prior.digest(current.encode()), previous_abi_sha256=prior.digest(before.encode()))
    abi(prior.reuse.abi(old_ir, s.ZERO), prior.reuse.abi(ir, s.ZERO), 'zero')
    return matched


def inspect(base, lane, functions, ir, bodies, constants):
    row, data, old_ir, report = prior.prior(base, 'scalar')
    previous = prior.c.previous.inventory(data)
    matched = helpers(functions, previous, ir, old_ir, lane, constants)
    return dict(prior_route=row['route'], prior_image_sha256=report['image_sha256'],
        prior_object_sha256=report['object_sha256'], prior_semantic_review_replayed=True,
        exact_instruction_contracts=matched, changed_zeroizer_separately_reviewed=zeroizer(bodies),
        round_constants_rebound_and_independently_derived=True,
        only_explicit_target_feature_and_length_range_substitutions=True,
        copy_length_scope='nonoverlapping valid regions shorter than 2**63 bytes',
        current_image_references_rebound_by_parent=True,
        caller_alias_lifetime_and_positive_zeroizer_lengths_pending=True,
        unlisted_equal_bodies_implicitly_qualified=False, whole_frame_qualified=False)
