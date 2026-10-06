"""Saved SIMD scalar-finalization contracts, not complete frame qualification."""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_finish256 as narrow
import windows_enclave_sha2_simd_finish512 as wide
import windows_enclave_sha2_simd_vector as vector


def geometry(lane, available, bits, consumed):
    _, _, block = vector.parameters(lane)
    for value in (available, bits, consumed): vector.unsigned(value)
    s.require(available == (bits + 7) // 8, 'caller canonical input extent')
    whole, remainder = divmod(bits // 8, block)
    s.require(consumed <= whole, 'SIMD consumed offset cannot exceed complete blocks')
    return dict(first=consumed * block, end=whole * block,
                blocks=whole - consumed, remainder=remainder,
                padding_blocks=1 + int(remainder >= block - (8 if lane == 'simd256' else 16)))


def padding(lane, remainder, partial, bits):
    """Independent byte-level model of the reviewed separator/length stores.

The caller supplies only complete trailing bytes plus the canonical partial
byte (if any). No production compression routine or fixture is called here.
"""
    _, _, block = vector.parameters(lane); vector.unsigned(bits)
    s.require(type(remainder) is bytes and len(remainder) == (bits // 8) % block,
              'exact scalar remainder')
    s.require(type(partial) is int and 0 <= partial <= 255, 'byte-shaped partial input')
    valid = bits % 8
    s.require(valid == 0 or partial & (255 >> valid) == 0, 'caller canonical partial byte')
    length_bytes = 8 if lane == 'simd256' else 16
    count = 1 + int(len(remainder) >= block - length_bytes)
    result = bytearray(count * block)
    result[:len(remainder)] = remainder
    result[len(remainder)] = 128 if valid == 0 else partial | (128 >> valid)
    result[-length_bytes:] = bits.to_bytes(length_bytes, 'big')
    return bytes(result)


def wide_output(tag, parameter=0):
    s.require(type(tag) is int and 0 <= tag <= 4, 'five typed wide identities')
    s.require(type(parameter) is int and 0 <= parameter <= 65535, 'typed general output parameter')
    if tag == 4:
        s.require(0 < parameter < 512 and parameter != 384, 'caller valid SHA-512/t parameter')
    bits = (384, 512, 224, 256, parameter)[tag]
    width = (bits + 7) // 8
    return width, (255 << ((-bits) % 8)) & 255


def region(bodies, lane):
    vector.parameters(lane); spec = narrow if lane == 'simd256' else wide
    values = {'zero': s.ZERO}
    for key, expression in (
        ('copy', r'secret_memory18copy_secret_region$'), ('wipe', r'HardenedSha2Owner4wipe$'),
        ('compress', r'hardened10compress' + ('32' if lane == 'simd256' else '64') + r'6native6scalar$'),
        ('padding', r'engine7padding$'), ('mask', r'secret_memory22apply_secret_byte_mask$')):
        values[key] = s.one(bodies, expression)
    return spec.START, spec.END, spec.CODE.format(**values).strip().splitlines()


def tables(assembly):
    result = {}
    for index, labels in ((5, [212, 216, 214, 215, 213]), (6, [220, 224, 222, 223, 221])):
        name = f'.LJTI23_{index}'
        found = re.findall(r'^' + re.escape(name) + r':\n((?:\s*\.long\s+[^\n]+\n)+)', assembly, re.M)
        s.require(len(found) == 1, 'unique scalar finish variant table')
        s.require(re.findall(r'\.long\s+(\S+)', found[0]) == [f'.LBB23_{n}-{name}' for n in labels],
                  'exact scalar finish width/mask variant order')
        result[name] = labels
    return result


def mask_helper(bodies, lane):
    name = s.one(bodies, r'secret_memory_mask9mask_byte$')
    wrapper = s.one(bodies, r'secret_memory22apply_secret_byte_mask$')
    body = bodies[name]
    for marker in ('BRYNJA_MASK_BEGIN', 'BRYNJA_MASK_ERASE', 'BRYNJA_MASK_END'):
        s.require(body.count(marker) == 1, 'one scalar finish mask marker')
    s.require(body.count('#APP') == body.count('#NO_APP') == 1, 'one opaque mask region')
    expected = ([] if lane == 'simd512' else ['movb $-1, %r8b'])
    keep, add = ('%r8b', '%dl') if lane == 'simd256' else ('%dl', '%r8b')
    expected += ['movzbl (%rcx), %eax', f'andb {keep}, %al', f'orb {add}, %al',
                 'movb %al, (%rcx)', 'xorl %eax, %eax', 'retq']
    opaque = body.split('#APP')[1].split('#NO_APP')[0]
    markers = ('BRYNJA_MASK_BEGIN', 'BRYNJA_MASK_ERASE', 'BRYNJA_MASK_END')
    s.require(all(marker in opaque for marker in markers), 'mask markers inside opaque region')
    positions = [opaque.index(marker) for marker in markers]
    s.require(positions == sorted(positions), 'mask active/erase/end marker order')
    active = opaque.split(markers[0])[1].split(markers[1])[0]
    erased = opaque.split(markers[1])[1].split(markers[2])[0]
    s.require(s.lines(active) == expected[-6:-2] and s.lines(erased) == ['xorl %eax, %eax'],
              'mask operation and clearing inside their declared boundaries')
    s.require(s.lines(body)[2:] == expected, 'complete scalar finish mask ABI and erase')
    s.require(s.lines(bodies[wrapper])[2:] == ['jmp ' + name], 'mask wrapper retains specialized ABI')
    return dict(function=name, byte_pointer='rcx', keep=keep, add=add,
                working_register_erased='eax', opaque_stack_accesses=0)


def inspect(bodies, lane):
    name = s.one(bodies, r'Resident6digest$' if lane == 'simd256' else r'Executor13digest_secret$')
    lines = s.lines(bodies[name]); start, end, expected = region(bodies, lane)
    s.require(lines.count(start + ':') == lines.count(end + ':') == 1, 'unique scalar finish boundaries')
    first, last = lines.index(start + ':'), lines.index(end + ':')
    s.require(first < last and lines[first:last] == expected, 'complete reviewed scalar finish region')
    labels = {line[:-1] for line in expected if re.fullmatch(r'\.B\d+:', line)} - {start}
    for line in lines[:first] + lines[last:]:
        s.require(not labels.intersection(re.findall(r'\.B\d+', line)), 'no direct scalar finish side entry')
    return dict(function=name, start=start, end=end, instructions=len(expected),
        scalar_remainder_and_padding_region_checked=True, padding_threshold=56 if lane == 'simd256' else 112,
        full_blocks_accounted_and_scratch_cleared=True, per_lane_owner_wiped_before_and_after_success=True,
        partial_byte_mask=mask_helper(bodies, lane),
        canonical_input_and_typed_algorithm_are_caller_preconditions=True,
        scalar_compression_helper_composition_pending=True,
        machine_alias_and_frame_lifetime_composition_pending=True, whole_frame_qualified=False)
