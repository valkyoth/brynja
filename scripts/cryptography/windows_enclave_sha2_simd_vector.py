"""Private SIMD vector-loop composition, with independent bounded geometry.

Exact emitted regions are reviewed snapshots, not a second compiler. The model
checks the arithmetic argument behind those regions; it does not execute x86 or
establish arbitrary alias freedom, scalar finalization or whole-frame erasure.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_vector256 as narrow
import windows_enclave_sha2_simd_vector512 as wide

MAX = (1 << 64) - 1


def unsigned(value):
    s.require(type(value) is int and 0 <= value <= MAX, 'unsigned vector geometry')
    return value


def parameters(lane):
    s.require(lane in ('simd256', 'simd512'), 'known vector family')
    return (8, 32, 64) if lane == 'simd256' else (4, 64, 128)


def span(index, stride, total):
    unsigned(index)
    start = index * stride
    s.require(start + stride <= total, 'vector transfer within its declared array')
    return (start, start + stride)


def geometry(lane, width, indices, inputs, minimum=1):
    """inputs are None or (available bytes, message bits), never message data.

Return interval summaries rather than iterating potentially 2**55 blocks.
Distinct active indices are supplied by the preceding compaction loop, an
explicit precondition here rather than a claim that this loop enforces it.
"""
    capacity, state, block = parameters(lane)
    unsigned(width); unsigned(minimum)
    s.require(lane != 'simd256' or minimum == 1, 'saved narrow minimum is one complete block')
    s.require(width in (capacity, capacity // 2), 'admitted kernel width')
    s.require(len(inputs) == capacity and len(indices) <= capacity,
              'fixed input capacity and bounded compact index table')
    s.require(len(set(indices)) == len(indices), 'unique compact indices precondition')
    for index in indices:
        unsigned(index)
        s.require(index < capacity and inputs[index] is not None, 'present indexed input')
    groups = []
    for group in range(0, len(indices), width):
        if len(indices) - group < width:
            break
        selected = indices[group:group + width]
        complete = []
        for index in selected:
            available, bits = inputs[index]
            unsigned(available); unsigned(bits)
            s.require(bits // 8 <= available, 'complete bytes fit original slice')
            complete.append(bits // (8 * block))
        common = min(complete)
        if common < minimum:
            continue
        rows = []
        for packed, index in enumerate(selected):
            last = None if common == 0 else (common - 1) * block
            end = common * block
            s.require(end <= inputs[index][0] and end <= inputs[index][1] // 8 and end <= MAX,
                      'last complete block cannot overflow or overread')
            rows.append(dict(index=index, packed=packed,
                state=span(index, state, 256), packed_state=span(packed, state, 256),
                block_destination=span(packed, block, 512),
                last_block_start=last, input_end=end, offset=common))
        groups.append(dict(group=group, common=common, rows=rows))
    return groups


def account(width, budget, used, before, after, calls, blocks):
    """Accepted counter result only; rejected paths may have already charged.

This deliberately does not claim request rollback or transactional control
mutation: the emitted narrow path stores its used count before testing carry.
"""
    for value in (width, budget, used, before, after, calls, blocks): unsigned(value)
    s.require(width in (2, 4, 8), 'positive admitted vector width')
    if budget < width: return 'WorkLimit'
    if used + width > MAX or before == MAX or after != before + 1:
        return 'Invariant'
    if calls == MAX or blocks + width > MAX: return 'Invariant'
    return (budget - width, used + width, calls + 1, blocks + width)


def regions(bodies, lane):
    parameters(lane)
    values = dict(copy=s.one(bodies, r'secret_memory18copy_secret_region$'),
                  session=s.one(bodies, r'Session14compress_bytes$'))
    if lane == 'simd256':
        values['poll'] = s.one(bodies, r'^_RNC.*Owner6digests2_0.*$')
    return [(start, end, text.format(**values).strip().splitlines()) for start, end, text
            in (narrow if lane == 'simd256' else wide).REGIONS]


def inspect(bodies, lane):
    capacity, state, block = parameters(lane)
    name = s.one(bodies, r'Resident6digest$' if lane == 'simd256' else r'Executor13digest_secret$')
    lines = s.lines(bodies[name]); reviewed = []
    if lane == 'simd256':
        s.sequences(bodies[name], ['.B65:|leaq 10784(%rbx), %rax|movq %rax, 104(%rbx)'])
    else:
        s.sequences(bodies[name], ['.B71:|movq %rax, 1032(%rbp)',
            'leaq 512(%rdi), %rax|movq %rax, 984(%rbp)|leaq 768(%rdi), %rax|movq %rax, 1000(%rbp)'])
    for start, end, expected in regions(bodies, lane):
        s.require(lines.count(start + ':') == lines.count(end + ':') == 1,
                  'unique vector region boundaries')
        first, last = lines.index(start + ':'), lines.index(end + ':')
        s.require(first < last and lines[first:last] == expected, 'complete reviewed vector region ' + start)
        reviewed.append(dict(start=start, end=end, instructions=len(expected)))
    # Core loop has one fall-through entry. No outside branch may jump into
    # its pack/block/unpack interiors and skip their preceding bounds checks.
    first = lines.index(reviewed[-1]['start'] + ':'); last = lines.index(reviewed[-1]['end'] + ':')
    labels = {line[:-1] for line in lines[first:last] if re.fullmatch(r'\.B\d+:', line)}
    for line in lines[:first] + lines[last:]:
        s.require(not labels.intersection(re.findall(r'\.B\d+', line)), 'no side entry into vector loop')
    return dict(function=name, regions=reviewed, capacity=capacity, state_bytes=state,
        block_bytes=block, kernel_widths=[capacity, capacity // 2],
        complete_block_bound_before_every_input_copy=True,
        state_pack_and_writeback_use_the_same_compact_index=True,
        compression_count_checked_before_report_commit=True,
        charge_failure_does_not_claim_control_rollback=True,
        compact_indices_unique_and_bounded_is_a_caller_precondition=True,
        original_input_slice_and_workspace_alias_preconditions_pending=True,
        scalar_finish_and_machine_frame_lifetimes_pending=True, whole_frame_qualified=False)
