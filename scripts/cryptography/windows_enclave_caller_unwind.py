"""Selected AMD64 version-1 unwind records, not an unwinder or stack proof.

Reject handlers and other versions; follow bounded in-function chained entries.
Microsoft x64 exception-handling layout is the format authority.
"""
import struct


def require(ok, message):
    if not ok: raise ValueError('caller unwind: ' + message)


def read(rows, address, size):
    found = [row for row in rows if 0 <= address - row['rva']
             and size <= min(len(row['code']), row['virtual_size']) - (address - row['rva'])]
    require(len(found) == 1 and 0 <= size <= 2048, 'mapped bounded unwind data')
    row = found[0]
    return row['code'][address-row['rva']:address-row['rva']+size]


def decode(rows, item):
    start, end, address = item
    header = read(rows, address, 4)
    version, flags = header[0] & 7, header[0] >> 3
    prolog, count, frame = header[1:]
    require(version == 1 and flags in (0, 4) and prolog <= end - start, 'supported unwind header')
    nonvolatile = (3, 5, 6, 7, 12, 13, 14, 15)
    require(frame == 0 or frame & 15 in nonvolatile, 'nonvolatile frame register')
    slots = read(rows, address + 4, count * 2)
    index, previous = 0, 256
    stack, saved, operations = 0, [], []
    while index < count:
        offset, opcode = slots[index*2:index*2+2]
        op, info = opcode & 15, opcode >> 4
        require(offset <= previous and offset <= prolog, 'ordered prolog code offsets')
        previous = offset
        widths = {0: 0, 1: 1 if info == 0 else 2, 2: 0, 3: 0, 4: 1, 5: 2, 8: 1, 9: 2}
        require(op in widths and (op != 1 or info <= 1), 'known bounded unwind operation')
        extra = widths[op]
        require(index + extra < count, 'complete unwind operands')
        operand = int.from_bytes(slots[(index+1)*2:(index+1+extra)*2], 'little')
        if op in (0, 4, 5): require(info in nonvolatile, 'nonvolatile saved GPR')
        if op in (8, 9): require(6 <= info <= 15, 'nonvolatile saved vector')
        if op == 1: require(operand > 0 and (info == 0 or operand % 8 == 0), 'positive aligned large allocation')
        if op == 0: stack += 8
        elif op == 1: stack += operand * (8 if info == 0 else 1)
        elif op == 2: stack += info * 8 + 8
        elif op == 3: require(info == 0 and frame & 15, 'frame-register declaration')
        else:
            position = operand * (8 if op == 4 else 16 if op == 8 else 1)
            saved.append(dict(register_class='xmm' if op in (8, 9) else 'gpr', register=info, offset=position))
        operations.append(dict(code_offset=offset, opcode=op, info=info, operand=operand))
        index += 1 + extra
    require(stack <= 65536, 'bounded local allocation')
    chain = struct.unpack('<III', read(rows, address + 4 + ((count + 1) & ~1) * 2, 12)) if flags == 4 else None
    return dict(start=start, end=end, unwind_rva=address, prolog_bytes=prolog, frame=frame,
                stack_bytes=stack, saved_registers=saved, operations=operations, chain=chain)


def extent(rows, functions, start, size):
    end = start + size
    parts = sorted(f for f in functions if f[0] < end and start < f[1])
    require(bool(parts) and parts[0][0] == start and parts[-1][1] == end
            and all(a[1] == b[0] for a, b in zip(parts, parts[1:]))
            and all(a < b for a, b, _ in parts), 'exact contiguous runtime-function extent')
    decoded = {item: decode(rows, item) for item in parts}
    root = parts[0]
    require(decoded[root]['chain'] is None, 'primary unwind record')
    for item in parts:
        seen, current = set(), item
        while decoded[current]['chain'] is not None:
            require(current not in seen, 'unwind chain cycle')
            seen.add(current)
            next_ = decoded[current]['chain']
            require(next_ in decoded and decoded[current]['frame'] == decoded[next_]['frame'],
                    'chain stays in same function/frame')
            require(decoded[current]['stack_bytes'] == 0, 'secondary chain cannot allocate another fixed frame')
            current = next_
        require(current == root, 'all fragments share primary')
    return list(decoded.values())
