#!/usr/bin/env python3
"""Model retained accelerated reader preflight and successful counter encoding."""
import argparse
import json
from pathlib import Path
import re

import check_accelerated_read as read

require = read.require
SSA = read.SSA
ATOM = r'(?:' + SSA + r'|-?\d+|true|false|poison|undef)'
MAX = (1 << 128) - 1


def evaluate(blocks, label, previous, env, state, session, stops, commit, *, portable_bulk=False):
    """Small closed interpreter; the already-inspected data loop is not simulated."""
    # Portable bulk squeeze has a different byte-aligned owner layout. Keep the
    # accelerated reader's original layout and strict arithmetic checks by default.
    offset_start = 16 if portable_bulk else 640
    def get(token):
        if token in ('undef', 'poison'):
            return None
        if token in ('true', 'false'):
            return int(token == 'true')
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in env, 'known counter operand: ' + token)
        return env[token]
    def vector(token, width):
        if token == 'poison':
            return [None] * width
        if token == 'zeroinitializer':
            return [0] * width
        if token.startswith('<'):
            values = re.findall(r'i\d+ (-?\d+|poison)', token)
            require(len(values) == width, 'complete constant vector')
            return [get(value) for value in values]
        values = get(token)
        require(isinstance(values, list) and len(values) == width, 'matching vector width')
        return values
    for _ in range(16):
        require(label in blocks, 'known counter block')
        if label == stops['error']:
            phi = read.match('(' + SSA + ') = phi i8 (.+)', blocks[label][0])
            selected = [value for value, pred in re.findall(r'\[ ([^,]+), %(' + read.LABEL + r') \]', phi[2]) if pred == previous]
            require(len(selected) == 1, 'counter failure predecessor')
            return 'error', get(selected[0]) % 256
        if label == stops['loop']:
            require(not commit and not state['writes'], 'preflight does not commit output count')
            return 'loop', dict(env)
        for line in blocks[label]:
            found = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr %self, i64 (\d+)', line)
            if found:
                env[found[1]] = ('owner', int(found[2])); continue
            found = re.fullmatch('(' + SSA + r') = load i(8|64), ptr (' + SSA + r'), align \d+', line)
            if found:
                require(not portable_bulk or line.endswith(', align 1'), 'byte-aligned portable counter load')
                address, bits = get(found[3]), int(found[2])
                require(isinstance(address, tuple) and address[0] == 'owner', 'owner counter/flag load')
                offset = address[1]
                if not portable_bulk and offset in (858, 859):
                    require(bits == 8, 'byte state flag')
                    env[found[1]] = state['squeezing' if offset == 858 else 'failed']
                else:
                    require(offset_start <= offset and offset + bits // 8 <= offset_start + 16, 'only output-counter metadata loaded')
                    env[found[1]] = (state['counter'] >> ((offset - offset_start) * 8)) & ((1 << bits) - 1)
                continue
            found = re.fullmatch('(' + SSA + r') = (zext|trunc)(?: nuw| nneg)? i\d+ (' + ATOM + r') to i(1|8|64|128)', line)
            if found:
                operand = get(found[3]); require(operand is not None, 'defined integer conversion')
                env[found[1]] = operand % (1 << int(found[4])); continue
            found = re.fullmatch('(' + SSA + r') = (shl|lshr|or|xor|add)((?: nuw| nsw| disjoint)*) i(1|8|64|128) (' + ATOM + '), (' + ATOM + ')', line)
            if found:
                output, op, flags, width, left, right = found.groups()
                bits = int(width); left, right = get(left), get(right)
                if portable_bulk and (left is None or right is None):
                    env[output] = None; continue
                require(left is not None and right is not None, 'defined counter arithmetic')
                mask = (1 << bits) - 1
                if op in ('shl', 'lshr'):
                    require(0 <= right < bits, 'valid counter shift')
                    value = left << right if op == 'shl' else (left & mask) >> right
                else:
                    value = left | right if op == 'or' else left ^ right if op == 'xor' else left + right
                if portable_bulk and (('nuw' in flags and not 0 <= value <= mask)
                                      or ('nsw' in flags and not -(1 << (bits - 1)) <= value < 1 << (bits - 1))
                                      or ('disjoint' in flags and left & right != 0)):
                    # Rust 1.90 computes a nuw sum even on its rejected overflow
                    # path. Poison in that unused value is not observable UB.
                    env[output] = None; continue
                require('nuw' not in flags or 0 <= value <= mask, 'no unsigned arithmetic poison')
                require('nsw' not in flags or -(1 << (bits - 1)) <= value < 1 << (bits - 1), 'no signed arithmetic poison')
                require('disjoint' not in flags or left & right == 0, 'disjoint counter fragments')
                env[output] = value & mask; continue
            found = re.fullmatch('(' + SSA + r') = icmp (eq|ult|ugt) i(1|8|64|128) (' + ATOM + '), (' + ATOM + ')', line)
            if found:
                output, op, width, left, right = found.groups()
                mask = (1 << int(width)) - 1
                left, right = get(left), get(right)
                require(left is not None and right is not None, 'defined counter comparison')
                left, right = left & mask, right & mask
                env[output] = int(left == right if op == 'eq' else left < right if op == 'ult' else left > right); continue
            found = re.fullmatch('(' + SSA + r') = select i1 (' + SSA + r'), i1 (' + ATOM + r'), i1 (' + ATOM + ')', line)
            if found:
                require(get(found[2]) in (0, 1), 'defined boolean selection condition')
                env[found[1]] = get(found[3] if get(found[2]) else found[4]); continue
            found = re.fullmatch('(' + SSA + r') = select i1 (' + SSA + r'), i128 (' + ATOM + r'), i128 (' + ATOM + ')', line)
            if found:
                require(portable_bulk and get(found[2]) in (0, 1), 'defined portable counter selection')
                env[found[1]] = get(found[3] if get(found[2]) else found[4]); continue
            found = re.fullmatch('(' + SSA + r') = select i1 (' + SSA + r'), i8 (' + ATOM + r'), i8 (' + ATOM + ')', line)
            if found:
                require(portable_bulk and get(found[2]) in (0, 1), 'defined portable bit-count selection')
                env[found[1]] = get(found[3] if get(found[2]) else found[4]); continue
            found = re.fullmatch('(' + SSA + r') = tail call \{ i128, i1 \} @llvm.uadd.with.overflow.i128\(i128 (' + SSA + '), i128 (' + SSA + r')\)', line)
            if found:
                left, right = get(found[2]), get(found[3])
                require(left is not None and right is not None, 'defined overflow intrinsic operands')
                total = left + right
                env[found[1]] = (total & MAX, int(total > MAX)); continue
            found = re.fullmatch('(' + SSA + r') = extractvalue \{ i128, i1 \} (' + SSA + '), ([01])', line)
            if found:
                env[found[1]] = get(found[2])[int(found[3])]; continue
            if 'invoke ' in line:
                require(not portable_bulk, 'portable counter has no session invocation')
                name, args = read.shared.invocation(line)
                require(name == session and len(args) == 1 and read.comparison.pointer(args[0]) == '%self', 'original session revalidation')
                output = read.match('(' + SSA + ') = invoke noundef i8 ', line[:re.search(read.comparison.SYMBOL, line).start()])[1]
                env[output] = state['session_result']; state['checks'] += 1
                continue
            if line.startswith('to label '):
                next_label, _ = read.shared.edges(line)
                previous, label = label, next_label; break
            found = re.fullmatch('(' + SSA + r') = insertelement <(\d+) x i128> (' + SSA + r'|poison), i128 (' + ATOM + r'), i64 (\d+)', line)
            if found:
                lanes = vector(found[3], int(found[2]))[:]
                require(int(found[5]) < len(lanes), 'insert inside vector')
                lanes[int(found[5])] = get(found[4]); env[found[1]] = lanes; continue
            found = re.fullmatch('(' + SSA + r') = shufflevector <(\d+) x i128> (' + SSA + r'), <\2 x i128> (' + SSA + r'|poison), <(\d+) x i32> (.+)', line)
            if found:
                joined = vector(found[3], int(found[2])) + vector(found[4], int(found[2]))
                indices = vector(found[6], int(found[5]))
                require(all(index is None or 0 <= index < len(joined) for index in indices), 'bounded vector shuffle')
                env[found[1]] = [None if index is None else joined[index] for index in indices]; continue
            found = re.fullmatch('(' + SSA + r') = lshr <(\d+) x i128> (' + SSA + r'), (.+)', line)
            if found:
                values, shifts = vector(found[3], int(found[2])), vector(found[4], int(found[2]))
                require(all(shift is not None and 0 <= shift < 128 for shift in shifts), 'bounded vector shifts')
                env[found[1]] = [None if value is None else value >> shift for value, shift in zip(values, shifts)]; continue
            found = re.fullmatch('(' + SSA + r') = trunc <16 x i128> (' + SSA + r') to <16 x i8>', line)
            if found:
                env[found[1]] = [None if value is None else value & 255 for value in vector(found[2], 16)]; continue
            found = re.fullmatch(r'store <16 x i8> (' + SSA + '), ptr (' + SSA + '), align ' + ('1' if portable_bulk else '32'), line)
            if found:
                require(get(found[2]) == ('owner', offset_start) and not state['writes'], 'one original output-counter commit')
                values = vector(found[1], 16)
                require(all(value is not None for value in values), 'no poison counter bytes')
                state['writes'].append(int.from_bytes(bytes(values), 'little')); continue
            found = re.fullmatch('(' + SSA + ') = phi i8 (.+)', line)
            if found:
                selected = [v for v, pred in re.findall(r'\[ ([^,]+), %(' + read.LABEL + r') \]', found[2]) if pred == previous]
                require(len(selected) == 1, 'successful return predecessor')
                env[found[1]] = get(selected[0]) % 256; continue
            found = re.fullmatch('(' + SSA + ') = phi i64 (.+)', line)
            if found:
                selected = {v for v, pred in re.findall(r'\[ ([^,]+), %(' + read.LABEL + r') \]', found[2]) if pred == previous}
                require(portable_bulk and len(selected) == 1, 'unambiguous portable complete-byte count')
                env[found[1]] = get(selected.pop()) % (1 << 64); continue
            found = re.fullmatch('br i1 (' + SSA + '), label %(' + read.LABEL + '), label %(' + read.LABEL + ')', line)
            if found:
                require(get(found[1]) in (0, 1), 'defined counter branch condition')
                previous, label = label, found[2] if get(found[1]) else found[3]; break
            found = re.fullmatch('br label %(' + read.LABEL + ')', line)
            if found:
                previous, label = label, found[1]; break
            found = re.fullmatch('ret i8 (' + SSA + ')', line)
            if found:
                return 'return', get(found[1])
            raise ValueError('unreviewed counter instruction: ' + line)
        else:
            raise ValueError('counter block lacks terminator')
    raise ValueError('counter control flow exceeded bound')


def scenarios(thorough):
    pairs = {(0, 0), (0, 1), (MAX, 0), (MAX, 1), (MAX - 1, 1), (MAX - 1, 2),
             (0x0102030405060708090a0b0c0d0e0f10, 0x10203)}
    if thorough:
        pairs |= {(1 << bit, 1) for bit in range(128)}
        for bit in range(63):
            length = 1 << bit
            pairs |= {(0, length), (MAX - length, length), (MAX - length + 1, length)}
    for counter, length in sorted(pairs):
        yield counter, length, 0, 1, False
    for counter, length in ((0, 0), (0, 1), (MAX, 1)):
        for failed, squeezing in ((0, 0), (1, 0), (1, 1)):
            yield counter, length, failed, squeezing, False
        yield counter, length, 0, 1, True


def inspect(sha3, core, cpu, compiler, thorough=True):
    read.inspect(sha3, core, cpu, compiler)
    definitions = read.comparison.definitions(sha3)
    function = definitions[read.shared.unique(definitions, 'accelerated', '6Engine4read')]
    blocks = read.shared.graph(function)
    session = read.shared.unique(read.comparison.definitions(cpu), '13KeccakSession5check')
    header = function.splitlines()[0]
    params = read.comparison.arguments(header, re.search(read.comparison.SYMBOL, header).end())
    length_name = re.search(SSA + '$', params[2])[0]
    finals = [label for label, body in blocks.items() if any('store <16 x i8>' in line for line in body)]
    require(len(finals) == 1, 'one successful counter-commit block')
    final = finals[0]
    error = next(label for label, body in blocks.items() if body[0].startswith('%_0.sroa.') and 'phi i8' in body[0] and any('6Memory4wipe' in line for line in body))
    loop = next(label for label, body in blocks.items() if len(body) == 5 and 'i64 616' in body[0] and 'i64 608' in body[1])
    success, backend_success = (12, 7) if compiler == '1.90.0' else (255, 255)
    count = 0
    for counter, length, failed, squeezing, revoked in scenarios(thorough):
        state = dict(counter=counter, failed=failed, squeezing=squeezing,
                     session_result=2 if revoked else backend_success, checks=0, writes=[])
        env = {length_name: length}
        stops = dict(error=error, loop=loop)
        outcome = evaluate(blocks, 'start', None, env, state, session, stops, False)
        code = 7 if failed or not squeezing else 2 if revoked else 8 if counter + length > MAX else None
        require(state['checks'] == (0 if failed or not squeezing else 1), 'session check before counter admission')
        if code is not None:
            require(outcome == ('error', code) and not state['writes'], 'preflight rejects before counter commit')
        else:
            if length:
                require(outcome[0] == 'loop', 'nonempty accepted read reaches data loop')
                # Model the counter commit on successful loop completion, not the loop's byte processing.
                outcome = evaluate(blocks, final, None, outcome[1], state, session, stops, True)
            require(outcome == ('return', success) and state['writes'] == [counter + length], 'exact little-endian u128 counter commit')
        count += 1
    return count


def main(record):
    before = read.comparison.capture.sources()
    results = [inspect(*case) for case in read.cases(record)]
    require(len(results) == 4 and before == read.comparison.capture.sources(), 'complete unchanged counter matrix')
    print(f'Accelerated read counters: four optimized bodies PASS; {sum(results)} modeled preflight/commit cases')
    print('Terminal/squeeze/session checks precede overflow admission; successful-loop counter encoding preserves all 128 bits')
    print('Record SHA-256: ' + read.comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(read.comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded model, not all-input formal proof, session internals, debug, full spills or native qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
