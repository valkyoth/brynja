"""Complete-byte prefix split: symbolic public length/bit cases in emitted CFG."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_tail_transfer as transfer

require, V, L = common.require, syntax.VALUE, common.LABEL


def captured(input_, kind, offset):
    m = input_.m
    values = []
    for value, (rhs, _) in m.defs.items():
        load = re.match(r'load ' + kind + r', ptr (' + V + '),', rhs)
        if not load or load[1] not in m.defs:
            continue
        if re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                        + re.escape(input_.job) + ', i64 ' + str(offset + input_.shift), m.defs[load[1]][0]):
            values.append(value)
    require(len(values) == 1, 'tail captured field population changed')
    return input_.field(values[0], kind, offset)


class Split:
    def __init__(self, input_):
        self.i, self.m = input_, input_.m
        self.length = captured(input_, 'i64', 56)
        self.bits = captured(input_, 'i8', 64)
        self.incoming = input_.phi(input_.split, 'i64') if input_.rhs(input_.split).startswith('phi ') else None
        self.block = self.m.defs[input_.split][1][0]

    def value(self, value, empty, byte, trail=()):
        # Affine expressions in arbitrary positive L, not sampled lengths.
        if value == self.length:
            return (0, 0) if empty else (1, 0)
        if value == self.bits:
            return (0, 8) if byte else 'non-eight'
        if value == self.i.split and getattr(self, 'verified', False):
            return (0, 0) if empty else ((1, 0) if byte else (1, -1))
        if re.fullmatch(r'-?\d+', value):
            return 0, int(value)
        if value in ('true', 'false'):
            return value == 'true'
        require(value not in trail and len(trail) < 64, 'cyclic tail split expression')
        if value not in self.m.defs:
            return None
        rhs = self.m.defs[value][0].split(', !', 1)[0]
        compare = re.fullmatch(r'icmp (eq|ne) i(?:8|64) (' + V + r'|-?\d+), (' + V + r'|-?\d+)', rhs)
        recurse = lambda operand: self.value(operand, empty, byte, (*trail, value))
        result = None
        if compare:
            left, right = recurse(compare[2]), recurse(compare[3])
            if left is not None and right is not None:
                if left == 'non-eight' or right == 'non-eight':
                    if (left, right) in (('non-eight', (0, 8)), ((0, 8), 'non-eight')):
                        result = False
                elif left == right:
                    result = True
                elif {left, right} == {(1, 0), (0, 0)}:
                    result = False  # L is strictly positive in this class.
                elif left[0] == right[0]:
                    result = False
                if result is not None and compare[1] == 'ne':
                    result = not result
        else:
            select = re.fullmatch(r'select i1 (' + V + r'), i(?:8|64) (' + V + r'|-?\d+), i(?:8|64) (' + V + r'|-?\d+)', rhs)
            arithmetic = re.fullmatch(r'(add|sub)(?: nuw)?(?: nsw)? i64 (' + V + r'|-?\d+), (' + V + r'|-?\d+)', rhs)
            extend = re.fullmatch(r'(sext|zext) i1 (' + V + ') to i64', rhs)
            saturate = re.fullmatch(r'(?:tail )?call i64 @llvm.usub.sat.i64\(i64 (' + V + r'), i64 1\)', rhs)
            boolean = re.fullmatch(r'(or|and) i1 (' + V + '), (' + V + ')', rhs)
            if select and isinstance(condition := recurse(select[1]), bool):
                result = recurse(select[2] if condition else select[3])
            elif arithmetic:
                left, right = recurse(arithmetic[2]), recurse(arithmetic[3])
                if isinstance(left, tuple) and isinstance(right, tuple):
                    sign = 1 if arithmetic[1] == 'add' else -1
                    result = left[0] + sign * right[0], left[1] + sign * right[1]
            elif extend and isinstance(operand := recurse(extend[2]), bool):
                result = 0, int(operand) * (-1 if extend[1] == 'sext' else 1)
            elif saturate and (operand := recurse(saturate[1])) is not None:
                require(operand in ((0, 0), (1, 0)), 'unreviewed saturating tail input')
                result = (0, 0) if operand == (0, 0) else (1, -1)
            elif boolean:
                left, right = recurse(boolean[2]), recurse(boolean[3])
                if isinstance(left, bool) and isinstance(right, bool):
                    result = (left or right) if boolean[1] == 'or' else (left and right)
        if result is not None:
            self.i.points.add(self.m.defs[value][1])
        return result

    def check(self):
        for empty in (False, True):
            for byte in (False, True):
                expected = (0, 0) if empty else ((1, 0) if byte else (1, -1))
                pending, seen, reached = [(next(iter(self.m.graph)), None)], set(), 0
                while pending:
                    block, predecessor = pending.pop()
                    require(block in self.m.graph, 'tail split edge missing')
                    if (block, predecessor) in seen:
                        continue
                    seen.add((block, predecessor))
                    require(len(seen) < 2000, 'tail split graph exceeds bound')
                    if block == self.block:
                        require(self.incoming is None or predecessor in self.incoming, 'unknown tail split predecessor')
                        actual = self.value(self.incoming[predecessor] if self.incoming else self.i.split, empty, byte)
                        require(actual == expected, 'tail split does not preserve complete/partial byte partition')
                        reached += 1
                        continue
                    lines = self.m.graph[block]
                    conditional = re.fullmatch(r'br i1 (' + V + '), label %' + L + ', label %' + L + r'(?:,.*)?', lines[-1])
                    if conditional:
                        value = self.value(conditional[1], empty, byte)
                        if isinstance(value, bool):
                            self.i.points.add((block, len(lines) - 1))
                            edges = [conditional[2] if value else conditional[3]]
                        else:
                            edges = list(conditional.groups()[1:])
                    else:
                        edges = re.findall(r'label %' + L, '\n'.join(lines))
                    pending.extend((edge, block) for edge in edges)
                require(reached, 'vacuous tail split length/bit class')
        self.verified = True

    def arguments(self, args, point):
        if len(args) == 4:  # General SHA-512/t inlines Backend::tail.
            values = [syntax.operand(args[1])]
            for argument, kind in zip(args[2:], ('i64', 'i8')):
                operand = re.fullmatch(kind + r' .*?(' + V + r'|\d+)$', argument)
                require(operand, 'tail constructor scalar argument changed')
                values.append(operand[1])
            return values
        require(len(args) == 2, 'tail constructor argument population')
        root = self.m.pointer(syntax.operand(args[1]), point)
        require(root and root[1] == 0 and self.m.allocs[root[0]] == 24, 'tail descriptor geometry')
        fields = {}
        for mode, at, destination, data in self.m.writes:
            address = self.m.pointer(destination, at)
            if not address or address[0] != root[0]:
                continue
            require(self.m.before(at, point), 'tail descriptor overwritten or conditional initialization')
            if mode == 'copy' and address[1] == 17 and data[2] == 'i64 7':
                continue  # Rust descriptor padding, not semantic input fields.
            require(mode == 'store' and address[1] in (0, 8, 16) and address[1] not in fields,
                    'tail descriptor overlapping/unreviewed write')
            kind = {0: 'ptr', 8: 'i64', 16: 'i8'}[address[1]]
            match = re.fullmatch(kind + ' (' + V + r'|\d+)', data)
            require(match, 'tail descriptor field type changed')
            fields[address[1]] = match[1]
            self.i.points.add(at)
        require(set(fields) == {0, 8, 16}, 'tail descriptor incomplete')
        return [fields[offset] for offset in (0, 8, 16)]

    def constructors(self):
        m = self.m
        calls = [(symbol, args, point) for symbol, args, point in m.calls
                 if m.names.get(symbol, '').endswith('::worker::Backend>::tail')
                 or m.names.get(symbol) == '<brynja_hash_core::bit_string::BitString>::new']
        require(len(calls) == 2 and calls[0][0] == calls[1][0], 'whole/partial tail constructor population')
        terminal = next(m.names[symbol] for symbol, _, point in m.calls
                        if point in {at for _, at, _ in m.terminals})
        algorithm = re.search(r'brynja_mac_hmac::(?:algorithms::Sha\w+|general::Sha512T<\d+>)', terminal)
        require(algorithm, 'tail algorithm identity absent')
        expected = ({'<brynja_hash_core::bit_string::BitString>::new'} if '::general::' in algorithm[0] else
                    {'<' + algorithm[0] + ' as ' + owner + '::worker::Backend>::tail' for owner in (
                        'brynja_crypto_cpu_std::strict_hmac', 'brynja_crypto_cpu_std::macos_resident::hmac')})
        require(m.names[calls[0][0]] in expected, 'tail constructor algorithm substituted')
        whole = [row for row in calls if m.before(row[2], m.defs[self.i.split][1])]
        require(len(whole) == 1, 'whole tail validation does not precede split')
        full = whole[0]
        partial = next(row for row in calls if row != full)
        require(m.before(m.defs[self.i.split][1], partial[2]), 'partial tail constructed before split')
        require(self.arguments(full[1], full[2]) == [self.i.tail_base, self.length, self.bits],
                'whole tail constructor does not validate captured bits')
        pointer, length, bits = self.arguments(partial[1], partial[2])
        self.i.gep(pointer, self.i.tail_base, self.i.split)
        for empty in (False, True):
            for byte in (False, True):
                require(self.value(length, empty, byte) == (0, int(not empty and not byte)),
                        'partial tail length is not the unabsorbed fractional byte')
                expected = (0, 0) if empty or byte else 'non-eight'
                require(self.value(bits, empty, byte) == expected, 'partial tail valid-bit count changed')
        self.i.points.update((full[2], partial[2]))
        self.full, self.partial = full, partial
        transfer.check(self)


def check(input_):
    result = Split(input_)
    result.check()
    result.constructors()
    input_.tail = result
    return result
