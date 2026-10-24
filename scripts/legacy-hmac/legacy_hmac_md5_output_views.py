"""Execute emitted public/secret accessors to bind returned tag field meanings.

Only readonly, bounded accessor instructions are modeled. These scenarios bind
layout and lane visibility, not construction of an OwnedSecretRegion or erasure.
"""
import re

import legacy_hmac_md5_report_return as r

require, VALUE, Pointer = r.require, r.VALUE, r.Pointer
UNKNOWN = object()


def body(fixture, llvm, secret):
    definitions, aliases = r.flow.definitions_and_aliases(fixture)
    code = r.n.pads.descriptors.admission.probe(definitions, aliases, 'secret_view' if secret else 'public_view')
    graph = r.flow.blocks(code)
    lines = next(iter(graph.values()))
    if len(graph) == 1 and len(lines) == 2 and (call := r.syntax.call(lines[0])):
        symbol, args = call
        require(secret and re.fullmatch(r'_ZN18brynja_legacy_hmac9md5_batch6output10SecretTags6expose17h[0-9a-f]+E', symbol)
                and [r.syntax.operand(args[0]), args[1].split()[-1]] == ['%tags', '%lane'], 'unbound output-view delegation')
        result = re.match(rf'({VALUE}) = ', lines[0])
        require(result and lines[1] == 'ret { ptr, i64 } ' + result[1], 'output-view delegation result changed')
        defs, other = r.flow.definitions_and_aliases(llvm)
        signature, code = r.flow.resolve(symbol, defs, other)
        params = r.syntax.parameters(signature)
        require(len(params) == 2 and r.syntax.operand(params[0]) == '%self' and params[1].split()[-1] == '%lane',
                'output-view leaf parameters changed')
        return code, '%self'
    return code, '%tags'


class State:
    def __init__(self, root, mask, lane, length, secret, extent):
        self.values = {root: Pointer('tags'), '%lane': lane}
        self.memory = {(i, 'i8'): (mask >> i) & 1 for i in range(8)}
        self.memory[8, 'ptr'] = Pointer('rows')
        self.memory[24 if secret else 16, 'i64'] = length
        if secret:
            self.memory[16, 'i64'] = extent

    def value(self, name):
        if name in ('undef', 'poison'):
            return UNKNOWN
        if name == 'null':
            return None
        if name == 'inttoptr (i64 1 to ptr)':
            return Pointer('dangling')
        if name in ('true', 'false'):
            return int(name == 'true')
        if re.fullmatch(r'\d+', name):
            return int(name)
        require(name in self.values, 'unbound output-view value: ' + name)
        return self.values[name]

    def expression(self, text):
        gep = re.fullmatch(rf'getelementptr inbounds(?: nuw)? (i8|\[16 x i8\]), ptr ({VALUE}), i64 ({VALUE}|\d+)', text)
        load = re.fullmatch(rf'load (i8|i64|ptr), ptr ({VALUE}), align \d+(?:, !.*)?', text)
        cast = re.fullmatch(rf'(trunc|zext)(?: nuw)? i(\d+) ({VALUE}) to i(\d+)', text)
        compare = re.fullmatch(r'icmp (eq|ne|ult|ugt|ule|uge) (?:i64|ptr) ([^,]+), ([^,]+)', text)
        select = re.fullmatch(r'select i1 ([^,]+), (ptr|i64) ([^,]+), \2 (.+)', text)
        binary = re.fullmatch(r'(add|shl)((?: nuw)?(?: nsw)?) i64 ([^,]+), ([^,]+)', text)
        extract = re.fullmatch(r'extractvalue \{ i64, i1 \} (%[-\w.]+), ([01])', text)
        insert = re.fullmatch(r'insertvalue \{ ptr, i64 \} ([^,]+), (?:ptr|i64) ([^,]+), ([01])', text)
        if gep:
            base, offset = self.value(gep[2]), self.value(gep[3])
            require(isinstance(base, Pointer) and isinstance(offset, int), 'output-view GEP is unbound')
            offset = base.offset + offset * (16 if gep[1].startswith('[') else 1)
            require(base.root in ('tags', 'rows') and 0 <= offset <= (32 if base.root == 'tags' else 128),
                    'output-view pointer leaves owned extent')
            return Pointer(base.root, offset)
        if load:
            address = self.value(load[2])
            require(isinstance(address, Pointer) and address.root == 'tags'
                    and (address.offset, load[1]) in self.memory, 'output-view reads unbound field')
            return self.memory[address.offset, load[1]]
        if cast:
            value, width = self.value(cast[3]), int(cast[4])
            require(isinstance(value, int) and (' nuw ' not in text or value < 2 ** width), 'output-view narrowing poison')
            return value % (2 ** width)
        if compare:
            left, right = self.value(compare[2]), self.value(compare[3])
            require(left is not UNKNOWN and right is not UNKNOWN, 'unknown output-view predicate')
            if compare[1] in ('eq', 'ne'):
                return int((left == right) == (compare[1] == 'eq'))
            require(isinstance(left, int) and isinstance(right, int), 'noninteger output-view ordering')
            return int({'ult': left < right, 'ugt': left > right, 'ule': left <= right, 'uge': left >= right}[compare[1]])
        if select:
            condition = self.value(select[1])
            require(condition in (0, 1), 'unknown output-view selection')
            return self.value(select[3 if condition else 4])
        if binary:
            left, right = self.value(binary[3]), self.value(binary[4])
            require(isinstance(left, int) and isinstance(right, int) and (binary[1] != 'shl' or right < 64),
                    'unknown output-view arithmetic')
            value = left + right if binary[1] == 'add' else left << right
            require(('nuw' not in binary[2] or value < 2 ** 64) and
                    ('nsw' not in binary[2] or value < 2 ** 63), 'output-view arithmetic poison')
            return value % (2 ** 64)
        if extract:
            aggregate = self.value(extract[1])
            require(isinstance(aggregate, tuple), 'output-view overflow pair changed')
            return aggregate[int(extract[2])]
        if insert:
            aggregate = (UNKNOWN, UNKNOWN) if insert[1] == 'poison' else self.value(insert[1])
            require(isinstance(aggregate, tuple), 'output-view slice pair changed')
            result = list(aggregate); result[int(insert[3])] = self.value(insert[2])
            return tuple(result)
        call = r.syntax.call('%projection = ' + text)
        require(call and call[0] == 'llvm.uadd.with.overflow.i64' and len(call[1]) == 2, 'unknown output-view effect: ' + text)
        values = [self.value(arg.split()[-1]) for arg in call[1]]
        require(all(isinstance(value, int) for value in values), 'unknown output-view checked addition')
        total = sum(values)
        return total % (2 ** 64), int(total >= 2 ** 64)


def run(code, root, mask, lane, length, secret, extent=128):
    graph, state = r.flow.blocks(code), State(root, mask, lane, length, secret, extent)
    label, previous, seen = next(iter(graph)), None, set()
    while True:
        require(label in graph and label not in seen, 'cyclic/unknown output-view path')
        seen.add(label); incoming = dict(state.values)
        for line in graph[label]:
            definition = re.fullmatch(rf'({VALUE}) = (.*)', line)
            branch = re.fullmatch(r'br i1 ([^,]+), label %' + r.flow.LABEL + ', label %' + r.flow.LABEL + r'(?:, !.*)?', line)
            jump = re.fullmatch('br label %' + r.flow.LABEL, line)
            if definition:
                phi = re.fullmatch(r'phi (?:ptr|i64) (.*)', definition[2])
                if phi:
                    selected = [value for value, parent in re.findall(r'\[ ([^,]+), %' + r.flow.LABEL + r' \]', phi[1]) if parent == previous]
                    require(len(selected) == 1, 'output-view phi predecessor changed')
                    saved = state.values; state.values = incoming
                    value = state.value(selected[0]); state.values = saved
                else:
                    value = state.expression(definition[2])
                state.values[definition[1]] = value
            elif branch or jump:
                condition = state.value(branch[1]) if branch else None
                require(not branch or condition in (0, 1), 'unknown output-view branch')
                previous, label = label, jump[1] if jump else branch[2 if condition else 3]
                break
            elif line.startswith('ret { ptr, i64 } '):
                actual = state.value(line.removeprefix('ret { ptr, i64 } '))
                present = lane < 8 and mask & (1 << lane) and (16 * lane + length <= extent if secret else length <= 16)
                require(isinstance(actual, tuple) and (actual == (Pointer('rows', 16 * lane), length) if present else actual[0] is None),
                        'output-view lane/activity/length provenance changed')
                return
            else:
                require(False, 'unparsed output-view instruction: ' + line)
        else:
            require(False, 'unterminated output-view block')


def validate(fixture, llvm):
    for secret in (False, True):
        code, root = body(fixture, llvm, secret)
        for mask in range(256):
            for lane in range(10):
                for length in range(10, 17):
                    run(code, root, mask, lane, length, secret)
        for lane in range(10):
            for length in (0, 1, 17, 2 ** 64 - 1):
                run(code, root, 255, lane, length, secret)
