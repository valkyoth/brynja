"""Bounded execution of actual hosted MD5 tag-copy paths.

Leaf SecretTags layout/accessor semantics and returned staging ownership are
reviewed callee premises. Inline accessors execute here, outlined accessors are
modeled at their exact call boundary. This ends at owned-region Drop admission,
not at a claim about erasure or complete host transactions.
"""
import re

import legacy_hmac_md5_output_views as views
import legacy_hmac_hosted_md5_result_tools as t
import legacy_hmac_hosted_md5_report_layout as layout

require, syntax, V, L = t.require, t.syntax, t.V, t.L
Pointer, UNKNOWN = views.Pointer, views.UNKNOWN
COPY = 'brynja_core::secret_memory::copy_secret_region'
EXPOSE = '<brynja_legacy_hmac::md5_batch::output::SecretTags>::expose'
DROP = '<brynja_core::secret_memory::OwnedSecretRegion as core::ops::drop::Drop>::drop'


def typed(population, compiler):
    definitions, aliases, names = population
    encodings = {'success': 4 if compiler == '1.90.0' else -1,
                 'empty': 0, 'overflow': 1, 'capacity': 2, 'incomplete': 3}
    for name, code in encodings.items():
        selected = [s for s in (*definitions, *aliases)
                    if names.get(s) == 'brynja_legacy_hmac_hosted_cleanup::tag_copy::' + name]
        require(len(selected) == 1, 'MD5 copy-status probe missing/ambiguous')
        arguments, body = layout.flow.resolve(selected[0], definitions, aliases)
        graph = layout.flow.blocks(body)
        require(not arguments.strip() and len(graph) == 1, 'MD5 copy-status ABI changed')
        cursor = layout.checked.Cursor(next(iter(graph.values())), names)
        cursor.take('ret i8 ' + str(code))
        cursor.end()


class State(views.State):
    def value(self, name):
        if re.fullmatch(r'-\d+', name):
            return int(name) % (2 ** 64)
        return super().value(name)

    def expression(self, text):
        gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (' + V + r'|\d+)', text)
        if gep:
            base, offset = self.value(gep[1]), self.value(gep[2])
            require(isinstance(base, Pointer) and isinstance(offset, int), 'MD5 output GEP unbound')
            limit = 32 if base.root == 'tags' else 128
            require(base.root in ('tags', 'rows', 'output') and 0 <= base.offset + offset <= limit,
                    'MD5 output pointer leaves its region')
            return Pointer(base.root, base.offset + offset)
        compare = re.fullmatch(r'icmp (eq|ne|ult|ugt|ule|uge) (i8|i64|ptr) ([^,]+), ([^,]+)', text)
        if compare:
            op, kind, a, b = compare.groups()
            a, b = self.value(a), self.value(b)
            require(a is not UNKNOWN and b is not UNKNOWN, 'MD5 output predicate unbound')
            if kind != 'ptr':
                require(type(a) is int and type(b) is int, 'MD5 output integer predicate changed')
                a, b = a % (2 ** int(kind[1:])), b % (2 ** int(kind[1:]))
            if op in ('eq', 'ne'):
                return int((a == b) == (op == 'eq'))
            require(type(a) is int and type(b) is int, 'MD5 output pointer ordering changed')
            return int({'ult': a < b, 'ugt': a > b, 'ule': a <= b, 'uge': a >= b}[op])
        select = re.fullmatch(r'select i1 ([^,]+), (ptr|i64|i1) ([^,]+), \2 (.+)', text)
        if select:
            condition = self.value(select[1])
            require(condition in (0, 1), 'MD5 output select unbound')
            return self.value(select[3 if condition else 4])
        extract = re.fullmatch(r'extractvalue \{ ptr, i64 \} (' + V + '), ([01])', text)
        if extract:
            pair = self.value(extract[1])
            require(isinstance(pair, tuple) and len(pair) == 2, 'MD5 exposed slice changed')
            return pair[int(extract[2])]
        return super().expression(text)


class Copies:
    def __init__(self, model, envelope, boundaries, transports, compiler):
        self.m, self.env, self.compiler = model, envelope, compiler
        self.auth, = [item for item in transports if hasattr(item, 'tags')]
        self.tags = self.auth.tags
        self.copies = {p for s, _, p in model.calls if model.names.get(s) == COPY}
        before = [p for p, guard in boundaries[1].items()
                  if all(model.before((guard[0], -1), copy) for copy in self.copies)]
        require(len(before) == 1 and self.copies, 'MD5 copy entry checkpoint missing/ambiguous')
        self.start = boundaries[1][before[0]][0]
        self.post, = set(boundaries[1]) - set(before)
        self.copy_ok = 4 if compiler == '1.90.0' else 255
        self.points, self.observed_copies, self.exits = set(), set(), {}
        self.aliases = {name: Pointer('tags', pointer[1]) for name in model.defs
                        if (pointer := model.pointer(name)) and pointer[0] == self.tags
                        and model.before(model.defs[name][1], (self.start, -1))}
        self.aliases[self.tags] = Pointer('tags')

    def run(self, mask, length, failure=None, error=0):
        state = State(self.tags, mask, 0, length, True, 128)
        state.values.update(self.aliases)
        state.values[self.env['loads'][16][1]] = Pointer('output')
        state.values[self.env['loads'][64][1]] = length
        expected = [i for i in range(8) if mask & (1 << i) and i * 16 + length <= 128]
        require(failure is None or failure in expected, 'invalid MD5 copy-failure scenario')
        require(error in range(4), 'invalid MD5 copy error')
        copied, failed, seen = [], False, set()
        label, previous = self.start, None
        while True:
            require(label in self.m.graph and label not in seen and len(seen) < 128, 'MD5 output path cycles/exceeds bound')
            seen.add(label)
            incoming = dict(state.values)
            for index, original in enumerate(self.m.graph[label]):
                point, line = (label, index), original.split(', !', 1)[0]
                self.points.add(point)
                define = re.fullmatch('(' + V + ') = (.*)', line)
                call = syntax.call(line)
                if call:
                    symbol, args = call
                    name = self.m.names.get(symbol, symbol)
                    if name == DROP:
                        require(len(args) == 1 and state.value(syntax.operand(args[0])) == Pointer('tags', 8),
                                'MD5 output cleanup uses another owner')
                        rejected = failed or (length > 16 and bool(expected))
                        wanted = expected[:expected.index(failure) + 1] if failure is not None else expected
                        if length > 16:
                            wanted = []
                        require(copied == wanted, 'MD5 copies skip/repeat/reorder active lanes')
                        if point not in self.exits:
                            returned = t.health.returned(self.m, point)
                            require(not any(self.m.can_precede(returned, use) for use in self.copies),
                                    'MD5 output resumes copying after owner cleanup')
                            self.exits[point] = returned, self.m.can_precede(returned, self.post)
                        returned, reaches_success = self.exits[point]
                        require(reaches_success != rejected, 'MD5 copy outcome reaches the wrong completion path')
                        if rejected:
                            known = {key: t.health.status.literal(value, 8) for key, value in state.values.items()
                                     if type(value) is int}
                            t.health.status.walk(self.m, self.env, returned[0], label, known, 8,
                                                 offset=returned[1])
                        return
                    require(define, 'MD5 output unexpected void call/effect')
                    if name == EXPOSE:
                        require(len(args) == 2 and state.value(syntax.operand(args[0])) == Pointer('tags')
                                and 'dereferenceable(32)' in args[0], 'MD5 output accessor owner changed')
                        lane = state.value(args[1].split()[-1])
                        require(type(lane) is int and 0 <= lane < 8, 'MD5 output accessor index changed')
                        state.values[define[1]] = (Pointer('rows', lane * 16), length) if lane in expected else (None, UNKNOWN)
                    elif name == COPY:
                        require(not failed and len(args) == 4, 'MD5 copy continued after rejection')
                        dest, size, source, width = [state.value(arg.split()[-1]) for arg in args]
                        require(type(size) is int and type(width) is int and isinstance(source, Pointer)
                                and source.root == 'rows' and source.offset % 16 == 0, 'MD5 copy source/width unbound')
                        lane = source.offset // 16
                        require(lane in expected and dest == Pointer('output', lane * 16)
                                and size == width == length and 0 <= length <= 16
                                and lane * 16 + length <= 128, 'MD5 source/destination lane or bounds changed')
                        copied.append(lane)
                        self.observed_copies.add(point)
                        failed = failure == lane
                        state.values[define[1]] = error if failed else self.copy_ok
                    else:
                        require(False, 'MD5 output unreviewed call: ' + name)
                    if 'invoke ' in line:
                        edge = self.m.graph[label][index + 1].split(', !', 1)[0]
                        match = re.fullmatch('to label %' + L + ' unwind label %' + L, edge)
                        require(match, 'MD5 output invoke continuation changed')
                        self.points.add((label, index + 1))
                        previous, label = label, match[1]
                        break
                elif define:
                    phi = re.fullmatch(r'phi (?:ptr|i8|i64) (.*)', define[2])
                    if phi:
                        pairs = re.findall(r'\[ ([^,]+), %' + L + r' \]', phi[1])
                        require(phi[1] == ', '.join('[ ' + value + ', %' + parent + ' ]' for value, parent in pairs),
                                'MD5 output phi has unparsed fields')
                        selected = [value for value, parent in pairs if parent == previous]
                        require(len(selected) == 1, 'MD5 output phi predecessor changed')
                        saved = state.values
                        state.values = incoming
                        value = state.value(selected[0])
                        state.values = saved
                    else:
                        value = state.expression(define[2])
                    state.values[define[1]] = value
                elif branch := re.fullmatch('br i1 ([^,]+), label %' + L + ', label %' + L, line):
                    value = state.value(branch[1])
                    require(value in (0, 1), 'MD5 output branch unbound')
                    previous, label = label, branch[2 if value else 3]
                    break
                elif jump := re.fullmatch('br label %' + L, line):
                    previous, label = label, jump[1]
                    break
                else:
                    require(False, 'MD5 output unreviewed instruction: ' + line)
            else:
                require(False, 'MD5 output continuation falls off block')

    def validate(self):
        for mask in range(256):
            for length in range(10, 17):
                self.run(mask, length)
        for length in (0, 1, 17, 128, 2 ** 64 - 1):
            for mask in (0, 255, *(1 << lane for lane in range(8))):
                self.run(mask, length)
        for lane in range(8):
            for length in (10, 16):
                for error in range(4):
                    self.run(255, length, lane, error)
        require(self.observed_copies == self.copies, 'MD5 output copy population not covered')
        return self


def check(model, envelope, boundaries, transports, compiler):
    return Copies(model, envelope, boundaries, transports, compiler).validate()
