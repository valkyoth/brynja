"""Scalar key-route, normalized Result/region and pad provenance over real LLVM.

Typed finalizers supply an initialized region on success and none on error;
their cryptography and the core region destructor are separate callee premises.
No native execution or compiler-copy/register-erasure claim is made here.
"""
import copy
import re

import legacy_hmac_hosted_normalization_contracts as contracts

require, syntax, V = contracts.require, contracts.syntax, contracts.V
DROP = '<brynja_core::secret_memory::OwnedSecretRegion as core::ops::drop::Drop>::drop'
COPY = 'brynja_core::secret_memory::copy_secret_region'
CLEAR = 'brynja_core::secret_memory::clear_owned_region'


class State:
    def __init__(self, route):
        self.route, self.values, self.live = route, {}, set()
        self.result, self.fields = None, {}
        self.finalized, self.dropped, self.copied = False, False, False
        self.pad, self.unwind = False, False

    def key(self):
        return (self.route, tuple(sorted(self.values.items())), frozenset(self.live), self.result,
                tuple(sorted(self.fields.items())), self.finalized, self.dropped, self.copied, self.pad, self.unwind)


class Model:
    def __init__(self, prefix, initial):
        self.p, self.m = prefix, prefix.m
        self.address = prefix.address
        self.width = 20 if self.m.identity == 'sha1' else 16
        self.core_ok = 4 if self.m.compiler == '1.90.0' else -1
        args = self.m.call_map[prefix.finish][1]
        self.result = self.address(syntax.operand(args[0]))
        require(self.result[1] == 0 and self.m.allocs.get(self.result[0]) == 24
                and self.result[0] not in prefix.scratch, 'normalization Result storage changed')
        copies = [(point, args) for symbol, args, point in self.m.calls if self.m.names.get(symbol) == COPY
                  and self.address(syntax.operand(args[0])) == prefix.pad and point != prefix.short_copy]
        require(len(copies) == 1, 'normalization copy population changed')
        self.copy, self.copy_args = copies[0]
        # The region is independently inferred from the move of Result's pointer
        # payload, not from local names or the argument of a candidate Drop.
        loads = {name for name, (rhs, _) in self.m.defs.items()
                 if (load := re.match(r'load ptr, ptr (' + V + '),', rhs))
                 and self.address(load[1]) == (self.result[0], 8)}
        destinations = {self.address(dest) for mode, _, dest, data in self.m.writes
                        if mode == 'store' and data in {'ptr ' + name for name in loads}}
        require(len(destinations) == 1, 'normalization region move missing/ambiguous')
        self.region = destinations.pop()
        require(self.region[1] == 0 and self.m.allocs.get(self.region[0]) == 16
                and self.region[0] != self.result[0] and self.region[0] not in prefix.scratch,
                'normalization region storage geometry changed')
        self.roots = {self.region[0], self.result[0]}
        masks = [point for symbol, args, point in self.m.calls
                 if self.m.names.get(symbol) == 'brynja_legacy_hmac::scratch::mask' and args[-1].split()[-1] == '54']
        require(len(masks) == 1, 'normalization first-pad phase missing')
        self.stop = masks[0]
        starts = [point for symbol, args, point in self.m.calls if symbol == 'llvm.lifetime.start.p0'
                  and self.address(syntax.operand(args[-1])) == prefix.pad]
        require(len(starts) == 1, 'normalization pad lifetime population')
        self.start = starts[0]
        self.successes, self.errors, self.drops = set(), set(), set()
        self.initialization(initial)
        self.storage()
        for point in (prefix.short_copy, self.copy):
            self.copy_partition(point)

    def copy_partition(self, point):
        """All failure encodings share one path, not just the sampled error 0."""
        line = self.m.graph[point[0]][point[1]]
        result = re.match('(' + V + ') = (?:tail )?(?:call|invoke)', line)
        require(result, 'normalization copy result missing')
        uses = [(site, rhs) for name, (rhs, site) in self.m.defs.items()
                if result[1] in re.findall(V, rhs)]
        require(len(uses) == 1 and re.fullmatch(r'icmp (eq|ne) i8 ' + re.escape(result[1])
                                               + ', ' + str(self.core_ok), uses[0][1]),
                'normalization copy success/error partition changed')
        for label, lines in self.m.graph.items():
            for index, row in enumerate(lines):
                if result[1] in re.findall(V, row):
                    require((label, index) in (point, uses[0][0]), 'normalization copy result has unreviewed use')

    def initialization(self, initial):
        require(len(initial) == self.p.width, 'normalization initial-owner contract missing')
        for mode, point, dest, data in self.m.writes:
            root, offset = self.address(dest)
            if root in self.p.roles and mode == 'store':
                value = re.fullmatch(r'(i\d+|<\d+ x i\d+>) (.*)', data)
                require(value, 'normalization initial-owner store type changed')
                content = contracts.literal(*value.groups())
                require(initial[offset:offset + len(content)] == content, 'normalization initial-owner bytes changed')
        for symbol, args, _ in self.m.calls:
            if symbol == 'llvm.memset.p0.i64':
                root, offset = self.address(syntax.operand(args[0]))
                if root in self.p.roles:
                    content = contracts.literal('i8', args[1].split()[-1]) * int(args[2].split()[-1])
                    require(initial[offset:offset + len(content)] == content, 'normalization initial-owner memset changed')

    def storage(self):
        result_loads = []
        for label, lines in self.m.graph.items():
            for index, line in enumerate(lines):
                point = label, index
                refs = [name for name in re.findall(V, line) if self.address(name)[0] in self.roots]
                if not refs:
                    continue
                call = self.m.call_map.get(point)
                if call:
                    symbol, args = call
                    require(symbol.startswith(('llvm.lifetime.', 'llvm.assume')) or point == self.p.finish
                            or (self.m.names.get(symbol) == DROP and len(args) == 1
                                and self.address(syntax.operand(args[0])) == self.region),
                            'normalization metadata escapes typed operations')
                elif line.startswith('store '):
                    store = re.fullmatch(r'store (ptr|i64) (' + V + '), ptr (' + V + r'), align \d+(?:,.*)?', line)
                    require(store and self.address(store[3])[0] == self.region[0]
                            and self.address(store[2])[0] not in self.roots, 'normalization metadata overwritten/escaped')
                elif '= load ' in line:
                    load = re.search(r'= load (i8|i64|ptr), ptr (' + V + '),', line)
                    require(load, 'normalization metadata load type')
                    root, offset = self.address(load[2])
                    if root == self.result[0]:
                        require(self.m.before(self.p.finish, point), 'normalization Result read before finalizer')
                        result_loads.append((offset, load[1]))
                elif '= getelementptr' in line:
                    require(self.m.pointer(line.split(' =')[0]) is not None, 'normalization dynamic metadata alias')
                else:
                    require(' = alloca ' in line, 'normalization unsupported metadata alias/effect')
        require(sorted(result_loads) == [(0, 'i8'), (1, 'i8'), (8, 'ptr'), (16, 'i64')],
                'normalization Result discriminant/error/payload read population changed')

    def value(self, state, token):
        if token in state.values:
            return state.values[token]
        if token == self.p.length:
            return ('range', *{'empty': (0, 0), 'short': (1, 64), 'long': (65, (1 << 64) - 1)}[state.route])
        if token == self.p.key:
            return ('key',)
        if token in ('true', 'false', 'null'):
            return int(token == 'true')
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        return None

    def evaluate(self, state, line, predecessor):
        definition = re.match('(' + V + ') = (.*)', line)
        if not definition:
            return
        name, rhs = definition.groups()
        value = None
        load = re.match(r'load (i8|i64|ptr), ptr (' + V + '),', rhs)
        if load and self.address(load[2])[0] in self.roots:
            root, offset = self.address(load[2])
            require(root in state.live, 'normalization reads inactive metadata')
            if root == self.result[0]:
                require(state.result is not None and not state.unwind, 'normalization reads result before normal return')
                if offset == 0 and load[1] == 'i8':
                    value = state.result
                elif offset == 1 and load[1] == 'i8':
                    require(state.result == 1, 'normalization reads error from success result')
                else:
                    require(state.result == 0 and not state.dropped, 'normalization reads error/consumed payload')
                    require((offset, load[1]) in ((8, 'ptr'), (16, 'i64')), 'normalization payload field changed')
                    value = ('digest',) if offset == 8 else self.width
            else:
                require(not state.dropped and offset in state.fields, 'normalization reads uninitialized/consumed region')
                value = state.fields[offset]
        elif (compare := re.fullmatch(r'icmp(?: samesign)? (eq|ne|ugt|ult) (ptr|i\d+) (' + V + r'), (null|-?\d+)', rhs)):
            source, other = self.value(state, compare[3]), self.value(state, compare[4])
            predicate = compare[1]
            if isinstance(source, tuple) and source[0] == 'range':
                lo, hi = source[1:]
                evaluate = lambda x: {'eq': x == other, 'ne': x != other, 'ugt': x > other, 'ult': x < other}[predicate]
                require(evaluate(lo) == evaluate(hi) and not (predicate in ('eq', 'ne') and lo < other < hi),
                        'normalization key partition does not cover comparison')
                value = int(evaluate(lo))
            elif source is not None:
                if compare[2] == 'ptr':
                    require(predicate in ('eq', 'ne') and other == 0, 'normalization pointer test changed')
                    value = int((source == 0) == (predicate == 'eq'))
                else:
                    require(isinstance(source, int), 'normalization noninteger comparison')
                    value = int({'eq': source == other, 'ne': source != other, 'ugt': source > other, 'ult': source < other}[predicate])
        elif (trunc := re.fullmatch(r'trunc(?: nuw)? i8 (' + V + ') to i1', rhs)):
            source = self.value(state, trunc[1])
            if isinstance(source, int):
                value = source & 1
        elif (select := re.fullmatch(r'select i1 (' + V + r'), (i\d+|ptr) (.*), \2 (.*)', rhs)):
            condition = self.value(state, select[1])
            if condition is not None:
                require(condition in (0, 1), 'normalization select condition changed')
                value = self.value(state, select[3 if condition else 4])
        elif (phi := re.fullmatch(r'phi i\d+ (.*)', rhs)):
            options = [value for value, label in re.findall(r'\[ ([-\w%.]+), %' + contracts.flow.LABEL + r' \]', phi[1]) if label == predecessor]
            require(len(options) == 1, 'normalization phi predecessor changed')
            value = self.value(state, options[0])
        state.values.pop(name, None)
        if value is not None:
            state.values[name] = value

    def step(self, state, point, line, predecessor):
        self.evaluate(state, line, predecessor)
        call = self.m.call_map.get(point)
        if call:
            symbol, args = call
            name = self.m.names.get(symbol)
            if symbol.startswith('llvm.lifetime.'):
                root, _ = self.address(syntax.operand(args[-1]))
                if symbol == 'llvm.lifetime.start.p0':
                    require(root not in state.live, 'normalization restarted storage')
                    state.live.add(root)
                else:
                    require(root in state.live, 'normalization inactive lifetime end')
                    if root == self.region[0]:
                        require(not state.fields or state.dropped, 'normalization ends live region')
                    if root == self.result[0] and state.result == 0:
                        require(state.fields == {0: ('digest',), 8: self.width}, 'normalization ends unmoved successful Result')
                    state.live.remove(root)
            elif symbol == 'llvm.memset.p0.i64' and self.address(syntax.operand(args[0])) == self.p.pad:
                require(not state.pad and not state.copied and args[1:] == ['i8 0', 'i64 64', 'i1 false'],
                        'normalization initial zero pad changed/reinitialized')
                state.pad = True
            elif symbol in ('llvm.memset.p0.i64', 'llvm.memcpy.p0.p0.i64'):
                require(self.address(syntax.operand(args[0]))[0] != self.p.pad[0],
                        'normalization pad overwritten outside typed operations')
            elif point == self.p.finish:
                require(state.route == 'long' and not state.finalized and self.result[0] in state.live,
                        'normalization finalizer route/repetition/lifetime changed')
                state.finalized = True
                return 'finalize'
            elif name == COPY and self.address(syntax.operand(args[0])) == self.p.pad:
                require(state.pad and not state.copied and not state.unwind, 'normalization pad copy ordering changed')
                if point == self.copy:
                    require(state.route == 'long' and state.result == 0 and not state.dropped
                            and state.fields == {0: ('digest',), 8: self.width}
                            and self.region[0] in state.live, 'normalization copy lacks live successful region')
                    wanted = [self.width, ('digest',), self.width]
                else:
                    require(point == self.p.short_copy and state.route == 'short', 'normalization short-key route changed')
                    wanted = [('range', 1, 64), ('key',), ('range', 1, 64)]
                require([self.value(state, arg.split()[-1]) for arg in args[1:]] == wanted,
                        'normalization pad copy source/length changed')
                return 'copy'
            elif name == DROP and self.address(syntax.operand(args[0])) == self.region:
                require(self.region[0] in state.live and state.fields == {0: ('digest',), 8: self.width}
                        and state.result == 0 and not state.dropped, 'normalization region Drop missing/repeated/wrong owner')
                state.dropped = True
                self.drops.add(point)
            elif name == CLEAR and self.address(syntax.operand(args[0])) == self.p.pad:
                state.pad = False
        elif (store := re.match(r'store (ptr|i64) (' + V + '), ptr (' + V + '),', line)):
            root, offset = self.address(store[3])
            if root == self.region[0]:
                require(root in state.live and not state.dropped and offset not in state.fields
                        and ((offset == 0 and store[1] == 'ptr') or (offset == 8 and store[1] == 'i64')),
                        'normalization region field write invalid')
                value = self.value(state, store[2])
                require(value == (('digest',) if offset == 0 else self.width), 'normalization region field provenance changed')
                state.fields[offset] = value
        if line.startswith('store '):
            destination = re.search(', ptr (' + V + '),', line)
            require(destination and self.address(destination[1])[0] != self.p.pad[0],
                    'normalization pad overwritten by store')
        return None


def check(prefix, initial):
    model = Model(prefix, initial)
    graph, queue, seen = prefix.m.graph, [(model.start, None, State(route)) for route in ('empty', 'short', 'long')], set()
    while queue:
        (label, index), predecessor, state = queue.pop()
        key = label, index, predecessor, state.key()
        if key in seen:
            continue
        seen.add(key)
        require(len(seen) < 20000 and label in graph, 'normalization flow exceeds bound')
        require(index < len(graph[label]), 'unterminated normalization block')
        point, line = (label, index), graph[label][index]
        if point == model.stop:
            require(not state.unwind and state.pad and (state.copied == (state.route != 'empty'))
                    and (state.finalized == (state.route == 'long'))
                    and (state.dropped == (state.route == 'long')), 'normalization incomplete/error path reaches pad mask')
            model.successes.add(state.route)
            continue
        if not prefix.m.can_precede(point, model.stop) and (state.result != 0 or state.dropped):
            model.errors.add((state.route, state.result, state.unwind))
            continue  # Existing constructor interpreter checks all remaining scratch/owner cleanup.
        effect = model.step(state, point, line, predecessor)
        if re.search(r'\binvoke\b', line):
            edge = re.fullmatch('to label %' + contracts.flow.LABEL + ' unwind label %' + contracts.flow.LABEL
                               + r'(?:,.*)?', graph[label][index + 1])
            require(edge, 'normalization invoke edges changed')
            normal, unwind = edge.groups()
            child = copy.deepcopy(state)
            child.unwind = True
            queue.append(((unwind, 0), label, child))
            following, previous = (normal, 0), label
        else:
            following, previous = (label, index + 1), predecessor
        if effect in ('finalize', 'copy'):
            for success in (False, True):
                child = copy.deepcopy(state)
                if effect == 'finalize':
                    child.result = 0 if success else 1
                else:
                    result = re.match('(' + V + ') = (?:tail )?(?:call|invoke)', line)
                    require(result, 'normalization copy Result value missing')
                    child.values[result[1]] = model.core_ok if success else 0
                    child.copied = success
                queue.append((following, previous, child))
        elif line.startswith(('br ', 'switch ')):
            if line.startswith('br label '):
                edges = [(re.fullmatch('br label %' + contracts.flow.LABEL + r'(?:,.*)?', line)[1], state)]
            else:
                match = re.fullmatch('br i1 (' + V + '), label %' + contracts.flow.LABEL + ', label %'
                                     + contracts.flow.LABEL + r'(?:,.*)?', line)
                require(match, 'normalization unsupported branch')
                value = model.value(state, match[1])
                edges = [(edge, copy.deepcopy(state)) for slot, edge in enumerate(match.groups()[1:])
                         if value is None or value == 1 - slot]
            queue.extend(((edge, 0), label, child) for edge, child in edges)
        elif line.startswith(('ret ', 'resume ')) or line == 'unreachable':
            fatal = contracts.flow.fatal_cleanup_block(graph[label])
            require((state.unwind and fatal) or state.result != 0 or state.dropped, 'normalization exits with live region')
        else:
            queue.append((following, previous, state))
    require(model.successes == {'empty', 'short', 'long'} and model.drops
            and any(route == 'long' and result == 1 for route, result, _ in model.errors),
            'vacuous normalization routes/result errors')
    return model
