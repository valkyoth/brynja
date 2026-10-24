"""Inlined scalar constructor ownership/scratch prefix through retained handoff.

This follows the real worker CFG, without extracting/replacing a pseudo-function.
Hash finalizers consume their owner; owner Drop and core clearing are separately
reviewed non-panicking premises. Normalization output provenance is separate.
"""
import re

from legacy_hmac_hosted_construct_model import Model, State, base, require, syntax, V


def scratch(model, state, line, call):
    if call and call[0].startswith('llvm.lifetime.'):
        symbol, args = call
        root, offset = model.address(syntax.operand(args[-1]))
        if root in model.scratch:
            require(offset == 0, 'interior scalar constructor scratch lifetime')
            if symbol == 'llvm.lifetime.start.p0':
                require(root not in state.scratch, 'restarted scalar constructor scratch')
                state.scratch[root] = 0
            else:
                require(state.scratch.get(root) == 1, 'scalar constructor scratch ends uncleared')
                del state.scratch[root]
        return
    if call and model.m.names.get(call[0]) == 'brynja_core::secret_memory::clear_owned_region':
        _, args = call
        root, offset = model.address(syntax.operand(args[0]))
        if root in model.scratch:
            require(offset == 0 and args[1].split()[-1] == str(model.scratch[root])
                    and root in state.scratch, 'scalar constructor scratch clear extent/lifetime changed')
            state.scratch[root] = 1
            model.clears.add(root)
        return
    if call and (call[0].startswith(('llvm.assume', 'llvm.experimental.noalias'))
                 or base.codegen.owner_drop(call[0], model.m.identity)):
        return
    # Conservatively dirty all live scratch for any other effect, including
    # operations through a secret-region descriptor rather than a direct alias.
    if re.search(r'\b(call|invoke|store|atomicrmw|cmpxchg)\b', line):
        for name in re.findall(V, line):
            root, _ = model.address(name)
            require(root not in model.scratch or root in state.scratch, 'scalar constructor uses inactive scratch')
        state.scratch = {root: 0 for root in state.scratch}


def step(model, state, line, point, predecessor):
    m, width = model.m, model.width
    address = model.address
    load = re.search(r'\bload .*?, ptr (' + V + ')', line)
    if load:
        require(address(load[1])[0] not in state.initializing, 'scalar constructor read before initialization')
        require(address(load[1])[0] not in model.scratch, 'scalar constructor scratch read outside typed operations')
        require(address(load[1])[0] not in model.roles and not state.overlap(address(load[1]), width),
                'scalar constructor owner read outside typed operations')
    base.shared.evaluate(line, state, address, predecessor)
    derived = re.match('(' + V + r') = getelementptr.*?, ptr (' + V + ')', line)
    if derived and (address(derived[2])[0] in model.roles or address(derived[2])[0] in model.scratch
                    or state.overlap(address(derived[2]), width)):
        require(m.pointer(derived[1]) is not None, 'unresolved scalar constructor owner arithmetic')
    if re.search(r'= (?:phi ptr|select .* ptr|ptrtoint|inttoptr|bitcast)', line):
        require(not any(address(name)[0] in model.roles or address(name)[0] in model.scratch
                        or state.overlap(address(name), width)
                        for name in re.findall(V, line)[1:]), 'scalar constructor owner alias/escape')
    call = m.call_map.get(point)
    scratch(model, state, line, call)
    if call:
        symbol, args = call
        name = m.names.get(symbol, symbol)
        if symbol.startswith('llvm.lifetime.'):
            root, offset = address(syntax.operand(args[-1]))
            require(symbol in ('llvm.lifetime.start.p0', 'llvm.lifetime.end.p0') and offset == 0,
                    'unknown/interior scalar constructor lifetime')
            if symbol == 'llvm.lifetime.start.p0':
                require(root not in state.live, 'restarted scalar constructor storage')
                state.live.add(root)
                if root in model.roles:
                    require(model.roles[root] not in state.born, 'duplicate scalar constructor owner birth')
                    state.initializing[root] = set()
            else:
                require(root in state.live and root not in state.initializing, 'scalar constructor lifetime absent/partial')
                remaining = {row for row in state.memory if row[0] != root}
                require(all(row[3] in state.done or any(other[3] == row[3] for other in remaining)
                            for row in state.memory if row[0] == root), 'scalar constructor lifetime ends live')
                state.end(root)
                state.live.remove(root)
        elif symbol == 'llvm.memset.p0.i64':
            dest, size = address(syntax.operand(args[0])), int(args[2].split()[-1])
            if not model.initialize(state, dest, size, bool(re.fullmatch(r'i8 -?\d+', args[1]))):
                require(not state.overlap(dest, size), 'scalar constructor overwrites live owner')
        elif symbol == 'llvm.memcpy.p0.p0.i64':
            dest, source = (address(syntax.operand(arg)) for arg in args[:2])
            size = int(args[2].split()[-1])
            require(source[0] not in state.initializing and dest[0] not in state.initializing,
                    'scalar constructor copies partial initialization')
            if state.overlap(source, size):
                token = state.complete(source, width)
                require(size == width and args[3] == 'i1 false' and dest[0] in state.live
                        and 0 <= dest[1] <= m.allocs.get(dest[0], 0) - size,
                        'scalar constructor owner copy extent/lifetime')
                if dest[0] == m.owner:
                    require(token in (1, 2) and dest[1] == model.fields[token - 1], 'scalar constructor swaps retained roles')
                state.transfer(dest, source, size)
            else:
                require(not state.overlap(dest, size), 'unrelated scalar constructor copy overwrites owner')
        elif base.codegen.owner_drop(symbol, m.identity) or base.final.hash_finalizer(symbol, m.identity):
            dropping = base.codegen.owner_drop(symbol, m.identity)
            token = state.complete(address(syntax.operand(args[0 if dropping else 1])), width)
            if not dropping:
                require(token == 0 and state.key_updated and point == model.finish,
                        'scalar normalization consumes wrong/unkeyed owner')
                state.normalized = True
            state.done.add(token)
            return dropping  # Primitive Drop cannot unwind; source-reviewed premise.
        elif base.codegen.adapter_update(symbol, m.identity):
            require(len(args) == 3, 'scalar constructor update arity')
            token = state.complete(address(syntax.operand(args[0])), width)
            require(model.panic == 'abort' or 'invoke ' in line, 'scalar constructor update lost unwind edge')
            if token == 0:
                require(not state.key_updated and [arg.split()[-1] for arg in args[1:]] == [model.key, model.length],
                        'scalar normalization key operand changed/repeated')
                state.key_updated = True
            else:
                require(address(syntax.operand(args[1])) == model.pad and args[2].split()[-1] == '64'
                        and state.events == (('mask54',) if token == 1 else ('mask54', 'inner', 'mask106')),
                        'scalar pad update order/operand changed')
                state.events += ('inner' if token == 1 else 'outer',)
            model.status(point, line)
            model.updates.add(token)
        elif base.mask(symbol):
            expected = 54 if not state.events else 106
            require(len(args) == 3 and address(syntax.operand(args[0])) == model.pad
                    and [arg.split()[-1] for arg in args[1:]] == ['64', str(expected)]
                    and state.events in ((), ('mask54', 'inner')), 'scalar pad mask order/constant changed')
            state.events += ('mask' + str(expected),)
            model.status(point, line)
        else:
            if point == model.short_copy:
                model.status(point, line, core=True)
            for arg in args:
                if arg.startswith('ptr '):
                    pointer = address(syntax.operand(arg))
                    require(pointer[0] not in state.initializing and not state.overlap(pointer, width),
                            'scalar constructor owner escapes typed operations')
                    require(pointer[0] not in model.scratch or name in (
                        'brynja_core::secret_memory::clear_owned_region',
                        'brynja_core::secret_memory::copy_secret_region'), 'scalar constructor scratch escapes unknown callee')
            nonpanic = name == 'brynja_core::secret_memory::clear_owned_region'
            require(model.panic == 'abort' or not state.born - state.done or 'invoke ' in line
                    or symbol.startswith('llvm.') or nonpanic or base.codegen.flow.panic_cleanup(symbol),
                    'scalar constructor live owner exposed to implicit unwind')
            return nonpanic
    elif re.search(r'\b(store|atomicrmw|cmpxchg)\b', line):
        store = re.match(r'store (i(\d+)|ptr|<(\d+) x i(\d+)>) (.*?), ptr (' + V + ')', line)
        require(store, 'unparsed scalar constructor write')
        kind, bits, count, element, value, dest = store.groups()
        size = int(count) * int(element) // 8 if count else (int(bits) + 7) // 8 if bits else 8
        public = bool(re.fullmatch(r'-?\d+|zeroinitializer|<i\d+ -?\d+(?:, i\d+ -?\d+)*>', value))
        if not model.initialize(state, address(dest), size, public):
            if kind == 'ptr' and re.fullmatch(V, value):
                require(address(value)[0] not in model.roles and address(value)[0] not in model.scratch
                        and not state.overlap(address(value), width),
                        'scalar constructor owner pointer stored')
            state.store(address(dest), size, state.value(value))
    elif re.search(r'\b(call|invoke)\b', line):
        require(not state.born - state.done and not state.initializing, 'indirect call with live scalar constructor owner')
    return False


def check(retained, envelope, panic):
    model = Model(retained, envelope, panic)
    graph, queue, seen = retained.graph, [(next(iter(retained.graph)), None, State())], set()
    while queue:
        label, predecessor, state = queue.pop()
        key = label, predecessor, state.key()
        if key in seen:
            continue
        seen.add(key)
        state.trail = (*state.trail[-11:], label)
        require(label in graph and len(seen) < 20000, 'scalar constructor prefix exceeds bound')
        lines = graph[label]
        for index, line in enumerate(lines):
            point = label, index
            call = retained.call_map.get(point)
            if call and retained.names.get(call[0]) == 'std::panicking::catch_unwind::cleanup':
                require(state.unwinding and not state.initializing and state.born <= state.done
                        and 0 not in state.scratch.values(), 'scalar constructor catch receives live owner/scratch')
                # The separately checked envelope owns catch/result handling.
                # Prove this handoff has no path back to constructor storage.
                if point not in model.checked_catch:
                    protected = {root for root, size in retained.allocs.items() if size == model.width} | set(model.scratch)
                    for block, rows in graph.items():
                        for offset, row in enumerate(rows):
                            if retained.can_precede(point, (block, offset)):
                                require(not any(model.address(name)[0] in protected for name in re.findall(V, row)),
                                        'scalar catch suffix reuses constructor storage')
                    model.checked_catch.add(point)
                model.failures += 1
                break
            nonpanic = step(model, state, line, point, predecessor)
            if point == retained.cut:
                require(not state.unwinding and not state.initializing and not state.scratch and state.born - state.done == {1, 2}
                        and (0 not in state.born or state.normalized)
                        and state.events == ('mask54', 'inner', 'mask106', 'outer'),
                        'scalar constructor handoff has live scratch/missing phase')
                for token, field in enumerate(model.fields, 1):
                    require(state.complete((retained.owner, field), model.width) == token, 'scalar retained owner provenance changed')
                model.successes += 1
                break
            if re.search(r'\binvoke\b', line):
                require(index + 1 < len(lines), 'scalar constructor invoke lacks successors')
                edges = re.fullmatch('to label %' + base.codegen.LABEL + ' unwind label %' + base.codegen.LABEL
                                     + r'(?:,.*)?', lines[index + 1])
                require(edges, 'scalar constructor invoke edges changed')
                for slot, edge in enumerate(edges.groups()[:1 if nonpanic else 2]):
                    child = state.clone()
                    child.unwinding |= slot == 1
                    queue.append((edge, label, child))
                break
            if line.startswith(('br ', 'switch ')):
                text = line if line.startswith('br ') else '\n'.join(lines[index:]).split(']', 1)[0]
                edges = re.findall('label %' + base.codegen.LABEL, text)
                require(edges, 'scalar constructor branch missing targets')
                condition = re.match('br i1 (' + V + '),', line)
                for slot, edge in enumerate(edges):
                    child = state.clone()
                    if condition:
                        value = state.value(condition[1])
                        if isinstance(value, int) and value != 1 - slot:
                            continue
                        child.assign(condition[1], 1 - slot)
                    queue.append((edge, label, child))
                break
            if line.startswith(('ret ', 'resume ')) or line == 'unreachable':
                fatal = base.codegen.flow.fatal_cleanup_block(lines) or any(
                    mcall and retained.names.get(mcall[0]) == 'core::panicking::panic_cannot_unwind'
                    for row in lines if (mcall := syntax.call(row)))
                if line == 'unreachable' and state.unwinding and fatal:
                    break  # Fatal cleanup abort is explicitly outside the recoverable contract.
                require(not state.initializing and state.born <= state.done and 0 not in state.scratch.values(),
                        'scalar constructor failure exits with live owner/scratch: '
                        + repr((label, state.born, state.done, state.scratch, line, state.trail)))
                model.failures += 1
                break
        else:
            require(False, 'unterminated scalar constructor prefix')
    require(model.successes and model.failures and model.births == model.updates == {0, 1, 2}
            and model.clears == set(model.scratch), 'vacuous scalar constructor prefix')
    return model
