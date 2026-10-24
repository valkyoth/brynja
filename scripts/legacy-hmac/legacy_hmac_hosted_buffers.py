"""Exact outlined buffer destructor effects; not host transaction admission."""
import re

import legacy_hmac_hosted_capture_model as capture

expressions = capture.shared.load('hmac_hosted_transaction_values')
flow, syntax, require, V = capture.flow, capture.syntax, capture.require, capture.V


def check(arguments, body, names, target):
    params = syntax.parameters(arguments)
    require(len(params) == 1 and 'dereferenceable(24)' in params[0], 'legacy buffer destructor formal changed')
    clear = ('<brynja_crypto_cpu_std::macos_resident::memory::ResidentBytes>::clear'
             if target == 'aarch64-apple-darwin' else '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear')
    graph, all_visited = flow.blocks(body), set()
    for keep in (0, 1):
        values = {syntax.operand(params[0]): ('guard', 0)}
        memory = {('guard', 0): ('destination', 0), ('guard', 8): ('staging', 0), ('guard', 16): keep}
        label, predecessor = next(iter(graph)), None
        visited, cleared = set(), []

        def value(token):
            if token in ('true', 'false'):
                return int(token == 'true')
            if re.fullmatch(r'-?\d+', token):
                return int(token)
            require(token in values, 'unknown legacy buffer SSA')
            return values[token]

        while True:
            require(label not in visited and len(visited) < 32, 'cyclic legacy buffer destructor')
            visited.add(label)
            for line in graph[label]:
                line = line.split(', !', 1)[0]
                define = re.match('(' + V + ') = (.*)', line)
                name, rhs = define.groups() if define else (None, line)
                gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (\d+)', rhs)
                load = re.fullmatch(r'load (ptr|i8), ptr (' + V + r'), align \d+', rhs)
                call = syntax.call(line)
                if gep:
                    base = value(gep[1])
                    require(isinstance(base, tuple) and base[0] == 'guard', 'legacy buffer pointer provenance')
                    values[name] = base[0], base[1] + int(gep[2])
                elif load:
                    location = value(load[2])
                    require(location in memory and load[1] == ('i8' if location[1] == 16 else 'ptr'),
                            'legacy buffer field/width changed')
                    values[name] = memory[location]
                elif call:
                    require('invoke ' not in line and names.get(call[0]) == clear and len(call[1]) == 1,
                            'unexpected legacy buffer destructor effect')
                    cleared.append(value(syntax.operand(call[1][0])))
                elif line.startswith('br '):
                    branch = re.fullmatch('br i1 (' + V + '), label %' + flow.LABEL + ', label %' + flow.LABEL, line)
                    jump = re.fullmatch('br label %' + flow.LABEL, line)
                    require(branch or jump, 'unparsed legacy buffer branch')
                    next_label = branch[2] if branch and expressions.integer(value(branch[1]), 1) else branch[3] if branch else jump[1]
                    predecessor, label = label, next_label
                    break
                elif line == 'ret void':
                    require(cleared == [('staging', 0)] + ([] if keep else [('destination', 0)]),
                            'legacy buffer cleanup identity/order/keep condition changed')
                    all_visited.update(visited)
                    break
                else:
                    require(name is not None, 'unreviewed legacy buffer instruction')
                    values[name] = expressions.evaluate(rhs, value, predecessor)
            else:
                require(False, 'unterminated legacy buffer destructor')
            if line == 'ret void':
                break
    require(all_visited == set(graph), 'unreviewed legacy buffer destructor path')
