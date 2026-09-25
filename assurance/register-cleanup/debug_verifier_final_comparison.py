"""Retained final-byte caller fragment, not whole-verifier or unwind execution."""
import re

import debug_verifier_comparison as bulk

model, guard, require, SSA = bulk.model, bulk.guard, bulk.require, bulk.SSA


def candidate_input(graph):
    blocks = [lines for lines in graph.values() if any('23valid_bits_in_last_byte' in line and 'invoke ' in line for line in lines)]
    require(len(blocks) == 1, 'one original accepted candidate-tail block')
    lines = blocks[0]
    fields = [m[1] for line in lines if (m := re.fullmatch('(' + SSA + r') = getelementptr inbounds i8, ptr ' + SSA + ', i64 8', line))]
    require(len(fields) == 1, 'one accepted candidate pointer field')
    loads = [m[1] for line in lines if (m := re.fullmatch('(' + SSA + ') = load ptr, ptr ' + re.escape(fields[0]) + ', align 8', line))]
    require(len(loads) == 1, 'one original accepted candidate tail pointer')
    return loads[0]


def extract(function, definitions):
    graph = model.blocks(function)
    candidate = candidate_input(graph)
    producers = [(b, line) for b, lines in graph.items() for line in lines
                 if 'invoke void @' in line and 'Reader' in line and '12final_secret' in line]
    require(len(producers) == 1, 'one actual consuming-final result producer')
    producer, line = producers[0]
    name, args = guard.call(line)
    require(name in definitions and len(args) in (5, 6)
            and args[0].startswith('ptr sret([24 x i8]) align 8 '), 'original consuming reader ABI')
    result = args[0].rsplit(' ', 1)[1]
    start = guard.successors(graph[producer])[0][0]
    allocations = {m[1]: int(m[2]) for line in graph['start']
                   if (m := re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+', line))}
    require(allocations.get(result) == 24 and allocations.get('%cleanup') == 8, 'original result and guard slots')
    selected, roles, stops, pending = {}, {}, {}, [start]
    allowed = {'branch', 'expose', 'array', 'next_mut', 'accumulate', 'error', 'drop'}
    helpers = {}
    while pending:
        label = pending.pop()
        if label in selected:
            continue
        lines = list(graph[label])
        selected[label] = lines
        invokes = [(i, line) for i, line in enumerate(lines) if 'invoke ' in line]
        if not invokes:
            targets, terminal = guard.successors(lines)
            require(terminal is None, 'no unreviewed final fragment exit')
            pending.extend(targets)
            continue
        require(len(invokes) == 1 and invokes[0][0] == len(lines) - 2, 'terminal final invoke')
        index, line = invokes[0]
        name, args = guard.call(line)
        matches = [role for role in allowed if bulk.TOKENS[role] in name or
                   (name.startswith('_R') and all(part in name for part in bulk.V0[role]))]
        if ('slice' in name and '5first' in name):
            matches.append('first')
        if ('option' in name and '5ok_or' in name):
            matches.append('option')
        require(len(matches) == 1, 'one recognized final comparison dependency')
        role = matches[0]
        if role == 'branch' and args[0].startswith('ptr sret([16 x i8])'):
            role = 'first_branch'
        require(role not in roles or roles[role] == name, 'unique final helper role')
        roles[role] = name
        if role != 'first':
            require(name in definitions and len(model.parameters(definitions[name])) == len(args)
                    and not re.search(r'\b(?:byval|inalloca)\b', definitions[name]), 'bound borrowed final helper ABI')
        else:
            # first() can reside in an external monomorphization; it remains
            # an explicit slice contract, not a claimed interpreted definition.
            require(len(args) == 2 and args[0].startswith('ptr ') and args[1].startswith('i64 ')
                    and re.fullmatch(SSA + r' = invoke (?:align 1 )?ptr @.+', line), 'slice first ABI')
        if role in ('branch', 'first_branch', 'option'):
            helpers[name] = model.parameters(definitions[name]), model.blocks(definitions[name])
        normal, unwind = guard.successors(lines)[0]
        if role in ('drop', 'error'):
            require(role != 'error' or args[0].startswith('i8 '), 'original residual byte')
            selected[label] = lines[:index] + ['call void @boundary_' + role + '(' + args[0] + ')',
                                             'ret i8 ' + str(int(role == 'error'))]
            stops[label] = role
        else:
            pending.append(normal)
            selected[unwind] = ['unreachable']
    require(set(roles) == allowed | {'first', 'option', 'first_branch'}
            and list(stops.values()).count('error') == 2 and list(stops.values()).count('drop') == 1,
            'complete final-byte success, reader-error and empty-output fragments')
    instructions = [line for lines in selected.values() for line in lines]
    values = {line.split(' = ', 1)[0]: line.split(' = ', 1)[1]
              for line in instructions if ' = ' in line}
    def arguments(role):
        calls = [guard.call(line)[1] for line in instructions if 'invoke ' in line and roles[role] in line]
        require(len(calls) == 1, 'one original ' + role + ' invocation')
        return calls[0]
    branch_result = arguments('first_branch')[0].rsplit(' ', 1)[1]
    actual = arguments('accumulate')[1].rsplit(' ', 1)[1]
    load = re.fullmatch(r'load ptr, ptr (' + SSA + r'), align 8', values.get(actual, ''))
    require(load and values.get(load[1]) == 'getelementptr inbounds i8, ptr ' + branch_result + ', i64 8',
            'actual comparison byte is extracted from first-result success, not an equal-valued owner alias')
    require(arguments('accumulate')[2].rsplit(' ', 1)[1] == candidate,
            'final comparison uses original accepted candidate pointer')
    selected['start'] = ['br label %' + start]
    functions = {'fragment': (list(allocations) + [candidate], selected), **helpers}
    return allocations, result, roles, functions, stops


class FinalModel(bulk.ComparisonModel):
    def __init__(self, functions, roles, base, length, tail):
        super().__init__(functions, roles, base, length, 1)
        self.tail, self.first_calls = tail, []

    def run(self, name, args, depth=0):
        p = model.Pointer
        if name in self.functions:
            return model.Model.run(self, name, args, depth)
        if name == self.roles.get('first'):
            expected = p('metadata', self.base) if self.length else p('empty')
            require(args == [expected, self.length] and self.length in (0, 1), 'exact returned final output slice')
            self.first_calls.append(tuple(args))
            return expected if self.length else 0
        if name == self.roles.get('accumulate'):
            require(not self.pairs and self.length == 1
                    and args == [p('metadata', self.base + 65), p('metadata', self.base), p('candidate', self.base + self.tail)],
                    'one final byte compared with the original candidate tail and difference owner')
            self.pairs.append(tuple(args))
            return None
        return super().run(name, args, depth)
