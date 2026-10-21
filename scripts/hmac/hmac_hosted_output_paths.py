"""Returned secret-owner cleanup dispatch on normal and recoverable unwind paths."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax

require, VALUE = common.require, syntax.VALUE


def check(output, panic):
    m = output.model
    require(panic in ('abort', 'unwind'), 'unknown output panic profile')
    queue = [(output.cut[0], output.cut[1] + 1, False, frozenset(), False)]
    seen, exits, drops = set(), set(), set()
    cleanup = {point for _, point in output.drops}
    while queue:
        label, start, done, facts, unwinding = queue.pop()
        state = label, start, done, facts, unwinding
        if state in seen:
            continue
        seen.add(state)
        require(label in m.graph and len(seen) < 15000, 'output cleanup graph exceeds bound')
        lines = m.graph[label]
        for index in range(start, len(lines)):
            line, point = lines[index], (label, index)
            definition = re.match('(' + VALUE + ') =', line)
            if definition:
                facts = frozenset(item for item in facts if item[0] != definition[1])
            if point in cleanup:
                require(not done, 'duplicate output owner destruction')
                done = True  # Dispatch on both edges, not a fatal-path erasure claim.
                drops.add(point)
            elif point == output.copy[1]:
                require(not done, 'output copy after owner destruction')
            load = re.search(r'\bload [^,]+, ptr (' + VALUE + '),', line)
            if load and (address := m.pointer(load[1])):
                require(not (done and address[0] == output.owner[0]), 'output read after destruction')
            if point in m.call_map:
                symbol, args = m.call_map[point]
                if symbol == 'llvm.lifetime.end.p0' and m.pointer(syntax.operand(args[-1])) == output.owner:
                    require(done, 'output lifetime ends without destruction')
                require(panic == 'abort' or done or symbol.startswith('llvm.') or 'invoke ' in line,
                        'live output call lacks unwind cleanup edge')
            elif re.search(r'\b(?:call|invoke)\b', line):
                require(done, 'indirect call with live output owner')
            if re.search(r'\binvoke\b', line):
                edges = re.fullmatch(r'to label %' + common.LABEL + r' unwind label %'
                                     + common.LABEL + r'(?:,.*)?', lines[index + 1])
                require(edges, 'output invoke edges changed')
                queue += [(edge, 0, done, facts, unwinding or exceptional)
                          for edge, exceptional in zip(edges.groups(), (False, True))]
                break
            if line.startswith(('br ', 'switch ')):
                text = line if line.startswith('br ') else '\n'.join(lines[index:]).split(']', 1)[0]
                edges = re.findall(r'label %' + common.LABEL, text)
                require(edges, 'output branch lacks targets')
                conditional = re.fullmatch(r'br i1 (' + VALUE + '), label %' + common.LABEL
                                           + ', label %' + common.LABEL + r'(?:,.*)?', line)
                if conditional:
                    known = dict(facts).get(conditional[1])
                    queue += [(edge, 0, done, facts | {(conditional[1], truth)}, unwinding)
                              for edge, truth in zip(edges, (True, False)) if known is None or known == truth]
                else:
                    queue += [(edge, 0, done, facts, unwinding) for edge in edges]
                break
            if line.startswith(('ret ', 'resume ')):
                require(done, 'worker exits without output owner destruction')
                exits.add(label)
                break
            if line == 'unreachable':
                require(unwinding and any(at[0] == label and m.names.get(symbol) in
                        ('core::panicking::panic_in_cleanup', 'core::panicking::panic_cannot_unwind')
                        for symbol, _, at in m.calls),
                        'unexpected output fatal path')
                break
        else:
            require(False, 'unterminated output cleanup block')
    require(exits and drops == cleanup, 'vacuous/unreachable output cleanup population')
    return seen
