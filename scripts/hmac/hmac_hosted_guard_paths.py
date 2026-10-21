"""Exactly one host guard drop on normal/recoverable unwind exits after initialization."""
import re

import hmac_engine_final as syntax
import hmac_hosted_transaction_values as expressions

require, L = expressions.require, expressions.L


def check(model):
    r = model.r
    queue = [(next(iter(r.graph)), False, 0, False)]
    seen, outcomes = set(), set()
    while queue:
        label, active, dropped, unwinding = queue.pop()
        state = label, active, dropped, unwinding
        if state in seen:
            continue
        seen.add(state)
        require(len(seen) < 1000, 'unbounded host guard lifecycle')
        lines = r.graph[label]
        for index, line in enumerate(lines):
            point = label, index
            call = model.calls.get(point)
            if call:
                name, args = call
                if name == 'llvm.lifetime.start.p0' and syntax.operand(args[-1]) == model.guard:
                    require(not active and not dropped, 'restarted buffer guard')
                    active = True
                if name == 'llvm.lifetime.end.p0' and syntax.operand(args[-1]) == model.guard:
                    require(active and dropped == 1, 'buffer guard reclaimed before destruction')
                    active = False
                if name == model.drop:
                    require(active and dropped == 0, 'missing/duplicate buffer guard owner')
                    dropped += 1
                if name in ('std::process::abort', 'core::panicking::panic_in_cleanup'):
                    outcomes.add('fatal-excluded')
                    break
                if 'invoke ' in line:
                    edge = re.match('to label %' + L + ' unwind label %' + L, lines[index + 1])
                    require(edge, 'guard invoke edges missing')
                    queue.append((edge[1], active, dropped, unwinding))
                    # Actual Buffers destructor is separately inspected; resource
                    # calls are source-bound non-unwinding contracts. All other
                    # invokes keep their real recoverable-unwind edge.
                    nonunwind = (name == model.drop or name.endswith(('Mapping>::clear', 'ProtectedBytes>::clear'))
                                 or '::thread::Attributes' in name and name.endswith(('::drop', '>'))
                                 or name == model.resource + '::thread::join')
                    if not nonunwind:
                        queue.append((edge[2], active, dropped, True))
                    break
            if line.startswith(('br ', 'switch ')):
                end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith(']')), len(lines))
                targets = re.findall('label %' + L, ' '.join(lines[index:end]) if line.startswith('switch ') else line)
                require(targets, 'guard branch without successors')
                queue.extend((target, active, dropped, unwinding) for target in targets)
                break
            if line.startswith(('ret ', 'resume ')):
                require(not active or dropped == 1, 'host exit bypasses buffer destruction')
                require(not unwinding or line.startswith('resume '), 'host swallows an unwind')
                outcomes.add('unwind' if unwinding else 'return')
                break
            require(line != 'unreachable', 'unreviewed guard fatal path')
        else:
            require(False, 'unterminated host guard lifecycle')
    require('return' in outcomes, 'vacuous host guard lifecycle')
    return outcomes
