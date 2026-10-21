"""Bounded emitted checkpoint callees; Authority.session internals remain a premise."""
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle

require, V, L = common.require, syntax.VALUE, common.LABEL
SESSION = '<brynja_crypto_cpu::static_execution::Authority>::session'


def run(arguments, body, names, compiled, healthy, cancelled, compiler):
    params = syntax.parameters(arguments)
    require(len(params) == (2 if compiled else 1), 'checkpoint callee parameter population')
    values = {syntax.operand(params[0]): 'cancel'}
    if compiled:
        values[syntax.operand(params[1])] = 'owner'
    graph = common.blocks(body)
    block, predecessor = next(iter(graph)), None
    live, session, loads, visited = set(), False, 0, set()
    slot = None

    def value(token):
        if token in ('undef', 'poison'):
            return 'undefined'
        if token == 'null':
            return None
        if re.fullmatch(r'-?\d+', token):
            return int(token) & 255
        require(token in values, 'unknown checkpoint callee value')
        return values[token]

    while True:
        require(block not in visited and len(visited) < 12, 'checkpoint callee loop/oversized graph')
        visited.add(block)
        incoming = dict(values)
        for line in graph[block]:
            line = line.split(', !', 1)[0]
            assignment = re.match('(' + V + ') = (.*)', line)
            name, rhs = assignment.groups() if assignment else (None, line)
            alloc = re.fullmatch(r'alloca \[16 x i8\], align 8', rhs)
            atomic = re.fullmatch(r'load atomic i8, ptr (' + V + r') acquire, align 1', rhs)
            load = re.fullmatch(r'load (ptr|i8), ptr (' + V + r'), align 8', rhs)
            gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 8', rhs)
            compare = re.fullmatch(r'icmp eq (?:i8|ptr) (' + V + r'), (0|null)', rhs)
            select = re.fullmatch(r'select i1 (' + V + r'), i8 (-?\d+), i8 (-?\d+)', rhs)
            phi = re.fullmatch(r'phi i8 (.*)', rhs)
            insert = re.fullmatch(r'insertvalue \{ i8, i8 \} (' + V + r'|poison|undef), i8 ('
                                 + V + r'|-?\d+|undef), ([01])', rhs)
            branch = re.fullmatch(r'br i1 (' + V + r'), label %' + L + ', label %' + L, rhs)
            jump = re.fullmatch(r'br label %' + L, rhs)
            returned = re.fullmatch(r'ret \{ i8, i8 \} (' + V + ')', rhs)
            if alloc:
                require(compiled and slot is None, 'checkpoint session slot population')
                slot = name
                values[name] = ('slot', 0)
            elif atomic:
                require(value(atomic[1]) == 'cancel' and (not compiled or session and healthy),
                        'cancellation read before successful authority check or wrong address')
                loads += 1
                values[name] = int(cancelled)
            elif load:
                require(session and slot in live, 'checkpoint result read outside initialized session slot')
                address = value(load[2])
                require(address == ('slot', 0) if load[1] == 'ptr' else address == ('slot', 8) and not healthy,
                        'checkpoint session result field changed')
                values[name] = ('borrowed-session' if healthy else None) if load[1] == 'ptr' else 'backend-error'
            elif gep:
                require(value(gep[1]) == ('slot', 0), 'checkpoint error payload address changed')
                values[name] = ('slot', 8)
            elif compare:
                values[name] = value(compare[1]) == value(compare[2])
            elif select:
                require(isinstance(value(select[1]), bool), 'unknown checkpoint select condition')
                values[name] = value(select[2] if value(select[1]) else select[3])
            elif phi:
                entries = re.findall(r'\[ (' + V + r'|-?\d+|undef), %' + L + r' \]', phi[1])
                require(phi[1] == ', '.join('[ ' + item + ', %' + label + ' ]' for item, label in entries),
                        'unparsed checkpoint phi')
                selected = [item for item, label in entries if label == predecessor]
                require(len(selected) == 1, 'checkpoint phi predecessor changed')
                values[name] = incoming[selected[0]] if selected[0] in incoming else value(selected[0])
            elif insert:
                base = value(insert[1])
                parts = ['undefined', 'undefined'] if base == 'undefined' else list(base)
                require(len(parts) == 2, 'checkpoint return aggregate shape')
                parts[int(insert[3])] = value(insert[2])
                values[name] = tuple(parts)
            elif branch or jump:
                if branch:
                    require(isinstance(value(branch[1]), bool), 'unknown checkpoint branch condition')
                    following = branch[2] if value(branch[1]) else branch[3]
                else:
                    following = jump[1]
                predecessor, block = block, following
                break
            elif returned:
                ok = 255 if compiler == '1.99.1' else 11
                expected = (9, 'backend-error') if compiled and not healthy else ((6 if cancelled else ok), 'undefined')
                require(value(returned[1]) == expected and not live
                        and session == compiled and loads == int(not compiled or healthy),
                        'checkpoint does not preserve health-before-cancellation result')
                return visited
            else:
                call = syntax.call(line) if '@' in line else None
                require(call and name is None and 'invoke ' not in line, 'unreviewed checkpoint callee instruction: ' + line)
                symbol, args = call
                if symbol.startswith('llvm.lifetime.'):
                    require(syntax.operand(args[-1]) == slot, 'checkpoint lifetime targets another slot')
                    if symbol == 'llvm.lifetime.start.p0':
                        require(slot not in live and not session, 'checkpoint slot restarted')
                        live.add(slot)
                    else:
                        require(symbol == 'llvm.lifetime.end.p0' and slot in live and session,
                                'checkpoint session lifetime ended prematurely')
                        live.remove(slot)
                else:
                    require(names.get(symbol) == SESSION and compiled and not session and loads == 0
                            and slot in live and len(args) == 2
                            and value(syntax.operand(args[0])) == ('slot', 0)
                            and value(syntax.operand(args[1])) == 'owner',
                            'checkpoint session does not borrow exact owner before cancellation')
                    session = True
        else:
            require(False, 'checkpoint callee block has no termination')


def validate(llvm, target, compiler):
    require(compiler in ('1.90.0', '1.99.1')
            and re.findall(r'!"rustc version ([\d.]+) ', llvm) == [compiler], 'checkpoint callee compiler changed')
    definitions, aliases = common.definitions_and_aliases(llvm)
    names = lifecycle.demangle({name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
    owner, _ = lifecycle.profile(target)
    targets = ('<' + owner + '::types::Cancellation>::check', owner + '::worker::checkpoint',
               owner + '::compiled::worker::checkpoint')
    checked = []
    for position, target_name in enumerate(targets):
        symbols = [symbol for symbol in (*definitions, *aliases) if names[symbol] == target_name]
        require(len(symbols) == 1, 'missing/ambiguous checkpoint callee')
        arguments, body = common.resolve(symbols[0], definitions, aliases)
        visited = set()
        for healthy in ((False, True) if position == 2 else (True,)):
            for cancelled in (False, True):
                visited.update(run(arguments, body, names, position == 2, healthy, cancelled, compiler))
        require(visited == set(common.blocks(body)), 'checkpoint callee contains unreviewed paths')
        checked.append((arguments, body, position == 2))
    return names, checked
