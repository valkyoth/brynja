"""Actual emitted buffer destructor: exact storage, conditional output, unconditional staging."""
import itertools
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_transaction_values as expressions

require, V, L = common.require, syntax.VALUE, common.LABEL


def run(arguments, body, names, apple, keep, states):
    params = syntax.parameters(arguments)
    require(len(params) == 1 and 'dereferenceable(24)' in params[0], 'buffer destructor formal changed')
    values = {syntax.operand(params[0]): ('guard', 0)}
    memory = {('guard', 0): ('destination', 0), ('guard', 8): ('staging', 0), ('guard', 16): keep}
    expected = []
    for role, length, (present, locked, same_pid) in zip(('staging', 'destination'), (17, 31), states):
        memory.update({(role, 0): (role + '-bytes', 0), (role, 8): (role, -1) if present else None,
                       (role, 24 if apple else 16): length,
                       (role, 52 if apple else 48): locked})
        if apple:
            memory[role, 48] = 1 if same_pid else 2
        if present and locked and (not apple or same_pid) and (role == 'staging' or not keep):
            expected.append((role + '-bytes', length))
    graph, cleared, visited = common.blocks(body), [], set()
    block, predecessor = next(iter(graph)), None

    def value(token):
        if token in ('null', 'true', 'false'):
            return {'null': None, 'true': 1, 'false': 0}[token]
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        require(token in values, 'unknown buffer destructor SSA')
        return values[token]

    while True:
        require(block not in visited and len(visited) < 40, 'cyclic/oversized buffer destructor')
        visited.add(block)
        for line in graph[block]:
            line = line.split(', !', 1)[0]
            assignment = re.match('(' + V + ') = (.*)', line)
            name, rhs = assignment.groups() if assignment else (None, line)
            gep = re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? i8, ptr (' + V + r'), i64 (\d+)', rhs)
            load = re.fullmatch(r'load (ptr|i8|i32|i64), ptr (' + V + r'), align \d+', rhs)
            call = syntax.call(line)
            if gep:
                base = value(gep[1])
                require(isinstance(base, tuple), 'buffer destructor pointer lost provenance')
                values[name] = base[0], base[1] + int(gep[2])
            elif load:
                address = value(load[2])
                require(address in memory, 'buffer destructor reads outside reviewed owners')
                values[name] = memory[address]
            elif call:
                symbol, args = call
                require('invoke ' not in line, 'buffer destructor unexpectedly unwinds')
                if symbol == 'llvm.experimental.noalias.scope.decl':
                    continue
                if symbol == 'getpid':
                    require(apple and args == [''], 'unexpected buffer PID query')
                    values[name] = 1
                else:
                    require(names.get(symbol) == 'brynja_core::secret_memory::clear_owned_region' and len(args) == 2,
                            'unreviewed buffer destructor call')
                    ptr = value(syntax.operand(args[0]))
                    length = value(re.search('(' + V + r'|\d+)$', args[1])[1])
                    require(isinstance(ptr, tuple) and ptr[1] == 0, 'buffer clear starts at wrong address')
                    cleared.append((ptr[0], length))
                    # The return is ignored in the reviewed destructor. Do not
                    # invent a concrete value that could prove a new branch.
            elif rhs.startswith('br '):
                branch = re.fullmatch(r'br i1 (' + V + '), label %' + L + ', label %' + L, rhs)
                jump = re.fullmatch('br label %' + L, rhs)
                require(branch or jump, 'unparsed buffer destructor branch')
                following = branch[2] if branch and expressions.integer(value(branch[1]), 1) else branch[3] if branch else jump[1]
                predecessor, block = block, following
                break
            elif rhs == 'ret void':
                require(cleared == expected, 'buffer staging/output clearing identity, extent or condition changed')
                return visited
            else:
                require(name is not None, 'unreviewed buffer destructor instruction')
                values[name] = expressions.evaluate(rhs, value, predecessor)
        else:
            require(False, 'unterminated buffer destructor')


def check(arguments, body, names, target):
    apple = target == 'aarch64-apple-darwin'
    states = tuple(itertools.product((0, 1), (0, 1), (0, 1) if apple else (1,)))
    visited = set()
    for keep, staging, output in itertools.product((0, 1), states, states):
        visited.update(run(arguments, body, names, apple, keep, (staging, output)))
    require(visited == set(common.blocks(body)), 'unreviewed buffer destructor path')


def validate(llvm, target):
    definitions, aliases = common.definitions_and_aliases(llvm)
    names = lifecycle.demangle({name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
    owner, _ = lifecycle.profile(target)
    expected = '<' + owner + '::Buffers as core::ops::drop::Drop>::drop'
    selected = [symbol for symbol in (*definitions, *aliases) if names[symbol] == expected]
    require(len(selected) == 1, 'missing/ambiguous buffer destructor')
    arguments, body = common.resolve(selected[0], definitions, aliases)
    check(arguments, body, names, target)
    return arguments, body, names
