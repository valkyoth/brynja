"""Path-sensitive MIR checks of run_with's local Storage/Operation drop obligations.

All CFG branches are explored without relying on branch values or assumes.
This is a local owner-invocation check, not a general borrow/resource proof.
Valid Rust references, the reviewed borrow-preserving call contracts and the
separately checked non-unwinding clearing methods remain assumptions. Abort,
double-panic termination, unreachable MIR and nonterminating paths do not
establish cleanup. Thread scope/join and arbitrary alias escape need other checks.
"""
import re

from batch_cleanup_flow import require, compact
import mir_cleanup_flow as flow

PREFIX = 'execution::batch::worker::'
STORAGE = PREFIX + 'Storage'
OPERATION = PREFIX + "Operation<'_, '_, '_, '_>"
RESULT = 'Result::<' + PREFIX + 'Work, execution::batch::Error>'


def blocks(function):
    matches = list(re.finditer(r'^    (bb\d+)(?: \(cleanup\))?: \{\n(.*?)^    }', function, re.M | re.S))
    result = {match[1]: [line.strip() for line in match[2].splitlines() if line.strip()] for match in matches}
    require(len(result) == len(matches) and 'bb0' in result, 'unique lifecycle MIR blocks')
    require(len(matches) == len(re.findall(r'^    bb\d+.*\{', function, re.M)), 'complete lifecycle block parsing')
    require(all(lines for lines in result.values()), 'nonempty lifecycle blocks')
    return result


def guard_check(mir, panic):
    function = flow.exact_function(mir, ('crates/brynja-hash-parallel-std/src/execution/batch/worker.rs:',
                                        '::drop(', '_1: &mut ' + OPERATION))
    code = blocks(function)
    require(set(code) == {'bb0', 'bb1', 'bb2'}, 'exact worker guard blocks')
    cleaned = {b: compact('\n'.join(line for line in lines if not line.startswith(('StorageLive(', 'StorageDead('))))
               for b, lines in code.items()}
    require(re.fullmatch(r'(?P<c>_\d+)=copy\(\(\*_1\)\.1:bool\);switchInt\(move(?P=c)\)->\[0:bb1,otherwise:bb2\];', cleaned['bb0']),
            'incomplete worker guard cancels')
    root = compact("brynja_hash_parallel::execution::Collector<'_, '_, '_>")
    pattern = (r'(?P<r>_\d+)=(?:no_retag)?copy\(\(\*_1\)\.0:&mut' + re.escape(root) + r'\);_\d+=' +
               re.escape(compact("Collector::<'_, '_, '_>::cancel(")) + r'move(?P=r)\)->\[return:bb2,unwind' +
               ('continue' if panic == 'unwind' else 'unreachable') + r'\];')
    require(re.fullmatch(pattern, cleaned['bb1']) and cleaned['bb2'] == 'return;', 'worker guard cancels exact root')
    return function


def owner_local(function, kind):
    found = re.findall(r'^ +let mut (_\d+): ' + re.escape(kind) + ';$', function, re.M)
    require(len(found) == 1, 'unique lifecycle owner type: ' + kind)
    return found[0]


def statements(lines, state, storage, operation):
    # Each owner: 0=not constructed, 1=live, 2=Drop invoked. Completion and
    # result kind are tracked separately; no join merges away a live path.
    s, o, complete, outcome, unwinding = state
    for line in lines:
        require(' -> ' not in line and not line.startswith(('deinit(', 'asm!')), 'no hidden terminator/escape')
        require(re.fullmatch(r'(?:StorageLive|StorageDead)\(_\d+\);|assume\(.+\);|.+ = .+;', line), 'reviewed MIR statement shape')
        require(not line.startswith('_2 = '), 'root input binding must not be reassigned')
        if re.fullmatch(re.escape(operation) + r' = ' + re.escape(PREFIX) +
                        r"Operation::<'_, '_, '_, '_> \{ root: copy _2, complete: const false };", line):
            require(o == 0, 'operation constructed exactly once')
            o = 1
            continue
        if re.fullmatch(re.escape(storage) + ' = ' + re.escape(STORAGE) + r'\(move _\d+\);', line):
            require(s == 0 and o == 1 and not complete, 'storage constructed under live incomplete guard')
            s = 1
            continue
        completion = re.fullmatch(r'\(' + re.escape(operation) + r'\.1: bool\) = const (true|false);', line)
        if completion:
            require(o == 1 and s == 1 and not unwinding, 'completion only while owners live normally')
            complete = completion[1] == 'true'
            continue
        if line.startswith('_0 = '):
            result = re.match('_0 = ' + re.escape(RESULT) + r'::(Ok|Err)\(', line)
            require(result, 'known lifecycle return identity')
            outcome = result[1]
        for local, status in ((storage, s), (operation, o)):
            if local not in re.findall(r'_\d+', line):
                continue
            if line == 'StorageLive(' + local + ');':
                require(status == 0, 'owner storage activation before construction')
                continue
            if line == 'StorageDead(' + local + ');':
                require(status != 1, 'live owner cannot lose storage before Drop')
                continue
            require(status == 1, 'no access to unconstructed/dropped owner')
            assignment = re.fullmatch(r'(_\d+) = (.*);', line)
            require(assignment and assignment[1] not in (storage, operation), 'no owner overwrite/field write')
            expression = assignment[2].removeprefix('no_retag ')
            require(expression.startswith(('copy (', '&mut (')) and
                    not re.search(r'\bmove\b', expression) and
                    re.search(r'\(' + re.escape(local) + r'\.0:', expression),
                    'only projected borrowed/metadata owner access, never ownership transfer')
    return s, o, complete, outcome, unwinding


def edges(text, panic):
    match = re.fullmatch(r'return: (bb\d+), unwind(?:: (bb\d+)| (unreachable|continue|terminate\(cleanup\)))', text)
    require(match, 'reviewed return/unwind edges')
    require(panic != 'abort' or match[3] == 'unreachable', 'abort profile must not claim unwind cleanup')
    return match[1], match[2], match[3]


def call_allowed(target):
    exact = {'live(', 'alloc::raw_vec::RawVecInner::try_reserve_exact(', 'Vec::<[[u8; 64]; 4]>::resize(',
             '<usize as Ord>::min(', PREFIX + 'Work::merge(', 'std::intrinsics::cold_path('}
    if target in exact:
        return True
    return re.fullmatch(r"scope::<'_, \{closure@crates/brynja-hash-parallel-std/src/execution/batch/worker.rs:\d+:\d+: \d+:\d+}, " +
                        re.escape('Result<' + PREFIX + 'Work, execution::batch::Error>') + r'>\(', target) is not None


def inspect(function, panic):
    code = blocks(function)
    storage, operation = owner_local(function, STORAGE), owner_local(function, OPERATION)
    pending = [('bb0', (0, 0, False, None, False))]
    visited, exits, events = set(), set(), set()
    while pending:
        block, incoming = pending.pop()
        require(block in code, 'known lifecycle successor')
        if (block, incoming) in visited:
            continue
        visited.add((block, incoming))
        lines = code[block]
        state = statements(lines[:-1], incoming, storage, operation)
        s, o, complete, outcome, unwinding = state
        if s == 1:
            events.add('storage')
        end = lines[-1]
        if end in ('return;', 'resume;'):
            require(s != 1 and o == 2, 'all constructed owners dropped before lifecycle exit')
            require(unwinding == (end == 'resume;'), 'unwind cannot become a normal return')
            if end == 'return;':
                require(outcome in ('Ok', 'Err'), 'known returned result')
                exits.add(outcome)
            else:
                exits.add('unwind')
            continue
        if end == 'unreachable;':
            require(lines == ['unreachable;'] and block != 'bb0', 'only isolated invalid-discriminant sink')
            continue  # Valid Rust discriminants/intrinsic contracts assumed.
        goto = re.fullmatch(r'goto -> (bb\d+);', end)
        branch = re.fullmatch(r'switchInt\(.+\) -> \[((?:\d+: bb\d+, )*otherwise: bb\d+)];', end)
        if goto or branch:
            for successor in ([goto[1]] if goto else re.findall(r'bb\d+', branch[1])):
                if code.get(successor) == ['unreachable;']:
                    # Only invalid 0/1 enum discriminants may use the assumed
                    # unreachable sink, not arbitrary dropped cleanup edges.
                    subject = re.fullmatch(r'switchInt\((?:copy|move) (_\d+)\) -> \[0: (bb\d+), 1: (bb\d+), otherwise: ' + successor + r'];', end)
                    require(subject and successor not in (subject[2], subject[3]) and
                            len(re.findall(re.escape(subject[1]) + r' = discriminant\(', function)) == 1,
                            'unreachable only for invalid enum discriminant')
                pending.append((successor, state))
            continue
        dropped = re.fullmatch(r'drop\((_\d+)\) -> \[(.*)];', end)
        call = flow.call_definition(end)
        if dropped:
            require(dropped[1] in (storage, operation), 'only exact owner drops')
            if dropped[1] == storage:
                require(s == 1 and o == 1, 'storage Drop once, before operation Drop')
                s = 2
                events.add('storage-drop')
            else:
                require(o == 1 and s != 1, 'operation Drop once, after any storage Drop')
                require(complete == (outcome == 'Ok'), 'only successful result disarms cancellation')
                o = 2
                events.add('operation-drop')
            edge_text = dropped[2]
        else:
            require(call and call_allowed(call[1]), 'only reviewed borrow-preserving lifecycle calls')
            require(call[0] != '_0', 'call must not overwrite tracked result')
            require(not ({storage, operation} & set(re.findall(r'_\d+', call[0] + call[2]))), 'no direct owner call escape/overwrite')
            if call[1].startswith('scope::'):
                require(s == o == 1 and not complete, 'worker scope under live incomplete owners')
                events.add('scope')
            edge_text = call[4]
        normal, unwind, terminal = edges(edge_text, panic)
        if panic == 'unwind':
            if dropped:
                require(terminal != 'unreachable', 'owner drop unwind cannot disappear')
                require(terminal != 'terminate(cleanup)' or unwinding, 'termination only during cleanup unwind')
            elif call[1] == 'std::intrinsics::cold_path(':
                require(terminal == 'unreachable', 'cold-path intrinsic is non-unwinding')
            else:
                require(unwind is not None, 'fallible call must retain its cleanup edge')
        require(code.get(normal) != ['unreachable;'], 'normal call/drop return cannot hide in unreachable')
        require(not unwind or code.get(unwind) != ['unreachable;'], 'unwind cannot hide in unreachable')
        state = s, o, complete, outcome, unwinding
        pending.append((normal, state))
        if unwind:
            pending.append((unwind, (s, o, complete, outcome, True)))
        elif terminal == 'continue':
            require(s != 1 and o == 2, 'no recoverable unwind escapes live owners')
            exits.add('unwind')
        # unreachable/terminate edges do not promise destruction on abort.
    require(exits == ({'Ok', 'Err', 'unwind'} if panic == 'unwind' else {'Ok', 'Err'}), 'nonvacuous normal/error/unwind coverage')
    require(events == {'storage', 'storage-drop', 'operation-drop', 'scope'}, 'nonvacuous owner/scope lifecycle')
    require({b for b, _ in visited} == set(code), 'no hidden/unvisited lifecycle blocks')
    return len(visited)


def check(row, panic):
    guard = guard_check(row['mir'], panic)
    function = flow.exact_function(row['mir'], ('fn ' + PREFIX + 'run_with(', '_2: &mut Collector<'))
    return inspect(function, panic), function, guard


def mutations(row, panic):
    states, function, guard = check(row, panic)
    storage = owner_local(function, STORAGE)
    cases = [(function, function.replace('complete: const false', 'complete: const true')),
             (function, function.replace('root: copy _2', 'root: copy _1')),
             (function, function.replace(' = const true;', ' = const false;')),
             (guard, guard.replace('0: bb1, otherwise: bb2', '0: bb2, otherwise: bb1')),
             (guard, guard.replace('::cancel(', '::omitted(')),
             (guard, guard.replace(').0: &mut', ').1: &mut'))]
    for match in re.finditer(r'drop\(_\d+\) -> \[return: (bb\d+), [^\n]+;', function):
        cases.append((function, function[:match.start()] + 'goto -> ' + match[1] + ';' + function[match.end():]))
    if panic == 'unwind':
        for match in re.finditer(r'unwind: bb\d+', function):
            cases.append((function, function[:match.start()] + 'unwind unreachable' + function[match.end():]))
    initialization = re.search(re.escape(storage) + ' = ' + re.escape(STORAGE) + r'\(move _\d+\);', function)
    require(initialization, 'exact worker storage initialization')
    cases.append((function, function.replace(initialization[0], initialization[0] + '\n        _999 = move ' + storage + ';')))
    for original, altered in cases:
        require(original != altered, 'nonvacuous lifecycle artifact mutation')
        try:
            check(dict(row, mir=row['mir'].replace(original, altered)), panic)
        except (ValueError, flow.MirCleanupFlowError):
            continue
        raise AssertionError('worker lifecycle artifact regression survived')
    return states, len(cases)
