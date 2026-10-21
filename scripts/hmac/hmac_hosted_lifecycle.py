"""Emitted host create/join/reclaim ordering; not worker payload qualification."""
import re
import shutil
import subprocess

import hmac_engine_codegen as common
import hmac_engine_final as syntax

require, VALUE = common.require, syntax.VALUE
OPERATIONS = ('compute', 'verify', 'compiled_compute', 'compiled_verify')


def demangle(names):
    names = sorted(names)
    command = (['llvm-cxxfilt'] if shutil.which('llvm-cxxfilt') else
               ['c++filt', '--format=rust', '--no-strip-underscore', '--no-verbose'])
    result = subprocess.run(command, input='\n'.join(names) + '\n',
                            text=True, capture_output=True, check=True, timeout=30)
    values = result.stdout.splitlines()
    require(len(values) == len(names), 'hosted demangler population changed')
    return {name: re.sub(r'::h[0-9a-f]{16}$', '', value) for name, value in zip(names, values)}


def profile(target):
    apple = target == 'aarch64-apple-darwin'
    require(apple or target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'),
            'unsupported hosted compiler target')
    owner = 'brynja_crypto_cpu_std::' + ('macos_resident::hmac' if apple else 'strict_hmac')
    resource = 'brynja_crypto_cpu_std::' + (
        'macos_resident::resource::darwin' if apple else 'protected_memory::platform')
    return owner, resource


def check_host(body, names, definitions, target):
    owner, resource = profile(target)
    mapping = '<' + resource + '::Mapping>'
    attribute = resource + '::thread::Attributes'
    events = {
        '<' + attribute + '>::new': 'attributes',
        mapping + '::clear': 'clear',
        'pthread_create': 'create',
        ('pthread_join' if 'darwin' in resource else resource + '::thread::join'): 'join',
        'std::process::abort': 'fatal', 'core::panicking::panic_in_cleanup': 'fatal',
    }
    allowed = {
        owner + '::types::validate', '<' + owner + '::types::Cancellation>::check',
        '<' + owner + '::Buffers as core::ops::drop::Drop>::drop',
        '<' + attribute + ' as core::ops::drop::Drop>::drop',
        'core::ptr::drop_glue::<' + attribute + '>',
        'core::ptr::drop_in_place<' + attribute + '>',
        '__rustc::__rust_dealloc', '__rust_dealloc',
        '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>::clear',
        mapping + '::bytes_mut', mapping + '::foreign',
    }
    intrinsics = {'llvm.lifetime.start.p0', 'llvm.lifetime.end.p0', 'llvm.memcpy.p0.p0.i64',
                  'llvm.experimental.noalias.scope.decl', 'llvm.assume'}
    calls = [(line, call) for line in body.splitlines() if (call := syntax.call(line))]
    by_event = {kind: [(line, args) for line, (symbol, args) in calls
                      if events.get(names.get(symbol, symbol)) == kind]
                for kind in ('attributes', 'create', 'join')}
    require(all(len(rows) == 1 for rows in by_event.values()), 'host launch/attribute/join population')
    stack = syntax.operand(by_event['attributes'][0][1][-1])
    create_args = by_event['create'][0][1]
    require(len(create_args) == 4, 'pthread_create signature changed')
    slot, job = syntax.operand(create_args[0]), syntax.operand(create_args[3])
    worker = re.fullmatch(r'ptr [^@]*@([\w.$]+)', create_args[2])
    require(worker and worker[1] in definitions, 'missing concrete hosted worker callback')
    require(names[worker[1]].startswith(resource + '::thread::enter<')
            or names[worker[1]].startswith(resource + '::thread::enter::<'),
            'wrong hosted worker callback')
    # Load the actual pthread handle, not another integer/pointer of the same type.
    joined = re.search('(' + VALUE + r')$', by_event['join'][0][1][0])
    require(joined and re.search(re.escape(joined[1]) + r' = load (?:i64|ptr), ptr '
                                + re.escape(slot) + ',', body), 'join handle not from created worker')
    graph = common.blocks(body)
    queue = [(next(iter(graph)), 'idle', (), False)]
    visited, outcomes = set(), set()
    while queue:
        label, phase, known, unwinding = queue.pop()
        state = label, phase, known, unwinding
        if state in visited:
            continue
        visited.add(state)
        require(label in graph and len(visited) < 10000, 'unknown/unbounded host flow')
        values = dict(known)
        lines = graph[label]
        terminal = False
        for index, line in enumerate(lines):
            call = syntax.call(line)
            event = None
            if call:
                symbol, args = call
                name = names.get(symbol, symbol)
                event = events.get(name)
                require(event or name in allowed or symbol in intrinsics, 'unreviewed host call: ' + name)
                if phase in ('running', 'join_failed'):
                    require(event in ('join', 'fatal'), 'call while unjoined worker remains live')
                if event in ('create', 'join'):
                    require(phase == ('idle' if event == 'create' else 'running'), 'duplicate/out-of-order native call')
                    result = re.match('(' + VALUE + r') = ', line)
                    require(result, 'missing native status')
                    if 'invoke ' in line:
                        edges = re.match(r'to label %' + common.LABEL + r' unwind label %' + common.LABEL,
                                         lines[index + 1])
                        require(edges, 'missing native invoke edge')
                        destination = edges[1]
                    else:
                        # Current create call is followed by one status compare and branch.
                        destination = None
                    variants = ((0, 'running'), (1, 'failed')) if event == 'create' else (
                        (0, 'joined'), (1, 'join_failed'))
                    if destination:
                        for value, next_phase in variants:
                            queue.append((destination, next_phase, ((result[1], value),), unwinding))
                        terminal = True
                        break
                    # A synchronous libc call never unwinds. Interpret the rest
                    # of its current block once per return-code class.
                    suffix = label + ':after:' + str(index)
                    graph[suffix] = lines[index + 1:]
                    for value, next_phase in variants:
                        queue.append((suffix, next_phase, ((result[1], value),), unwinding))
                    terminal = True
                    break
                if event == 'clear' and syntax.operand(args[0]) == stack:
                    require(phase in ('failed', 'joined'), 'stack clear before termination')
                    phase = 'cleared_' + phase
                if event == 'fatal':
                    outcomes.add('fatal')
                    terminal = True
                    break
                if symbol == 'llvm.lifetime.end.p0' and syntax.operand(args[-1]) in (job, slot):
                    require(phase.startswith('cleared_'), 'job reclaimed before join/clear')
                if 'invoke ' in line:
                    edges = re.match(r'to label %' + common.LABEL + r' unwind label %' + common.LABEL,
                                     lines[index + 1])
                    require(edges, 'missing host invoke edges')
                    queue.append((edges[1], phase, tuple(sorted(values.items())), unwinding))
                    # Mapping.clear and native attribute destruction are separately
                    # source-bound non-unwinding leaves; no fictional unwind edge.
                    if event != 'clear' and not ('Attributes' in name and name.endswith('::drop')):
                        queue.append((edges[2], phase, tuple(sorted(values.items())), True))
                    terminal = True
                    break
            comparison = re.fullmatch('(' + VALUE + r') = icmp (eq|ne) i32 (' + VALUE + r'), 0', line)
            if comparison and comparison[3] in values:
                values[comparison[1]] = int((values[comparison[3]] == 0) == (comparison[2] == 'eq'))
            if phase in ('running', 'join_failed'):
                handle_load = re.fullmatch(VALUE + r' = load (?:i64|ptr), ptr '
                                          + re.escape(slot) + r',.*', line)
                require(handle_load or comparison or line.startswith('br '),
                        'unreviewed instruction while worker live')
            if line.startswith('br '):
                targets = re.findall(r'label %' + common.LABEL, line)
                condition = re.match('br i1 (' + VALUE + '),', line)
                require(len(targets) in (1, 2), 'unknown host branch')
                if condition and condition[1] in values:
                    targets = [targets[0 if values[condition[1]] else 1]]
                queue.extend((target, phase, tuple(sorted(values.items())), unwinding) for target in targets)
                terminal = True
                break
            if line.startswith('switch '):
                end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith(']')), None)
                require(end is not None, 'unterminated host switch')
                targets = re.findall(r'label %' + common.LABEL, ' '.join(lines[index:end]))
                require(targets, 'empty host switch')
                queue.extend((target, phase, tuple(sorted(values.items())), unwinding) for target in targets)
                terminal = True
                break
            if line.startswith(('ret ', 'resume ')):
                require(phase == 'idle' or phase.startswith('cleared_'), 'return without completed reclaim')
                outcomes.add(phase)
                terminal = True
                break
            require(line != 'unreachable', 'unreviewed host unreachable')
        require(terminal, 'unterminated host lifecycle block: ' + label)
    require({'cleared_joined', 'cleared_failed', 'fatal'} <= outcomes, 'vacuous hosted lifecycle')
    return worker[1]
