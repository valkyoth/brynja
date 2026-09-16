"""Post-spawn cleanup reachability in the actual inlined LLVM coordinator.

After native thread creation is attempted, all normal returns and recoverable
unwind exits must pass Storage clear or its qualified retained drop glue. This
is call reachability, NOT argument provenance, worker joining, store preservation,
or the full caller lifecycle before spawn. Valid LLVM/Rust execution and callee
contracts are assumed; abort, invalid-enum sinks and infinite paths prove no wipe.
"""
import re

import batch_worker_arguments as arguments
import batch_worker_drop_glue as glue
import batch_worker_cfg as cfg
from batch_cleanup_flow import require, llvm_function

SPAWN = (r'(?:_ZN3std3sys3pal4unix6thread6Thread3new17h[0-9a-f]+E|'
         r'_RNvMs0_NtNtNtCs[\w]+_3std3sys6thread4unixNtB5_6Thread3new)')


def inspect(body, clear, drop, noreturn):
    blocks, edges, predecessors = cfg.parse(body)
    spawn_sites = [(b, i) for b, lines in blocks.items() for i, line in enumerate(lines)
                   if re.fullmatch(SPAWN, cfg.callee(line) or '')]
    require(len(spawn_sites) == 1, 'one native worker-spawn site in coordinator')
    # Start at entry so even the spawn marker itself must be reachable. Preserve
    # separate facts at joins rather than forgetting a possibly dirty path.
    pending, seen, exits, reached_spawn = [('start', False, False)], set(), set(), False
    cleared_sites = set()
    while pending:
        block, active, dirty = pending.pop()
        state = block, active, dirty
        if state in seen:
            continue
        seen.add(state)
        for index, line in enumerate(blocks[block]):
            symbol = cfg.callee(line)
            if (block, index) == spawn_sites[0]:
                active = dirty = reached_spawn = True
            elif symbol == clear or (drop is not None and symbol == drop):
                if active:
                    cleared_sites.add((block, index))
                dirty = False
        kind, successors = edges[block]
        if kind in ('ret', 'resume'):
            require(not dirty, 'inlined worker exit bypasses Storage cleanup: ' + block)
            if active:
                exits.add(kind)
        elif kind == 'unreachable':
            require(cfg.unreachable_is_terminal(block, blocks, edges, predecessors, noreturn),
                    'unreviewed coordinator unreachable sink: ' + block)
        else:
            pending.extend((successor, active, dirty) for successor in successors)
    require(reached_spawn and cleared_sites and 'ret' in exits, 'non-vacuous post-spawn cleanup paths')
    require({b for b, _, _ in seen} == set(blocks), 'all coordinator CFG blocks reached')
    return len(seen), exits, cleared_sites


def check(row, panic):
    body = llvm_function(row['ll'], ('9execution5batch', '8Executor7execute'))
    retained = glue.check(row, panic)
    drop = (re.search('@(' + cfg.SYMBOL + r')\(', retained[0].splitlines()[0])[1].strip('"')
            if retained else None)
    clear = arguments.functions(row)[2]
    stats = inspect(body, clear, drop, cfg.noreturn_symbols(row['ll']))
    require(('resume' in stats[1]) == (panic == 'unwind'), 'profile-correct post-spawn exit coverage')
    return body, clear, drop, stats


def mutations(row, panic):
    body, clear, drop, stats = check(row, panic)
    blocks, _, _ = cfg.parse(body)
    count = 0
    for block, index in stats[2]:
        symbol = cfg.callee(blocks[block][index])
        # Preserve valid LLVM instructions/CFG and alter just one real callee.
        # Locate the original single-line invocation before joined successors.
        call_line = blocks[block][index].split(' to label ', 1)[0]
        headers = list(re.finditer('^(' + cfg.LABEL + r'):', body, re.M))
        positions = [i for i, header in enumerate(headers) if header[1] == block]
        require(len(positions) == 1, 'unique cleanup mutation block')
        position = positions[0]
        start = headers[position].end()
        end = headers[position + 1].start() if position + 1 < len(headers) else len(body)
        segment = body[start:end]
        require(segment.count(call_line) == 1, 'unique emitted cleanup call within block')
        changed = body[:start] + segment.replace(call_line, call_line.replace(symbol, symbol + '_omitted')) + body[end:]
        try:
            inspect(changed, clear, drop, cfg.noreturn_symbols(row['ll']))
        except ValueError:
            count += 1
        else:
            raise AssertionError('inlined cleanup bypass survived')
    require(count >= 2, 'normal and error cleanup sites are mutation tested')
    return stats[0], count
