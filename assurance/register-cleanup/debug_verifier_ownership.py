"""Retained post-finish descriptor fragments, not a whole-verifier interpreter."""
import re

import check_kmac_guard_paths as guard

comparison, model, require = guard.comparison, guard.metadata.model, guard.require
SSA = guard.SSA


def extract(function, definitions, names):
    # Reuse the separately tested whole-CFG invocation/dominance check. It does
    # not prove descriptor provenance; the replay below supplies that link.
    guard.debug_paths(function, names['GLUE'], set(definitions))
    graph = model.blocks(function)
    finishes = [(label, index, line) for label, lines in graph.items() for index, line in enumerate(lines)
                if 'invoke void @' in line and 'core_state' in line and '6finish' in line]
    require(len(finishes) == 1, 'unique original finish-result producer')
    label, index, line = finishes[0]
    finish, args = guard.call(line)
    width = re.fullmatch(r'ptr sret\(\[(24|32) x i8\]\) align 8 (' + SSA + ')', args[0])
    require(width and finish in definitions and index == len(graph[label]) - 2,
            'defined finish with original borrowed result ABI')
    width, result = int(width[1]), width[2]
    start, unwind = guard.successors(graph[label])[0]
    branch_lines = graph[start]
    require(len(branch_lines) == 2 and branch_lines[0].startswith('invoke void @'), 'single actual result-branch handoff')
    branch, args = guard.call(branch_lines[0])
    require(branch in definitions and '6branch' in branch and len(args) == 2
            and args[1] == 'ptr align 8 ' + result, 'branch consumes exact finish-result slot')
    output = re.fullmatch(r'ptr sret\(\[' + str(width) + r' x i8\]\) align 8 (' + SSA + ')', args[0])
    require(output, 'branch preserves complete result width')
    output = output[1]
    decision, branch_unwind = guard.successors(branch_lines)[0]
    require(branch_unwind == unwind, 'branch failure retains original pre-transfer unwind edge')
    initialized = [(b, i) for b, lines in graph.items() for i, line in enumerate(lines)
                   if re.fullmatch(r'store ptr ' + SSA + r', ptr %cleanup, align 8', line)]
    require(len(initialized) == 1, 'unique original guard initialization')
    success, end = initialized[0]
    flags = [match[1] for line in graph[success][:end + 1]
             if (match := re.fullmatch(r'store i8 1, ptr (' + SSA + r'), align 1', line))]
    require(len(flags) == 1, 'one original live-reader flag set before guard publication')
    live = flags[0]
    targets, terminal = guard.successors(graph[decision])
    require(terminal is None and len(targets) == 2 and targets.count(success) == 1,
            'result decision has one guard-construction successor')
    error = next(b for b in targets if b != success)
    error_lines = graph[error]
    require(error_lines[-2].startswith(('%', 'invoke ')) and '13from_residual' in error_lines[-2],
            'error leaves fragment through original residual conversion')
    residual, residual_args = guard.call(error_lines[-2])
    require(residual in definitions and len(residual_args) == 2
            and re.fullmatch('i8 ' + SSA, residual_args[0]), 'actual error-byte residual handoff')
    branch_body = definitions[branch]
    require(branch_body.startswith('define void @') and model.parameters(branch_body) == ['%_0', '%self']
            and 'sret([' + str(width) + ' x i8])' in branch_body.splitlines()[0]
            and not re.search(r'\b(?:byval|inalloca)\b', branch_body), 'original result helper ABI')
    for body in (branch_body,):
        calls = [guard.call(line)[0] for lines in model.blocks(body).values() for line in lines if 'call ' in line]
        require(calls == ['llvm.memcpy.p0.p0.i64'] * 2, 'result helper has only two descriptor moves')
    allocations = {}
    for line in graph['start']:
        item = re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+', line)
        if item:
            require(item[1] not in allocations, 'distinct original verifier slots')
            allocations[item[1]] = int(item[2])
    require(all(allocations.get(slot) == size for slot, size in (
        (result, width), (output, width), ('%val', width), ('%reader', width - 8), ('%cleanup', 8), (live, 1))),
        'original separate result, reader and guard storage widths')
    require(result != output, 'nonaliasing finish and branch slots')
    # Only selected original instructions execute. Explicit synthetic returns
    # mark the boundary before later candidate/error-conversion work; they are
    # not claimed to be verifier exits. Finish itself is a result-contract input.
    fragment = {'start': ['br label %' + start], start: branch_lines, decision: graph[decision],
                success: graph[success][:end + 1] + ['ret i8 0'],
                error: error_lines[:-2] + ['call void @capture_error(' + residual_args[0] + ')', 'ret i8 1'],
                unwind: ['unreachable']}
    require(len(fragment) == 6 and len({start, decision, success, error, unwind, 'start'}) == 6,
            'distinct bounded post-finish fragment blocks')
    selected = {'fragment': (list(allocations), fragment),
                branch: (model.parameters(branch_body), model.blocks(branch_body))}
    for role in ('GLUE', 'GUARD', 'WIPE'):
        body = definitions[names[role]]
        require(body.startswith('define void @') and len(model.parameters(body)) == 1
                and not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed actual cleanup helper')
        selected[names[role]] = model.parameters(body), model.blocks(body)
    return width, result, output, allocations, selected, (start, decision, success, error), live


class OwnershipModel(model.Model):
    def __init__(self, functions, names, base):
        super().__init__(functions, '', '')
        self.names, self.base = names, base
        self.requests, self.moves = [], []
        self.observed_error = None
        self.step_limit = 10000

    def run(self, name, args, depth=0):
        if name == 'capture_error':
            require(self.observed_error is None and len(args) == 1 and type(args[0]) is int and 0 <= args[0] <= 255,
                    'one initialized error byte at residual-conversion boundary')
            self.observed_error = args[0]
            return None
        if name == self.names['CLEAR']:
            require(len(args) == 2 and isinstance(args[0], model.Pointer) and args[0].region == 'metadata'
                    and (args[0].offset - self.base, args[1]) in ((64, 1), (0, 64), (65, 1)),
                    'only exact original metadata clearing regions')
            self.address(args[0], args[1], access=False)
            self.requests.append((args[0].offset - self.base, args[1]))
            return 0  # Request only; physical clearing is separately qualified.
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[3] == 0 and args[2] in (24, 32), 'complete local ownership descriptor copy')
            destination, source, width, _ = args
            self.address(destination, width)
            self.address(source, width)
            require(destination.region != source.region and destination.offset == source.offset == 0,
                    'disjoint whole local descriptor moves, never secret payload')
            fields = [(p.offset, n, value) for p, (n, value) in self.memory.items()
                      if p.region == source.region and p.offset + n <= width]
            self.store(destination, width, model.UNKNOWN)
            for offset, n, value in fields:
                self.store(model.Pointer(destination.region, offset), n, value)
            self.moves.append((destination.region, source.region, width))
            return None
        return super().run(name, args, depth)
