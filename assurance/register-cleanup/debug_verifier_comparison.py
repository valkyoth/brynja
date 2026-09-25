"""Replay actual debug bulk caller instructions under explicit iterator contracts."""
import re

from debug_verifier_ownership import OwnershipModel, guard, model, comparison, require

SSA = guard.SSA
TOKENS = {'branch': 'Try$GT$6branch', 'expose': 'HardenedSha3SecretOutput6expose',
          'iter': '$u5b$T$u5d$$GT$4iter', 'zip': 'Iterator3zip',
          'identity': '_ZN63_$LT$I$u20$as', 'array': '_ZN4core5array',
          'next_zip': 'zip..Zip$LT$A$C$B$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next',
          'next_mut': 'IterMut$LT$T$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next',
          'accumulate': '33accumulate_secret_byte_difference', 'error': '13from_residual',
          'drop': 'drop_in_place$LT$brynja_hash_sha3..hardened..output..HardenedSha3SecretOutput'}
V0 = {'branch': ('3Try6branch',), 'expose': ('HardenedSha3SecretOutput6expose',),
      'iter': ('5sliceSh4iter',), 'zip': ('Iterator3zip',),
      'identity': ('7collectI', '3Zip', '12IntoIterator9into_iter'),
      'array': ('5array', '12IntoIterator9into_iter'),
      'next_zip': ('8adapters3zip', 'Iterator4next'),
      'next_mut': ('7IterMut', 'Iterator4next'),
      'accumulate': ('33accumulate_secret_byte_difference',),
      'error': ('13from_residual',), 'drop': ('9drop_glue', '24HardenedSha3SecretOutput')}


def chunk_inputs(graph):
    definitions = {line.split(' = ', 1)[0]: line.split(' = ', 1)[1]
                   for lines in graph.values() for line in lines if ' = ' in line}
    destinations = []
    for lines in graph.values():
        for line in lines:
            if 'invoke ' in line and '7get_mut' in line:
                _, args = guard.call(line)
                if len(args) == 3 and args[1] == 'i64 64' and re.fullmatch('i64 ' + SSA, args[2]):
                    destinations.append(args[2].split()[-1])
    require(len(destinations) == 1, 'one original chunk-sized verification slice')
    length = destinations[0]
    address = re.fullmatch(r'load i64, ptr (' + SSA + r'), align 8', definitions[length])
    require(address, 'original chunk length load')
    origin = re.fullmatch(r'getelementptr inbounds i8, ptr (' + SSA + r'), i64 8', definitions[address[1]])
    require(origin, 'original chunk length field')
    slot = origin[1]
    # Two pointer loads exist: Option discrimination and the accepted value.
    # Select the accepted-value load in the length-load block.
    block = next(lines for lines in graph.values() if length + ' = ' + definitions[length] in lines)
    pointers = [line.split(' = ', 1)[0] for line in block if line.endswith(' = load ptr, ptr ' + slot + ', align 8')]
    require(len(pointers) == 1, 'one accepted original candidate chunk pointer')
    stores = [line for lines in graph.values() for line in lines
              if re.fullmatch('store ptr ' + SSA + ', ptr ' + re.escape(slot) + ', align 8', line)]
    require(len(stores) == 1, 'one chunk-result pointer producer')
    source = stores[0].split()[2].rstrip(',')
    pair = re.fullmatch(r'extractvalue \{ ptr, i64 } (' + SSA + '), 0', definitions[source])
    require(pair and 'Chunks' in definitions[pair[1]] and '4next' in definitions[pair[1]],
            'candidate fragment input is from the actual chunk iterator')
    return [pointers[0], length]


def extract(function, definitions):
    graph = model.blocks(function)
    candidate = chunk_inputs(graph)
    producers = [(b, line) for b, lines in graph.items() for line in lines
                 if 'invoke void @' in line and 'Reader' in line and re.search(r'6secret(?:17h|\()', line)]
    require(len(producers) == 1, 'one actual bulk producer')
    producer, line = producers[0]
    _, args = guard.call(line)
    require(len(args) == 4 and args[0].startswith('ptr sret([24 x i8]) align 8 '), 'original reader result ABI')
    result = args[0].rsplit(' ', 1)[1]
    start = guard.successors(graph[producer])[0][0]
    allocations = {m[1]: int(m[2]) for line in graph['start']
                   if (m := re.fullmatch('(' + SSA + r') = alloca \[(\d+) x i8\], align \d+', line))}
    require(allocations.get(result) == 24 and allocations.get('%cleanup') == 8, 'original result and guard slots')
    selected, roles, stops, pending, external = {}, {}, {}, [start], set()
    while pending:
        label = pending.pop()
        if label in selected:
            continue
        lines = list(graph[label])
        selected[label] = lines
        invokes = [(i, line) for i, line in enumerate(lines) if 'invoke ' in line]
        if invokes:
            require(len(invokes) == 1 and invokes[0][0] == len(lines) - 2, 'terminal original invoke')
            index, line = invokes[0]
            name, args = guard.call(line)
            matches = [role for role, token in TOKENS.items() if token in name or
                       (name.startswith('_R') and all(part in name for part in V0[role]))]
            require(len(matches) == 1 and name in definitions, 'bound original caller dependency: ' + name)
            role = matches[0]
            require(role not in roles or roles[role] == name, 'unique caller dependency role')
            roles[role] = name
            require(not re.search(r'\b(?:byval|inalloca)\b', definitions[name]), 'borrowed boundary ABI')
            require(len(model.parameters(definitions[name])) == len(args), 'actual boundary argument count')
            if role == 'zip':
                require(len(args) == 5 and args[0].startswith('ptr sret([48 x i8])'), 'byte-slice zip ABI')
                external.update(arg.rsplit(' ', 1)[1] for arg in args[3:])
                require([arg.rsplit(' ', 1)[1] for arg in args[3:]] == candidate,
                        'zip uses original chunk input, not an invented fragment parameter')
            normal, unwind = guard.successors(lines)[0]
            if role in ('error', 'drop'):
                # A synthetic stop is not the original verifier exit or Drop.
                selected[label] = lines[:index] + [
                    'call void @boundary_' + role + '(' + args[0] + ')', 'ret i8 ' + str(int(role == 'error'))]
                stops[role] = label
            else:
                pending.append(normal)
                selected[unwind] = ['unreachable']  # This replay does not inject unwinding.
        else:
            targets, terminal = guard.successors(lines)
            require(terminal is None, 'no unreviewed caller exit before comparison boundary')
            pending.extend(targets)
    require(set(roles) == set(TOKENS) and set(stops) == {'drop', 'error'}, 'complete bounded comparison fragment')
    require(len(external) == 2 and all(value not in allocations for value in external), 'distinct external candidate slice')
    selected['start'] = ['br label %' + start]
    branch = definitions[roles['branch']]
    functions = {'fragment': (list(allocations) + candidate, selected),
                 roles['branch']: (model.parameters(branch), model.blocks(branch))}
    return allocations, result, roles, functions, stops


class ComparisonModel(OwnershipModel):
    """Iterator/expose contracts are explicit, not simulated secret-byte copies."""
    def __init__(self, functions, roles, base, length, candidate_length):
        super().__init__(functions, {}, base)
        self.roles = roles
        self.length, self.candidate_length = length, candidate_length
        self.pairs, self.boundaries, self.exposures = [], [], []
        self.step_limit = 100000

    def move(self, destination, source, width):
        self.address(destination, width)
        self.address(source, width)
        require(destination.region != source.region and width in (24, 48), 'disjoint bounded iterator/owner descriptors')
        fields = [(p.offset - source.offset, n, value) for p, (n, value) in self.memory.items()
                  if p.region == source.region and source.offset <= p.offset and p.offset + n <= source.offset + width]
        self.store(destination, width, model.UNKNOWN)
        for offset, n, value in fields:
            self.store(model.Pointer(destination.region, destination.offset + offset), n, value)

    def run(self, name, args, depth=0):
        p = model.Pointer
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[3] == 0, 'nonvolatile descriptor move')
            self.move(*args[:3])
            return None
        if name.startswith('boundary_'):
            require(len(args) == 1, 'single original boundary argument')
            if name == 'boundary_drop':
                require(self.exposures == args, 'normal fragment reaches original exposed output owner Drop')
            else:
                require(name == 'boundary_error' and type(args[0]) is int, 'original initialized residual byte')
            self.boundaries.append((name, *args))
            return None
        role = next((role for role, symbol in self.roles.items() if symbol == name), None)
        if role in (None, 'branch'):
            return model.Model.run(self, name, args, depth)
        if role == 'expose':
            require(len(args) == 1 and not self.exposures, 'one output expose per chunk')
            self.exposures.append(args[0])
            tag = self.load(args[0], 8)
            require(tag in (0, 1), 'only successful output variants can be exposed')
            if tag == 0:
                require(self.length == 0, 'empty descriptor only for empty reader output')
                return p('empty'), 0
            pointer = self.load(p(args[0].region, args[0].offset + 8), 8)
            length = self.load(p(args[0].region, args[0].offset + 16), 8)
            require((pointer, length) == (p('metadata', self.base), self.length), 'original returned verification buffer')
            return pointer, length
        if role == 'iter':
            require(len(args) == 2 and type(args[1]) is int, 'byte slice iterator contract')
            self.address(args[0], args[1], access=False)
            return args[0], p(args[0].region, args[0].offset + args[1])
        if role == 'zip':
            out, begin, end, candidate, length = args
            require(begin.region == end.region and end.offset - begin.offset == self.length
                    and candidate == p('candidate', self.base) and length == self.candidate_length,
                    'zip receives exact exposed output and original candidate slice')
            for offset, value in enumerate((begin, end, candidate, length, 0, min(length, self.length))):
                self.store(p(out.region, out.offset + offset * 8), 8, value)
            return None
        if role == 'identity':
            require(len(args) == 2, 'iterator identity descriptor ABI')
            self.move(*args, 48)
            return None
        if role == 'next_zip':
            out = args[0]
            begin, _, candidate, _, index, limit = [self.load(p(out.region, out.offset + n), 8) for n in range(0, 48, 8)]
            if index == limit:
                return 0, model.UNKNOWN
            require(0 <= index < limit <= 64, 'bounded paired iteration')
            self.store(p(out.region, out.offset + 32), 8, index + 1)
            return p(begin.region, begin.offset + index), p(candidate.region, candidate.offset + index)
        if role == 'array':
            require(args == [p('metadata', self.base + 65)], 'exact one-byte original difference accumulator')
            return args[0], p('metadata', self.base + 66)
        if role == 'next_mut':
            iterator = args[0]
            begin, end = [self.load(p(iterator.region, iterator.offset + n), 8) for n in (0, 8)]
            if begin == end:
                return 0
            require((begin, end) == (p('metadata', self.base + 65), p('metadata', self.base + 66)), 'single difference byte')
            self.store(iterator, 8, end)
            return begin
        require(role == 'accumulate' and len(args) == 3, 'only original comparison primitive boundary')
        index = len(self.pairs)
        require(args == [p('metadata', self.base + 65), p('metadata', self.base + index), p('candidate', self.base + index)]
                and index < min(self.length, self.candidate_length), 'original ordered paired bytes, no payload copy')
        self.pairs.append(tuple(args))
        return None  # Actual comparison assembly has separate retained evidence.
