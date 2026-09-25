"""Retained static Keccak authority/operation metadata, never secret payloads."""
from dataclasses import dataclass
from pathlib import Path
import re

import check_debug_reader_primitives as readers

model, comparison, require = readers.model, readers.comparison, readers.require
REGIONS = ((0, 200), (200, 40), (240, 40), (280, 200), (480, 32), (512, 32), (544, 32))


@dataclass(frozen=True)
class Case:
    cpu: str
    core: str
    sha3: str
    compiler: str
    arm: bool


def cases(record):
    for row, _, core, _ in comparison.cases(record):
        if row['profile'] != 'debug' or row['mode'] != 'accelerated':
            continue
        def artifact(package):
            paths = [p for p in row['artifacts'] if Path(p).name.startswith(package + '-') and p.endswith('.ll')]
            require(len(paths) == 1, 'unique same-row dependency: ' + package)
            return (record.parent / paths[0]).read_text()
        yield Case(artifact('brynja_crypto_cpu'), core, artifact('brynja_hash_sha3'),
                   '1.90.0' if 'rustc 1.90.0 ' in row['compiler'] else '1.98.1', row['target'].startswith('aarch64'))


def closure(case):
    artifacts = {key: comparison.definitions(getattr(case, key)) for key in ('cpu', 'core')}
    tokens = dict(check='13KeccakSession5check', permute='13KeccakSession7permute',
                  authority=r'static_execution.*9Authority5check', quarantine=r'static_execution.*9Authority10quarantine',
                  dispatch='6keccak8dispatch', scratch='13KeccakScratch4wipe',
                  kernel=('aarch64_sha3_keccak14permute_secret' if case.arm else 'x86_avx2_keccak14permute_secret'),
                  wipe='secret_memory_volatile23zeroize_region_volatile')
    names = {}
    for role, token in tokens.items():
        found = [name for source in artifacts.values() for name in source if re.search(token, name)]
        require(len(found) == 1, 'unique original CPU role: ' + role)
        names[role] = found[0]
    for role, result, types in (('check', 'i8', ('ptr',)), ('permute', 'i8', ('ptr', 'ptr')),
                               ('authority', 'i8', ('ptr', 'i64')), ('quarantine', 'void', ('ptr',)),
                               ('dispatch', 'i8', ('i8', 'ptr', 'ptr')), ('scratch', 'void', ('ptr',)),
                               ('kernel', 'i8', ('ptr', 'ptr')), ('wipe', 'void', ('ptr', 'i64'))):
        definition = next(source[names[role]] for source in artifacts.values() if names[role] in source)
        header = definition.splitlines()[0]
        args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
        require(re.match(r'^define(?: internal)? ' + result + r' @', header) and len(args) == len(types)
                and all(arg.startswith(kind + ' ') for arg, kind in zip(args, types))
                and not re.search(r'\b(?:byval|inalloca)\b', header), 'exact original CPU boundary ABI: ' + role)
    for role, count in (('check', 1), ('permute', 2)):
        declarations = [line for line in case.sha3.splitlines() if line.startswith('declare i8 @') and names[role] + '(' in line]
        require(len(declarations) == 1, 'same-row SHA-3 imports exact CPU identity: ' + role)
        args = comparison.arguments(declarations[0], re.search(comparison.SYMBOL, declarations[0]).end())
        require(len(args) == count and all(arg == 'ptr' or arg.startswith('ptr ') for arg in args)
                and not re.search(r'\b(?:byval|inalloca)\b', declarations[0]), 'borrowed CPU import ABI')
    selected, pending = {}, [(names[role], 'cpu') for role in ('check', 'permute', 'quarantine')]
    while pending:
        name, source = pending.pop()
        if name.startswith('llvm.'):
            require(name == 'llvm.memcpy.p0.p0.i64', 'only local metadata-copy intrinsic')
            continue
        if 'panic_in_cleanup' in name:
            continue  # No claim for double panic/abort.
        if name not in artifacts[source]:
            owners = [key for key in artifacts if name in artifacts[key]]
            require(len(owners) == 1, 'unique same-row CPU helper: ' + name)
            source = owners[0]
        body = artifacts[source][name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'no by-value secret/helper ABI')
        if name in (names['kernel'], names['wipe']):
            header = body.splitlines()[0]
            args = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
            require(len(args) == 2 and all(arg.startswith(kind + ' ') for arg, kind in zip(
                args, ('ptr', 'ptr') if name == names['kernel'] else ('ptr', 'i64'))), 'exact opaque primitive ABI')
            continue
        if name in selected:
            require(model.parameters(body) == model.parameters(selected[name]) and model.blocks(body) == model.blocks(selected[name]),
                    'identical cross-crate helper')
            continue
        selected[name] = body
        pending.extend((callee, source) for callee in readers.composed.bridges.bulk.calls(body))
    require(all(names[role] in selected for role in ('check', 'permute', 'authority', 'quarantine', 'dispatch', 'scratch')),
            'actual authority, dispatch and scratch cleanup bodies included')
    require(not any('runtime_execution' in n for n in selected), 'retained fixture is static-only, not hosted qualification')
    names['success'] = 7 if case.compiler == '1.90.0' else 255
    return names, selected


class SessionModel(model.Model):
    def __init__(self, functions, constants, names, kernel, health, owner_generation, session_generation,
                 kernel_result, revocation):
        # Boolean XOR and inequality have the same i1 truth table. Normalize
        # only this scalar operation; keep retained artifacts/interpreter intact.
        lowered = {name: (params, {label: [re.sub(r'^(%[-.$\w]+ = )xor i1 ', r'\1icmp ne i1 ', line)
                    for line in lines] for label, lines in graph.items()})
                   for name, (params, graph) in functions.items()}
        super().__init__(lowered, constants, '')
        self.names, self.kernel_result, self.revocation = names, kernel_result, revocation
        self.exception = (model.Pointer('@original_exception'), 19)
        self.authority_calls = 0
        self.step_limit = 30000
        self.allocate('session', 608, payload=True)
        self.allocate('state', 200, payload=True)
        self.allocate('authority', 16)
        self.owner, self.generation = model.Pointer('authority'), session_generation
        self.memory.update({self.owner: (8, owner_generation), model.Pointer('authority', 8): (1, health),
                            model.Pointer('authority', 9): (1, kernel)})
        for line in constants.splitlines():
            found = re.fullmatch(r'(@[-.$\w]+) = private unnamed_addr constant \[1 x i8\] c"\\([0-9A-Fa-f]{2})", align 1', line)
            if found and found[1] not in self.sizes:
                self.allocate(found[1], 1)
                self.memory[model.Pointer(found[1])] = (1, int(found[2], 16))

    def value(self, token, env):
        if token in ('{ i1 true, i8 poison }', '{ i1 false, i8 poison }'):
            return (int('true' in token), model.UNKNOWN)
        return super().value(token, env)

    def load(self, ptr, width):
        if isinstance(ptr, model.Pointer) and ptr.region == 'session':
            require((ptr.offset, width) in ((576, 8), (584, 8)), 'session reads only original owner/generation metadata')
            return self.owner if ptr.offset == 576 else self.generation
        value = super().load(ptr, width)
        if isinstance(ptr, model.Pointer) and ptr.region == 'authority':
            require((ptr.offset, width) in ((0, 8), (8, 1), (9, 1)), 'exact authority metadata read')
        return value

    def store(self, ptr, width, value):
        if isinstance(ptr, model.Pointer) and ptr.region == 'authority':
            require((ptr.offset, width, value) in ((8, 1, 2), (0, 8, 3)), 'only terminal quarantine metadata updates')
            self.events.append(('authority-store', ptr.offset, width, value))
        return super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        if name == self.names['authority']:
            require(args == [self.owner, self.generation], 'original owner and borrowed generation')
            self.authority_calls += 1
            self.events.append(('authority',))
            if self.revocation == self.authority_calls:
                # Explicit internal fault probe between calls, not a claim of a
                # concurrent mutable owner or signal-safe API.
                model.Model.store(self, model.Pointer('authority', 8), 1, 2)
        if name == self.names['kernel']:
            require(args == [model.Pointer('session'), model.Pointer('state')], 'original scratch and caller state to exact kernel')
            self.events.append(('kernel',))
            if self.kernel_result == 'unwind':
                raise model.Unwind(self.exception)
            return self.kernel_result
        if name == self.names['wipe']:
            require(len(args) == 2 and isinstance(args[0], model.Pointer) and args[0].region == 'session'
                    and (args[0].offset, args[1]) in REGIONS, 'one complete original scratch region')
            self.events.append(('wipe', args[0].offset, args[1]))
            return None  # Same-record clearing body qualified separately.
        if name == self.names['quarantine']:
            require(args == [self.owner], 'original authority quarantine')
            self.events.append(('quarantine',))
        return super().run(name, args, depth)
