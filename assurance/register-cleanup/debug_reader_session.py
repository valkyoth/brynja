"""Same-row static CPU sessions inside retained readers and volatile clearing."""
import re

import debug_keccak_session_model as cpu
import debug_reader_clear as clearing

model, require = cpu.model, cpu.require


def closure(case, cpu_case, consuming):
    require(case.core == cpu_case.core and case.sha3 == cpu_case.sha3,
            'reader and CPU dependencies from identical retained row')
    root, producer, names, merged = clearing.closure(case, consuming)
    roles, selected = cpu.closure(cpu_case)
    require((names['session'], names['permutation'], names['wipe'], names['session_success']) ==
            (roles['check'], roles['permute'], roles['wipe'], roles['success']),
            'exact imported session, permutation, clear and result identities')
    for name, body in selected.items():
        require(name not in merged or (model.parameters(body) == model.parameters(merged[name])
                and model.blocks(body) == model.blocks(merged[name])), 'identical CPU/reader shared helpers')
        merged[name] = body
    names['cpu_roles'], names['cpu_arm'] = roles, cpu_case.arm
    names['cpu_constants'] = '\n'.join(line for line in cpu_case.cpu.splitlines()
                                       if line.startswith(('@anon.', '@alloc_')))
    return root, producer, names, merged


class SessionReader(clearing.ClearingReader):
    def __init__(self, functions, constants, names, *args):
        lowered = {name: (params, {label: [re.sub(r'^(%[-.$\w]+ = )xor i1 ', r'\1icmp ne i1 ', line)
                    for line in lines] for label, lines in graph.items()})
                   for name, (params, graph) in functions.items()}
        constants += '\n' + names['cpu_constants']
        super().__init__(lowered, constants, names, *args)
        self.cpu_active = False
        self.cpu_events, self.cpu_records, self.clear_requests = [], [], []
        self.owner = self.allocate('authority', 16)
        self.generation = 2
        self.memory.update({self.owner: (8, 2), model.Pointer('authority', 8): (1, 1),
                            model.Pointer('authority', 9): (1, 5 if names['cpu_arm'] else 4)})
        for line in constants.splitlines():
            found = re.fullmatch(r'(@[-.$\w]+) = private unnamed_addr constant \[1 x i8\] c"\\([0-9A-Fa-f]{2})", align 1', line)
            if found and found[1] not in self.sizes:
                self.allocate(found[1], 1)
                self.memory[model.Pointer(found[1])] = (1, int(found[2], 16))
        self.step_limit = 4000000

    def value(self, token, env):
        if token in ('{ i1 true, i8 poison }', '{ i1 false, i8 poison }'):
            return (int('true' in token), model.UNKNOWN)
        return super().value(token, env)

    def load(self, ptr, width):
        if isinstance(ptr, model.Pointer) and ptr.region == 'authority':
            require((ptr.offset, width) in ((0, 8), (8, 1), (9, 1)), 'exact public CPU authority metadata')
            return model.Model.load(self, ptr, width)
        if self.cpu_active and isinstance(ptr, model.Pointer) and ptr.region == 'storage':
            require((ptr.offset, width) in ((576, 8), (584, 8)), 'CPU only reads original owner/generation, never payload')
            return self.owner if ptr.offset == 576 else self.generation
        return super().load(ptr, width)

    def store(self, ptr, width, value):
        if self.clearing is not None:
            return super().store(ptr, width, value)
        if self.cpu_active:
            require(isinstance(ptr, model.Pointer), 'known CPU store pointer')
            if ptr.region == 'authority':
                require((ptr.offset, width, value) in ((8, 1, 2), (0, 8, 3)), 'terminal CPU quarantine updates only')
                self.cpu_events.append(('authority-store', ptr.offset, width, value))
            else:
                require(re.match(r'^\d+:', ptr.region) and self.cpu_frame_start < int(ptr.region.split(':', 1)[0]) <= self.frames,
                        'CPU stores only fresh helper descriptors, never reader payload/metadata')
            return model.Model.store(self, ptr, width, value)
        return super().store(ptr, width, value)

    def cpu_call(self, name, args, depth, kind, result):
        require(not self.cpu_active and self.clearing is None and self.primitive is None, 'nonrecursive CPU boundary')
        self.cpu_active, self.kernel_result = True, result
        self.cpu_events, self.cpu_frame_start = [], self.frames
        returned = None
        try:
            returned = model.Model.run(self, name, args, depth)
            return returned
        except model.Unwind as error:
            require(error.value == self.exception, 'original kernel exception through CPU guard')
            returned = 'unwind'
            raise
        finally:
            self.cpu_records.append((kind, returned, tuple(self.cpu_events)))
            self.cpu_active = False

    def cpu_clear(self, name, args, depth):
        require(self.clearing is None and len(args) == 2 and isinstance(args[0], model.Pointer)
                and args[0].region == 'storage' and (args[0].offset, args[1]) in cpu.REGIONS,
                'CPU clears complete original scratch region only')
        base, length = args
        self.cpu_events.append(('wipe', base.offset, length))
        self.clear_requests.append((base.region, base.offset, length))
        self.clear_frame_start = self.frames
        self.clearing = [base, length, 0, 0, 0]
        try:
            value = model.Model.run(self, name, args, depth)
            require(value is None and self.clearing == [base, length, length, length, 1],
                    'complete actual CPU volatile clear with final fence')
            self.completed_clears.append((base.region, base.offset, length))
            return value
        finally:
            self.clearing = None

    def run(self, name, args, depth=0):
        roles = self.names['cpu_roles']
        if not self.cpu_active and name == self.names['session']:
            require(self.in_preflight and args == [model.Pointer('storage')], 'original preflight session alias')
            self.session_calls += 1
            self.engine_events.append(('session',))
            if self.session_fault and self.session_fault[0] == self.session_calls:
                error = self.session_fault[1]
                require(error in (3, 4, 5), 'real admission-metadata fault only')
                if error == 5:
                    self.generation = 1
                else:
                    self.memory[model.Pointer('authority', 8)] = (1, 0 if error == 3 else 2)
            return self.cpu_call(name, args, depth, 'check', self.names['session_success'])
        if not self.cpu_active and name == self.names['permutation']:
            require(self.in_read and args == [model.Pointer('storage'), model.Pointer('storage', 656)],
                    'reader passes original scratch and lane array to CPU')
            self.permutations += 1
            self.read_trace.append(('permute',))
            result = (self.read_fault[2] if self.read_fault and self.read_fault[:2] == ('permute', self.permutations)
                      else self.names['session_success'])
            return self.cpu_call(name, args, depth, 'permute', result)
        if self.cpu_active and name == roles['authority']:
            require(args == [self.owner, self.generation], 'original CPU authority and borrowed generation')
            self.cpu_events.append(('authority',))
        if self.cpu_active and name == roles['quarantine']:
            require(args == [self.owner], 'original CPU quarantine owner')
            self.cpu_events.append(('quarantine',))
        if self.cpu_active and name == roles['kernel']:
            require(args == [model.Pointer('storage'), model.Pointer('storage', 656)], 'exact raw kernel borrowed regions')
            self.cpu_events.append(('kernel',))
            if self.kernel_result == 'unwind':
                raise model.Unwind(self.exception)
            return self.kernel_result  # Raw payload computation remains opaque.
        if name == self.names['wipe']:
            if self.cpu_active:
                return self.cpu_clear(name, args, depth)
            require(len(args) == 2 and isinstance(args[0], model.Pointer), 'original caller clear descriptor')
            self.clear_requests.append((args[0].region, args[0].offset, args[1]))
        if self.cpu_active and name != self.names['clear_precondition']:
            return model.Model.run(self, name, args, depth)
        return super().run(name, args, depth)
