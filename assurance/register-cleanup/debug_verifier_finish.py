"""Actual finish body composed with the retained caller ownership fragment."""
import re

import debug_verifier_ownership as ownership

model, guard, comparison, require = ownership.model, ownership.guard, ownership.comparison, ownership.require


def closure(function, definitions, names, text):
    transfer = ownership.extract(function, definitions, names)
    calls = [guard.call(line) for lines in model.blocks(function).values() for line in lines
             if 'invoke void @' in line and 'core_state' in line and '6finish' in line]
    require(len(calls) == 1 and len(calls[0][1]) == 6, 'one actual finish ABI')
    root = calls[0][0]
    roles, constants, helpers = {}, {}, {}
    pending = [root]
    while pending:
        name = pending.pop()
        if name in helpers or name in roles.values() or name == 'llvm.memcpy.p0.p0.i64':
            continue
        if '16panic_in_cleanup' in name:
            continue  # Never injected: double-panic abort is not modeled.
        require(name in definitions, 'same-artifact finish dependency: ' + name)
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body), 'borrowed finish/helper ABI')
        role = next((role for role, token in (('none', '7is_none'), ('key', '10key_policy'),
                     ('ne', 'PartialEq2ne'), ('suffix', '13append_suffix')) if token in name), None)
        if ('drop_in_place' in name or 'drop_glue' in name):
            role = 'core_drop' if 'core_state' in name else 'state_drop' if 'Borrowed' in name else None
            require(role, 'identified finish destructor boundary')
        if role:
            require(role not in roles, 'unique finish boundary: ' + role)
            roles[role] = name
            continue
        helpers[name] = model.parameters(body), model.blocks(body)
        for lines in model.blocks(body).values():
            for line in lines:
                if 'call ' in line or 'invoke ' in line:
                    callee, args = guard.call(line)
                    pending.append(callee)
                    if 'PartialEq2ne' in callee:
                        literal = args[1].rsplit(' ', 1)[1]
                        require(re.fullmatch(r'@[-.$\w]+', literal) and
                                re.search(re.escape(literal) + r' = private unnamed_addr constant \[1 x i8\] zeroinitializer, align 1', text),
                                'actual FullStrength constant is zero')
                        constants[literal] = 0
    require(set(roles) == {'none', 'key', 'ne', 'suffix', 'core_drop', 'state_drop'} and len(constants) == 1,
            'complete explicit finish contract boundaries')
    for name, value in transfer[4].items():
        require(name not in helpers or helpers[name] == value, 'identical shared finish/transfer helper')
        helpers[name] = value
    return root, roles, constants, helpers, transfer


class FinishModel(ownership.OwnershipModel):
    def __init__(self, functions, names, roles, constants, base, width, scenario):
        super().__init__(functions, names, base)
        self.roles, self.width, self.scenario = roles, width, scenario
        self.boundary_events = []
        self.reader_fields = []
        self.step_limit = 30000
        for name, value in constants.items():
            self.allocate(name, 1)
            self.memory[model.Pointer(name)] = (1, value)

    def run(self, name, args, depth=0):
        p = model.Pointer
        if name == 'llvm.memcpy.p0.p0.i64':
            require(len(args) == 4 and args[3] == 0 and args[2] in (16, 24, 32), 'whole finish descriptor move')
            destination, source, width, _ = args
            self.address(destination, width)
            self.address(source, width)
            require(destination.region != source.region and source.offset == destination.offset == 0,
                    'disjoint original descriptor storage')
            fields = [(ptr.offset, size, value) for ptr, (size, value) in self.memory.items()
                      if ptr.region == source.region and ptr.offset + size <= width]
            self.store(destination, width, model.UNKNOWN)
            for offset, size, value in fields:
                self.store(p(destination.region, offset), size, value)
            self.moves.append((destination.region, source.region, width))
            return None
        role = next((role for role, symbol in self.roles.items() if symbol == name), None)
        if role is None:
            return super().run(name, args, depth)
        present, strong, bits, strength, production, outcome, variant = self.scenario
        if role in ('none', 'key', 'core_drop', 'state_drop'):
            expected = p('core', 8 if role in ('none', 'state_drop') else 0)
            require(args == [expected], 'original core/state at boundary: ' + role)
            self.boundary_events.append(role)
            if role == 'none':
                return int(not present)
            if role == 'key':
                return int(not strong)
            return None  # Destructor request, not body/physical erasure.
        if role == 'ne':
            require(len(args) == 2 and args[1] in self.memory and args[1].region.startswith('@')
                    and self.load(args[1], 1) == 0, 'original FullStrength policy constant')
            value = self.load(args[0], 1)
            require(value in (0, 1), 'initialized key-policy discriminant')
            self.boundary_events.append(role)
            return int(value != 0)
        require(role == 'suffix' and len(args) == 4 and args[1] == p('core', 8) and args[3] == bits,
                'suffix receives original state and exact requested bit length')
        for offset, size, value in self.input_fields:
            require(self.load(p(args[2].region, args[2].offset + offset), size) == value,
                    'whole original optional-input descriptor forwarded')
        self.boundary_events.append(role)
        if outcome == 'unwind':
            raise model.Unwind((p('exception'), 37))
        if outcome is None:
            self.reader_fields = ([(0, 8, p('engine', self.base)), (8, 1, variant)] if self.width == 24 else
                                  [(0, 8, p('engine', self.base)), (8, 8, p('scratch')), (16, 8, variant)])
            fields = self.reader_fields
        else:
            fields = [(0, 1, outcome), (8, 1, 2)] if self.width == 24 else [(0, 8, 0), (8, 1, outcome)]
        for offset, size, value in fields:
            self.store(p(args[0].region, args[0].offset + offset), size, value)
        return None  # Framing/state consumption is an explicit producer contract.
