"""Actual retained Core/state destructor chains, stopping at clear requests."""
import re

import debug_verifier_finish as finish

model, guard, comparison, require = finish.model, finish.guard, finish.comparison, finish.require
PORTABLE = ((48, 200), (248, 168), (0, 16), (16, 16), (32, 16),
            (1036, 1), (1037, 3), (1032, 4), (416, 168), (584, 168),
            (752, 40), (792, 40), (832, 200))
ACCELERATED = ((656, 200), (624, 16), (640, 16), (856, 2), (864, 168), (1056, 2))
METADATA = ((64, 1), (0, 64), (65, 1))


def closure(function, definitions, names, text):
    _, roles, _, _, transfer = finish.closure(function, definitions, names, text)
    roots = {role: roles[role] for role in ('core_drop', 'state_drop')}
    selected, pending = {}, list(roots.values())
    while pending:
        name = pending.pop()
        if name in selected or name == names['CLEAR'] or '16panic_in_cleanup' in name:
            continue
        require(name in definitions, 'same-row destructor dependency: ' + name)
        body = definitions[name]
        require(not re.search(r'\b(?:byval|inalloca)\b', body) and len(model.parameters(body)) == 1,
                'borrowed single-owner destructor ABI')
        selected[name] = model.parameters(body), model.blocks(body)
        for lines in model.blocks(body).values():
            for line in lines:
                if 'call ' in line or 'invoke ' in line:
                    pending.append(guard.call(line)[0])
    require(all(names[role] in selected for role in ('GLUE', 'GUARD', 'WIPE')),
            'actual metadata cleanup closure included')
    return roots, selected, transfer[0] == 32


class DestructorModel(finish.ownership.OwnershipModel):
    def __init__(self, functions, names, roots, base, accelerated, unwind=False):
        super().__init__(functions, names, base)
        self.roots, self.accelerated, self.unwind = roots, accelerated, unwind
        self.trace, self.flags, self.state_calls = [], [], 0

    def store(self, ptr, width, value):
        if isinstance(ptr, model.Pointer) and ptr.region == 'engine':
            self.address(ptr, width, access=False)
            event = ptr.offset - self.base, width, value
            require(self.accelerated and event in ((859, 1, 1), (616, 8, 0)),
                    'only exact cancellation metadata stores, never secret payload')
            self.flags.append(event)
            self.trace.append(('flag', *event))
            return
        return super().store(ptr, width, value)

    def run(self, name, args, depth=0):
        p = model.Pointer
        if name == self.roots['state_drop']:
            require(args == [p('core', self.base + 8)], 'original borrowed state descriptor')
            self.state_calls += 1
            if self.unwind:
                raise model.Unwind((p('exception'), 37))
        if name == self.names['CLEAR']:
            require(len(args) == 2 and isinstance(args[0], p), 'borrowed clearing request ABI')
            ptr, width = args
            allowed = {'metadata': METADATA, 'engine': ACCELERATED if self.accelerated else PORTABLE}
            require(ptr.region in allowed and (ptr.offset - self.base, width) in allowed[ptr.region],
                    'only complete original owned clearing regions')
            self.address(ptr, width, access=False)
            self.trace.append((ptr.region, ptr.offset - self.base, width))
            return 0  # Physical volatile clearing retains its separate evidence.
        return super().run(name, args, depth)
