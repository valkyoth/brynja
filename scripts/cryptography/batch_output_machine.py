"""Symbolic ABI/memory model for the reviewed output-destructor assembly subset.

Not a general ISA emulator. Valid owner/table layout and non-unwinding exact
clearing callees are assumptions. Stack/register contents unrelated to the
owner are opaque; calls invalidate all caller-saved registers and flags.
"""
import re

from batch_cleanup_flow import require


def callee(symbol):
    require(re.fullmatch(r'__?(?:ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E|'
                         r'RNvNtCs[A-Za-z0-9_]+_11brynja_core13secret_memory18clear_owned_region)', symbol),
            'exact assembly clearing callee')
    return ('callee', 'clear')


def offset(base, amount):
    require(type(amount) is int, 'concrete address/loop stride')
    if type(base) is int:
        require(0 <= base + amount < 2**64, 'nonwrapping loop arithmetic')
        return base + amount
    require(isinstance(base, tuple) and base[0] in ('owner', 'stack'), 'known address provenance')
    require(-4096 <= base[1] + amount <= 4096, 'bounded owner/stack offset')
    return (base[0], base[1] + amount)


class Machine:
    def __init__(self, shapes, arm):
        self.shapes, self.arm = shapes, arm
        self.saved = [f'x{i}' for i in range(19, 31)] if arm else ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']
        self.regs = {r: ('opaque', r) for r in self.saved}
        self.regs['sp' if arm else 'rsp'] = ('stack', 0)
        self.regs['x0' if arm else 'rdi'] = ('owner', 0)
        self.stack, self.cleared, self.flag = {}, [], None

    def register(self, name):
        name = name.removeprefix('%')
        if self.arm:
            require(name == 'sp' or re.fullmatch(r'[xw](?:[12]?\d|30)', name), 'reviewed Arm register')
            return ('x' + name[1:] if name.startswith('w') else name, name.startswith('w'))
        aliases = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
                   'edi': 'rdi', 'esi': 'rsi', 'ebp': 'rbp', 'esp': 'rsp'}
        if name in aliases:
            return aliases[name], True
        if re.fullmatch(r'r(?:[89]|1[0-5])d', name):
            return name[:-1], True
        require(name in ('rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp') or
                re.fullmatch(r'r(?:[89]|1[0-5])', name), 'reviewed x86 register')
        return name, False

    def read(self, name):
        register, narrow = self.register(name)
        require(register in self.regs, 'uninitialized/call-clobbered register: ' + register)
        value = self.regs[register]
        if narrow:
            require(type(value) is int, 'no truncated symbolic address/length')
            value &= 0xffffffff
        return value

    def write(self, name, value):
        register, narrow = self.register(name)
        if narrow:
            require(type(value) is int and 0 <= value < 2**32, 'exact zero-extended register write')
        self.regs[register] = value

    def load(self, address):
        require(isinstance(address, tuple), 'known load address')
        if address[0] == 'stack':
            require(address in self.stack, 'initialized stack load')
            return self.stack[address]
        require(address[0] == 'owner', 'only owner/stack reads')
        slot, field = divmod(address[1], 16)
        require(0 <= slot < len(self.shapes) and field in (0, 8), 'exact destination-table field')
        shape = self.shapes[slot]
        if field == 0:
            return 0 if shape == 0 else ('destination', slot)
        require(shape != 0, 'no length read from absent option')
        return 0 if shape == 1 else ('length', slot)

    def store(self, address, value):
        require(isinstance(address, tuple) and address[0] == 'stack' and address[1] < 0,
                'only allocated stack saves')
        sp = self.read('sp' if self.arm else '%rsp')
        require(sp[1] <= address[1] and address[1] % 8 == 0, 'aligned in-frame stack save')
        self.stack[address] = value

    def address(self, expression):
        if self.arm:
            match = re.fullmatch(r'\[(x\d+|sp)(?:, #(-?\d+))?\]', expression)
            require(match, 'reviewed Arm address')
            return offset(self.read(match[1]), int(match[2] or 0))
        match = re.fullmatch(r'(-?\d*)\((%\w+)(?:,(%\w+))?\)', expression)
        require(match, 'reviewed x86 address')
        index = self.read(match[3]) if match[3] else 0
        require(type(index) is int, 'concrete loop index')
        return offset(self.read(match[2]), int(match[1] or 0) + index)

    def operand(self, expression):
        if re.fullmatch(r'[$#]-?\d+', expression):
            return int(expression[1:])
        if expression.endswith('@GOTPCREL(%rip)'):
            return callee(expression.removesuffix('@GOTPCREL(%rip)'))
        if expression.endswith(')') or expression.startswith('['):
            return self.load(self.address(expression))
        return self.read(expression)

    def clear(self, target):
        function = self.operand(target[1:]) if target.startswith('*') else callee(target)
        require(function == ('callee', 'clear'), 'known exact indirect clearing call')
        self.cleared.append((self.read('x0' if self.arm else '%rdi'),
                             self.read('x1' if self.arm else '%rsi')))
        clobbered = [f'x{i}' for i in range(19)] + ['x30'] if self.arm else [
            'rax', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11']
        for register in clobbered:
            self.regs.pop(register, None)
        self.flag = None

    def finish(self, metadata):
        expected = [(('destination', i), ('length', i)) for i, shape in enumerate(self.shapes) if shape == 2]
        expected += [(('owner', start), width) for start, width in metadata]
        require(self.cleared == expected, 'exact ordered full-slice and metadata assembly cleanup')

    def restored(self):
        require(self.read('sp' if self.arm else '%rsp') == ('stack', 0), 'balanced destructor stack')
        require(all(self.regs.get(r) == ('opaque', r) for r in self.saved), 'restored callee-saved registers/link')
