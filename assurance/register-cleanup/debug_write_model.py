"""Small retained-LLVM descriptor model, not a general LLVM interpreter."""
from dataclasses import dataclass
import re

import check_accelerated_staging as shared

require = shared.require
SSA = shared.SSA
UNKNOWN = object()
MASK = (1 << 64) - 1


class Unwind(Exception):
    """Synthetic exception identity for selected recoverable-unwind paths."""

    def __init__(self, value):
        super().__init__('modeled recoverable unwind')
        self.value = value


@dataclass(frozen=True)
class Pointer:
    region: str
    offset: int = 0


def arguments(text, position):
    args = shared.comparison.arguments(text, position)
    return [] if args == [''] else args


def parameters(function):
    header = function.splitlines()[0]
    symbol = re.search(shared.comparison.SYMBOL, header)
    require(symbol is not None, 'debug function symbol')
    args = arguments(header, symbol.end())
    result = []
    for arg in args:
        found = re.search('(' + SSA + ')$', arg)
        require(found is not None, 'named debug parameter')
        result.append(found[1])
    return result


def blocks(function):
    return {label: [line for line in lines if not line.startswith('#dbg_')]
            for label, lines in shared.graph(function).items()}


class Model:
    """Evaluate scalar metadata; forbid payload loads/stores outside opaque copy."""

    def __init__(self, functions, globals_text, copy_name, fault=None):
        self.functions = functions
        self.copy_name = copy_name
        self.fault = fault
        self.memory, self.sizes, self.payloads = {}, {}, set()
        self.events, self.visited = [], set()
        self.frames = self.steps = 0
        self.step_limit = 3000
        for line in globals_text.splitlines():
            found = re.fullmatch(r'(@[-.$\w]+) = private unnamed_addr constant '
                                 r'<\{ \[(4|8|16) x i8\], \[\2 x i8\] }> '
                                 r'<\{ \[\2 x i8\] (zeroinitializer|c"\\01\\00\\00\\00"), '
                                 r'\[\2 x i8\] undef }>, align \2', line)
            if found:
                width = int(found[2])
                require(found[3] == 'zeroinitializer' or width == 4, 'exact constant discriminator width')
                self.sizes[found[1]] = 2 * width
                self.memory[Pointer(found[1])] = (width, int(found[3] != 'zeroinitializer'))

    def allocate(self, name, size, payload=False):
        require(name not in self.sizes and size >= 0, 'distinct bounded model allocation')
        self.sizes[name] = size
        if payload:
            self.payloads.add(name)
        return Pointer(name)

    def address(self, ptr, width, access=True):
        require(isinstance(ptr, Pointer) and ptr.region in self.sizes,
                'known non-null descriptor pointer')
        require(0 <= ptr.offset <= self.sizes[ptr.region] - width, 'bounded model access')
        require(not access or ptr.region not in self.payloads, 'no direct payload access')

    def store(self, ptr, width, value):
        self.address(ptr, width)
        require(not ptr.region.startswith('@'), 'constant global is read-only')
        for other, (size, _) in list(self.memory.items()):
            if other.region == ptr.region and max(other.offset, ptr.offset) < min(other.offset + size, ptr.offset + width):
                del self.memory[other]
        self.memory[ptr] = (width, value)
        if ptr.region == 'owner':
            self.events.append(('store', ptr.offset, width, value))

    def load(self, ptr, width):
        self.address(ptr, width)
        item = self.memory.get(ptr)
        # Inactive Option payload bytes may be undefined. They must not affect
        # arithmetic, addresses, predicates or the observed output/copy events.
        if item is None:
            return UNKNOWN
        require(item[0] == width, 'typed descriptor reload width')
        return item[1]

    def value(self, token, env):
        if token in env:
            return env[token]
        if token in ('poison', 'undef'):
            return UNKNOWN
        if token in ('null', 'false'):
            return 0
        if token == 'true':
            return 1
        field = r'(?:i\d+ (?:-?\d+|poison|undef)|ptr (?:null|poison|undef))'
        aggregate = re.fullmatch(r'\{ (' + field + '), (' + field + r') }', token)
        if aggregate:
            return tuple(self.typed(item, env) for item in aggregate.groups())
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        if re.fullmatch(r'@[-.$\w]+', token):
            return Pointer(token)
        found = re.fullmatch(r'getelementptr inbounds \(i8, ptr (@[-.$\w]+), i64 (\d+)\)', token)
        require(found is not None, 'known debug operand: ' + token)
        return Pointer(found[1], int(found[2]))

    def typed(self, text, env):
        found = re.fullmatch(r'(ptr|i\d+)(?: .*?)? (' + SSA + r'|@[-.$\w]+|-?\d+|null|true|false|poison|undef)', text)
        require(found is not None, 'typed scalar debug argument: ' + text)
        value = self.value(found[2], env)
        if found[1] != 'ptr' and isinstance(value, int):
            value &= (1 << int(found[1][1:])) - 1
        return value

    def volatile_store(self, ptr, value):
        raise ValueError('volatile writes are outside this descriptor model')

    def compiler_fence(self, order):
        raise ValueError('fences are outside this descriptor model')

    def run(self, name, args, depth=0):
        require(depth < 20, 'bounded debug helper nesting')
        if self.fault is not None and name == self.fault[0]:
            self.events.append(('fault', name))
            return self.fault[1]
        if name in ('llvm.uadd.with.overflow.i64', 'llvm.uadd.with.overflow.i128', 'llvm.umul.with.overflow.i32'):
            require(len(args) == 2 and all(type(x) is int for x in args), 'integer checked-add operands')
            mask = (1 << int(name.rsplit('i', 1)[1])) - 1
            require(all(0 <= value <= mask for value in args), 'checked-add operands match integer width')
            value = args[0] * args[1] if '.umul.' in name else args[0] + args[1]
            return (value & mask, int(value > mask))
        if name == self.copy_name:
            require(len(args) == 3 and type(args[2]) is int, 'opaque copy ABI')
            self.address(args[0], args[2], access=False)
            self.address(args[1], args[2], access=False)
            self.events.append(('copy', *args))
            return None
        require(name in self.functions, 'bound debug callee: ' + name)
        params, graph = self.functions[name]
        require(len(params) == len(args), 'debug call argument count')
        env = dict(zip(params, args))
        exception = None
        self.frames += 1
        frame = self.frames
        label = 'start'
        while True:
            require(label in graph, 'debug successor exists')
            self.visited.add((name, label))
            lines = graph[label]
            for index, line in enumerate(lines):
                self.steps += 1
                require(self.steps < self.step_limit, 'bounded debug instruction count')
                dest, op = (line.split(' = ', 1) if ' = ' in line else (None, line))
                val = UNKNOWN
                found = re.fullmatch(r'alloca \[(\d+) x i8\], align (\d+)', op)
                if found:
                    val = self.allocate(f'{frame}:{dest}', int(found[1]))
                elif found := re.fullmatch(r'load (ptr|i\d+), ptr (.+), align \d+', op):
                    width = 8 if found[1] == 'ptr' else int(found[1][1:]) // 8
                    val = self.load(self.value(found[2], env), width)
                elif found := re.fullmatch(r'store (ptr|i\d+) (\S+), ptr (\S+), align \d+', op):
                    width = 8 if found[1] == 'ptr' else int(found[1][1:]) // 8
                    self.store(self.value(found[3], env), width, self.typed(found[1] + ' ' + found[2], env))
                elif found := re.fullmatch(r'store volatile i8 (\S+), ptr (\S+), align 1', op):
                    self.volatile_store(self.value(found[2], env), self.typed('i8 ' + found[1], env))
                elif found := re.fullmatch(r'fence syncscope\("singlethread"\) (seq_cst|acq_rel|acquire|release)', op):
                    self.compiler_fence(found[1])
                elif found := re.fullmatch(r'getelementptr inbounds(?: nuw)? i8, ptr (\S+), i64 (\S+)', op):
                    ptr, offset = self.value(found[1], env), self.value(found[2], env)
                    require(isinstance(ptr, Pointer) and type(offset) is int, 'descriptor GEP operands')
                    val = Pointer(ptr.region, ptr.offset + offset)
                    self.address(val, 0, access=False)
                elif found := re.fullmatch(r'ptrtoint ptr (\S+) to i64', op):
                    ptr = self.value(found[1], env)
                    require(ptr == 0 or isinstance(ptr, Pointer), 'initialized optional pointer')
                    # Only null discrimination is supported, not numeric addresses.
                    val = 0 if ptr == 0 else 1
                elif found := re.fullmatch(r'(?:zext|trunc)(?: nuw)? i(\d+) (\S+) to i(\d+)', op):
                    value = self.value(found[2], env)
                    require(type(value) is int, 'initialized conversion operand')
                    if 'nuw' in op:
                        require(value < 1 << int(found[3]), 'non-poison truncation')
                    val = value & ((1 << int(found[3])) - 1)
                elif found := re.fullmatch(r'icmp (eq|ne) ptr (\S+), (\S+)', op):
                    a, b = self.value(found[2], env), self.value(found[3], env)
                    require((a == 0 or isinstance(a, Pointer)) and (b == 0 or isinstance(b, Pointer)),
                            'initialized pointer comparison operands')
                    val = int(a == b) if found[1] == 'eq' else int(a != b)
                elif found := re.fullmatch(r'icmp (eq|ne|ult|ule|ugt|uge) i(\d+) (\S+), (\S+)', op):
                    a = self.typed('i' + found[2] + ' ' + found[3], env)
                    b = self.typed('i' + found[2] + ' ' + found[4], env)
                    require(type(a) is int and type(b) is int, 'initialized comparison operands')
                    val = int({'eq': a == b, 'ne': a != b, 'ult': a < b,
                               'ule': a <= b, 'ugt': a > b, 'uge': a >= b}[found[1]])
                elif found := re.fullmatch(r'(add|sub)( nuw)? i(64|128) (\S+), (\S+)', op):
                    a, b = self.value(found[4], env), self.value(found[5], env)
                    require(type(a) is int and type(b) is int, 'initialized arithmetic operands')
                    mask = (1 << int(found[3])) - 1
                    result = a + b if found[1] == 'add' else a - b
                    require(not found[2] or 0 <= result <= mask, 'non-poison arithmetic')
                    val = result & mask
                elif found := re.fullmatch(r'select i1 (\S+), (i\d+ \S+), (i\d+ \S+)', op):
                    condition = self.value(found[1], env)
                    require(condition in (0, 1), 'initialized select condition')
                    val = self.typed(found[2] if condition else found[3], env)
                elif found := re.fullmatch(r'(and|or|shl) i(32|128) (\S+), (\S+)', op):
                    a = self.typed('i' + found[2] + ' ' + found[3], env)
                    b = self.typed('i' + found[2] + ' ' + found[4], env)
                    require(type(a) is int and type(b) is int, 'initialized bit operation operands')
                    bits = int(found[2])
                    if found[1] == 'shl':
                        require(b < bits, 'non-poison shift amount')
                        val = (a << b) & ((1 << bits) - 1)
                    else:
                        val = a & b if found[1] == 'and' else a | b
                elif found := re.fullmatch(r'extractvalue \{ [^}]+ } (\S+), ([01])', op):
                    pair = self.value(found[1], env)
                    require(isinstance(pair, tuple) and len(pair) == 2, 'two-field aggregate')
                    val = pair[int(found[2])]
                elif found := re.fullmatch(r'insertvalue \{ [^}]+ } (\S+|\{ [^{}]+ }), ((?:ptr|i\d+) \S+), ([01])', op):
                    pair = self.value(found[1], env)
                    require(pair is UNKNOWN or isinstance(pair, tuple), 'aggregate insertion')
                    pair = list((UNKNOWN, UNKNOWN) if pair is UNKNOWN else pair)
                    pair[int(found[3])] = self.typed(found[2], env)
                    val = tuple(pair)
                elif found := re.fullmatch(r'switch i64 (\S+), label %(\S+) \[', op):
                    require(lines[-1] == ']', 'terminal switch closing bracket')
                    cases = {}
                    for case in lines[index + 1:-1]:
                        entry = re.fullmatch(r'i64 (\d+), label %(\S+)', case)
                        require(entry is not None and int(entry[1]) not in cases, 'unique switch case')
                        cases[int(entry[1])] = entry[2]
                    selector = self.value(found[1], env)
                    require(type(selector) is int, 'initialized switch selector')
                    label = cases.get(selector, found[2])
                    break
                elif op.startswith('invoke '):
                    require(index == len(lines) - 2, 'invoke followed by terminal edges')
                    normal, unwind = shared.edges(lines[index + 1])
                    symbol = re.search(shared.comparison.SYMBOL, op)
                    require(symbol is not None, 'named direct debug invoke')
                    call_args = arguments(op, symbol.end())
                    try:
                        val = self.run(symbol[1], [self.typed(a, env) for a in call_args], depth + 1)
                    except Unwind as error:
                        exception = error.value
                        label = unwind
                    else:
                        if dest is not None:
                            env[dest] = val
                        label = normal
                    break
                elif op == 'landingpad { ptr, i32 }':
                    require(exception is not None and index + 1 < len(lines)
                            and lines[index + 1] == 'cleanup', 'recoverable cleanup landingpad')
                    val = exception
                elif op == 'cleanup':
                    require(index > 0 and lines[index - 1].endswith('landingpad { ptr, i32 }'),
                            'landingpad cleanup clause')
                elif op.startswith('resume { ptr, i32 } '):
                    require(index == len(lines) - 1, 'terminal exception resume')
                    raise Unwind(self.value(op.rsplit(' ', 1)[1], env))
                elif op.startswith('call '):
                    symbol = re.search(shared.comparison.SYMBOL, op)
                    require(symbol is not None, 'named direct debug call')
                    call_args = arguments(op, symbol.end())
                    val = self.run(symbol[1], [self.typed(a, env) for a in call_args], depth + 1)
                elif found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', op):
                    condition = self.value(found[1], env)
                    require(condition in (0, 1) and index == len(lines) - 1, 'terminal conditional branch')
                    label = found[2] if condition else found[3]
                    break
                elif found := re.fullmatch(r'br label %(\S+)', op):
                    require(index == len(lines) - 1, 'terminal branch')
                    label = found[1]
                    break
                elif op.startswith('ret '):
                    require(index == len(lines) - 1, 'terminal return')
                    if op == 'ret void':
                        return None
                    if op.startswith('ret {'):
                        return self.value(op.rsplit(' ', 1)[1], env)
                    return self.typed(op[4:], env)
                else:
                    raise ValueError('unreviewed debug instruction: ' + op)
                if dest is not None:
                    env[dest] = val
            else:
                raise ValueError('unterminated debug block')
