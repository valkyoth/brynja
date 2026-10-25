"""Hosted MD5 budget/cancellation descriptor and actual vtable target provenance.

Checks transport into both reviewed consumers, not the consumers' charging
semantics. The cancellation flag is cooperative, not a scheduler guarantee.
Post-consumer output and whole-host transactions are separate obligations.
"""
import re

import legacy_hmac_hosted_md5_report_layout as layout
import legacy_hmac_hosted_md5_lanes as lanes

t, syntax, require, V = lanes.t, lanes.syntax, lanes.require, lanes.V
G = r'@[-\w.$]+'


def typed(population):
    definitions, aliases, names = population
    for name in ('construct', 'remaining'):
        wanted = 'brynja_legacy_hmac_hosted_cleanup::control::' + name
        selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
        require(len(selected) == 1, 'MD5 typed control probe missing/ambiguous')
        arguments, body = layout.flow.resolve(selected[0], definitions, aliases)
        graph = layout.flow.blocks(body)
        require(len(graph) == 1, 'MD5 typed control probe conditional')
        cursor = layout.checked.Cursor(next(iter(graph.values())), names)
        if name == 'remaining':
            value = layout.field(arguments, cursor, 16, 'i64', 24)
            cursor.take('ret i64 ' + re.escape(value))
        else:
            args = syntax.parameters(arguments)
            require(len(args) == 4 and 'sret([24 x i8])' in args[0]
                    and args[1].startswith('i64 ') and args[2].startswith('ptr ')
                    and 'dereferenceable(40)' in args[3], 'MD5 control constructor ABI changed')
            root, budget, data, vtable = [arg.split()[-1] for arg in args]
            budget_field, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                        + re.escape(root) + ', i64 16')
            cursor.take('store i64 ' + re.escape(budget) + ', ptr ' + re.escape(budget_field) + ', align 8')
            cursor.take('store ptr ' + re.escape(data) + ', ptr ' + re.escape(root) + ', align 8')
            table_field, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                                       + re.escape(root) + ', i64 8')
            cursor.take('store ptr ' + re.escape(vtable) + ', ptr ' + re.escape(table_field) + ', align 8')
            cursor.take('ret void')
        cursor.end()


def callback(arguments, body, names):
    args = syntax.parameters(arguments)
    require(len(args) == 1 and args[0].startswith('ptr '), 'MD5 cancellation callback ABI changed')
    graph = layout.flow.blocks(body)
    require(len(graph) == 1, 'MD5 cancellation callback has unreviewed paths')
    cursor = layout.checked.Cursor(next(iter(graph.values())), names)
    pointer, = cursor.take('(' + V + ') = load ptr, ptr ' + re.escape(syntax.operand(args[0])) + ', align 8')
    value, = cursor.take('(' + V + ') = load atomic i8, ptr ' + re.escape(pointer) + ' acquire, align 1')
    cancelled, = cursor.take('(' + V + ') = icmp ne i8 ' + re.escape(value) + ', 0')
    cursor.take('ret i1 ' + re.escape(cancelled))
    cursor.end()


def vtable(llvm, symbol, population, target):
    # Reviewed 64-bit FnMut ABI: no destructor, size/alignment 8, then
    # call_once and call_mut. Follow both actual pointers, not nearby labels.
    rows = [line.split(', !', 1)[0] for line in llvm.splitlines() if line.startswith(symbol + ' = ')]
    header = r'\00' * 8 + (r'\08' + r'\00' * 7) * 2
    pattern = (re.escape(symbol + ' = private unnamed_addr constant <{ [24 x i8], ptr, ptr }> <{ [24 x i8] c"'
                         + header + '", ptr ') + '(' + G + '), ptr (' + G + r') \}>, align 8')
    match = re.fullmatch(pattern, rows[0]) if len(rows) == 1 else None
    require(match, 'MD5 cancellation vtable shape/identity changed')
    definitions, aliases, names = population
    prefix = 'brynja_legacy_hmac_std::' + ('macos_resident' if 'apple' in target else 'strict_execution')
    direct = names.get(match[2][1:], '')
    require(re.fullmatch(re.escape(prefix + '::md5_compiled::worker::run::') + r'\{closure#\d+\}', direct),
            'MD5 cancellation vtable points outside its worker')
    require(names.get(match[1][1:]) == '<' + direct + ' as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}',
            'MD5 cancellation shim identity changed')
    for entry in match.groups():
        callback(*layout.flow.resolve(entry[1:], definitions, aliases), names)
    return tuple(entry[1:] for entry in match.groups())


class Control:
    def __init__(self, model, envelope):
        self.m, self.envelope, self.points = model, envelope, set()
        consumers = [(p, a) for _, a, p in model.calls if p in {p for _, p, _ in model.consumers}]
        require(len(consumers) == 2 and all(len(a) == 5 and 'dereferenceable(24)' in a[4] for _, a in consumers),
                'MD5 control consumer population/ABI changed')
        roots = {syntax.operand(a[4]) for _, a in consumers}
        require(len(roots) == 1, 'MD5 consumers do not share their control')
        self.root, = roots
        self.consumers = dict(consumers)
        starts = [p for s, a, p in model.calls if s == 'llvm.lifetime.start.p0'
                  and syntax.operand(a[-1]) == self.root]
        require(len(starts) == 1, 'MD5 control start missing/duplicated')
        self.start, = starts
        t.allocation(model, self.root, 24, self.start)
        require(self.start[1] >= 2, 'MD5 cancellation context not initialized before control')
        cursor = self.cursor((self.start[0], self.start[1] - 2))
        call = syntax.call(cursor.rows[0])
        require(call and call[0] == 'llvm.lifetime.start.p0', 'MD5 cancellation context start missing')
        self.context = syntax.operand(call[1][-1])
        t.allocation(model, self.context, 8, self.start)
        require(self.root != self.context, 'MD5 control/context alias')
        require(all(offset in envelope['loads'] for offset in (56, 72)), 'MD5 control capture fields absent')
        cancel, budget = (envelope['loads'][offset][1] for offset in (56, 72))
        require(all(model.before(envelope['loads'][offset][0], (self.start[0], self.start[1] - 2))
                    for offset in (56, 72)), 'MD5 control reads before capture')
        cursor.lifetime('start', self.context)
        cursor.write('ptr', cancel, self.context)
        cursor.lifetime('start', self.root)
        cursor.write('i64', budget, cursor.gep(self.root, 16))
        cursor.write('ptr', self.context, self.root)
        table_field = cursor.gep(self.root, 8)
        self.table, = cursor.take('store ptr (' + G + '), ptr ' + re.escape(table_field) + ', align 8')
        self.ready = cursor.block, cursor.offset + cursor.index - 1
        require(all(model.before(self.ready, p) for p in self.consumers), 'MD5 consumer bypasses initialized control')
        self.audit()

    def cursor(self, point):
        return lanes.Cursor(self.m, point, self.points)

    def audit(self):
        model = self.m
        roots = {self.root, self.context}
        for point, args in self.consumers.items():
            require(model.pointer(syntax.operand(args[4]), point) == (self.root, 0)
                    and not any((value := model.pointer(syntax.operand(arg))) and value[0] in roots
                                for arg in args[:4]), 'MD5 control aliases another consumer argument')
            self.points.add(point)
        for root in roots:
            starts, ends = [], []
            for symbol, args, point in model.calls:
                if symbol.startswith('llvm.lifetime.') and syntax.operand(args[-1]) == root:
                    operation = 'start' if symbol == 'llvm.lifetime.start.p0' else 'end'
                    if operation == 'end':
                        self.cursor(point).lifetime(operation, root)
                    (starts if operation == 'start' else ends).append(point)
            require(len(starts) == 1 and ends, 'MD5 control lifetime population changed')
            require(not any(a != b and model.can_precede(a, b) for a in ends for b in ends),
                    'MD5 control lifetime ends twice on a path')
            for point in tuple(self.points):
                line = model.graph[point[0]][point[1]]
                if 'llvm.lifetime.' in line:
                    continue
                if any((p := model.pointer(v)) and p[0] == root for v in re.findall(V, line)):
                    require(model.before(starts[0], point) and not any(model.can_precede(end, point) for end in ends),
                            'MD5 control/context used outside lifetime')
        for block, rows in model.graph.items():
            for index, line in enumerate(rows):
                if not any((p := model.pointer(v)) and p[0] in roots for v in re.findall(V, line)):
                    continue
                if re.fullmatch(V + r' = alloca \[\d+ x i8\], align \d+', line):
                    continue
                require((block, index) in self.points, 'MD5 control/context has unreviewed read/write/escape')


def check(model, envelope, llvm, population, target):
    result = Control(model, envelope)
    result.callbacks = vtable(llvm, result.table, population, target)
    return result
