"""Actual MD5 checkpoint Result/health/cancellation callee data flow.

Md5Batch::new's reviewed revalidation contract is a callee premise. The
temporary is a borrowed selector, not a secret owner. No whole-worker claim.
"""
import re

import legacy_hmac_hosted_authority as authority

require, syntax, V, flow = authority.require, authority.syntax, authority.V, authority.flow
L = flow.LABEL
NEW = '<brynja_legacy_hmac::md5_batch::Md5Batch>::new'


class Cursor:
    def __init__(self, rows, names):
        self.rows, self.names, self.index = [line.split(', !', 1)[0] for line in rows], names, 0

    def take(self, pattern):
        require(self.index < len(self.rows), 'MD5 checkpoint missing instruction')
        found = re.fullmatch(pattern, self.rows[self.index])
        require(found, 'MD5 checkpoint instruction/provenance changed: ' + self.rows[self.index])
        self.index += 1
        return found.groups()

    def call(self, name):
        require(self.index < len(self.rows), 'MD5 checkpoint missing call')
        line = self.rows[self.index]
        require(re.match(r'(?:tail )?call void @', line), 'MD5 checkpoint call effect/return changed')
        symbol, args = syntax.call(line)
        require(self.names.get(symbol, symbol) == name, 'MD5 checkpoint callee substitution')
        self.index += 1
        return args

    def lifetime(self, operation, result):
        args = self.call('llvm.lifetime.' + operation + '.p0')
        require(len(args) in (1, 2) and syntax.operand(args[-1]) == result
                and (len(args) == 1 or args[0] == 'i64 24'), 'MD5 checkpoint selector lifetime changed')

    def end(self):
        require(self.index == len(self.rows), 'unreviewed MD5 checkpoint effects')


def nonnull(cursor, result):
    """1.90 reconstructs the borrowed nonnull pointer before discarding it.

Check the exact 16+48-bit reconstruction; do not silently ignore llvm.assume
or arbitrary arithmetic/loads as harmless compiler scaffolding.
"""
    low, = cursor.take('(' + V + ') = load i16, ptr ' + re.escape(result) + r', align 8')
    extended, = cursor.take('(' + V + ') = zext i16 ' + re.escape(low) + ' to i64')
    address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                           + re.escape(result) + ', i64 2')
    high, = cursor.take('(' + V + ') = load i48, ptr ' + re.escape(address) + ', align 2')
    cursor.lifetime('end', result)
    upper, = cursor.take('(' + V + ') = zext i48 ' + re.escape(high) + ' to i64')
    shifted, = cursor.take('(' + V + ') = shl nuw i64 ' + re.escape(upper) + ', 16')
    joined, = cursor.take('(' + V + ') = or disjoint i64 ' + re.escape(shifted) + ', ' + re.escape(extended))
    condition, = cursor.take('(' + V + ') = icmp ne i64 ' + re.escape(joined) + ', 0')
    require(cursor.call('llvm.assume') == ['i1 ' + condition], 'MD5 selector nonnull assumption changed')


def validate(arguments, body, names, compiler):
    require(compiler in ('1.90.0', '1.99.1'), 'unreviewed MD5 checkpoint compiler')
    params = syntax.parameters(arguments)
    require(len(params) == 2, 'MD5 checkpoint arity changed')
    owner, cancel = [syntax.operand(arg) for arg in params]
    graph = flow.blocks(body)
    require(len(graph) == 4, 'MD5 checkpoint CFG population changed')
    cursor = Cursor(next(iter(graph.values())), names)
    result, = cursor.take('(' + V + r') = alloca \[24 x i8\], align 8')
    cursor.lifetime('start', result)
    args = cursor.call(NEW)
    require(len(args) == 2 and [syntax.operand(arg) for arg in args] == [result, owner]
            and 'sret([24 x i8])' in args[0], 'MD5 checkpoint constructor result/executor changed')
    address, = cursor.take('(' + V + ') = getelementptr(?: inbounds)?(?: nuw)? i8, ptr '
                           + re.escape(result) + ', i64 16')
    status, = cursor.take('(' + V + ') = load i8, ptr ' + re.escape(address) + ', align 8')
    rejected, = cursor.take('(' + V + ') = icmp eq i8 ' + re.escape(status) + ', 2')
    bad, good = cursor.take('br i1 ' + re.escape(rejected) + ', label %' + L + ', label %' + L)
    cursor.end()
    require(good in graph and bad in graph and good != bad, 'MD5 checkpoint admission edges changed')
    failure = Cursor(graph[bad], names)
    error, = failure.take('(' + V + ') = load i8, ptr ' + re.escape(result) + ', align 8')
    failure.lifetime('end', result)
    merged, = failure.take('br label %' + L)
    failure.end()
    success = Cursor(graph[good], names)
    if compiler == '1.90.0':
        nonnull(success, result)
    else:
        success.lifetime('end', result)
    atomic, = success.take('(' + V + ') = load atomic i8, ptr ' + re.escape(cancel) + ' acquire, align 1')
    condition, = success.take('(' + V + ') = icmp eq i8 ' + re.escape(atomic) + ', 0')
    ok = '10' if compiler == '1.90.0' else '-1'
    selected, = success.take('(' + V + ') = select i1 ' + re.escape(condition) + ', i8 ' + ok + ', i8 6')
    aggregate, = success.take('(' + V + r') = insertvalue \{ i8, i8 \} poison, i8 ' + re.escape(selected) + ', 0')
    success.take('br label %' + re.escape(merged))
    success.end()
    require(set(graph) == {next(iter(graph)), bad, good, merged} and merged in graph,
            'MD5 checkpoint unreachable/aliased blocks')
    join = Cursor(graph[merged], names)
    value, = join.take('(' + V + r') = phi \{ i8, i8 \} \[ ' + re.escape(aggregate) + ', %' + re.escape(good)
                       + r' \], \[ \{ i8 7, i8 poison \}, %' + re.escape(bad) + r' \]')
    payload, = join.take('(' + V + r') = phi i8 \[ undef, %' + re.escape(good) + r' \], \[ '
                         + re.escape(error) + ', %' + re.escape(bad) + r' \]')
    returned, = join.take('(' + V + r') = insertvalue \{ i8, i8 \} ' + re.escape(value)
                          + ', i8 ' + re.escape(payload) + ', 1')
    join.take(r'ret \{ i8, i8 \} ' + re.escape(returned))
    join.end()
