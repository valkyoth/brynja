"""Candidate mode and public verification decision through final worker status.

The leaf comparison and authenticated tag copies are separate reviewed paths.
This checks original candidate/staging operands, consumer selection, the typed
decision projection, and all three success payloads through final admission.
"""
import re

import legacy_hmac_hosted_md5_result_tools as t
import legacy_hmac_hosted_md5_report_layout as layout
import legacy_hmac_hosted_md5_boundaries as boundary

require, syntax, V, L, status = t.require, t.syntax, t.V, t.L, boundary.status


def typed(population, compiler):
    definitions, aliases, names = population
    for name in ('candidates', 'projection', 'expose', 'matched', 'unmatched', 'authenticated'):
        wanted = 'brynja_legacy_hmac_hosted_cleanup::decision::' + name
        selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
        require(len(selected) == 1, 'MD5 typed decision probe missing/ambiguous')
        arguments, body = layout.flow.resolve(selected[0], definitions, aliases)
        graph = layout.flow.blocks(body)
        require(len(graph) == 1, 'MD5 typed decision projection conditional')
        cursor = layout.checked.Cursor(next(iter(graph.values())), names)
        args = syntax.parameters(arguments)
        if name == 'candidates':
            value = layout.field(arguments, cursor, 0, 'ptr', 8)
            cursor.take('ret ptr ' + re.escape(value))
        elif name == 'projection':
            value = layout.field(arguments, cursor, 88, 'i8', 96)
            failed, = cursor.take('(' + V + ') = icmp eq i8 ' + re.escape(value) + ', 2')
            projected, = cursor.take('(' + V + ') = select i1 ' + re.escape(failed)
                                      + ', ptr null, ptr ' + re.escape(syntax.operand(args[0])))
            cursor.take('ret ptr ' + re.escape(projected))
        elif name == 'expose':
            require(len(args) == 1 and args[0].startswith('i8 '), 'MD5 decision scalar ABI changed')
            value, = cursor.take('(' + V + ') = icmp ne i8 ' + re.escape(args[0].split()[-1]) + ', 0')
            cursor.take('ret i1 ' + re.escape(value))
        else:
            require(not arguments.strip(), 'MD5 success representation probe acquired inputs')
            payload = {'unmatched': 0, 'matched': 1, 'authenticated': 2}[name]
            tag = 10 if compiler == '1.90.0' else 255
            cursor.take('ret i16 ' + str(tag + (payload << 8)))
        cursor.end()


class Decision:
    def __init__(self, model, envelope, boundaries, transports, compiler):
        self.m, self.env, self.points = model, envelope, set()
        self.ok = 10 if compiler == '1.90.0' else -1
        self.calls = {p: (s, a) for s, a, p in model.calls}
        self.verify, = [item for item in transports if hasattr(item, 'decision')]
        self.auth, = [item for item in transports if not hasattr(item, 'decision')]
        self.candidates()
        self.result(boundaries)

    def cursor(self, point):
        return t.Cursor(self.m, point, self.points)

    def parents(self, block):
        return {parent for parent, rows in self.m.graph.items()
                if block in re.findall('label %' + L, '\n'.join(rows))}

    def candidates(self):
        m = self.m
        require(all(offset in self.env['loads'] for offset in (0, 48)), 'MD5 mode/input capture absent')
        capture = self.env['loads'][48][1]
        reads = [(value, point) for value, (rhs, point) in m.defs.items()
                 if rhs.split(', !', 1)[0] == 'load ptr, ptr ' + capture + ', align 8']
        require(len(reads) == 1, 'MD5 candidate Option read missing/duplicated')
        self.candidate, candidate_read = reads[0]
        require(m.before(self.env['loads'][48][0], candidate_read), 'MD5 candidate Option read before capture')
        self.points.add(candidate_read)
        verify_args = self.calls[self.verify.consumer][1]
        auth_args = self.calls[self.auth.consumer][1]
        require(len(verify_args) == len(auth_args) == 5
                and syntax.operand(verify_args[3]) == self.candidate and 'dereferenceable(128)' in verify_args[3]
                and syntax.operand(auth_args[3]) == self.env['loads'][0][1] and 'dereferenceable(128)' in auth_args[3],
                'MD5 candidates/staging not from original captures')
        choices = [(value, point) for value, (rhs, point) in m.defs.items()
                   if rhs == 'icmp eq ptr ' + self.candidate + ', null']
        require(len(choices) == 1, 'MD5 mode predicate missing/duplicated')
        condition, point = choices[0]
        cursor = self.cursor(point)
        cursor.take(re.escape(condition) + ' = icmp eq ptr ' + re.escape(self.candidate) + ', null')
        auth, verify = cursor.branch(condition)
        require(m.before(candidate_read, point)
                and m.before((auth, -1), self.auth.consumer) and m.before((verify, -1), self.verify.consumer)
                and not m.can_precede((auth, -1), self.verify.consumer)
                and not m.can_precede((verify, -1), self.auth.consumer), 'MD5 mode switches/bypasses consumers')
        self.points.update((self.env['loads'][48][0], self.verify.consumer, self.auth.consumer))
        require(m.before(self.env['loads'][0][0], self.auth.consumer), 'MD5 staging used before capture')
        # An unparsed cast, GEP, load or escape of the candidate-array pointer
        # is not silently treated as another valid candidate source.
        for block, rows in m.graph.items():
            for index, line in enumerate(rows):
                if not {capture, self.candidate} & set(re.findall(V, line)) or (block, index) in self.points:
                    continue
                # Compiler reference-validity assumptions concern the borrowed
                # Option slot, never the nullable candidate-array value.
                compare = re.fullmatch('(' + V + ') = icmp ne ptr ' + re.escape(capture) + ', null', line)
                if compare:
                    cursor = self.cursor((block, index + 1))
                    require(cursor.call('llvm.assume') == ['i1 ' + compare[1]], 'MD5 Option nonnull assumption changed')
                    self.points.add((block, index))
                    continue
                require(re.fullmatch(r'(?:tail )?call void @llvm.assume\(i1 true\) \[ "nonnull"\(ptr '
                                     + re.escape(capture) + r'\) \]', line), 'MD5 candidate pointer has an unreviewed use')
                self.points.add((block, index))

    def result(self, boundaries):
        m, report = self.m, self.verify.report
        report_value = re.match('(' + V + ') = ', m.graph[report[0]][report[1]])
        require(report_value, 'MD5 verification report result missing')
        block, offset = t.health.returned(m, report)
        good, _, _ = boundary.branch(m, block, offset, report_value[1], self.ok, self.points)
        require(self.parents(good) == {block}, 'MD5 decision exposure bypasses report admission')
        cursor = self.cursor((good, 0))
        if hasattr(self.verify, 'decision_cleanup'):
            if hasattr(self.verify, 'decision_byte'):
                byte = self.verify.decision_byte
            else:
                byte, = cursor.take('(' + V + ') = zext i1 ' + re.escape(self.verify.decision_bool) + ' to i8')
            for root in self.verify.decision_cleanup:
                cursor.lifetime('end', root)
        else:
            public, = cursor.take('(' + V + ') = icmp ne i8 ' + re.escape(self.verify.decision) + ', 0')
            byte, = cursor.take('(' + V + ') = zext i1 ' + re.escape(public) + ' to i8')
        merged, = cursor.take('br label %' + L)
        cursor.end()
        cursor = self.cursor((merged, 0))
        self.payload, pairs = cursor.take('(' + V + ') = phi i8 (.*)')
        fields = re.findall(r'\[ (' + V + r'|2), %' + L + r' \]', pairs)
        require(len(fields) == 2 and pairs == ', '.join('[ ' + value + ', %' + label + ' ]' for value, label in fields)
                and fields.count((byte, good)) == 1, 'MD5 decision mode merge changed')
        auth_end, = [label for value, label in fields if value == '2']
        require(self.parents(merged) == {good, auth_end} and m.before(self.auth.report, (auth_end, len(m.graph[auth_end])))
                and not m.can_precede(self.verify.consumer, (auth_end, -1)), 'MD5 authentication result not on its admitted path')
        post = merged, cursor.index
        require(post in boundaries[1], 'MD5 decision bypasses final checkpoint')
        self.post = post
        success, _, previous, aggregate, tag = boundaries[1][post]
        self.success = success
        for value in (0, 1, 2):
            # The typed probes bind all three Option<bool> representations;
            # exact parsing above binds the merge to the returned decision.
            known = {self.payload: status.literal(value, 8),
                     aggregate: (status.literal(self.ok, 8), status.ERROR), tag: status.literal(self.ok, 8)}
            self.points.update(status.walk(m, self.env, success, previous, known, self.ok, status.literal(value, 8)))


def check(model, envelope, boundaries, transports, compiler):
    return Decision(model, envelope, boundaries, transports, compiler)
