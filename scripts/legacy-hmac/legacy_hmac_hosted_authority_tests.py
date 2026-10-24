"""Authority and keyed-selection mutations of emitted real worker bodies."""
import re
from pathlib import Path


class AuthorityTests:
    def test_compiled_out_workers_only_reject(self):
        h, count = self.driver.hosted, 0
        for case, identity, worker, population, _ in self.hosts():
            if not identity.endswith('_compiled'):
                continue
            signature, body = h.flow.resolve(worker, *population[:2])
            if any('::for_compiled_target' in population[2].get(call[0], '') for line in body.splitlines()
                   if (call := h.syntax.call(line))):
                continue
            env = h.envelope.check(signature, body, population[2], identity)
            h.unavailable.check(body, env, identity)
            graph = h.flow.blocks(body)
            site = env['result']
            line = graph[site[0]][site[1]]
            self.rejects(case, body, line, re.sub(r'store i(8|16) [^,]+,', r'store i\1 10,', line))
            for extra in ('call void @unknown()', '%extra = load i8, ptr @external, align 1',
                          'store i8 1, ptr @external, align 1'):
                self.rejects(case, body, line, extra + '\n' + line)
            count += 1
        self.assertEqual(count, 3)

    def test_compiled_mode_declarations(self):
        h = self.driver.hosted
        root = Path(self.directory.name) / 'authority-modes'
        for file in h.authority.MODE_FILES:
            path = root / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text((self.driver.ROOT / file).read_text())
        h.authority.modes(root)
        for file in h.authority.MODE_FILES:
            path = root / file
            text = path.read_text()
            for before, after in (('    Require,', '    Require = 9,'), ('    Prefer,', '    Other, Prefer,')):
                self.assertIn(before, text)
                try:
                    path.write_text(text.replace(before, after, 1))
                    with self.assertRaises(ValueError):
                        h.authority.modes(root)
                finally:
                    path.write_text(text)

    def authorities(self):
        h = self.driver.hosted
        for case, identity, worker, population, _ in self.hosts():
            if not identity.endswith('_compiled'):
                continue
            signature, body = h.flow.resolve(worker, *population[:2])
            if not any('::for_compiled_target' in population[2].get(call[0], '') for line in body.splitlines()
                       if (call := h.syntax.call(line))):
                continue
            compiler = re.findall(r'!"rustc version ([\d.]+) ', next(iter(case[0].values())))[0]
            t = h.authority.check(body, population[2], compiler, identity)
            yield case, identity, signature, body, population[2], t

    def test_authority_factory_mode_identity_and_keyed_borrow(self):
        for case, _, _, body, _, t in self.authorities():
            factory = t.graph[t.factory[0]][t.factory[1]]
            keyed = t.graph[t.keyed[0]][t.keyed[1]]
            symbol, args = self.driver.hosted.syntax.call(factory)
            for before, after in ((symbol, symbol + '_other'), (args[1], 'i8 noundef 1'),
                                  (args[1], 'i8 noundef 0'), (args[0], 'ptr ' + t.owner)):
                self.rejects(case, body, factory, factory.replace(before, after))
            symbol, args = self.driver.hosted.syntax.call(keyed)
            for before, after in ((symbol, symbol + '_other'), (args[1], 'ptr ' + t.result),
                                  (args[0], 'ptr ' + t.owner), (args[0], 'ptr ' + t.result)):
                self.rejects(case, body, keyed, keyed.replace(before, after))
            checkpoint = next((args, site) for symbol, args, site in t.calls
                              if t.names.get(symbol, '').endswith('::worker::checkpoint'))
            args, site = checkpoint
            line = t.graph[site[0]][site[1]]
            self.rejects(case, body, line, line.replace(args[1], 'ptr ' + t.result))
            self.rejects(case, body, line, line.replace(args[1], 'ptr ' + t.owner))

    def test_authority_every_transfer_write_and_escape(self):
        count = 0
        for case, _, _, body, _, t in self.authorities():
            for mode, site, dest, data in t.writes:
                p = t.pointer(dest, site)
                if not p or p[0] != t.owner:
                    continue
                line = t.graph[site[0]][site[1]]
                replacement = (line.replace(data[2], 'i64 ' + str(int(data[2].split()[-1]) - 1), 1)
                               if mode == 'copy' else line.replace(data, data.split()[0] + ' 0', 1))
                for changed in ('', replacement, line + '\n' + line):
                    self.rejects(case, body, line, changed)
                    count += 1
            keyed = t.graph[t.keyed[0]][t.keyed[1]]
            for root in (t.owner, t.result):
                for extra in ('store i8 0, ptr ' + root + ', align 1',
                              'call void @unknown(ptr ' + root + ')',
                              '%escaped = ptrtoint ptr ' + root + ' to i64',
                              'store ptr ' + root + ', ptr @external, align 8',
                              'call void @llvm.memcpy.p0.p0.i64(ptr @external, ptr ' + root + ', i64 24, i1 false)'):
                    self.rejects(case, body, keyed, extra + '\n' + keyed)
            self.rejects(case, body, keyed, '%late = getelementptr i8, ptr ' + t.owner
                         + ', i64 24\n' + keyed)
        self.assertEqual(count, 135)
        print(f'Legacy authority: {count} removed/corrupted/duplicate transfer writes rejected', flush=True)

    def test_authority_error_exclusion_and_live_storage(self):
        for case, _, _, body, _, t in self.authorities():
            line = t.graph[t.guard[0]][t.guard[1]]
            alternate = line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line else line.replace('icmp ne', 'icmp eq')
            self.rejects(case, body, line, alternate)
            self.rejects(case, body, line, line.rsplit(', ', 1)[0] + ', 99')
            branch = t.graph[t.guard[0]][-1]
            self.rejects(case, body, branch, re.sub(r'br i1 %[-\w.]+,', 'br i1 true,', branch))
            keyed = t.graph[t.keyed[0]][t.keyed[1]]
            self.rejects(case, body, keyed, 'call void @llvm.lifetime.end.p0(i64 24, ptr '
                         + t.owner + ')\n' + keyed)
            for site in t.reads:
                read = t.graph[site[0]][site[1]]
                self.rejects(case, body, read, 'call void @llvm.lifetime.end.p0(i64 24, ptr '
                             + t.result + ')\n' + read)

    def test_keyed_selection_capture_operands(self):
        h = self.driver.hosted
        for case, identity, signature, body, names, t in self.authorities():
            env = h.envelope.check(signature, body, names, identity)
            h.constructor.check(t, env)
            line = t.graph[t.keyed[0]][t.keyed[1]]
            _, args = h.syntax.call(line)
            for index in ((2, 3, 4) if identity == 'sha1_compiled' else (2,)):
                alternate = 'ptr null' if index == 2 and identity == 'sha1_compiled' else 'i64 8'
                self.rejects(case, body, line, line.replace(args[index], alternate))
            if identity == 'sha1_compiled':
                reference = env['loads'][16][1]
                self.rejects(case, body, line, 'store i64 8, ptr ' + reference + ', align 8\n' + line)
                self.rejects(case, body, line, 'call void @unknown(ptr ' + reference + ')\n' + line)

    def test_worker_backend_matching_guard(self):
        h = self.driver.hosted
        for case, identity, signature, body, names, t in self.authorities():
            env = h.envelope.check(signature, body, names, identity)
            site = h.backend.check(t, env)
            line = t.graph[site[0]][site[1]]
            for truth in ('true', 'false'):
                self.rejects(case, body, line, re.sub(r'br i1 %[-\w.]+,', 'br i1 ' + truth + ',', line))
            targets = re.findall('label %' + h.flow.LABEL, line)
            changed = line.replace('label %' + targets[0] + ', label %' + targets[1],
                                   'label %' + targets[1] + ', label %' + targets[0])
            self.rejects(case, body, line, changed)
            if identity == 'sha1_compiled':
                reference = env['loads'][8][1]
                self.rejects(case, body, line, 'store i8 0, ptr ' + reference + ', align 1\n' + line)
            # Substituting a constant backend in the predicate must not pass
            # simply because the current target happens to use that backend.
            report = None
            if identity == 'sha1_compiled':
                report_site = next(site for symbol, _, site in t.calls
                                   if names.get(symbol) == h.authority.SHA1 + '::report')
                report = re.match(r'(%[-\w.]+) = ', t.graph[report_site[0]][report_site[1]])[1]
            substitutions = 0
            for name, (rhs, point) in t.defs.items():
                if ((report and rhs == 'extractvalue { i1, i8 } ' + report + ', 1') or
                    (identity == 'md5_compiled' and (m := re.match(r'load i8, ptr (%[-\w.]+),', rhs))
                     and t.pointer(m[1], point) == (t.owner, 9))):
                    original = t.graph[point[0]][point[1]]
                    self.rejects(case, body, original, name + ' = add i8 0, 0')
                    substitutions += 1
            self.assertEqual(substitutions, 1)

    def test_authority_compiler_identity_is_not_inferred_from_niche(self):
        h = self.driver.hosted
        for artifacts, target, _, panic in self.cases:
            changed = {key: re.sub(r'!"rustc version [\d.]+ ', '!"rustc version 9.99.0 ', value)
                       for key, value in artifacts.items()}
            with self.assertRaises(ValueError):
                h.validate(changed, target, panic)
            changed = dict(artifacts)
            first = next(iter(changed))
            old = re.findall(r'!"rustc version ([\d.]+) ', changed[first])[0]
            changed[first] = changed[first].replace('rustc version ' + old,
                                                    'rustc version ' + ('1.90.0' if old == '1.99.1' else '1.99.1'))
            with self.assertRaises(ValueError):
                h.validate(changed, target, panic)
