"""Mutations of actual inline scalar constructors, not synthetic proof bodies."""
import re


class ConstructTests:
    def prefix_models(self):
        h = self.driver.hosted
        for case, identity, body, names, compiler, envelope, retained, _ in self.scalar_models():
            prefix = h.scalar.construct.check(retained, envelope, case[3])
            yield case, identity, body, names, compiler, envelope, retained, prefix

    def reject_prefix(self, case, identity, names, compiler, envelope, mutant):
        h = self.driver.hosted
        with self.subTest(identity=identity, target=case[1]), self.assertRaises(ValueError):
            model = h.scalar.Retained(mutant, names, compiler, identity, envelope)
            h.scalar.construct.check(model, envelope, case[3])

    def test_scalar_constructor_births_transfers_and_renaming(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, env, m, prefix in self.prefix_models():
            mutants = []
            for mode, point, dest, data in m.writes:
                if not m.can_precede(point, m.cut):
                    continue
                root, _ = prefix.address(dest)
                if root in prefix.roles:
                    line = m.graph[point[0]][point[1]]
                    mutants.extend((body.replace(line, '', 1),
                                    body.replace(line, 'store i8 %unknown_initializer, ptr ' + dest + ', align 1', 1)))
                elif mode == 'copy' and m.allocs.get(root) == prefix.width:
                    line = m.graph[point[0]][point[1]]
                    mutants.extend((body.replace(line, '', 1),
                                    body.replace(line, line.replace(data[2], 'i64 ' + str(prefix.width - 1)), 1),
                                    body.replace(line, line.replace(data[1], 'ptr %unrelated'), 1)))
            for symbol, args, point in m.calls:
                root = prefix.address(h.syntax.operand(args[0]))[0] if args and args[0].startswith('ptr ') else None
                if root in prefix.roles and symbol == 'llvm.memset.p0.i64':
                    line = m.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line.replace(args[2], 'i64 1'), 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                self.reject_prefix(case, identity, names, compiler, env, mutant)
                count += 1
            # Roles follow typed moves and geometry, not %inner/%outer names.
            renamed = body
            for number, root in enumerate(prefix.roles):
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', '%renamed_constructor_' + str(number), renamed)
            h.scalar.construct.check(h.scalar.Retained(renamed, names, compiler, identity, env), env, case[3])
        self.assertGreater(count, 180)
        print(f'Legacy inline constructor: {count} initialization/transfer defects rejected', flush=True)

    def test_scalar_constructor_key_pad_status_and_cleanup(self):
        h, count = self.driver.hosted, 0
        base = h.scalar.construct.base
        for case, identity, body, names, compiler, env, m, prefix in self.prefix_models():
            mutants = []
            for symbol, args, point in m.calls:
                if not m.can_precede(point, m.cut) and not base.codegen.owner_drop(symbol, identity):
                    continue
                dropping = base.codegen.owner_drop(symbol, identity)
                update = base.codegen.adapter_update(symbol, identity)
                mask = base.mask(symbol)
                if not (dropping or update or mask or point in (prefix.finish, prefix.short_copy)):
                    continue
                # Only constructor-owned primitive drops, not later retained drops.
                if dropping and prefix.address(h.syntax.operand(args[0]))[0] not in prefix.roles:
                    continue
                line = m.graph[point[0]][point[1]]
                mutants.append(body.replace(line, line.replace(symbol, symbol + '_wrong'), 1))
                if dropping:
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1))
                    if 'invoke ' in line:
                        edge = m.graph[point[0]][point[1] + 1]
                        normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                        mutants.append(body.replace(line, 'br label %' + normal, 1).replace(edge, '', 1))
                    else:
                        mutants.append(body.replace(line, '', 1))
                if update or mask:
                    mutants.append(body.replace(line, line.replace(args[1], 'ptr %unrelated' if update else 'i64 63'), 1))
                    mutants.append(body.replace(line, line.replace(args[2], 'i64 0' if update else 'i8 0'), 1))
                    if update:
                        mutants.append(body.replace(line, '%raw_constructor_owner = load i8, ptr '
                                                    + h.syntax.operand(args[0]) + ', align 1\n' + line, 1))
                if point == prefix.short_copy:
                    mutants.append(body.replace(line, line.replace(args[2], 'ptr %unrelated'), 1))
                    mutants.append(body.replace(line, line.replace(args[3], 'i64 1'), 1))
                if update or mask or point == prefix.short_copy:
                    value = re.match('(' + h.keyed.V + ') = (?:tail )?(?:call|invoke) ', line)[1]
                    comparisons = [(rhs, at) for rhs, at in m.defs.values()
                                   if re.fullmatch(r'icmp (eq|ne) i8 ' + re.escape(value) + r', -?\d+', rhs)]
                    self.assertEqual(len(comparisons), 1)
                    rhs, at = comparisons[0]
                    old = m.graph[at[0]][at[1]]
                    opposite = rhs.replace('icmp eq', 'icmp ne') if 'icmp eq' in rhs else rhs.replace('icmp ne', 'icmp eq')
                    mutants.extend((body.replace(old, old.replace(rhs, opposite), 1),
                                    body.replace(old, re.sub(r', -?\d+$', ', 99', old), 1)))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                self.reject_prefix(case, identity, names, compiler, env, mutant)
                count += 1
        self.assertGreater(count, 300)
        print(f'Legacy inline constructor: {count} key/pad/status/cleanup defects rejected', flush=True)

    def test_scalar_constructor_scratch_and_catch_boundary(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, env, m, prefix in self.prefix_models():
            mutants = []
            for symbol, args, point in m.calls:
                if names.get(symbol) != 'brynja_core::secret_memory::clear_owned_region':
                    continue
                root = prefix.address(h.syntax.operand(args[0]))[0]
                if root not in prefix.scratch:
                    continue
                line = m.graph[point[0]][point[1]]
                mutants.extend((body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1),
                                body.replace(line, line.replace(args[1], 'i64 1'), 1),
                                body.replace(line, line.replace(symbol, symbol + '_wrong'), 1)))
            # Direct aliases/escapes cannot be hidden by a later clear.
            for root in prefix.scratch:
                point = next(at for symbol, args, at in m.calls if symbol == 'llvm.memset.p0.i64'
                             and prefix.address(h.syntax.operand(args[0])) == (root, 0))
                line = m.graph[point[0]][point[1]]
                for extra in ('store ptr ' + root + ', ptr @escaped, align 8',
                              '%escaped = ptrtoint ptr ' + root + ' to i64',
                              '%escaped = getelementptr i8, ptr ' + root + ', i64 %unknown_offset',
                              'call void @unknown_scratch(ptr ' + root + ')'):
                    mutants.append(body.replace(line, line + '\n' + extra, 1))
            for symbol, _, point in m.calls:
                if names.get(symbol) == 'std::panicking::catch_unwind::cleanup':
                    line = m.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, '%late_scratch = load i8, ptr ' + prefix.pad[0]
                                                + ', align 1\n' + line, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                self.reject_prefix(case, identity, names, compiler, env, mutant)
                count += 1
        self.assertGreater(count, 180)
        print(f'Legacy inline constructor: {count} scratch/escape/catch defects rejected', flush=True)
