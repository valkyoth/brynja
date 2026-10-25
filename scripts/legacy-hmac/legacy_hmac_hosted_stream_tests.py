"""Adversarial mutations of actual legacy streaming-worker compiler output."""
import copy
import re
from types import SimpleNamespace


class StreamTests:
    def test_scalar_checkpoint_boundaries_and_error_transport(self):
        h, count = self.driver.hosted, 0
        generator = h.shared.load('hmac_hosted_checkpoint_tests').CheckpointTests.checkpoint_mutations
        helper = SimpleNamespace(driver=SimpleNamespace(syntax=h.syntax, common=h.flow,
                                                        checkpoints=h.checkpoints.shared))
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            if identity.endswith('_compiled'):
                continue
            model, envelope = self.stream_model(arguments, body, names, compiler, identity)
            incoming = h.input_flow.check(model, arguments, envelope, case[3], compiler)
            outgoing = h.output.check(model, arguments, case[3])
            checked = h.checkpoints.Checkpoints(incoming, outgoing, case[1], compiler).check()
            normalized = '\n'.join(label + ':\n' + '\n'.join(lines) for label, lines in model.graph.items())
            for mutant in generator(helper, checked, normalized):
                with self.subTest(identity=identity, target=case[1], mutation=count), self.assertRaises(ValueError):
                    # Preserve independently checked landmarks so cancellation
                    # defects must be rejected by the checkpoint interpreter.
                    altered = h.scalar.Retained(mutant, names, compiler, identity, envelope)
                    altered.factories = checked.m.factories
                    flow = copy.copy(incoming)
                    flow.m = altered
                    h.checkpoints.Checkpoints(flow, outgoing, case[1], compiler).check()
                count += 1
        self.assertGreater(count, 450)
        print(f'Legacy scalar checkpoints: {count} boundary/error-transport defects rejected', flush=True)

    def test_scalar_checkpoint_callee_acquire_and_result(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-std']
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            compiler = re.findall(r'!"rustc version ([\d.]+) ', llvm)[0]
            wanted = (h.checkpoints.owner(case[1]) + '::worker::checkpoint',
                      '<' + h.checkpoints.owner(case[1]) + '::types::Cancellation>::check')
            for name in wanted:
                symbol = next(symbol for symbol in (*definitions, *aliases) if names.get(symbol) == name)
                arguments, body = h.flow.resolve(symbol, definitions, aliases)
                h.checkpoints.callee(arguments, body, compiler)
                mutants = (body.replace(' acquire,', ' monotonic,'), body.replace('icmp eq', 'icmp ne'),
                           body.replace(', i8 6', ', i8 0'), body.replace(', i8 undef, 1', ', i8 0, 1'),
                           re.sub(r'load atomic i8, ptr ' + h.syntax.VALUE, 'load atomic i8, ptr %wrong', body),
                           body.replace('ret { i8, i8 }', 'call void @unknown()\nret { i8, i8 }'))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    with self.assertRaises(ValueError):
                        h.checkpoints.callee(arguments, mutant, compiler)
                    count += 1
        self.assertEqual(count, 72)

    def stream_workers(self):
        h = self.driver.hosted
        for case, identity, worker, (definitions, aliases, names), _ in self.hosts():
            if identity == 'md5_compiled':
                continue
            arguments, body = h.flow.resolve(worker, definitions, aliases)
            if identity == 'sha1_compiled' and not any(
                    '::for_compiled_target' in names.get(call[0], '') for line in body.splitlines()
                    if '@' in line and (call := h.syntax.call(line))):
                continue
            compiler = re.findall(r'!"rustc version ([\d.]+) ', next(iter(case[0].values())))[0]
            yield case, identity, arguments, body, names, compiler

    def stream_model(self, arguments, body, names, compiler, identity):
        h = self.driver.hosted
        envelope = h.envelope.check(arguments, body, names, identity)
        model = (h.keyed.Admission(body, names, compiler, identity) if identity.endswith('_compiled')
                 else h.scalar.Retained(body, names, compiler, identity, envelope))
        return model, envelope

    def test_stream_input_iterators_tail_and_error_admission(self):
        h, count, workers = self.driver.hosted, 0, 0
        generator = h.shared.load('hmac_hosted_input_tests').InputTests.input_mutations
        helper = SimpleNamespace(driver=SimpleNamespace(syntax=h.syntax, common=h.flow))
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            model, envelope = self.stream_model(arguments, body, names, compiler, identity)
            flow = h.input_flow.check(model, arguments, envelope, case[3], compiler)
            for mutant in generator(helper, flow.m, flow, body):
                with self.subTest(identity=identity, target=case[1], compiler=compiler, mutation=count):
                    with self.assertRaises(ValueError):
                        altered, env = self.stream_model(arguments, mutant, names, compiler, identity)
                        h.input_flow.check(altered, arguments, env, case[3], compiler)
                count += 1
            workers += 1
        self.assertEqual(workers, 16)
        self.assertGreater(count, 900)
        print(f'Legacy streaming input/tail: {count} emitted defects rejected across {workers} workers', flush=True)

    def test_stream_iteration_repeated_update(self):
        h, count = self.driver.hosted, 0
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            if case[3] != 'unwind':
                continue
            model, envelope = self.stream_model(arguments, body, names, compiler, identity)
            flow = h.input_flow.check(model, arguments, envelope, case[3], compiler)
            self.assertFalse(flow.rotated)
            changed = copy.copy(flow)
            changed.m = copy.copy(flow.m)
            changed.m.graph = {block: list(lines) for block, lines in model.graph.items()}
            lines = changed.m.graph[flow.update[0]]
            self.assertIn('invoke ', lines[flow.update[1]])
            normal = re.match('to label %' + h.flow.LABEL, lines[flow.update[1] + 1])[1]
            lines[flow.update[1] + 1] = lines[flow.update[1] + 1].replace(
                'label %' + normal, 'label %' + flow.update[0], 1)
            with self.assertRaisesRegex(ValueError, 'same input part updated more than once'):
                changed.iteration()
            count += 1
        self.assertEqual(count, 9)

    def test_stream_output_provenance_and_cleanup(self):
        h, count, workers = self.driver.hosted, 0, 0
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            model, _ = self.stream_model(arguments, body, names, compiler, identity)
            out = h.output.check(model, arguments, case[3])
            mutants = []
            for value, point in out.origins.items():
                line = model.graph[point[0]][point[1]]
                rhs = model.defs[value][0]
                if rhs.startswith('getelementptr'):
                    altered = re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 8), line)
                elif rhs.startswith('select'):
                    altered = line.replace('ptr inttoptr (i64 1 to ptr)', 'ptr null') if 'ptr ' in rhs else line.replace('i64 0', 'i64 1')
                else:
                    self.assertTrue(rhs.startswith('load'))
                    altered = re.sub('ptr ' + h.syntax.VALUE + ',', 'ptr %unknown,', line)
                self.assertNotEqual(line, altered)
                mutants.append(body.replace(line, altered, 1))
            for args, point in (out.verify, out.final, out.copy):
                line = model.graph[point[0]][point[1]]
                indexes = (2, 3) if point == out.verify[1] else ((3, 4) if point == out.final[1] else range(4))
                for index in indexes:
                    replacement = 'ptr %unknown' if args[index].startswith('ptr ') else 'i64 0'
                    mutants.append(body.replace(line, line.replace(args[index], replacement, 1), 1))
            for point in out.stores:
                line = model.graph[point[0]][point[1]]
                mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
            copy_line = model.graph[out.copy[1][0]][out.copy[1][1]]
            for root in (out.owner[0], out.result[0]):
                for extra in ('%escaped = ptrtoint ptr ' + root + ' to i64',
                              'store ptr ' + root + ', ptr %escaped_destination, align 8',
                              'call void @unknown_owner(ptr ' + root + ')'):
                    mutants.append(body.replace(copy_line, extra + '\n' + copy_line, 1))
                # A Result descriptor may legitimately end after admission,
                # before copying the separate live secret owner. End it before
                # its finalizer instead; end the live owner before its copy.
                at = copy_line if root == out.owner[0] else model.graph[out.final[1][0]][out.final[1][1]]
                mutants.append(body.replace(at, 'call void @llvm.lifetime.end.p0(ptr ' + root + ')\n' + at, 1))
            for args, point in out.drops:
                line = model.graph[point[0]][point[1]]
                mutants.append(body.replace(line, line.replace(args[0], 'ptr %unknown'), 1))
                if 'invoke ' in line:
                    edge = model.graph[point[0]][point[1] + 1]
                    normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                    mutants.append(body.replace(line, 'br label %' + normal, 1).replace(edge, '', 1))
                else:
                    mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
            for extra in ('ret ptr null', 'resume {ptr, i32} zeroinitializer', 'call void @unknown_may_unwind()'):
                if case[3] == 'abort' and extra == 'call void @unknown_may_unwind()':
                    continue
                cut = model.graph[out.cut[0]][out.cut[1]]
                mutants.append(body.replace(cut, cut + '\n' + extra, 1))
            success, failure = out.guard()
            branch = next(line for lines in model.graph.values() for line in lines if line.startswith('br i1 ')
                          and set(re.findall('label %' + h.flow.LABEL, line)) == {success, failure})
            swapped = branch.replace('label %' + success, 'label %__swap', 1).replace(
                'label %' + failure, 'label %' + success, 1).replace('label %__swap', 'label %' + failure)
            mutants.append(body.replace(branch, swapped, 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], compiler=compiler, mutation=count):
                    self.assertNotEqual(mutant, body)
                    with self.assertRaises(ValueError):
                        altered, _ = self.stream_model(arguments, mutant, names, compiler, identity)
                        h.output.check(altered, arguments, case[3])
                count += 1
            workers += 1
        self.assertEqual(workers, 16)
        self.assertGreater(count, 500)
        print(f'Legacy streaming output: {count} provenance/cleanup defects rejected', flush=True)
