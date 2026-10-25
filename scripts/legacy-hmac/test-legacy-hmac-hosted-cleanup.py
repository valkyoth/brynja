#!/usr/bin/env python3
"""Regression mutations of real legacy host launch/reclaim artifacts."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import unittest
from legacy_hmac_hosted_capture_tests import CaptureTests
from legacy_hmac_hosted_authority_tests import AuthorityTests
from legacy_hmac_hosted_keyed_tests import KeyedTests
from legacy_hmac_hosted_scalar_tests import ScalarTests
from legacy_hmac_hosted_construct_tests import ConstructTests
from legacy_hmac_hosted_normalization_tests import NormalizationTests
from legacy_hmac_hosted_normalization_compiled_tests import NormalizationCompiledTests
from legacy_hmac_hosted_stream_tests import StreamTests
from legacy_hmac_hosted_stream_compiled_tests import StreamCompiledTests
from legacy_hmac_hosted_checkpoint_tests import AcceleratedCheckpointTests
from legacy_hmac_hosted_checkpoint_compiled_tests import CheckpointCompiledTests
from legacy_hmac_hosted_md5_checkpoint_tests import Md5CheckpointTests
from legacy_hmac_hosted_md5_compiled_tests import Md5CompiledTests
from legacy_hmac_hosted_md5_report_tests import Md5ReportTests
from legacy_hmac_hosted_md5_report_compiled_tests import Md5ReportCompiledTests
from legacy_hmac_hosted_md5_result_tests import Md5ResultTests
from legacy_hmac_hosted_md5_lane_tests import Md5LaneTests

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-hosted-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
h = driver.hosted


class Hosted(Md5LaneTests, Md5ResultTests, Md5ReportTests, Md5ReportCompiledTests, Md5CheckpointTests, Md5CompiledTests,
             AcceleratedCheckpointTests, CheckpointCompiledTests,
             CaptureTests, AuthorityTests, KeyedTests,
             ScalarTests, ConstructTests, NormalizationTests,
             NormalizationCompiledTests, StreamTests, StreamCompiledTests, unittest.TestCase):
    driver = driver
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target, panic, simd in (
                ('1.90.0', driver.TARGETS[0], 'abort', False),
                ('1.90.0', driver.TARGETS[0], 'unwind', True),
                ('1.99.1', driver.TARGETS[0], 'unwind', True),
                ('1.99.1', driver.TARGETS[1], 'abort', False),
                ('1.99.1', driver.TARGETS[2], 'abort', False),
                ('1.99.1', driver.TARGETS[2], 'unwind', True)):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target + panic), compiler, target, panic, simd)
            cls.cases.append((artifacts, target, h.validate(artifacts, target, panic), panic))
        env = driver.runner.environment(Path(cls.directory.name))
        cls.metadata = json.loads(driver.runner.run(['cargo', '+1.99.1', 'metadata', '--manifest-path', str(driver.FIXTURE),
            '--locked', '--offline', '--format-version', '1', '--filter-platform', driver.TARGETS[0]], env))

    def rejects(self, case, body, before, after):
        artifacts, target, _, panic = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        packages = [key for key, llvm in artifacts.items() if body in llvm]
        self.assertEqual(len(packages), 1)
        changed = dict(artifacts)
        changed[packages[0]] = changed[packages[0]].replace(body, body.replace(before, after, 1), 1)
        with self.subTest(target=target, before=before, after=after), self.assertRaises(ValueError):
            h.validate(changed, target, panic)

    def calls(self, body, names):
        return [(line, symbol, args, names.get(symbol, symbol)) for line in body.splitlines()
                if (call := h.syntax.call(line)) for symbol, args in (call,)]

    def hosts(self):
        for case in self.cases:
            for identity, (_, worker, population, body) in case[2].items():
                yield case, identity, worker, population, body

    def test_native_call_population_and_handle_identity(self):
        for case, _, _, (_, _, names), body in self.hosts():
            for line, symbol, args, name in self.calls(body, names):
                if name == 'pthread_create' or name.endswith('::thread::join') or name == 'pthread_join':
                    self.rejects(case, body, line, line.replace(symbol, symbol + '_wrong'))
                    self.rejects(case, body, line, line.replace(args[0], args[0].rsplit(' ', 1)[0] + ' %wrong_handle'))
                    self.rejects(case, body, line, line + '\n' + line)

    def test_exact_worker_identity_not_another_valid_closure(self):
        for case, identity, worker, (_, _, names), body in self.hosts():
            replacement = next(item[1] for other, item in case[2].items() if other != identity)
            line = next(line for line, _, _, name in self.calls(body, names) if name == 'pthread_create')
            self.rejects(case, body, line, line.replace('@' + worker, '@' + replacement))

    def test_create_and_join_status_polarity(self):
        count = 0
        for case, _, _, (_, _, names), body in self.hosts():
            for line, _, _, name in self.calls(body, names):
                if name == 'pthread_create' or name.endswith('::thread::join') or name == 'pthread_join':
                    value = re.match(r'\s*(%[-\w.]+) =', line)[1]
                    comparison = re.search(r'^.*icmp (eq|ne) i32 ' + re.escape(value) + r', 0.*$', body, re.M)[0]
                    inverted = comparison.replace('icmp eq', 'icmp ne') if 'icmp eq' in comparison else comparison.replace('icmp ne', 'icmp eq')
                    self.rejects(case, body, comparison, inverted)
                    count += 1
        self.assertEqual(count, 48)

    def test_stack_clear_identity_and_completion(self):
        for case, _, _, (_, _, names), body in self.hosts():
            _, resource = h.profile(case[1])
            calls = self.calls(body, names)
            attributes = next(args for _, _, args, name in calls if name == '<' + resource + '::thread::Attributes>::new')
            stack = h.syntax.operand(attributes[-1])
            clears = [line for line, _, args, name in calls if name == '<' + resource + '::Mapping>::clear'
                      and h.syntax.operand(args[0]) == stack]
            self.assertTrue(clears)
            for line in clears:
                self.rejects(case, body, line, line.replace(stack, '%different_mapping'))
                # Retargeting preserves valid CFG/invoke continuations while
                # removing the actual worker-stack clearing obligation.

    def test_no_work_or_reclaim_while_worker_unjoined(self):
        for case, _, _, (_, _, names), body in self.hosts():
            line, _, args, _ = next(item for item in self.calls(body, names)
                                    if item[3].endswith('::thread::join') or item[3] == 'pthread_join')
            create = next(args for _, _, args, name in self.calls(body, names) if name == 'pthread_create')
            job = h.syntax.operand(create[3])
            for extra in ('call void @unknown_effect()',
                          'call void @llvm.lifetime.end.p0(ptr ' + job + ')',
                          '%extra_min = call i64 @llvm.umin.i64(i64 1, i64 2)'):
                self.rejects(case, body, line, extra + '\n' + line)
            _, resource = h.profile(case[1])
            attributes = next(args for _, _, args, name in self.calls(body, names)
                              if name == '<' + resource + '::thread::Attributes>::new')
            stack = h.syntax.operand(attributes[-1])
            clear = next(symbol for _, symbol, args, name in self.calls(body, names)
                         if name == '<' + resource + '::Mapping>::clear' and h.syntax.operand(args[0]) == stack)
            self.rejects(case, body, line, 'call void @' + clear + '(ptr ' + stack + ')\n' + line)

    def test_unknown_effects_and_fatal_join_failure(self):
        for case, _, _, (_, _, names), body in self.hosts():
            start = next(iter(h.flow.blocks(body))) + ':'
            self.rejects(case, body, start, start + '\n  call void @unknown_effect()')
            fatal = [line for line, _, _, name in self.calls(body, names) if name == 'std::process::abort']
            self.assertTrue(fatal)
            for line in fatal:
                self.rejects(case, body, line, '')

    def test_consumer_arguments_and_route_binding(self):
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            consumers = {'brynja_legacy_hmac_hosted_cleanup::' + identity + '::' + operation
                         for identity in ('sha1', 'md5', 'sha1_compiled', 'md5_compiled')
                         for operation in ('compute', 'verify')}
            for consumer in sorted(consumers):
                selected = [symbol for symbol in (*definitions, *aliases) if names[symbol] == consumer]
                self.assertEqual(len(selected), 1)
                signature, body = h.flow.resolve(selected[0], definitions, aliases)
                call = next(item for item in self.calls(body, names) if item[3].startswith('<brynja_legacy_hmac_std::'))
                line, callee, args, _ = call
                self.rejects(case, body, line, line.replace(callee, callee + '_wrong'))
                for arg in args:
                    if arg.split()[-1] in ('undef', 'poison'):
                        continue
                    self.rejects(case, body, line, line.replace(arg, arg.rsplit(' ', 1)[0] + ' %unbound', 1))

    def test_compiled_public_adapter_arguments(self):
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-std']
            definitions, _ = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            owner, _ = h.profile(case[1])
            for symbol, (_, body) in definitions.items():
                if names[symbol].startswith('<' + owner + '::') and names[symbol].endswith(('Session>::compute', 'Session>::verify')):
                    line, _, args, _ = next(item for item in self.calls(body, names) if item[3].endswith('::execute'))
                    for arg in args:
                        if arg.split()[-1] not in ('undef', 'poison'):
                            self.rejects(case, body, line, line.replace(arg, arg.rsplit(' ', 1)[0] + ' %unbound', 1))

    def test_graph_identity_features_paths_and_edges(self):
        alternative = copy.deepcopy(self.metadata)
        package = next(p for p in alternative['packages'] if p['name'] == 'brynja-legacy-hmac-std')
        explicit = Path(self.directory.name) / 'explicit-host-copy/Cargo.toml'
        package['manifest_path'] = str(explicit)
        with self.assertRaises(ValueError):
            h.graph(alternative, driver.FIXTURE)
        h.graph(alternative, driver.FIXTURE, explicit)
        with self.assertRaises(ValueError):
            h.graph(alternative, driver.FIXTURE, explicit.with_name('wrong.toml'))
        legacy = copy.deepcopy(self.metadata)
        package = next(p for p in legacy['packages'] if p['name'] == 'brynja-legacy-hmac')
        package['manifest_path'] = str(explicit)
        with self.assertRaises(ValueError):
            h.graph(legacy, driver.FIXTURE)
        h.graph(legacy, driver.FIXTURE, legacy_manifest=explicit)
        with self.assertRaises(ValueError):
            h.graph(legacy, driver.FIXTURE, legacy_manifest=explicit.with_name('wrong.toml'))
        h.graph(self.metadata, driver.FIXTURE)
        mutations = []
        for field, value in (('source', 'registry+forged'), ('manifest_path', '/tmp/other/Cargo.toml')):
            data = copy.deepcopy(self.metadata); data['packages'][0][field] = value; mutations.append(data)
        data = copy.deepcopy(self.metadata); data['packages'][0]['targets'][0]['kind'] = ['custom-build']; mutations.append(data)
        data = copy.deepcopy(self.metadata); data['packages'].pop(); mutations.append(data)
        for extra in ('runtime-execution', 'default'):
            data = copy.deepcopy(self.metadata)
            package = next(p for p in data['packages'] if p['name'] == 'brynja-legacy-hmac-std')
            next(n for n in data['resolve']['nodes'] if n['id'] == package['id'])['features'].append(extra)
            mutations.append(data)
        data = copy.deepcopy(self.metadata)
        package = next(p for p in data['packages'] if p['name'] == 'brynja-legacy-hmac-std')
        next(n for n in data['resolve']['nodes'] if n['id'] == package['id'])['features'].remove('strict-md5-batch')
        mutations.append(data)
        for node in self.metadata['resolve']['nodes']:
            if node['dependencies']:
                data = copy.deepcopy(self.metadata)
                next(n for n in data['resolve']['nodes'] if n['id'] == node['id'])['dependencies'].pop()
                mutations.append(data)
        for data in mutations:
            with self.assertRaises(ValueError):
                h.graph(data, driver.FIXTURE)

    def test_launch_storage_and_attribute_transport(self):
        for case, identity, _, (definitions, aliases, names), body in self.hosts():
            symbol = case[2][identity][0]
            signature = h.flow.resolve(symbol, definitions, aliases)[0]
            _, resource = h.profile(case[1])
            launch = h.launch.Launch(signature, body, names, case[1], identity, resource)
            create = launch.graph[launch.create[0]][launch.create[1]]
            args = h.syntax.call(create)[1]
            for index in (1, 3):
                self.rejects(case, body, create, create.replace(args[index], 'ptr null'))
            for root in (launch.handle, launch.job):
                self.rejects(case, body, create, 'call void @llvm.lifetime.end.p0(ptr ' + root + ')\n' + create)
            construct = launch.graph[launch.construct[0]][launch.construct[1]]
            self.rejects(case, body, construct, construct.replace(launch.stack, launch.owner))
            for site in launch.chain:
                line = launch.graph[site[0]][site[1]]
                args = h.syntax.call(line)[1]
                width = int(args[2].split()[-1])
                self.rejects(case, body, line, line.replace(args[2], 'i64 ' + str(width - 1)))
                self.rejects(case, body, line, line.replace(args[1], args[1].rsplit(' ', 1)[0] + ' ' + launch.job))
            # Extra writes and pointer aliases must not bypass copy provenance.
            for extra in ('store i8 0, ptr ' + launch.result + ', align 1',
                          '%escaped = ptrtoint ptr ' + launch.result + ' to i64'):
                self.rejects(case, body, create, extra + '\n' + create)

    def test_attribute_error_cannot_launch(self):
        for case, identity, _, (definitions, aliases, names), body in self.hosts():
            signature = h.flow.resolve(case[2][identity][0], definitions, aliases)[0]
            launch = h.launch.Launch(signature, body, names, case[1], identity, h.profile(case[1])[1])
            for label, lines in launch.graph.items():
                if any(re.search(r'load i8, ptr ' + re.escape(launch.result) + ',', line) for line in lines):
                    branch = lines[-1]
                    targets = re.findall('label %' + h.flow.LABEL, branch)
                    self.assertEqual(len(targets), 2)
                    inverse = branch.replace('label %' + targets[0] + ', label %' + targets[1],
                                             'label %' + targets[1] + ', label %' + targets[0])
                    self.rejects(case, body, branch, inverse)

    def test_shared_checker_is_unchanged_and_intrinsics_are_narrow(self):
        original = h.shared.load('hmac_hosted_lifecycle')
        self.assertIsNot(original, h.model)
        self.assertEqual(original.profile(driver.TARGETS[0])[0], 'brynja_crypto_cpu_std::strict_hmac')
        self.assertIs(original.syntax, h.syntax)
        for line in ('%v = call i64 @llvm.umin.i64(i64 1, i64 2)',
                     '%v = call {i128,i1} @llvm.uadd.with.overflow.i128(i128 1, i128 2)'):
            self.assertIsNone(h.lifecycle_call(line))
        for line in ('%v = invoke i64 @llvm.umin.i64(i64 1, i64 2)',
                     '%v = call i64 @llvm.umin.i64(ptr %secret, i64 2)',
                     '%v = call i64 @llvm.umin.i64(i64 1)'):
            with self.assertRaises(ValueError):
                h.lifecycle_call(line)
        self.assertIsNotNone(h.lifecycle_call('call void @llvm.evil()'))

    def test_compiled_consumer_route_mutants(self):
        work = Path(self.directory.name) / 'consumer-mutants'
        shutil.copytree(driver.FIXTURE.parent / 'src', work / 'src')
        shutil.copyfile(driver.FIXTURE.parent / 'Cargo.lock', work / 'Cargo.lock')
        manifest = driver.FIXTURE.read_text().replace('../../crates/', str(driver.ROOT / 'crates') + '/')
        (work / 'Cargo.toml').write_text(manifest)
        path = work / 'src/lib.rs'
        original = path.read_text()
        for before, after in (
                ('scalar!(sha1, Sha1);', 'scalar!(sha1, Md5);'),
                ('session.compute(request, cancel)', 'session.compute(request, &Cancellation::new())'),
                ('session.verify(request, candidate, cancel)', 'session.verify(request, &candidate[..0], cancel)'),
                ('session.compute(request, cancel)',
                 'session.compute(Request { key: request.tail.bytes, ..request }, cancel)'),
                ('session.verify(inputs, candidates, cancel)', 'session.verify(inputs, &[None; 8], cancel)')):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            # Compilation must succeed. These are semantic dispatch/provenance
            # defects, not malformed Rust or artificial missing symbols.
            artifacts = driver.emit(work, '1.99.1', driver.TARGETS[0], 'unwind', True, work / 'Cargo.toml')
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                h.validate(artifacts, driver.TARGETS[0], 'unwind')
        path.write_text(original)
        h.validate(driver.emit(work, '1.99.1', driver.TARGETS[0], 'unwind', True, work / 'Cargo.toml'), driver.TARGETS[0], 'unwind')


if __name__ == '__main__':
    unittest.main()
