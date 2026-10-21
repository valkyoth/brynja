#!/usr/bin/env python3
"""Real hosted emissions, resource-source drift and compiled lifecycle mutants."""
import importlib.util
import copy
import json
from pathlib import Path
import re
import shutil
import unittest
from unittest import mock
from hmac_hosted_capture_tests import CaptureTests
from hmac_hosted_authority_tests import AuthorityTests
from hmac_hosted_keyed_tests import KeyedTests

spec = importlib.util.spec_from_file_location(
    'hosted', Path(__file__).with_name('check-hmac-hosted-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class HostedTests(CaptureTests, AuthorityTests, KeyedTests, unittest.TestCase):
    driver = driver

    @classmethod
    def setUpClass(cls):
        cls.directory = driver.verifier.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.profiles = {}
        for target in driver.TARGETS:
            llvm = driver.emit(cls.root / target, '1.99.1', target, 'unwind')[1]
            definitions, aliases, names, checked = driver.validate(llvm, target)
            cls.profiles[target] = llvm, definitions, aliases, names, checked

    def test_demangler_fallback_and_exact_population(self):
        for target, (llvm, _, _, _, _) in self.profiles.items():
            with self.subTest(target=target), mock.patch.object(driver.lifecycle.shutil, 'which', return_value=None):
                driver.validate(llvm, target)  # GNU binutils Rust v0 decoder.
            with self.assertRaises(ValueError):
                driver.validate(llvm + llvm, target)
            with self.assertRaises(ValueError):
                driver.validate(llvm.replace('6sha2247compute', '6sha2247missing'), target)
        with mock.patch.object(driver.lifecycle.subprocess, 'run', return_value=mock.Mock(stdout='')):
            with self.assertRaises(ValueError):
                driver.lifecycle.demangle({'_Rmissing'})

    def test_nonunwinding_source_premises_are_raw_byte_bound(self):
        work = self.root / 'sources'
        sources = {**driver.contracts.clearing.CLEAR_INPUTS,
                   **{driver.contracts.PREFIX + name: digest
                      for name, digest in driver.contracts.INPUTS.items()}}
        for name in sources:
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(driver.ROOT / name, path)
        driver.contracts.validate(work)
        for name in sources:
            path = work / name
            original = path.read_bytes()
            for changed in (original + b'\n', original.replace(b'\n', b'\r\n')):
                with self.subTest(name=name):
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        driver.contracts.validate(work)
            path.write_bytes(original)
        driver.contracts.validate(work)

    def test_graph_contamination_and_missing_owners(self):
        command = ['cargo', '+1.99.1', 'metadata', '--manifest-path', str(driver.FIXTURE),
                   '--locked', '--offline', '--format-version', '1']
        document = json.loads(driver.verifier.run(command, driver.verifier.environment(self.root)))
        driver.graph(document)
        for index in range(len(driver.PACKAGES)):
            for mode in ('runtime', 'registry', 'missing-package', 'missing-node', 'duplicate'):
                mutant = copy.deepcopy(document)
                if mode == 'runtime':
                    mutant['resolve']['nodes'][index]['features'].append('runtime-execution')
                elif mode == 'registry':
                    mutant['packages'][index]['source'] = 'registry'
                elif mode == 'missing-package':
                    mutant['packages'].pop(index)
                elif mode == 'missing-node':
                    mutant['resolve']['nodes'].pop(index)
                else:
                    mutant['resolve']['nodes'].append(mutant['resolve']['nodes'][index])
                with self.subTest(index=index, mode=mode), self.assertRaises(ValueError):
                    driver.graph(mutant)
        for feature in ('strict-hmac-acceleration', 'macos-resident-hmac-acceleration'):
            mutant = copy.deepcopy(document)
            node = next(row for row in mutant['resolve']['nodes'] if feature in row['features'])
            node['features'].remove(feature)
            with self.assertRaises(ValueError):
                driver.graph(mutant)

    def test_unavailable_only_build_cannot_count_as_accelerated_coverage(self):
        target = driver.TARGETS[0]
        with mock.patch.dict(driver.FEATURES, {target: '-sha,-sha512,-avx2'}):
            llvm = driver.emit(self.root / 'unavailable', '1.99.1', target, 'unwind')[1]
        with self.assertRaises(ValueError):
            driver.validate(llvm, target)

    def test_each_host_executor_rejects_lifecycle_mutations(self):
        cases = 0
        for target, (_, definitions, _, names, checked) in self.profiles.items():
            for symbol in checked:
                body = definitions[symbol][1]
                graph = driver.common.blocks(body)
                calls = [(line, call) for line in body.splitlines()
                         if (call := driver.syntax.call(line))]
                create = next((line, args) for line, (name, args) in calls if name == 'pthread_create')
                join = next((line, args) for line, (name, args) in calls
                            if names.get(name, name).endswith(('::thread::join', 'pthread_join')))
                attr = next(args for _, (name, args) in calls if names.get(name, '').endswith('Attributes>::new'))
                stack = driver.syntax.operand(attr[-1])
                clears = [line for line, (name, args) in calls
                          if names.get(name, '').endswith('Mapping>::clear')
                          and driver.syntax.operand(args[0]) == stack]
                self.assertEqual(len(clears), 2)
                status = re.search(r'(%[-\w.]+) = ', create[0])[1]
                branch = next(line for line in body.splitlines() if re.search(
                    r'icmp (?:eq|ne) i32 ' + re.escape(status) + ', 0', line))
                flip = branch.replace('icmp eq', 'icmp ne') if 'icmp eq' in branch else branch.replace('icmp ne', 'icmp eq')
                mutants = [body.replace(join[0], '', 1),
                           body.replace(join[0], join[0].replace(join[1][0], 'i64 0'), 1),
                           body.replace(branch, flip, 1),
                           body.replace(create[0], create[0] + '\n  store i8 0, ptr %foreign', 1),
                           body.replace(create[0], create[0] + '\n  %bad = atomicrmw xchg ptr %foreign, i8 0 seq_cst', 1),
                           body.replace(create[0], create[0] + '\n  %bad = load i8, ptr %foreign, align 1', 1),
                           body.replace(create[0], create[0] + '\n  call void @unexpected()', 1)]
                for clear in clears:
                    mutants.append(body.replace(clear, clear.replace(stack, '%other_stack'), 1))
                fatal = next(line for line, (name, _) in calls if names.get(name) == 'std::process::abort')
                mutants.append(body.replace(fatal, '  ret void', 1))
                lifetime = '  call void @llvm.lifetime.end.p0(i64 8, ptr ' + driver.syntax.operand(create[1][3]) + ')'
                mutants.append(body.replace(create[0], create[0] + '\n' + lifetime, 1))
                for mutant in mutants:
                    with self.subTest(target=target, executor=names[symbol], case=cases):
                        with self.assertRaises(ValueError):
                            driver.lifecycle.check_host(mutant, names, definitions, target)
                    cases += 1
                self.assertTrue(graph)
        self.assertEqual(cases, 792)

    def test_callbacks_must_resolve_and_belong_to_the_actual_session(self):
        for target, (llvm, definitions, _, names, checked) in self.profiles.items():
            body = definitions[next(iter(checked))][1]
            create = next(call for line in body.splitlines()
                          if (call := driver.syntax.call(line)) and call[0] == 'pthread_create')
            callback = re.search(r'@(\w+)', create[1][2])[1]
            missing = dict(definitions)
            del missing[callback]
            with self.assertRaises(ValueError):
                driver.lifecycle.check_host(body, names, missing, target)
            changed = dict(names)
            changed[callback] = changed[callback].replace('execute::{closure#0}', 'other::{closure#0}')
            with mock.patch.object(driver.lifecycle, 'demangle', return_value=changed):
                with self.assertRaises(ValueError):
                    driver.validate(llvm, target)

    def test_real_compiled_resource_and_capture_mutants(self):
        # Private copied host owner; upstream cryptographic implementations stay
        # untouched. Mutants must compile before the emitted lifecycle check fails.
        work = self.root / 'compiled-mutants'
        host, fixture = work / 'host', work / 'consumer'
        original_host = driver.ROOT / 'crates/brynja-crypto-cpu-std'
        shutil.copytree(original_host / 'src', host / 'src')
        manifest = original_host.joinpath('Cargo.toml').read_text().split('[lints]')[0]
        for key, value in (('edition', '"2024"'), ('rust-version', '"1.90"'),
                           ('license', '"MIT OR Apache-2.0"'), ('repository', '"https://github.com/valkyoth/brynja"')):
            manifest = manifest.replace(key + '.workspace = true', key + ' = ' + value)
        manifest = re.sub(r'(brynja-[\w-]+) = \{ workspace = true',
                          lambda m: m[1] + ' = { default-features = false, path = "'
                          + str(driver.ROOT / 'crates' / m[1]) + '"', manifest)
        (host / 'Cargo.toml').write_text('[workspace]\n' + manifest)
        shutil.copytree(driver.FIXTURE.parent / 'src', fixture / 'src')
        (fixture / 'Cargo.toml').write_text(driver.FIXTURE.read_text().replace(
            '../../crates/brynja-crypto-cpu-std', str(host)))
        driver.verifier.run(['cargo', '+1.99.1', 'generate-lockfile', '--offline',
                            '--manifest-path', str(fixture / 'Cargo.toml')], driver.verifier.environment(work))
        for target, relative, join in (
                (driver.TARGETS[0], 'protected_memory/platform/thread.rs', 'if join(worker) != 0 {'),
                (driver.TARGETS[2], 'macos_resident/resource/darwin/thread.rs',
                 'if unsafe { pthread_join(worker, core::ptr::null_mut()) } != 0 {')):
            path = host / 'src' / relative
            original = path.read_text()
            def emit():
                return driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
            driver.validate(emit(), target)

            anchor = 'mapping.clear();'
            # Only single-worker run, not the separately reviewed group path.
            start = original.index('pub(super) fn run<')
            end = original.index('\n}', start) + 2
            run = original[start:end]
            self.assertEqual(run.count(join), 1)
            self.assertGreaterEqual(run.count(anchor), 2)
            mutants = [run.replace(join, 'if false {'), run.replace(anchor, '/* no stack clear */')]
            for mutant in mutants:
                try:
                    path.write_text(original[:start] + mutant + original[end:])
                    emitted = emit()
                    with self.assertRaises(ValueError):
                        driver.validate(emitted, target)
                finally:
                    path.write_text(original)
            driver.validate(emit(), target)

        self.check_compiled_capture_mutants(host, fixture, work)
        self.check_compiled_authority_mutants(host, fixture, work)
        self.check_compiled_keyed_mutants(host, fixture, work)


if __name__ == '__main__':
    unittest.main()
