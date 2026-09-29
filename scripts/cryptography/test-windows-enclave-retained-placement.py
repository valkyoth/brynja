#!/usr/bin/env python3
"""In-page ownership boundary tests, not native residency qualification."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import windows_enclave_retained_build as base
from windows_enclave_placement_build import command, run, miri_manifest


class Tests(unittest.TestCase):
    def test_miri_rejects_narrowed_page_provenance(self):
        with tempfile.TemporaryDirectory(prefix='brynja-placement-provenance-') as tmp:
            directory = Path(tmp)
            source = directory / 'retained_placement.rs'
            original = (base.SOURCE / source.name).read_text()
            anchor = 'NonNull::from(&mut *page).cast::<u8>()'
            self.assertEqual(original.count(anchor), 1)
            source.write_text(original.replace(anchor, 'NonNull::from(&mut page[0]).cast::<u8>()'))
            shutil.copyfile(base.SOURCE / 'retained_placement_tests.rs', directory / 'retained_placement_tests.rs')
            manifest = miri_manifest(directory, source)
            env = os.environ.copy()
            for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
                env.pop(key, None)
            env['MIRIFLAGS'] = '-Zmiri-strict-provenance'
            env['CARGO_TARGET_DIR'] = str(directory / 'build')
            result = subprocess.run(['cargo', '+nightly-2026-09-11', 'miri', 'test', '--offline',
                                     '--manifest-path', str(manifest), '--lib',
                                     'destruction_clears_ready_result_before_page_release_and_reuse'],
                                    env=env, capture_output=True, text=True, timeout=180)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Undefined Behavior: attempting a write access', result.stderr)
            self.assertIn('tag does not exist in the borrow stack', result.stderr)
            self.assertIn('page.as_ptr().add(offset).write_volatile(0)', result.stderr)

    def test_placement_boundaries_and_compiled_regressions(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-retained-placement-') as tmp:
            directory = Path(tmp)
            base.build(directory, target, panic='unwind')
            for name in ('retained_placement.rs', 'retained_placement_tests.rs'):
                shutil.copyfile(base.SOURCE / name, directory / name)
            source = directory / 'retained_placement.rs'
            original = source.read_text()
            variants = {
                'no-destruction': ('unsafe { self.owner.as_ptr().drop_in_place() };', '',
                                   'owner must clear before page erase'),
                'no-page-wipe': ('unsafe { erase(self.page) };', '', 'byte 4224'),
                'overlap': ('const OWNER_OFFSET: usize = 256;', 'const OWNER_OFFSET: usize = 16;', None),
                'past-end': ('const OWNER_OFFSET: usize = 256;', 'const OWNER_OFFSET: usize = PAGE;', None),
                'unaligned': ('const OWNER_OFFSET: usize = 256;', 'const OWNER_OFFSET: usize = 257;', None),
            }
            for level in ('0', '2'):
                source.write_text(original)
                result = run(command(directory, target, level, True))
                self.assertEqual(result.returncode, 0, result.stderr)
                binary = directory / ('placement.exe' if os.name == 'nt' else 'placement')
                result = run([str(binary)])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('4 passed', result.stdout)
                for name, (before, after, diagnostic) in variants.items():
                    self.assertEqual(original.count(before), 1, name)
                    source.write_text(original.replace(before, after))
                    result = run(command(directory, target, level, True))
                    if diagnostic is None:
                        self.assertNotEqual(result.returncode, 0, name)
                        self.assertIn('E0080', result.stderr, name)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        result = run([str(binary)])
                        self.assertNotEqual(result.returncode, 0, name)
                        self.assertIn(diagnostic, result.stdout + result.stderr, name)
            source.write_text(original)
            result = run(command(directory, target, '2', False))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.check_consumers(directory)
        print('Placement: four tests and five regressions at O0/O2; eleven ownership rejections.')

    def check_consumers(self, directory):
        prefix = 'use retained_placement::Placed; use core::mem::MaybeUninit;\n'
        positive = "pub fn use_page(page: &mut [MaybeUninit<u8>]) { if let Ok(owner)=Placed::new(page,[1,2]) { drop(owner); } page[0]=MaybeUninit::new(1); }"
        cases = [(positive, None)]
        cases += [(f'fn bound<T:{trait}>() {{}} fn check() {{ bound::<Placed>(); }}', 'E0277')
                  for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
        cases += [
            ('fn check(page: &mut [MaybeUninit<u8>]) { let mut p=Placed::new(page,[1,2]).unwrap(); page[0]=MaybeUninit::new(1); p.quarantine(); }', 'E0506'),
            ('fn check(page: &mut [MaybeUninit<u8>]) { let p=Placed::new(page,[1,2]).unwrap(); let _=Placed::new(page,[1,2]); drop(p); }', 'E0499'),
            ("fn check() -> Placed<'static> { let mut p=[MaybeUninit::new(0);4096]; Placed::new(&mut p,[1,2]).unwrap() }", 'E0515'),
            ('fn check(p: Placed) { let _=p.owner; }', 'E0616'),
            ('fn check(p: Placed) { let _=p.page; }', 'E0616'),
            ('fn check(p: Placed) { drop(p); drop(p); }', 'E0382'),
        ]
        for body, diagnostic in cases:
            source = directory / 'consumer.rs'
            source.write_text(prefix + body)
            result = run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                          '--emit=metadata', '-L', 'dependency=' + str(directory),
                          '--extern', 'retained_placement=' + str(directory / 'libretained_placement.rlib'),
                          str(source), '-o', str(directory / 'consumer.rmeta')])
            if diagnostic is None:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0, body)
                self.assertIn(diagnostic, result.stderr)


if __name__ == '__main__':
    unittest.main()
