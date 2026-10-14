#!/usr/bin/env python3
"""Direct NT symbolic-link variant of the isolated shipping image-path test."""
import importlib.util
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('image_path', Path(__file__).with_name(
    'test-windows-enclave-image-path.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def replace_once(before, after):
    if base.FIXTURE.count(before) != 1:
        raise AssertionError('missing or duplicate NT probe anchor: ' + before)
    base.FIXTURE = base.FIXTURE.replace(before, after)


def configure():
    anchor = '        let pin = pin::Pin::open'
    if base.FIXTURE.count(anchor) != 1:
        raise AssertionError('missing preclaimed-name test anchor')
    replace_once(anchor, r'''
        let source = std::fs::File::open(std::env::args().nth(3).unwrap()).unwrap();
        let target = sys::volume_path(std::os::windows::io::AsRawHandle::as_raw_handle(&source)).unwrap();
        for invalid in [r"C:\worker.dll", r"\\?\GLOBALROOT", "\\\\?\\GLOBALROOT\\Device\\bad\0"] {
            assert!(matches!(namespace::ImageName::create(&invalid.encode_utf16().collect::<Vec<_>>()), Err(Error::Image)));
        }
        crate::nt_shadow::preclaimed(|| matches!(namespace::ImageName::create(&target), Err(Error::Image)));
        drop(source);
''' + anchor)
    before = 'crate::shadow::Shadow::globalroot(&canonical, &args[2])'
    if base.FIXTURE.count(before) != 1:
        raise AssertionError('missing direct-NT replacement anchor')
    # The branch types differ; store only their public redirect path plus an
    # erased RAII owner. Both guards remain alive across the canonical read.
    replace_once(
        'let shadow = if globalroot {',
        'let (redirect_path, _shadow): (String, Box<dyn core::any::Any>) = if globalroot {')
    replace_once(before,
        'let shadow = crate::nt_shadow::Shadow::globalroot(&canonical, &args[2]);\n'
        '            (shadow.path.clone(), Box::new(shadow))')
    replace_once('            shadow\n',
        '            (shadow.path.clone(), Box::new(shadow))\n')
    replace_once('drop(shadow);', 'drop(_shadow);')
    replace_once('drop(pin);',
        'crate::nt_shadow::held_alias(&path);\n        drop(pin);\n'
        '        crate::nt_shadow::released_alias(&path);')
    base.SHADOW += (ROOT / 'assurance/windows-enclave-probe/nt_namespace.rs').read_text()
    # Give the imported runner's redirect mutant a fixture-local view.
    replace_once('assert_eq!(std::fs::read(&path)',
        'struct Redirect { path: String }\n'
        '        let shadow = Redirect { path: redirect_path };\n'
        '        let _ = &shadow.path;\n'
        '        assert_eq!(std::fs::read(&path)')


if __name__ == '__main__':
    if os.name != 'nt':
        raise RuntimeError('native Windows required; no skipped pass')
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        with open(sys.argv[2], 'w', buffering=1) as log:
            sys.stdout = sys.stderr = log
            try:
                configure()
                base.run()
                print('Direct NT namespace: O0/O2 real control and GLOBALROOT checks PASS')
            except BaseException:
                import traceback
                traceback.print_exc()
                sys.exit(1)
    else:
        from windows_enclave_namespace import isolated
        isolated(Path(__file__).resolve())
