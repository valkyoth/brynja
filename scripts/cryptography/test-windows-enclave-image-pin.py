#!/usr/bin/env python3
"""Artifact admission and result validation; native sharing checks are separate."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_image_pin_build as build
import windows_enclave_image_pin_run as native


class Tests(unittest.TestCase):
    def test_hash_and_mutations(self):
        target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
        with tempfile.TemporaryDirectory(prefix='image-pin-rust-') as tmp:
            root = Path(tmp); build.dependencies(root, target, testing=True)
            source = (build.ROOT/'assurance/windows-enclave-probe/image_pin.rs').read_text()
            for level in ('0', '2'):
                for replacement in (None, 'true', 'digest.as_bytes() != expected'):
                    code = source if replacement is None else source.replace('digest.as_bytes() == expected', replacement)
                    if replacement == 'true': code = code.replace('let Ok(digest)', 'let Ok(_digest)').replace('expected: &[u8; 32]', '_expected: &[u8; 32]')
                    (root/'image_pin.rs').write_text(code)
                    command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-D', 'warnings',
                        '-C', 'opt-level='+level, '-L', 'dependency='+str(root), '--extern',
                        'brynja_hash_sha2='+str(root/'libbrynja_hash_sha2.rlib'),
                        str(root/'image_pin.rs'), '-o', str(root/'tests')]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(root/'tests')], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, replacement is None, result.stdout+result.stderr)
                    self.assertIn('3 passed' if replacement is None else 'FAILED', result.stdout)

    def test_paths_are_not_device_stream_or_traversal_inputs(self):
        source = (build.ROOT/'assurance/windows-enclave-probe/image_pin.c').read_text()
        start = source.index('static int normal_path('); end = source.index('\nstatic int directory(', start)
        validator = source[start:end]
        checks = r'''
int main(void) {
    size_t length = 0;
    const wchar_t* bad[] = {L"", L"x.dll", L"C:x.dll", L"c:\\x.dll", L"C:/x.dll",
        L"C:\\", L"C:\\\\x.dll", L"C:\\a\\..\\x.dll", L"C:\\a\\.\\x.dll",
        L"C:\\x.dll:stream", L"C:\\x.\\y.dll", L"C:\\x \\y.dll", L"C:\\x.dll ",
        L"\\\\?\\C:\\x.dll", L"\\\\server\\share\\x.dll", L"C:\\a*\\x.dll", L"C:\\a?\\x.dll",
        L"C:\\a\"\\x.dll", L"C:\\a<\\x.dll", L"C:\\a>\\x.dll", L"C:\\a|\\x.dll", L"C:\\a\n.dll"};
    wchar_t long_path[PIN_PATH+1];
    if (!normal_path(L"C:\\a\\candidate.dll", &length) || length != 18) return 1;
    if (normal_path(NULL, &length)) return 2;
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) if(normal_path(bad[i],&length)) return 3;
    wmemset(long_path,L'a',PIN_PATH); long_path[0]=L'C'; long_path[1]=L':'; long_path[2]=L'\\'; long_path[PIN_PATH]=0;
    if(normal_path(long_path,&length)) return 4;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='image-pin-c-') as tmp:
            root = Path(tmp); path = root/'paths.c'
            path.write_text('#include <wchar.h>\n#include <stddef.h>\n#define PIN_PATH 1024\n'+validator+checks)
            for level in ('0', '2'):
                result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O'+level,
                    str(path), '-o', str(root/'paths')], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(root/'paths')], timeout=10)
                self.assertEqual(result.returncode, 0)

    def test_exact_capture_schema(self):
        for expected in native.EXPECTED.values():
            normal = expected == (0, 0)
            value = {'kind':'image-pin', 'result':expected[1], 'child_completed':int(normal),
                'write_denied':int(normal), 'delete_denied':int(normal), 'rename_denied':int(normal),
                'parent_rename_error':32 if normal else 0}
            native.validate(value, expected[0], expected)
            for field in native.FIELDS-{'kind'}:
                for bad in (value[field]+100, bool(value[field])):
                    with self.assertRaises(ValueError): native.validate(dict(value, **{field:bad}), expected[0], expected)
            with self.assertRaises(ValueError): native.validate(value, expected[0]+1, expected)
            with self.assertRaises(ValueError): native.validate(dict(value, extra=0), expected[0], expected)


if __name__ == '__main__': unittest.main()
