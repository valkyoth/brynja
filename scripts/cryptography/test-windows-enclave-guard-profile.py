#!/usr/bin/env python3
"""Compile the actual guard-control body in default and diagnostic profiles."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe/window_guard.c'
PREFIX = '''#include <stdint.h>
#include <assert.h>
typedef uintptr_t ULONG_PTR;
#define __declspec(x)
#define CALLBACK
static int active, low_changed, high_changed;
static ULONG_PTR mode, stats[12];
'''
MAIN = r'''
int main(void) {
    assert(PublicGuardControl(0) == (void*)1);
    for (uintptr_t i=1; i<=4; ++i) {
#ifdef BRYNJA_DIAGNOSTIC_GUARD_FAULTS
        assert(PublicGuardControl((void*)i) == (void*)1);
        assert(mode == i);
#else
        assert(PublicGuardControl((void*)i) == 0);
        assert(mode == 0);
#endif
    }
    for (uintptr_t i=5; i<16; ++i) assert(PublicGuardControl((void*)i) == 0);
    for (uintptr_t i=0; i<12; ++i) {
        stats[i]=100+i;
        assert((uintptr_t)PublicGuardControl((void*)(16+i)) == 100+i);
    }
    assert(PublicGuardControl((void*)28) == 0);
    low_changed=1;
    assert(PublicGuardControl((void*)28) == (void*)1);
    assert(PublicGuardControl((void*)29) == 0);
    active=1;
    assert(PublicGuardControl(0) == 0);
    return 0;
}
'''


def run():
    source = SOURCE.read_text()
    anchor = '__declspec(dllexport) void* CALLBACK PublicGuardControl'
    assert source.count(anchor) == 1
    control = source[source.index(anchor):]
    with tempfile.TemporaryDirectory(prefix='brynja-guard-profile-') as name:
        root = Path(name)
        # Preprocess the actual guard source without SDK declarations. This
        # verifies exclusion, not native compilation or OS behavior.
        (root / 'window_guard.c').write_text(source)
        (root / 'window_lock.c').write_text('')
        for diagnostic in (False, True):
            defines = ['-DBRYNJA_DIAGNOSTIC_GUARD_FAULTS'] if diagnostic else []
            expanded = subprocess.check_output(['cc', '-E', '-P', *defines,
                                                str(root / 'window_guard.c')], text=True)
            assert ('boundary_filter' in expanded) == diagnostic
            assert ('*(volatile unsigned char*)address = 0xa5' in expanded) == diagnostic
            (root / 'test.c').write_text(PREFIX + control + MAIN)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', *defines,
                            str(root / 'test.c'), '-o', str(root / 'test')], check=True)
            subprocess.run([str(root / 'test')], check=True, timeout=10)
        changed = control.replace('#ifdef BRYNJA_DIAGNOSTIC_GUARD_FAULTS', '#if 1')
        assert changed != control
        (root / 'test.c').write_text(PREFIX + changed + MAIN)
        subprocess.run(['cc', '-std=c11', '-O2', str(root / 'test.c'), '-o', str(root / 'test')], check=True)
        result = subprocess.run([str(root / 'test')], capture_output=True, timeout=10)
        assert result.returncode != 0 and b'Assertion' in result.stderr
    print('Guard profiles: default rejects fault modes; diagnostic opts in; regression mutant rejected')


if __name__ == '__main__':
    run()
