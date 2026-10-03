#!/usr/bin/env python3
"""Compile the real public probe with POSIX atomic shims, not VBS emulation."""
import argparse
import ctypes as c
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from windows_enclave_concurrent import ROOT, exercise

HEADER = r'''
#include <stdint.h>
#define __declspec(value)
#define __int64 long long
#define CALLBACK
#define WINAPI
#define TRUE 1
#define IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE 0
#define IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE 1
typedef uintptr_t ULONG_PTR;
typedef int32_t LONG;
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HINSTANCE;
typedef void* LPVOID;
typedef struct {
    unsigned long a,b,c,d,e,f;
    unsigned char family[16], image[16];
    unsigned long g,h;
    uintptr_t size;
    unsigned long threads,flags;
} IMAGE_ENCLAVE_CONFIG;
static inline LONG InterlockedCompareExchange(volatile LONG* p, LONG n, LONG old) {
    __atomic_compare_exchange_n(p, &old, n, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return old;
}
#define InterlockedOr(p,v) __atomic_fetch_or(p,v,__ATOMIC_SEQ_CST)
#define InterlockedAnd(p,v) __atomic_fetch_and(p,v,__ATOMIC_SEQ_CST)
#define InterlockedExchange(p,v) __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST)
'''
MUTANTS = (
    ('missing completion', 'InterlockedOr(&completed, bit);', '(void)bit;'),
    ('missing active exit', 'InterlockedAnd(&active, ~bit);', '(void)bit;'),
    ('wrong return', '(void*)(lane + 100)', '(void*)(lane + 101)'),
    ('premature release', 'static volatile LONG claimed[4], active, completed, released, exhausted;',
     'static volatile LONG claimed[4], active, completed, exhausted; static volatile LONG released = 1;'),
    ('bad query', 'default: return (void*)(ULONG_PTR)-1;', 'default: return 0;'),
    ('missing release', 'InterlockedExchange(&released, 1);', '(void)released;'),
    ('exhausted budget', 'remaining = 0x100000000ULL', 'remaining = 0'),
)


class NativeProcess:
    def __init__(self, path):
        self.library = c.CDLL(str(path))
        for name in ('PublicConcurrentWorker', 'PublicConcurrentControl'):
            function = getattr(self.library, name)
            function.restype, function.argtypes = c.c_void_p, [c.c_void_p]

    def create(self):
        return 1

    def load(self, base, image):
        return True, 0

    def initialize(self, base):
        return 5  # Only the real Windows run observes OS thread creation.

    def export(self, base, name):
        return getattr(self.library, name.decode())

    def call(self, routine, value):
        return routine(value) or 0

    def terminate(self, base):
        pass

    def delete(self, base):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', type=Path)
    args = parser.parse_args()
    if args.child:
        exercise(NativeProcess(args.child), args.child, 0.2)
        print('PUBLIC_CONCURRENCY_PROCESS: PASS')
        return
    compiler = shutil.which('cc')
    if not compiler:
        raise RuntimeError('C compiler required; no silent skip')
    source = (ROOT / 'assurance/windows-enclave-probe/concurrent_entry.c').read_text()
    with tempfile.TemporaryDirectory(prefix='brynja-public-concurrent-') as temporary:
        root = Path(temporary)
        (root / 'winenclave.h').write_text(HEADER)
        (root / 'intrin.h').write_text('#define _mm_pause() ((void)0)\n')
        for index, (name, before, after) in enumerate((('baseline', '', ''),) + MUTANTS):
            if before and source.count(before) != 1:
                raise RuntimeError('mutation location changed: ' + name)
            (root / 'probe.c').write_text(source.replace(before, after, 1) if before else source)
            library = root / f'probe-{index}.so'
            subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-shared', '-fPIC', '-I', str(root), str(root / 'probe.c'),
                            '-o', str(library)], check=True, timeout=30, capture_output=True)
            result = subprocess.run([sys.executable, __file__, '--child', str(library)],
                                    capture_output=True, text=True, timeout=3)
            if index == 0:
                if result.returncode or result.stdout.strip() != 'PUBLIC_CONCURRENCY_PROCESS: PASS':
                    raise RuntimeError('baseline failed: ' + result.stderr)
            elif result.returncode == 0 or 'ProbeError' not in result.stderr:
                raise RuntimeError('mutant not cleanly rejected: ' + name + result.stderr)
    print('Public concurrent-entry C baseline passed; seven compiled mutations rejected; not VBS proof')


if __name__ == '__main__':
    main()
