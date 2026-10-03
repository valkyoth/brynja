"""Compile real OS-copy boundary with stubs; rejection tests, NOT Windows proof."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

from windows_enclave_parallel_accelerated_worker_build import replace_exact
from windows_enclave_parallel_input_image import SOURCE

spec = importlib.util.spec_from_file_location('atomic_stubs', Path(__file__).with_name('test-windows-enclave-concurrent-c.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
HEADER = r'''
#include <stddef.h>
#include <stdio.h>
typedef void* PVOID;
typedef size_t SIZE_T;
typedef int HRESULT;
#define S_OK 0
#define InterlockedIncrement(p) __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST)
static volatile LONG root_claimed;
static struct { volatile LONG done; } slots[13];
static unsigned char buffer[4096];
static int fail_copy, calls;
static ULONG_PTR PrivateWaveRootRegion(ULONG_PTR p, ULONG_PTR size) {
    ULONG_PTR low=(ULONG_PTR)buffer;
    return p>=low && size<=sizeof(buffer) && p-low<=sizeof(buffer)-size;
}
static HRESULT EnclaveCopyIntoEnclave(void* d,const void* s,SIZE_T n) {
    (void)d;(void)s;(void)n; ++calls; return fail_copy ? -1 : S_OK;
}
static HRESULT EnclaveCopyOutOfEnclave(void* d,const void* s,SIZE_T n) {
    (void)d;(void)s;(void)n; ++calls; return fail_copy ? -1 : S_OK;
}
'''
MAIN = r'''
#define CHECK(x) do { if (!(x)) { puts("COPY_REJECTED"); return 1; } } while(0)
int main(void) {
    CHECK(!PublicInputOutputSource(NULL));
    CHECK(PublicInputOutputSource((void*)0x10000)==(void*)1);
    CHECK(!PublicInputOutputSource((void*)0x20000));
    CHECK(PublicInputQuery(0)==(void*)(ULONG_PTR)-1);
    CHECK(!PrivateInputCopy(0,1,buffer+1,4096));
    CHECK(!PrivateInputCopy(0,1,buffer+4090,128));
    CHECK(!PrivateInputCopy(0,1,buffer,127));
    CHECK(!PrivateInputCopy(0,(ULONG_PTR)-2,buffer,128));
    CHECK(!PrivateInputCopy(1,1,buffer,1));
    CHECK(!PrivateInputCopy(2,1,buffer,1));
    CHECK(calls==0);
    fail_copy=1; CHECK(!PrivateInputCopy(0,1,buffer,128) && input_errors==1 && input_copies[0]==0);
    fail_copy=0; CHECK(PrivateInputCopy(0,1,buffer,128));
    CHECK(!PrivateInputCopy(0,1,buffer,128));
    CHECK(!PrivateInputCopy(1,1,buffer,1025));
    CHECK(PrivateInputCopy(1,1,buffer,1024));
    CHECK(!PrivateInputCopy(1,1,buffer,1));
    CHECK(!PrivateInputOutput(buffer,1));
    CHECK(PrivateInputCopy(2,1,buffer,4096));
    CHECK(PrivateInputCopy(2,1,buffer,4096));
    CHECK(PrivateInputCopy(2,1,buffer,1));
    CHECK(!PrivateInputCopy(2,1,buffer,1));
    CHECK(!PrivateInputOutput(buffer,1025));
    CHECK(!PrivateInputOutput(buffer+4095,2));
    fail_copy=1; CHECK(!PrivateInputOutput(buffer,32) && input_exported==1 && input_errors==2);
    fail_copy=0; CHECK(!PrivateInputOutput(buffer,32));
    slots[12].done=1;
    CHECK(PublicInputQuery((void*)2)==(void*)3 && PublicInputQuery((void*)3)==(void*)1);
    puts("COPY_PASS"); return 0;
}
'''
MUTANTS = (
    ('|| input_copies[0] != 0', ''),
    ('|| input_copies[1] != 0', ''),
    ('|| input_copies[2] >= 3', ''),
    ('input_copies[2] != 3', 'input_copies[2] > 3'),
    ('size > 1024 || input_copies[0] != 1', 'size > 4096 || input_copies[0] != 1'),
    ('!PrivateWaveRootRegion((ULONG_PTR)destination, size)', '0'),
    ('!PrivateWaveRootRegion((ULONG_PTR)source, size)', '0'),
    ('InterlockedCompareExchange(&input_exported, 1, 0) != 0', '0'),
    ('return (void*)(ULONG_PTR)-1;\n    if (field < 3)', 'return 0;\n    if (field < 3)'),
)


def main():
    original = (SOURCE / 'parallel_input_copy.h').read_text()
    compiler = shutil.which('cc')
    if not compiler: raise RuntimeError('C compiler required')
    with tempfile.TemporaryDirectory(prefix='brynja-input-copy-') as tmp:
        root = Path(tmp)
        for number, mutation in enumerate((None,) + MUTANTS):
            source = replace_exact(original, *mutation) if mutation else original
            path, binary = root / 'test.c', root / f'copy-{number}'
            path.write_text(support.HEADER + HEADER + source + MAIN)
            result = subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                str(path), '-o', str(binary)], capture_output=True, text=True, timeout=30)
            if result.returncode: raise AssertionError('must compile: ' + result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=3)
            if mutation:
                if result.returncode != 1 or result.stdout != 'COPY_REJECTED\n': raise AssertionError(f'mutant {number} escaped/crashed')
            elif result.returncode or result.stdout != 'COPY_PASS\n': raise AssertionError('baseline failed')
    print('Native copy C boundary: baseline and nine compiled mutations PASS (stubbed OS calls, not VBS)')


if __name__ == '__main__': main()
