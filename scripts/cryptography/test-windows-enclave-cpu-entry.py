#!/usr/bin/env python3
"""Compile the actual C diagnostic entry against public mocked feature queries.

No enclave/CPU emulation claim: tests admission control BEFORE Rust entry.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'assurance/windows-enclave-probe/cpu_kernel_entry.c'
STUB = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#define __declspec(value)
#define CALLBACK
#define FAST_FAIL_FATAL_APP_EXIT 1
#define __fastfail(value) abort()
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
#define INVALID_QUERY (~(ULONG_PTR)0)
static ULONG_PTR inventory[11];
static unsigned calls;
void* PublicCpuInventory(void* context) { return (void*)inventory[(uintptr_t)context]; }
SIZE_T PublicCpuKernels(SIZE_T route) { ++calls; return route; }
'''
TEST = r'''
#include <assert.h>
#include "cpu_kernel_entry.c"
static void reset(void) {
    const ULONG_PTR values[11] = {0x42525943,1,15,7,1U<<26,0x1c000000U,(1U<<29)|(1U<<5),1,1,6,0};
    for (unsigned i=0;i<11;++i) inventory[i]=values[i];
    calls=0;
}
static void rejected(void) {
    assert(PublicCpuKernelProbe((void*)1)==0);
    assert(calls==0);
}
int main(void) {
    for (unsigned route=1;route<=5;++route) {
        reset();
        assert((uintptr_t)PublicCpuKernelProbe((void*)(uintptr_t)route)==route);
        assert(calls==1);
    }
    const ULONG_PTR invalid[3]={0,6,INVALID_QUERY};
    for (unsigned i=0;i<3;++i) {
        reset();
        assert(PublicCpuKernelProbe((void*)invalid[i])==0);
        assert(calls==0);
    }
    for (unsigned index=0;index<11;++index) {
        reset(); inventory[index]=INVALID_QUERY; rejected();
    }
    const unsigned bits[][2]={{2,0},{2,1},{2,2},{2,3},{4,26},{5,26},{5,27},{5,28},{6,29},{6,5},{9,1},{9,2}};
    for (unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) {
        reset(); inventory[bits[i][0]]&=~((ULONG_PTR)1<<bits[i][1]); rejected();
    }
    reset(); inventory[0]=0; rejected();
    reset(); inventory[1]=2; rejected();
    reset(); inventory[2]=31; rejected();
    reset(); inventory[3]=6; rejected();
    return 0;
}
'''
MUTANTS = ('route < 1 || route > 5', 'words[i] == INVALID_QUERY',
           'words[0] != 0x42525943', 'words[1] != 1', 'words[2] != 15',
           'words[3] < 7', '!(words[4] & (1U << 26))',
           '(words[5] & 0x1c000000U) != 0x1c000000U',
           '!(words[6] & (1U << 29))', '!(words[6] & (1U << 5))', '(words[9] & 6) != 6')


def main():
    original = SOURCE.read_text()
    with tempfile.TemporaryDirectory(prefix='enclave-cpu-entry-') as tmp:
        root = Path(tmp)
        source = root/'cpu_kernel_entry.c'
        (root/'cpu_inventory.c').write_text(STUB)
        (root/'test.c').write_text(TEST)
        def test(text, success):
            source.write_text(text)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(root/'test.c'),
                            '-o',str(root/'entry-test')], check=True, capture_output=True, timeout=30)
            result = subprocess.run([str(root/'entry-test')], capture_output=True, timeout=10)
            if (result.returncode == 0) != success:
                raise AssertionError('Unexpected entry-test result: '+result.stderr.decode())
        test(original, True)
        for before in MUTANTS:
            if original.count(before) != 1:
                raise AssertionError('Stale entry mutation: '+before)
            test(original.replace(before, '0'), False)
        test(original, True)
    print('CPU entry rejects missing features, query faults and unknown routes; eleven compiled gate mutants rejected')


if __name__ == '__main__':
    main()
