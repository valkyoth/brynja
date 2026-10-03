"""Compile reusable native generation gate: real C, ordinary process atomics."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from windows_enclave_parallel_input_image import SOURCE
from windows_enclave_parallel_accelerated_worker_build import replace_exact

HEADER = r'''
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
typedef uintptr_t ULONG_PTR;
typedef uint64_t ULONGLONG;
typedef int64_t LONG64;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
static inline LONG64 InterlockedCompareExchange64(volatile LONG64* p, LONG64 n, LONG64 old) {
    __atomic_compare_exchange_n(p,&old,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST); return old;
}
'''
MAIN = r'''
#define CHECK(x) do { if (!(x)) { puts("SCHEDULER_REJECTED"); return 1; } } while(0)
static void* delayed(void* unused) {
    (void)unused;
    for (unsigned i=0;i<10000;++i) {
        if (scheduler_enter(1,0) || scheduler_read_begin(1)) return (void*)1;
    }
    return NULL;
}
int main(void) {
    ULONG_PTR gen,lane; pthread_t thread; void* result;
    CHECK(!scheduler_reserve(0,1) && !scheduler_reserve(1,0) && !scheduler_reserve(1,5));
    CHECK(!scheduler_enter(0,0) && !scheduler_read_begin(0));
    for(gen=1;gen<=33;++gen) {
        ULONG_PTR lanes=(gen%4)+1;
        CHECK(scheduler_reserve(gen,lanes));
        CHECK(!scheduler_reserve(gen,lanes) && !scheduler_reserve(gen+1,lanes));
        CHECK(!scheduler_enter(gen,0) && !scheduler_read_begin(gen));
        CHECK(scheduler_publish(gen) && !scheduler_publish(gen));
        CHECK(!scheduler_read_begin(gen) && !scheduler_enter(gen+1,0));
        CHECK(!scheduler_enter(gen,4));
        for(lane=lanes;lane<4;++lane) CHECK(!scheduler_enter(gen,lane));
        if(gen==2) CHECK(pthread_create(&thread,NULL,delayed,NULL)==0);
        for(lane=0;lane<lanes;++lane) CHECK(scheduler_enter(gen,lane) && !scheduler_enter(gen,lane));
        CHECK(!scheduler_retire(gen));
        CHECK(scheduler_close(gen) && scheduler_close(gen));
        CHECK(!scheduler_quiescent(gen) && !scheduler_complete(gen) && !scheduler_read_begin(gen));
        for(lane=0;lane<lanes;++lane) {
            CHECK(!scheduler_leave(gen+1,lane,TRUE));
            CHECK(scheduler_leave(gen,lane,TRUE) && !scheduler_leave(gen,lane,TRUE));
            CHECK(!scheduler_enter(gen,lane));
        }
        CHECK(scheduler_quiescent(gen) && scheduler_complete(gen));
        CHECK(!scheduler_read_begin(gen+1) && scheduler_read_begin(gen));
        CHECK(!scheduler_retire(gen) && !scheduler_reserve(gen+1,1));
        CHECK(!scheduler_read_end(gen+1) && scheduler_read_end(gen) && !scheduler_read_end(gen));
        if(gen==2) { CHECK(pthread_join(thread,&result)==0); CHECK(result==NULL); }
        CHECK(scheduler_retire(gen) && !scheduler_retire(gen));
        CHECK(!scheduler_read_begin(gen) && !scheduler_enter(gen,0));
    }
    CHECK(scheduler_reserve(34,1) && scheduler_publish(34) && scheduler_close(34));
    CHECK(scheduler_quiescent(34) && !scheduler_complete(34) && !scheduler_retire(34));
    CHECK(!scheduler_publish(34) && !scheduler_reserve(35,1));
    /* Independent unreachable-state injection for exhaustion/failed-cleanup boundaries. */
    scheduler_state=(LONG64)(SCHED_MAX_GENERATION<<32);
    CHECK(!scheduler_reserve(SCHED_MAX_GENERATION+1,1) && !scheduler_reserve(1,1));
    scheduler_state=0;
    CHECK(scheduler_reserve(1,1) && scheduler_publish(1) && scheduler_enter(1,0));
    CHECK(scheduler_leave(1,0,FALSE) && scheduler_close(1));
    CHECK(!scheduler_complete(1) && !scheduler_retire(1));
    scheduler_state=(LONG64)((1ULL<<32)|SCHED_CLOSED|SCHED_READERS);
    CHECK(!scheduler_read_begin(1));
    puts("SCHEDULER_PASS"); return 0;
}
'''
MUTANTS = (
    ('(old & SCHED_LOW) != 0', '(old & SCHED_LOW) == 1'),
    ('(old >> 32) + 1 != generation', '(old >> 32) + 2 != generation'),
    ('generation > SCHED_MAX_GENERATION || lanes', 'generation > SCHED_MAX_GENERATION + 1 || lanes'),
    ('|| !(old & SCHED_OPEN)', '|| 0'),
    ('|| (old & bit) ||', '|| 0 ||'),
    ('|| !(old & (bit << 12))', '|| 0'),
    ('old | bit | (bit << 4)', 'old | bit'),
    ('(old & ~SCHED_OPEN) | SCHED_CLOSED', 'old | SCHED_CLOSED'),
    ('clean ? bit << 8 : 0', 'clean ? bit << 8 : bit << 8'),
    ('(old & ~(bit << 4))', 'old'),
    ('old + SCHED_READ_ONE', 'old'),
    ('old - SCHED_READ_ONE', 'old'),
    ('| SCHED_READERS)) != SCHED_CLOSED', ')) != SCHED_CLOSED'),
    ('(old & SCHED_READERS) == SCHED_READERS', '(old & SCHED_READERS) == SCHED_READERS - SCHED_READ_ONE'),
)


def main(directory):
    directory.mkdir(parents=True, exist_ok=False)
    original = (SOURCE / 'parallel_scheduler_gate.h').read_text()
    compiler = shutil.which('cc')
    if not compiler: raise RuntimeError('C compiler required')
    records = []
    for index, mutation in enumerate((None,) + MUTANTS):
        text = replace_exact(original, *mutation) if mutation else original
        source, binary = directory / f'gate-{index}.c', directory / f'gate-{index}'
        source.write_text(HEADER + text + MAIN)
        command = [compiler, '-std=c11', '-pthread', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError('must compile: ' + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        if mutation:
            if result.returncode != 1 or result.stdout != 'SCHEDULER_REJECTED\n': raise AssertionError(f'mutant {index} escaped/crashed')
        elif result.returncode or result.stdout != 'SCHEDULER_PASS\n': raise AssertionError('baseline failed')
        records.append(dict(command=command, mutation=mutation, stdout=result.stdout, stderr=result.stderr,
                            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
    (directory / 'results.json').write_text(json.dumps(dict(status='PROCESS_GATE_TESTS_ONLY', enclave_execution=False,
        source_sha256=hashlib.sha256((SOURCE / 'parallel_scheduler_gate.h').read_bytes()).hexdigest(),
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), records=records), indent=2)+'\n')
    print(f'Native scheduler gate: baseline and {len(MUTANTS)} compiled mutants PASS; NOT VBS evidence')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    main(parser.parse_args().directory.resolve())
