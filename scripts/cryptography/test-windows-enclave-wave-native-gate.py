"""Compile actual native gate with POSIX atomics; not Windows/VBS evidence."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

from windows_enclave_parallel_wave_image import SOURCE
from windows_enclave_parallel_accelerated_worker_build import replace_exact

spec = importlib.util.spec_from_file_location('concurrent_c', Path(__file__).with_name('test-windows-enclave-concurrent-c.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
MAIN = r'''
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { puts("GATE_REJECTED"); return 1; } } while(0)
int main(int argc, char** argv) {
    ULONG_PTR generation, lane;
    (void)argv;
    CHECK(!wave_open(0) && !wave_open(4));
    CHECK(!wave_enter(0, 0) && !wave_enter(4, 0));
    if (argc > 1) {
        CHECK(wave_open(1)); wave_close(1);
        CHECK(!wave_open(1) && wave_quiescent(1) && !wave_complete(1));
    } else for (generation = 1; generation <= 3; ++generation) {
        ULONG_PTR lanes = generation == 3 ? 2 : 4;
        CHECK(!wave_enter(generation, 0));
        CHECK(wave_open(generation) && !wave_open(generation));
        CHECK(!wave_enter(generation, 4));
        if (generation > 1) CHECK(!wave_enter(generation - 1, 0));
        for (lane = lanes; lane < 4; ++lane) CHECK(!wave_enter(generation, lane));
        for (lane = 0; lane < lanes; ++lane) {
            CHECK(wave_enter(generation, lane));
            CHECK(!wave_enter(generation, lane));
        }
        wave_close(generation);
        CHECK(!wave_quiescent(generation) && !wave_complete(generation));
        for (lane = 0; lane < lanes; ++lane) {
            wave_leave(generation, lane, !(generation == 2 && lane == 1));
            CHECK(!wave_enter(generation, lane));
        }
        CHECK(wave_quiescent(generation));
        CHECK(wave_complete(generation) == (generation != 2));
        CHECK(!wave_open(generation));
    }
    puts("GATE_PASS"); return 0;
}
'''
MUTANTS = (
    ('!(state & WAVE_OPEN) || (state & bit)', '(state & bit)'),
    ('!(state & WAVE_OPEN) || (state & bit)', '!(state & WAVE_OPEN)'),
    ('if (!(wave_mask(generation) & bit))', 'if (FALSE)'),
    ('state | bit | (bit << 4)', 'state | bit'),
    ('InterlockedAnd(&native_waves[generation - 1], ~WAVE_OPEN);', '(void)generation;'),
    ('InterlockedOr(&native_waves[generation - 1], 1L << 17);', '(void)generation;'),
    ('if (clean) InterlockedOr', 'if (TRUE) InterlockedOr'),
    ('if (clean) InterlockedOr', 'if (FALSE) InterlockedOr'),
    ('InterlockedAnd(&native_waves[generation - 1], ~(bit << 4));', '(void)bit;'),
    ('return !(InterlockedCompareExchange(&native_waves[generation - 1], 0, 0) & (WAVE_OPEN | WAVE_LIVE));',
     'return !(InterlockedCompareExchange(&native_waves[generation - 1], 0, 0) & WAVE_OPEN);'),
)


def main():
    original = (SOURCE / 'parallel_wave_native_gate.h').read_text()
    compiler = shutil.which('cc')
    if not compiler: raise RuntimeError('C compiler required')
    with tempfile.TemporaryDirectory(prefix='brynja-wave-native-gate-') as temporary:
        root = Path(temporary)
        for number, mutation in enumerate((None,) + MUTANTS):
            source = replace_exact(original, *mutation) if mutation else original
            path = root / 'test.c'
            path.write_text(support.HEADER + '\n#define FALSE 0\n' + source + MAIN)
            binary = root / f'gate-{number}'
            result = subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-parameter', str(path), '-o', str(binary)], capture_output=True, text=True, timeout=30)
            if result.returncode: raise AssertionError('must compile: ' + result.stderr)
            results = [subprocess.run([str(binary)] + extra, capture_output=True, text=True, timeout=3)
                       for extra in ([], ['empty'])]
            if mutation:
                if not any(r.returncode == 1 and r.stdout == 'GATE_REJECTED\n' for r in results):
                    raise AssertionError('mutant escaped: ' + str(number))
            elif any(r.returncode or r.stdout != 'GATE_PASS\n' for r in results):
                raise AssertionError('baseline failed')
    print('Native C wave gate: baseline and ten compiled mutants PASS (POSIX atomic shims, not VBS)')


if __name__ == '__main__': main()
