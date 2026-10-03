"""Private variable-wave native image with generation-pinned reusable records."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_parallel_input_image as base
from windows_enclave_parallel_accelerated_worker_build import replace_exact as replace

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_scheduler_gate.h', 'parallel_scheduler_body.h', 'parallel_scheduler_entry.h', 'parallel_scheduler_query.h')


def rust_body(text):
    text = replace(text, '// Still three waves/ten leaves; lengths/content otherwise caller supplied.',
                   '// Variable waves within the existing checked ingress bounds; one operation per image.')
    start = text.index('    // Keep the existing native three-gate/ten-leaf diagnostic shape.')
    end = text.index('    let authority = authority()?;', start)
    text = text[:start] + text[end:]
    text = replace(text, '    for _ in 0..3 {', '    let waves = request.input_bits.div_ceil(request.block.checked_mul(32)?);\n    for _ in 0..waves {')
    text = replace(text, '        publication.retired = true;',
        '        // SAFETY: typed slot cleanup and both independent joins completed.\n'
        '        if unsafe { PrivateSchedulerRetire(publication.wave.generation()) } != 1 { return None; }\n'
        '        publication.retired = true;')
    text = replace(text, '    root.finish().ok()?;',
        '    root.finish().ok()?;\n    // SAFETY: final Rust framing succeeded; C verifies every native generation retired.\n'
        '    if unsafe { PrivateSchedulerComplete(waves) } != 1 { return None; }')
    return (text + '\nunsafe extern "C" {\n    fn PrivateSchedulerRetire(generation: u32) -> usize;\n'
        + '    fn PrivateSchedulerComplete(waves: usize) -> usize;\n}\n')


def build(directory):
    base.build(directory)
    record = json.loads((directory / 'parallel-input-image-build.json').read_text())
    for name in FILES: shutil.copyfile(SOURCE / name, directory / name)
    (directory / 'parallel_input_bridge_body.rs').write_text(rust_body((SOURCE / 'parallel_input_bridge_body.rs').read_text()))
    command = record['commands'][-1]
    base.base.base.base.base.base.run(command)
    record['commands'].append(command)
    path = directory / 'parallel_wave_image.h'
    text = replace(path.read_text(), '#include "parallel_wave_native_gate.h"', '#include "parallel_scheduler_gate.h"')
    path.write_text(replace(text, 'root_claimed, root_generation;', 'root_claimed;'))
    path = directory / 'concurrent_stack.c'
    text = replace(path.read_text(), 'static STACK_SLOT slots[13];', 'static STACK_SLOT slots[5];')
    text = replace(text, '#include "parallel_wave_body.h"', '#include "parallel_scheduler_body.h"')
    text = replace(text, '#include "parallel_wave_entry.h"', '#include "parallel_scheduler_entry.h"')
    start = text.index('/* Query only after')
    path.write_text(text[:start] + '#include "parallel_scheduler_query.h"\n')
    path = directory / 'parallel_input_copy.h'
    text = replace(path.read_text(), 'static volatile LONG input_registration, input_exported;',
        'static volatile LONG input_registration, input_exported, scheduler_completed;')
    text = replace(text, 'input_copies[2] >= 3', '(ULONG_PTR)input_copies[2] >= SCHED_MAX_GENERATION')
    text = replace(text, 'input_copies[2] != 3', 'InterlockedCompareExchange(&scheduler_completed, 0, 0) != 1')
    text = replace(text, '&slots[12].done', '&slots[4].done')
    text += '\nULONG_PTR PrivateSchedulerComplete(ULONG_PTR waves) {\n'
    text += '    if (waves > SCHED_MAX_GENERATION || scheduler_load() != ((ULONGLONG)waves << 32) ||\n'
    text += '        (ULONG_PTR)input_copies[2] != waves || InterlockedCompareExchange(&scheduler_completed, 1, 0) != 0) return 0;\n'
    text += '    return 1;\n}\n'
    path.write_text(text)
    paths = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/test-windows-enclave-scheduler-gate.py',
        ROOT / 'scripts/cryptography/windows_enclave_parallel_scheduler_native.py',
        ROOT / 'scripts/cryptography/windows_enclave_parallel_scheduler_host.py',
        ROOT / 'scripts/cryptography/windows_enclave_parallel_scheduler_validate.py',
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-scheduler.py']
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='PRIVATE_VARIABLE_WAVE_IMAGE_BUILD_ONLY', production_qualified=False)
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                 if p.suffix in ('.rs', '.c', '.h', '.asm', '.cmd', '.s', '.ll', '.lib')}
    (directory / 'parallel-scheduler-image-build.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory.resolve())
