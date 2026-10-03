"""Private bounded copied-input VBS image; not general scheduling or qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import windows_enclave_parallel_wave_image as base
from windows_enclave_parallel_accelerated_worker_build import replace_exact as replace

ROOT, SOURCE = base.ROOT, base.SOURCE
FILES = ('parallel_wave_input.rs', 'parallel_wave_request.rs', 'parallel_input_bridge_body.rs',
         'parallel_input_copy.h')


def bridge(text):
    text = replace(text, 'mod parallel_wave_expected;', '')
    text = replace(text, 'const TOTAL_BITS: usize = 32 * 9 * 8 + 3;',
        'static INPUT: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());\n'
        'static WIDTH: AtomicUsize = AtomicUsize::new(0);\n'
        'static BLOCK: AtomicUsize = AtomicUsize::new(0);')
    text = replace(text, 'OFFSET.store(0, Ordering::Relaxed);',
        'OFFSET.store(0, Ordering::Relaxed);\n'
        'INPUT.store(core::ptr::null_mut(), Ordering::Relaxed);\n'
        'WIDTH.store(0, Ordering::Relaxed);\nBLOCK.store(0, Ordering::Relaxed);')
    text = replace(text, 'slots: &mut [Slot<\'_>],\n)',
        'slots: &mut [Slot<\'_>],\ninput: &[u8],\nblock: usize,\n)')
    text = replace(text, 'if !contained(plan) || !contained(slots) {',
        'if !contained(plan) || !contained(slots) || !contained(input) {')
    text = replace(text, 'OFFSET.store(offset, Ordering::Relaxed);',
        'OFFSET.store(offset, Ordering::Relaxed);\n'
        'INPUT.store(input.as_ptr().cast_mut(), Ordering::Relaxed);\n'
        'WIDTH.store(input.len(), Ordering::Relaxed);\nBLOCK.store(block, Ordering::Relaxed);')
    text = replace(text, 'if !(1..=4).contains(&identity) || CLAIMED.swap(true, Ordering::AcqRel) {',
        'if identity == 0 || CLAIMED.swap(true, Ordering::AcqRel) {')
    start, end = text.index('fn root(identity:'), text.index('/// # Safety\n/// Baseline CPU and independent')
    text = text[:start] + 'include!("parallel_input_bridge_body.rs");\n\n' + text[end:]
    start, end = text.index('    let result = (|| {', text.index('pub unsafe extern "C" fn PrivateWaveLeaf')), text.index('    if result {')
    text = text[:start] + '    let result = run_input_leaf(pointer, lane).unwrap_or(false);\n' + text[end:]
    return text


def build(directory):
    base.build(directory)
    record = json.loads((directory / 'parallel-wave-image-build.json').read_text())
    for name in FILES: shutil.copyfile(SOURCE / name, directory / name)
    previous = record['commands'][-1]
    common = previous[:previous.index('--crate-name')]
    deps = [part for name in ('brynja_core', 'brynja_hash_sha3', 'parallel_waves')
            for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    command = common + ['--crate-name', 'parallel_input', '--crate-type=rlib',
        str(directory / 'parallel_wave_input.rs'), '-o', str(directory / 'libparallel_input.rlib')] + deps
    base.base.base.base.base.run(command)
    record['commands'].append(command)
    entry = directory / 'parallel_input_bridge.rs'
    entry.write_text(bridge((SOURCE / 'parallel_wave_bridge.rs').read_text()))
    command = [word.replace(str(directory / 'parallel_wave_bridge.rs'), str(entry)) for word in previous]
    command += ['--extern', 'parallel_input=' + str(directory / 'libparallel_input.rlib')]
    base.base.base.base.base.run(command)
    record['commands'].append(command)
    path = directory / 'parallel_wave_body.h'
    path.write_text(replace(path.read_text(), 'PrivateWaveRoot((ULONG_PTR)InterlockedCompareExchange(&root_identity, 0, 0))',
                           'PrivateWaveRoot((ULONG_PTR)root_source)'))
    path = directory / 'parallel_wave_image.h'
    path.write_text(replace(path.read_text(), 'static volatile LONG root_identity, root_claimed, root_generation;',
                           'static volatile LONG root_claimed, root_generation;\nstatic PVOID root_source;'))
    path = directory / 'parallel_wave_entry.h'
    text = replace(path.read_text(), 'if (identity < 1 || identity > 4 ||',
                   'if (identity == 0 || InterlockedCompareExchange(&input_registration, 0, 0) != 2 ||')
    text = replace(text, 'InterlockedExchange(&root_identity, (LONG)identity);', 'root_source = (PVOID)identity;')
    path.write_text(text)
    path = directory / 'concurrent_stack.c'
    path.write_text(replace(path.read_text(), '#include "parallel_wave_entry.h"',
        '#include "parallel_input_copy.h"\n#include "parallel_wave_entry.h"'))
    sources = [SOURCE / name for name in FILES] + [Path(__file__).resolve(),
        ROOT / 'scripts/cryptography/windows_enclave_parallel_input_native.py',
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-input-native.py',
        ROOT / 'scripts/cryptography/test-windows-enclave-parallel-input-copy.py']
    record['source_sha256'].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    record.update(status='PRIVATE_COPIED_INPUT_IMAGE_BUILD_ONLY', production_qualified=False)
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                 if p.suffix in ('.rs', '.c', '.h', '.asm', '.cmd', '.s', '.ll', '.lib')}
    (directory / 'parallel-input-image-build.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory.resolve())
