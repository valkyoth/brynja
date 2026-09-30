"""Private batch placement checks; mocks deliberately refuse all OS transport."""
import json
import shutil
import subprocess
import windows_enclave_sha2_stream_build as base


def check(directory, miri_toolchain=None):
    fixture = directory/'placement'
    fixture.mkdir()
    stream = directory/'placement-stream'
    stream.mkdir()
    dependencies = '[dependencies]\n'
    for name in ('brynja-core', 'brynja-hash-sha2'):
        dependencies += name+'={path='+json.dumps(str(base.ROOT/'crates'/name))
        dependencies += ',features='+('[]' if name == 'brynja-core' else '["general-sha512-t"]')+'}\n'
    (stream/'Cargo.toml').write_text('[package]\nname="sha2_stream"\nversion="0.0.0"\nedition="2024"\n'
        '[lib]\npath='+json.dumps(str(base.SOURCE/'sha2_stream.rs'))+'\n'+dependencies+'[workspace]\n')
    for name in ('sha2_batch_worker.rs', 'sha2_batch_placement_tests.rs'):
        shutil.copyfile(base.SOURCE/name, fixture/name)
    worker = fixture/'sha2_batch_worker.rs'
    (fixture/'Cargo.toml').write_text('[package]\nname="enclave-sha2-batch-placement"\nversion="0.0.0"\nedition="2024"\n'
        '[lib]\nname="sha2_batch"\npath='+json.dumps(str(base.SOURCE/'sha2_batch.rs'))+'\n'
        '[[test]]\nname="placement"\npath='+json.dumps(str(worker))+'\n'+dependencies+
        'sha2_stream={path='+json.dumps(str(stream))+'}\n[workspace]\n')
    arguments = ['test', '--offline', '--manifest-path', str(fixture/'Cargo.toml'), '--test', 'placement']
    command = ['cargo', '+'+(miri_toolchain or '1.98.1')]
    if miri_toolchain: command += ['miri']
    output = base.run(command+arguments)
    if '1 passed; 0 failed' not in output: raise AssertionError(output)
    print(output, flush=True)
    original = worker.read_text()
    for before, after in (('for offset in 0..4096 {', 'for offset in 0..0 {'), ('*live = None;', '')):
        if original.count(before) != 1: raise AssertionError('Stale placement mutant: '+before)
        try:
            worker.write_text(original.replace(before, after))
            base.run(['cargo', '+1.98.1', *arguments, '--no-run'])
            result = subprocess.run(['cargo', '+1.98.1', *arguments], capture_output=True, text=True, timeout=120)
            if result.returncode == 0 or 'placed_owner_is_destroyed_before_full_page_clear_and_can_be_recreated ... FAILED' not in result.stdout:
                raise AssertionError('Placement mutant survived or failed unexpectedly: '+result.stdout+result.stderr)
        finally:
            worker.write_text(original)
    print('SHA-2 batch placement: two compiled allocation-clear/lifetime mutants rejected', flush=True)
