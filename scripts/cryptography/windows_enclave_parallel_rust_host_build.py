"""Build an isolated five-thread Rust host, not a shipping admission-policy change."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_image_pin_build as pin
from windows_enclave_parallel_scheduler_native import cases, oracle

ROOT = pin.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'
HOST = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave'
FILES = ('parallel_host_windows.rs', 'parallel_host_windows_callbacks.rs',
         'parallel_host_windows_main.rs', 'parallel_host_scheduler.rs')


def replace(text, before, after):
    if text.count(before) != 1: raise ValueError('exact source transform: ' + before)
    return text.replace(before, after)


def vectors():
    model = oracle()
    selected = [dict(case, fault=0) for case in cases() if case['mode'] == 'normal']
    selected += [dict(selected[4], fault=fault) for fault in (1, 2, 3)]
    rows = ['const CASES: &[Case] = &[']
    for case in selected:
        bits, cbits, obits = case['input_bits'], case['custom_bits'], case['output_bits']
        message, custom = model.oracle.canonical(71+bits, bits), model.oracle.canonical(131, cbits)
        expected = model.parallel_hash(168 if case['identity']%2 else 136,
            model.oracle.byte_bits(message)[:bits], case['block'], model.oracle.byte_bits(custom)[:cbits],
            obits, case['identity']>2)
        fields = dict(identity=case['identity'], block=case['block'], bits=bits, custom_bits=cbits,
                      output_bits=obits, fault=case['fault'])
        values = ','.join(f'{key}:{value}' for key, value in fields.items())
        values += ',' + ','.join(f'{key}:&{list(value)}' for key, value in (
            ('message',message), ('custom',custom), ('expected',expected)))
        rows.append('Case {' + values + '},')
    return '\n'.join(rows + ['];','']), selected


def build(directory, image):
    directory.mkdir(parents=True, exist_ok=False)
    adapter = directory / 'adapter'
    adapter.mkdir()
    commands = pin.dependencies(directory, 'x86_64-pc-windows-msvc', testing=True)
    shutil.copyfile(SOURCE / FILES[0], adapter / 'transport.rs')
    (adapter / 'transport').mkdir()
    shutil.copyfile(SOURCE / FILES[1], adapter / 'transport/callbacks.rs')
    shutil.copyfile(SOURCE / FILES[2], directory / 'main.rs')
    shutil.copyfile(SOURCE / FILES[3], directory / FILES[3])
    for name in ('policy.rs', 'image.rs'): shutil.copyfile(HOST / name, directory / name)
    for name in ('pin.rs', 'sys.rs'): shutil.copyfile(HOST / 'native' / name, adapter / name)
    path = directory / 'image.rs'
    path.write_text(replace(path.read_text(), 'admit_threads(b, policy, 1)', 'admit_threads(b, policy, 5)'))
    path = adapter / 'sys.rs'
    path.write_text(replace(path.read_text(), 'initialize_threads(base, 1)', 'initialize_threads(base, 5)') + '''
#[link(name="onecore")]
unsafe extern "system" {
    fn GetProcessWorkingSetSize(process: Handle, low: *mut usize, high: *mut usize) -> i32;
    fn SetProcessWorkingSetSize(process: Handle, low: usize, high: usize) -> i32;
}
pub(super) fn budget() -> Result<(), Error> {
    let (mut low,mut high)=(0,0);
    // SAFETY: current process and fixed initialized output words. Probe-only
    // allowance change; VirtualLock still must actually succeed for every frame.
    unsafe {
        let process=GetCurrentProcess();
        if GetProcessWorkingSetSize(process,&mut low,&mut high)==0 {return Err(Error::Platform);}
        let requested=(low.max(8*1024*1024),high.max(16*1024*1024));
        if SetProcessWorkingSetSize(process,requested.0,requested.1)==0 ||
            GetProcessWorkingSetSize(process,&mut low,&mut high)==0 ||
            low<requested.0 || high<requested.1 {return Err(Error::Platform);}
    }
    Ok(())
}
''')
    (adapter / 'mod.rs').write_text('use crate::{Error,protocol};\n'
        '#[allow(dead_code)] mod sys;\nmod pin;\nmod transport;\n'
        'pub(crate) use transport::Enclave;\npub(crate) fn budget()->Result<(),Error>{sys::budget()}\n')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    (directory / 'host_policy.rs').write_text('// Probe build input bound to the reviewed development image, not runtime metadata.\n'
        'static POLICY: ImagePolicy = ImagePolicy::reviewed_sha256(' + repr(list(bytes.fromhex(digest))) + ','
        + repr(list(b'BRYN'+bytes(12))) + ',' + repr(list(b'PAWV'+bytes(12))) + ',1,1,[0,0]);\n')
    data, selected = vectors()
    (directory / 'host_vectors.rs').write_text(data)
    command = ['rustc','+1.98.1','--edition=2024','-Dwarnings','-C','opt-level=2','-C','panic=unwind',
        '-C','overflow-checks=yes','-L','dependency='+str(directory),'--extern',
        'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),str(directory/'main.rs'),
        '-o',str(directory/'rust-host.exe')]
    subprocess.run(command,check=True,timeout=120)
    commands.append(command)
    sources = set(pin.SOURCES) | {p.relative_to(ROOT).as_posix() for p in [
        *[SOURCE / name for name in FILES], HOST / 'policy.rs', HOST / 'image.rs',
        HOST / 'native/pin.rs', HOST / 'native/sys.rs', Path(__file__).resolve(),
        ROOT/'scripts/cryptography/windows_enclave_parallel_scheduler_native.py',
        ROOT/'scripts/cryptography/test-windows-enclave-parallel-rust-host.py',
        ROOT/'scripts/cryptography/test-windows-enclave-rust-host-runner.py']}
    record = dict(schema=1, status='PRIVATE_FIVE_THREAD_HOST_BUILD_ONLY', enclave_execution=False,
        production_qualified=False, image_sha256=digest, cases=selected, commands=commands,
        source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(sources)},
        artifact_sha256={p.relative_to(directory).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in directory.rglob('*') if p.is_file()})
    (directory/'rust-host-build.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('image',type=Path)
    args=parser.parse_args()
    build(args.directory.resolve(),args.image.resolve(strict=True))
