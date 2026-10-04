"""Typed host contract tests; ordinary process evidence, never fake VBS execution."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_image_pin_build as pin

ROOT = pin.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('parallel_host_contract.rs', 'parallel_host_contract_tests.rs')
MUTANTS = (
    ('output_bits > 8192', 'output_bits > 8193'),
    ('!(1..=1024).contains(&block)', '!(0..=1024).contains(&block)'),
    ('if last == 0', 'if last <= 1'),
    ('!(1..=8).contains(&last)', '!(0..=8).contains(&last)'),
    ('self.input.message.bits > maximum', 'self.input.message.bits > maximum + 1'),
    ('self.input.custom.bits > 8192', 'self.input.custom.bits > 8193'),
    ('if self.state != State::Ready', 'if false'),
    ('if output.len() != plan.output_bytes()', 'if output.len() > 1024'),
    ('self.state = State::Quarantined;', 'self.state = State::Ready;'),
    ('self.channel.settled()?;', 'let _ = self.channel.settled();'),
    ('        result?;', '        let _ = result;'),
    ('b >> remainder != 0', 'false'),
    ('self.state = State::Complete;', 'self.state = State::Ready;'),
)


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command): return subprocess.run(command, capture_output=True, text=True, timeout=120)


def checked(command):
    result = run(command)
    if result.returncode: raise RuntimeError(result.stdout + result.stderr)
    return result


def prelude():
    text = (SOURCE / 'parallel_host_windows_main.rs').read_text()
    return text[:text.index('#[allow(dead_code)]')] + '''
pub struct ImagePolicy;
pub static POLICY: ImagePolicy = ImagePolicy;
#[path="parallel_host_contract.rs"] pub mod contract;
mod adapter {
    use crate::{Error,ImagePolicy,contract::{Channel,Request}};
    pub struct Enclave;
    impl Enclave {
        pub(crate) fn open(_: &std::path::Path, _: &ImagePolicy, _: bool)->Result<Self,Error>{
            Err(Error::Unsupported)
        }
    }
    impl Channel for Enclave {
        fn execute(&mut self, r:&Request<'_>, _: &mut [u8;1024])->Result<(),Error>{
            let _=r.header()?; Err(Error::Unsupported)
        }
        fn settled(&self)->Result<(),Error>{Err(Error::Unsupported)}
    }
}
'''


def campaign(directory):
    directory.mkdir(parents=True, exist_ok=False)
    compiler = checked(['rustc', '+1.98.1', '-vV']).stdout
    target = compiler.split('host: ')[1].splitlines()[0]
    suffix = '.exe' if 'windows' in target else ''
    commands = pin.dependencies(directory, target, testing=True)
    for name in FILES: shutil.copyfile(SOURCE/name, directory/name)
    (directory/'component.rs').write_text(prelude())
    common = ['rustc', '+1.98.1', '--edition=2024', '-Dwarnings', '--crate-name', 'host_contract',
        '-L', 'dependency='+str(directory), '--extern', 'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib')]
    source, library = directory/'component.rs', directory/'libhost_contract.rlib'
    checked(common + ['--crate-type=rlib', str(source), '-o', str(library)])
    command = common + ['--test', str(source), '-o']
    binary = directory/('contract'+suffix)
    checked(command + [str(binary)])
    baseline = checked([str(binary)])
    if '8 passed; 0 failed' not in baseline.stdout: raise AssertionError('test count')
    print(baseline.stdout, flush=True)
    clippy = ['rustup','run','1.98.1','clippy-driver'] + common[2:] + [
        '--crate-type=rlib',str(source),'--emit=metadata','-o',str(directory/'clippy.rmeta')]
    checked(clippy)
    mutated = directory / FILES[0]
    original = mutated.read_bytes()
    mutations = []
    try:
        for index, (before, after) in enumerate(MUTANTS):
            if original.count(before.encode()) != 1: raise AssertionError('anchor: '+before)
            mutated.write_bytes(original.replace(before.encode(), after.encode()))
            mutant = directory/(f'mutant-{index}'+suffix)
            checked(command + [str(mutant), '-Aunused-variables'])
            result = run([str(mutant)])
            if result.returncode != 101 or 'test result: FAILED.' not in result.stdout:
                raise AssertionError('escaped/crashed mutant: '+before+'\n'+result.stdout+result.stderr)
            mutations.append(dict(before=before, stdout=result.stdout, stderr=result.stderr,
                binary=mutant.name, binary_sha256=digest(mutant)))
            print('REJECTED: '+before, flush=True)
    finally: mutated.write_bytes(original)
    negatives = []
    probes = [(trait, 'fn need<T:'+trait+'>(){}fn main(){need::<host_contract::contract::Session>();}', 'E0277')
        for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug')]
    probes += [
        ('private-request','fn main(){let _:Option<host_contract::contract::Request>=None;}','E0603'),
        ('private-channel','fn main(){fn bound<T:host_contract::contract::Channel>(){}}','E0603'),
        ('private-plan','use host_contract::contract::*;fn main(){let _=Plan{algorithm:Algorithm::ParallelHash128,block:0,output_bits:0};}','E0451'),
        ('private-part','use host_contract::contract::*;fn main(){let _=Part{bytes:&[],bits:u64::MAX};}','E0451'),
        ('private-transport','fn main(){let _=host_contract::contract::Session::from_transport;}','E0624'),
        ('required-declassification','use host_contract::contract::*;fn attempt(s:&mut Session,p:Plan,i:Input){let _=s.digest_public(p,i,&mut []);}fn main(){}','E0061'),
        ('borrowed-input','use host_contract::contract::*;fn main(){let mut b=[0];let p=Part::bytes(&b).unwrap();b[0]=1;let _=Input::new(p,Part::bytes(&[]).unwrap());}','E0506'),
        ('input-lifetime','use host_contract::contract::*;fn main(){let p;{let b=[0];p=Part::bytes(&b).unwrap();}let _=Input::new(p,Part::bytes(&[]).unwrap());}','E0597'),
    ]
    for name, text, expected in probes:
        path = directory/'negative.rs'; path.write_text(text)
        result = run(common + [str(path),'--extern','host_contract='+str(library),
            '--emit=metadata','-o',str(directory/'negative.rmeta')])
        if result.returncode == 0 or expected not in result.stderr:
            raise AssertionError('negative '+name+'\n'+result.stderr)
        negatives.append(dict(name=name, diagnostic=expected, stderr=result.stderr))
    final = checked([str(binary)])
    paths = [SOURCE/name for name in FILES] + [SOURCE/'parallel_host_windows_main.rs', Path(__file__).resolve()]
    sources = set(pin.SOURCES) | {p.relative_to(ROOT).as_posix() for p in paths}
    record = dict(status='PRIVATE_TYPED_HOST_CONTRACT_PASS', enclave_execution=False,
        production_qualified=False, compiler=compiler, baseline=baseline.stdout, final=final.stdout,
        commands=commands+[command+[str(binary)],clippy], mutations=mutations, negatives=negatives,
        source_sha256={name:digest(ROOT/name) for name in sorted(sources)},
        artifact_sha256={p.relative_to(directory).as_posix():digest(p) for p in directory.rglob('*') if p.is_file()})
    (directory/'contract-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Typed host contract: 8 tests, 13 runtime mutants, 13 compiled negatives PASS')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    campaign(parser.parse_args().directory.resolve())
