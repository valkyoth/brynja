#!/usr/bin/env python3
"""Native private AVX2 placement/wire tests, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_tuple_accelerated_build as base

FILES = ('tuple_accelerated_resident.rs', 'tuple_accelerated_resident_tests.rs')
MUTANTS = [
    [
        "wire",
        "version != VERSION",
        "false"
    ],
    [
        "wire",
        "route != 1",
        "false"
    ],
    [
        "wire",
        "reserved != 0",
        "false"
    ],
    [
        "wire",
        "sequence == 0",
        "false"
    ],
    [
        "wire",
        "!(BEGIN..=CANCEL).contains(&operation)",
        "false"
    ],
    [
        "wire",
        "length > 1024",
        "false"
    ],
    [
        "wire",
        "width > 1024",
        "false"
    ],
    [
        "wire",
        "last > 8",
        "false"
    ],
    [
        "wire",
        "terminal > 1",
        "false"
    ],
    [
        "wire",
        "source.checked_add(length).ok_or(Error::Length)?;",
        "let _ = source;"
    ],
    [
        "wire",
        "((length == 0) != (source == 0))",
        "false"
    ],
    [
        "wire",
        "(!payload && length != 0)",
        "false"
    ],
    [
        "wire",
        "(names && !(1..=4).contains(&identity))",
        "false"
    ],
    [
        "wire",
        "(!names && identity != 0)",
        "false"
    ],
    [
        "wire",
        "(!shaped && width != 0)",
        "false"
    ],
    [
        "wire",
        "(operation != SQUEEZE && terminal != 0)",
        "false"
    ],
    [
        "wire",
        "(operation != ITEM_BEGIN && (item_low != 0 || item_high != 0))",
        "false"
    ],
    [
        "wire",
        "(!matches!(operation, BEGIN | REHASH) && (custom_low != 0 || custom_high != 0))",
        "false"
    ],
    [
        "wire",
        "(!payload && !shaped && last != 0)",
        "false"
    ],
    [
        "wire",
        "(length == 0 && last != 0)",
        "false"
    ],
    [
        "wire",
        "(length != 0 && last == 0)",
        "false"
    ],
    [
        "wire",
        "operation == SQUEEZE && terminal == 0 && last != if width == 0 { 0 } else { 8 }",
        "false"
    ],
    [
        "wire",
        "(width == 0 && last != 0)",
        "false"
    ],
    [
        "wire",
        "(width != 0 && last == 0)",
        "false"
    ],
    [
        "wire",
        "input.len() != self.length",
        "false"
    ],
    [
        "wire",
        "guard.complete = result.is_ok();",
        "guard.complete = true;"
    ],
    [
        "resident",
        "owner.quarantine();",
        ""
    ],
    [
        "resident",
        "unsafe { self.owner.as_mut() }.quarantine();",
        "let _ = unsafe { self.owner.as_mut() };"
    ],
    [
        "resident",
        "pointer.as_ptr().add(offset).write_volatile(0)",
        "pointer.as_ptr().add(offset).write_volatile(0xa5)"
    ]
]


def invoke(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(str(command)+'\n'+result.stdout+result.stderr)
    return result.stdout


def run(directory, target):
    component, binary = base.build(directory, target)
    component_output = invoke([str(binary)])
    if '9 passed; 0 failed' not in component_output:
        raise AssertionError(component_output)
    record = json.loads((directory/'tuple-accelerated-build.json').read_text())
    owner_compile = record['commands'][-2]
    common = component[:component.index('--crate-name')]
    for name in FILES:
        shutil.copyfile(base.SOURCE/name, directory/name)
    generated, count = base.scalar.oracle_tests()
    generated = '\n'.join(line for line in generated.splitlines() if not line.startswith('super::tuple_stream_wire_tests::'))
    tests = directory/'tuple_accelerated_resident_tests.rs'
    tests.write_text(tests.read_text()+'\n'+generated)
    dependencies = [part for name in ('tuple_accelerated', 'brynja_crypto_cpu')
                    for part in ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    compile_base = common+['--crate-name', 'tuple_accelerated_resident', str(directory/FILES[0])]+dependencies
    library = compile_base+['--crate-type', 'rlib', '-o', str(directory/'libtuple_accelerated_resident.rlib')]
    command = compile_base+['--test', '-o', str(directory/'tuple-resident-test')]
    invoke(library)
    invoke(command)

    def execute(success):
        result = subprocess.run([str(directory/'tuple-resident-test')], capture_output=True, text=True, timeout=180)
        if ((result.returncode == 0) != success or
                ('5 passed; 0 failed' if success else 'FAILED') not in result.stdout):
            raise AssertionError(result.stdout+result.stderr)
        return dict(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    initial = execute(True)
    print(initial['stdout'], flush=True)
    mutations = []
    for kind, before, after in MUTANTS:
        print('Mutation: '+kind+' '+before, flush=True)
        path = directory/('tuple_accelerated_'+kind+'.rs')
        original = path.read_bytes()
        text = original.decode()
        if text.count(before) != 1:
            raise AssertionError('Stale mutation: '+before)
        try:
            path.write_text(text.replace(before, after))
            if kind == 'wire':
                invoke(owner_compile+['-A', 'unused_variables'])
            invoke(command)
            mutations.append(dict(source=path.name, before=before, after=after, result=execute(False)))
        finally:
            path.write_bytes(original)
            if kind == 'wire':
                invoke(owner_compile)
    invoke(command)
    final = execute(True)
    invoke(library)
    probes = [f'fn bound<T:{trait}>(){{}} fn main(){{bound::<tuple_accelerated_resident::Resident<\'static>>();}}'
              for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    probes += [
        'fn main(){let r={let mut p=tuple_accelerated_resident::Page::empty();'
        'tuple_accelerated_resident::Resident::new(&mut p).unwrap()};drop(r);}',
        'fn main(){let mut p=tuple_accelerated_resident::Page::empty();'
        'let r=tuple_accelerated_resident::Resident::new(&mut p).unwrap();drop(p);drop(r);}',
    ]
    negative_command = common+['--crate-name', 'ownership_probe', '--extern',
                              'tuple_accelerated_resident='+str(directory/'libtuple_accelerated_resident.rlib'),
                              '--emit=metadata', '-o', str(directory/'probe.rmeta')]
    path = directory/'probe.rs'
    path.write_text('fn main(){let mut p=tuple_accelerated_resident::Page::empty();'
                    'let r=tuple_accelerated_resident::Resident::new(&mut p).unwrap();drop(r);drop(p);}')
    invoke(negative_command+[str(path)])
    negatives = []
    for index, text in enumerate(probes):
        path.write_text(text)
        result = subprocess.run(negative_command+[str(path)], capture_output=True, text=True, timeout=120)
        code = 'E0597' if index == 5 else 'E0505' if index == 6 else 'E0277'
        if result.returncode == 0 or code not in result.stderr:
            raise AssertionError(result.stderr)
        negatives.append(dict(source=text, error_code=code, diagnostics=result.stderr))
    for name, expected in record['generated_sha256'].items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != expected:
            raise AssertionError('Mutation restoration mismatch: '+name)
    paths = [base.SOURCE/name for name in FILES]+[Path(__file__).resolve()]
    record['source_sha256'].update({p.relative_to(base.ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in paths})
    record.update(schema=1, status='RESIDENT_COMPONENT_PASS', enclave_execution=False,
                  production_qualified=False, target=target, component_output=component_output,
                  initial=initial, final=final, mutations=mutations, negatives=negatives,
                  resident_commands=[library, command], oracle_cases=count,
                  compiler=invoke(['rustc', '+1.98.1', '-vV']),
                  binary_sha256=hashlib.sha256((directory/'tuple-resident-test').read_bytes()).hexdigest())
    (directory/'tuple-resident-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(f'Five resident/wire tests; {len(mutations)} compiled mutants and seven ownership negatives rejected', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--attest-native-bundle', action='store_true', required=True)
    args = parser.parse_args()
    target = invoke(['rustc', '+1.98.1', '-vV']).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'):
        parser.error('Native AVX/AVX2 required')
    run(args.directory.resolve(), target)
