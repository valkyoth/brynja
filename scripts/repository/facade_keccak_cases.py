"""Reuse the independent bit oracle through both extracted public facades.

Only public synthetic test data is embedded in the generated consumer. These
portable checks do not claim native acceleration or private-workspace inspection.
"""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
ALGORITHMS = ('sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
              'shake128', 'shake256', 'cshake128', 'cshake256')


def validate_corpus(requests, answers):
    rows = requests.splitlines()
    if len(rows) != 256 or len(answers) != 256:
        raise ValueError('facade Keccak oracle population changed')
    counts = dict.fromkeys(ALGORITHMS, 0)
    for row, answer in zip(rows, answers):
        lanes, outputs = row.split(';'), answer.split(';')
        if len(lanes) != 4 or len(outputs) != 4:
            raise ValueError('facade Keccak lane population changed')
        for lane, output in zip(lanes, outputs):
            fields = lane.split()
            if len(fields) != 8 or fields[0] not in counts:
                raise ValueError('facade Keccak request identity changed')
            counts[fields[0]] += 1
            bits = int(fields[4])
            decoded = bytes.fromhex(output)
            if len(decoded) != (bits + 7) // 8 or (bits % 8 and decoded[-1] >> (bits % 8)):
                raise ValueError('facade Keccak oracle output shape changed')
    if set(counts.values()) != {128}:
        raise ValueError('facade Keccak identity population changed')


def corpus():
    directory = ROOT / 'scripts/sha3'
    sys.path.insert(0, str(directory))
    try:
        spec = importlib.util.spec_from_file_location(
            'facade_keccak_oracle', directory / 'check-keccak-batch.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        requests, answers = module.corpus()
    finally:
        sys.path.pop(0)
    validate_corpus(requests, answers)
    return requests, '\n'.join(answers) + '\n'


def install(consumer, data):
    for name, content in zip(('requests', 'answers'), data):
        (consumer / 'src' / f'keccak-{name}.txt').write_text(content)


def require_runtime_rejection(result, name):
    if not (result.returncode == 101 and
            f'test {name} ... FAILED' in result.stdout and
            'test result: FAILED. 0 passed; 1 failed; 0 ignored;' in result.stdout):
        raise ValueError('facade Keccak mutant did not fail its runtime assertion: ' +
                         result.stdout[-2000:] + result.stderr[-2000:])


def mutants(api, consumer, roots, cargo, env):
    leaf = roots['brynja-hash-sha3'] / 'src'
    changes = (
        ('batch/engine.rs', 'output.copy_from_slice(source);', 'let _ = source;', 'ordinary'),
        ('batch/engine.rs', 'output.copy_from_slice(source);',
         'if let (Some(o), Some(s)) = (output.first_mut(), source.first()) { *o = *s; }', 'ordinary'),
        ('batch/engine.rs', '.scalar_permutations\n                    .checked_add(1)',
         '.scalar_permutations\n                    .checked_add(0)', 'ordinary'),
        ('hardened_batch/output.rs', 'let _ = clear_owned_region(destination);',
         'let _ = destination;', 'secret'),
        ('hardened_batch/engine.rs', 'mask(input.output_bits() % 8)', '255', 'secret'),
    )
    for relative, before, after, test in changes:
        path = leaf / relative
        original = path.read_text()
        api.require(original.count(before) == 1, 'Keccak mutant anchor drift: ' + relative)
        name = f'keccak_facade::{test}_oracle'
        command = cargo + ['test', '--offline', '--release', '--lib', name]
        try:
            path.write_text(original.replace(before, after))
            # Compilation failure is never evidence that a behavioral test works.
            api.run(command + ['--no-run'], consumer, env)
            result = api.run(command + ['--', '--exact', '--test-threads=1'],
                             consumer, env, success=False)
            require_runtime_rejection(result, name)
        finally:
            path.write_text(original)
    api.test_run(cargo, consumer, env, 3, ['--release'])
    print('PASS: facade Keccak: five compiled commit/report/cleanup/masking mutants rejected', flush=True)


RUST = r'''
#[cfg(test)]
mod keccak_facade {
    extern crate std;
    use super::api;
    use std::{vec, vec::Vec};
    use api::sha3::{batch, hardened_batch as secret, Fips202BitString};

    fn hex(value: &str) -> Vec<u8> {
        if value == "-" { return Vec::new(); }
        assert_eq!(value.len() % 2, 0);
        value.as_bytes().chunks_exact(2).map(|pair|
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
    }
    fn bits(bytes: &[u8], length: usize) -> Fips202BitString<'_> {
        assert_eq!(bytes.len(), length.div_ceil(8));
        Fips202BitString::new(bytes, if length == 0 { 0 } else {
            u8::try_from((length - 1) % 8 + 1).unwrap()
        }).unwrap()
    }
    struct Request<'a> { name: &'a str, lengths: [usize; 4], data: [Vec<u8>; 3] }
    fn parse(lane: &str) -> Request<'_> {
        let f: Vec<_> = lane.split_whitespace().collect();
        assert_eq!(f.len(), 8);
        Request { name: f[0], lengths: core::array::from_fn(|i| f[i + 1].parse().unwrap()),
                  data: core::array::from_fn(|i| hex(f[i + 5])) }
    }
    macro_rules! input {
        ($module:ident, $r:expr) => {{
            let r = $r;
            use $module::Algorithm as A;
            let algorithm = match r.name {
                "sha3-224" => A::Sha3_224, "sha3-256" => A::Sha3_256,
                "sha3-384" => A::Sha3_384, "sha3-512" => A::Sha3_512,
                "shake128" => A::Shake128, "shake256" => A::Shake256,
                "cshake128" => A::Cshake128, "cshake256" => A::Cshake256,
                _ => panic!("unexpected oracle identity"),
            };
            $module::Input::with_customization(algorithm, bits(&r.data[0], r.lengths[0]),
                bits(&r.data[1], r.lengths[1]), bits(&r.data[2], r.lengths[2]), r.lengths[3]).unwrap()
        }};
    }
    fn cases() -> impl Iterator<Item = (Vec<Request<'static>>, Vec<Vec<u8>>)> {
        let requests: Vec<_> = include_str!("keccak-requests.txt").lines().collect();
        let answers: Vec<_> = include_str!("keccak-answers.txt").lines().collect();
        assert_eq!(requests.len(), 256);
        assert_eq!(answers.len(), 256);
        requests.into_iter().zip(answers).map(|(requests, answers)| {
            let r: Vec<_> = requests.split(';').map(parse).collect();
            let a: Vec<_> = answers.split(';').map(hex).collect();
            assert_eq!(r.len(), 4); assert_eq!(a.len(), 4);
            (r, a)
        })
    }
    macro_rules! report {
        ($report:expr, $control:expr) => {{
            let report = $report;
            assert_eq!(report.kernel, None);
            assert_eq!(report.vector_calls, 0);
            assert_eq!(report.vector_permutations, 0);
            assert_eq!(report.scalar_permutations, $control.used());
            assert!(report.scalar_permutations > 0);
        }};
    }
    fn destinations(storage: &mut [Vec<u8>; 4]) -> [Option<&mut [u8]>; 4] {
        storage.each_mut().map(|v| { let n = v.len() - 1; Some(&mut v[..n]) })
    }

    #[test]
    fn ordinary_oracle() {
        for (requests, expected) in cases() {
            let inputs: Vec<_> = requests.iter().map(|r| input!(batch, r)).collect();
            let executor = batch::Executor::portable();
            let mut workspace = batch::Workspace::new();
            for (budget, cancel) in [(4096, false), (0, false), (4096, true), (4096, false)] {
                let mut buffers: [Vec<u8>; 4] = core::array::from_fn(|i| vec![0xa5; expected[i].len() + 1]);
                let mut out = destinations(&mut buffers).map(Option::unwrap);
                let mut staging = vec![0x5a; expected.iter().map(Vec::len).sum::<usize>() + 7];
                let mut cancelled = || cancel;
                let mut control = batch::Control::new(budget, &mut cancelled);
                let result = executor.digest(batch::PublicData::new(&inputs), &mut out,
                    &mut workspace, &mut staging, &mut control);
                if budget == 0 || cancel {
                    assert!(result.is_err());
                    assert!(buffers.iter().flatten().all(|&v| v == 0xa5));
                } else {
                    report!(result.unwrap(), control);
                    for (actual, expected) in buffers.iter().zip(&expected) {
                        assert_eq!(&actual[..expected.len()], expected);
                        assert_eq!(actual.last(), Some(&0xa5));
                    }
                }
            }
        }
    }

    #[test]
    fn secret_oracle() {
        for (requests, expected) in cases() {
            let inputs = core::array::from_fn(|i| Some(input!(secret, &requests[i])));
            let executor = secret::Executor::portable();
            let mut workspace = secret::Workspace::new();
            for (phase, (budget, cancel)) in [(4096, false), (0, false), (4096, true), (4096, false)].into_iter().enumerate() {
                let mut buffers: [Vec<u8>; 4] = core::array::from_fn(|i| vec![0xa5; expected[i].len() + 1]);
                let mut staging = vec![0x5a; expected.iter().map(Vec::len).sum::<usize>() + 7];
                let mut cancelled = || cancel;
                let mut control = secret::Control::new(budget, &mut cancelled);
                {
                    let result = executor.digest_secret(&inputs, destinations(&mut buffers),
                        &mut workspace, &mut staging, &mut control);
                    if budget == 0 || cancel { assert!(result.is_err()); }
                    else {
                        let (output, report) = result.unwrap();
                        report!(report, control);
                        for i in 0..4 {
                            assert_eq!(output.expose(i), Some(expected[i].as_slice()));
                            assert_eq!(output.algorithm(i), Some(inputs[i].as_ref().unwrap().algorithm()));
                            assert_eq!(output.output_bits(i), Some(requests[i].lengths[3]));
                        }
                        assert_eq!(output.expose(4), None);
                        if phase == 3 {
                            let mut public: [Vec<u8>; 4] = core::array::from_fn(|i|
                                vec![0xa5; expected[i].len() + 1]);
                            output.declassify(destinations(&mut public),
                                api::sha3::Sha3PublicDeclassification::acknowledge()).unwrap();
                            for (actual, expected) in public.iter().zip(&expected) {
                                assert_eq!(&actual[..expected.len()], expected);
                                assert_eq!(actual.last(), Some(&0xa5));
                            }
                        }
                    }
                }
                assert!(staging.iter().all(|&v| v == 0));
                for buffer in &buffers {
                    assert_eq!(buffer.last(), Some(&0xa5));
                    assert!(buffer[..buffer.len() - 1].iter().all(|&v| v == 0));
                }
            }
        }
    }

    #[test]
    fn hardened_public_oracle() {
        for (case, (requests, expected)) in cases().enumerate() {
            // Dense and sparse slot layouts use the same independent answers;
            // absent destinations must retain every byte, including canaries.
            for omitted in [None, Some(case % 4)] {
                let inputs = core::array::from_fn(|i| if omitted == Some(i) { None }
                    else { Some(input!(secret, &requests[i])) });
                let executor = secret::Executor::portable();
                let mut workspace = secret::Workspace::new();
                for phase in 0..5 {
                    let mut buffers: [Vec<u8>; 4] = core::array::from_fn(|i| vec![0xa5; expected[i].len() + 1]);
                    let mut staging = vec![0x5a; expected.iter().map(Vec::len).sum::<usize>() + 7];
                    let mut cancelled = || phase == 2;
                    let mut control = secret::Control::new(if phase == 1 { 0 } else { 4096 }, &mut cancelled);
                    if phase == 4 { executor.quarantine(); }
                    let out = destinations(&mut buffers).into_iter().enumerate()
                        .map(|(i, slot)| if omitted == Some(i) { None } else { slot })
                        .collect::<Vec<_>>().try_into().unwrap();
                    let result = executor.digest_public(&inputs, out, &mut workspace,
                        &mut staging, &mut control, api::sha3::Sha3PublicDeclassification::acknowledge());
                    if phase == 1 || phase == 2 || phase == 4 {
                        assert!(result.is_err());
                        assert!(buffers.iter().flatten().all(|&v| v == 0xa5));
                    } else {
                        report!(result.unwrap(), control);
                        for (i, actual) in buffers.iter().enumerate() {
                            if omitted == Some(i) { assert!(actual.iter().all(|&v| v == 0xa5)); }
                            else { assert_eq!(&actual[..expected[i].len()], &expected[i]); }
                            assert_eq!(actual.last(), Some(&0xa5));
                        }
                    }
                    assert!(staging.iter().all(|&v| v == 0));
                }
            }
        }
    }
}
'''
