"""Bounded independent SHA-512-family batch corpus and packaged regression checks."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'assurance/sha512-batch'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, cwd=ROOT, env=None, data=None, success=True):
    result = subprocess.run(command, cwd=cwd, env=env, input=data, text=True,
                            capture_output=True, timeout=600)
    if (result.returncode == 0) != success:
        raise ValueError(f'{command}\n{result.stdout[-6000:]}\n{result.stderr[-6000:]}')
    return result


def corpus():
    import sha512_t_digest_oracle as general
    oracle = load('batch_bit_oracle', 'check-sha2-bit-differential.py')
    requests, expected = [], []
    valid = [t for t in range(1, 512) if t != 384]
    for case in range(4846):
        slots, answers = [], []
        for lane in range(4):
            if case < 256 and not (case % 16) & (1 << lane):
                slots.append('-'); answers.append('-'); continue
            named = ('sha384', 'sha512', 'sha512_224', 'sha512_256')
            identity = named[(case + lane) % 4]
            if case >= 256 and lane == (case % 4):
                identity = 't' + str(valid[(case - 256) // 9])
            boundaries = (0, 1, 7, 8, 887, 888, 895, 896, 1023, 1024, 1025, 1919, 1920, 2047, 2048)
            bits = boundaries[(case + lane) % len(boundaries)] if case < 256 else 1024 + boundaries[(case + lane) % len(boundaries)]
            data = bytearray((index * 31 + lane * 17 + case) % 256 for index in range((bits + 7) // 8))
            if bits % 8: data[-1] &= 255 << (8 - bits % 8)
            slots.append(f'{identity}:{bits}:{data.hex()}')
            answer = general.digest(int(identity[1:]), bytes(data), bits).hex() if identity.startswith('t') else oracle.oracle(identity, bytes(data), bits)
            answers.append(answer)
        requests.append(';'.join(slots)); expected.append(';'.join(answers))
    return '\n'.join(requests) + '\n', expected


def check(consumer=FIXTURE, env=None, mode='portable', data=None, expected=None):
    if data is None: data, expected = corpus()
    run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release'], consumer, env)
    result = run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', mode], consumer, env, data)
    if result.stdout.splitlines() != expected: raise ValueError('independent batch oracle mismatch')
    match = re.search(r'SHA512_BATCH_ACCEPTANCE: batches=4846; vector_calls=(\d+)', result.stderr)
    if not match or (mode == 'portable' and int(match[1]) != 0): raise ValueError('missing/incorrect work marker')
    if mode == 'required' and int(match[1]) == 0: raise ValueError('required route did not execute SIMD')
    print(f'SHA-512-family batch independent oracle: 4846 batches; mode={mode}; vector_calls={match[1]}')


def malformed(consumer, env):
    binary = ['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', 'portable']
    for data in ('x\n', ';'.join(['sha512:1:01'] * 4) + '\n',
                 ';'.join(['sha384:32769:00'] * 4) + '\n',
                 ';'.join(['sha512:18446744073709551616:00'] * 4) + '\n',
                 ';'.join(['sha512:8:éé'] * 4) + '\n', 'a' * 66001 + '\n'):
        result = run(binary, consumer, env, data, success=False)
        if 'panicked at' in result.stderr or result.stdout:
            raise ValueError('malformed adapter request panicked or produced a digest')
    print('Six malformed batch adapter requests rejected without output/panic')


def packaged(env, mutations=True, native=False):
    import tempfile
    helper = load('batch_package', 'check-sha2-execution.py')
    with tempfile.TemporaryDirectory(prefix='brynja-sha512-batch-package-') as temporary:
        root = Path(temporary)
        env = dict(os.environ if env is None else env, CARGO_TARGET_DIR=str(root / 'target'))
        consumer, roots = helper.package(root, env, fixture_name='sha512-batch')
        run(['cargo', '+1.98.1', 'generate-lockfile', '--offline'], consumer, env)
        data, expected = corpus()
        check(consumer, env, data=data, expected=expected)
        malformed(consumer, env)
        negative(consumer, env)
        if mutations: mutants(consumer, roots, env, data, expected)
        if native: native_mutants(consumer, roots, env, data, expected)


def negative(consumer, env):
    path = consumer / 'src/main.rs'
    original = path.read_text()
    cases = []
    for owner in ('Authority', "Session<'static>", "Executor<'static>"):
        for trait in ('Send', 'Sync', 'Copy', 'Clone', 'std::fmt::Debug'):
            cases.append((f'fn need<T: {trait}>() {{}} need::<brynja_hash_sha2::batch512::{owner}>();', 'E0277'))
    for trait in ('Send', 'Sync', 'Copy', 'Clone', 'std::fmt::Debug'):
        cases.append((f'fn need<T: {trait}>() {{}} need::<brynja_crypto_cpu_std::sha512_batch::Authority>();', 'E0277'))
    cases.extend((
        ('fn bad(e: &Executor, i: &[Option<Input>; 4], o: &mut [Option<Digest>; 4], c: &mut Control) { let _ = e.digest(i, o, c); }', 'E0308'),
        ("fn bad(a: Authority) -> Session<'static> { a.session().unwrap() }", 'E0515'),
        ('let _ = brynja_hash_sha2::HardenedSha512::new(Executor::portable());', 'E0061'),
        ('let _ = Authority::from_platform(Kernel::Avx2, |_| true);', 'E0133'),
    ))
    try:
        # Public inherent visibility is deliberate even from a private module.
        # Name its unsafe function type without executing an attestation or KAT.
        path.write_text(original + '''
fn intentional_platform_import() {
    let _: unsafe fn(Kernel, fn(Kernel) -> bool) -> Result<Authority, BackendError>
        = Authority::from_platform;
}
''')
        run(['cargo', '+1.98.1', 'check', '--locked', '--offline'], consumer, env)
        for source, diagnostic in cases:
            path.write_text(original + '\nfn forbidden() { ' + source + ' }\n')
            result = run(['cargo', '+1.98.1', 'check', '--locked', '--offline'], consumer, env, success=False)
            if f'error[{diagnostic}]' not in result.stderr: raise ValueError('wrong negative diagnostic: ' + result.stderr)
    finally: path.write_text(original)
    print('Packaged public unsafe platform-import signature: PASS (not executed)')
    print(f'{len(cases)} packaged batch ownership/classification/authority negatives rejected')


def mutants(consumer, roots, env, data, expected):
    leaf = roots['brynja-hash-sha2'] / 'src/batch512'
    cases = (
        ('engine.rs', 'parameter.initial_words()', 'crate::sha512::INITIAL_STATE'),
        ('engine.rs', 'crate::Sha512TDigest::computed(parameter, &bytes)', 'crate::Sha512TDigest::computed(crate::Sha512TBits::new(1).map_err(|_| Error::Invariant)?, &bytes)'),
        ('engine.rs', 'Algorithm::Sha384 => crate::sha384::INITIAL_STATE', 'Algorithm::Sha384 => crate::sha512::INITIAL_STATE'),
        ('engine.rs', '0x80_u8 >> valid', '0x80_u8 >> 0'),
        ('engine.rs', 'remainder.len() >= 112', 'remainder.len() > 112'),
        ('engine.rs', '&length.to_be_bytes()', '&length.to_le_bytes()'),
        ('engine.rs', 'crate::compress64::compress(state, block);', 'let _ = (state, block);'),
        ('mod.rs', '*output = staged;', 'let _ = staged;'),
    )
    for name, before, after in cases:
        path = leaf / name; original = path.read_text()
        if original.count(before) != 1: raise ValueError('missing unique mutant: ' + before)
        try:
            path.write_text(original.replace(before, after))
            result = run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', 'portable'], consumer, env, data)
            if result.stdout.splitlines() == expected: raise ValueError('surviving batch mutant: ' + before)
        finally: path.write_text(original)
    print(f'{len(cases)} compiled batch algorithm/output mutants rejected')


def native_mutants(consumer, roots, env, data, expected):
    data = '\n'.join(data.splitlines()[256:]) + '\n'
    expected = expected[256:]
    engine = roots['brynja-hash-sha2'] / 'src/batch512/engine.rs'
    original = engine.read_text()
    before = '''session
                    .compress(PublicData::new(&mut packed), PublicData::new(&blocks))
                    .map_err(Error::Backend)?;'''
    cases = (
        (before, 'for (state, block) in packed.iter_mut().zip(&blocks).take(width) { crate::compress64::compress(state, block); }'),
        (before, 'let _ = (&mut packed, &blocks);'),
        ('*states.get_mut(*index).ok_or(Error::Invariant)? = *state;', 'let _ = (state, index);'),
    )
    try:
        for before, after in cases:
            if original.count(before) != 1: raise ValueError('missing native mutation site')
            engine.write_text(original.replace(before, after))
            # Require a successfully built mutant, not rejection by compilation.
            run(['cargo', '+1.98.1', 'build', '--locked', '--offline', '--release'], consumer, env)
            result = subprocess.run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', 'required'],
                cwd=consumer, env=env, input=data, text=True, capture_output=True, timeout=600)
            if result.returncode == 0 and result.stdout.splitlines() == expected:
                raise ValueError('native no-op/scalar-only/uncommitted mutant survived')
    finally: engine.write_text(original)
    print('Three compiled actual-vector/scalar-substitution/commit mutants rejected')
    main = consumer / 'src/main.rs'
    original = main.read_text()
    before = 'let mut total_vector = 0_u64;'
    if original.count(before) != 1: raise ValueError('missing fixture counter injection site')
    try:
        main.write_text(original.replace(before, 'let mut total_vector = u64::MAX;'))
        result = run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--', 'required'],
                     consumer, env, data, success=False)
        if result.stdout or 'Error: "vector call counter overflow"' not in result.stderr:
            raise ValueError('fixture overflow did not reject cleanly before output')
    finally: main.write_text(original)
    print('Native fixture counter overflow injection: clean rejection before output')
