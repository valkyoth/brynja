"""Fail-closed population and behavioral-mutation harness regressions."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import facade_keccak_cases as keccak


def rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('accepted facade Keccak harness regression')


def check():
    # Synthetic shape fixtures only: production acceptance uses the real oracle.
    rows = [';'.join(f'{keccak.ALGORITHMS[(case + lane) % 8]} 0 0 0 8 - - -'
                     for lane in range(4)) for case in range(256)]
    requests = '\n'.join(rows) + '\n'
    answers = ['00;00;00;00'] * 256
    keccak.validate_corpus(requests, answers)
    invalid = (
        ('\n'.join(rows[:-1]), answers), (requests, answers[:-1]),
        (requests.replace(';', ' ', 1), answers),
        (requests, ['00;00;00'] + answers[1:]),
        (requests.replace('sha3-224', 'unknown', 1), answers),
        (requests.replace('sha3-224', 'sha3-256', 1), answers),
        (requests, ['0000;00;00;00'] + answers[1:]),
        (requests, ['zz;00;00;00'] + answers[1:]),
        (requests.replace('0 0 0 8', '0 0 0 1', 1), ['80;00;00;00'] + answers[1:]),
    )
    for data, expected in invalid:
        rejected(lambda: keccak.validate_corpus(data, expected))
    name = 'keccak_facade::ordinary_oracle'
    output = f'test {name} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;'
    good = SimpleNamespace(returncode=101, stdout=output, stderr='')
    keccak.require_runtime_rejection(good, name)
    for result in (
        SimpleNamespace(returncode=0, stdout=output, stderr=''),
        SimpleNamespace(returncode=101, stdout='', stderr='error[E0308]'),
        SimpleNamespace(returncode=101, stdout=output.replace(name, 'wrong_test'), stderr=''),
        SimpleNamespace(returncode=101, stdout=output.replace('1 failed', '0 failed'), stderr=''),
        SimpleNamespace(returncode=101, stdout=output.replace('0 ignored', '1 ignored'), stderr=''),
        SimpleNamespace(returncode=-9, stdout=output, stderr=''),
    ):
        rejected(lambda: keccak.require_runtime_rejection(result, name))
    # Verify finally restoration for build errors, incorrect runtime failures,
    # and surviving mutants. No compiler or real repository file is touched.
    with TemporaryDirectory(prefix='facade-keccak-harness-') as directory:
        root = Path(directory)
        path = root / 'src/batch/engine.rs'
        path.parent.mkdir(parents=True)
        original = 'output.copy_from_slice(source);'
        for failure in ('build', 'runtime', 'survived'):
            path.write_text(original)

            def run(command, *args, **kwargs):
                assert path.read_text() == 'let _ = source;'
                if failure == 'build':
                    raise ValueError('synthetic compilation failure')
                if '--no-run' in command:
                    return None
                return SimpleNamespace(returncode=0 if failure == 'survived' else 101,
                                       stdout='', stderr='synthetic failure')

            def require(value, message):
                if not value:
                    raise ValueError(message)

            api = SimpleNamespace(require=require, run=run)
            rejected(lambda: keccak.mutants(api, root, {'brynja-hash-sha3': root}, [], {}))
            assert path.read_text() == original
    print('Facade Keccak harness rejects nine corpus and six runtime regressions; '
          'restores extracted sources on three failure paths')
