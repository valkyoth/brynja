"""No-compiler tests for scoped SHA-2 corpus, route and mutation orchestration."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_scoped_sha2 as acceptance
import facade_scoped_sha2_regressions as probes
from test_facade_keccak import rejected
from test_facade_sha2_execution import probe


def good_result(routes):
    revoked = (2 if routes[0] != 'Portable' else 0) + (9 if routes[1] != 'Portable' else 0)
    return SimpleNamespace(returncode=0, stderr='', stdout=
        f'SHA-2 scoped execution acceptance: PASS; named=240; general=4590; lifecycle=11; revocations={revoked}\n'
        f'narrow={routes[0]}; wide={routes[1]}\n'
        'consumer-observable output/reuse checks; no private-storage qualification; independently verified: NO; FIPS validated: NO\n')


def check():
    sources = acceptance.sources
    base = acceptance.ROOT / 'assurance/sha2-hardened-execution/src'
    original = (base / 'main.rs').read_text()
    adapted = sources.main(original)
    assert adapted.split('enum Owner')[1].split('fn main')[0] == original.split('enum Owner')[1].split('fn main')[0]
    assert 'lifecycle::run(mode, narrow_only)?' in adapted
    for bad in ('', original + original, original.replace('mod general;', ''),
                original.replace('    let count = named::run(&narrow, &wide)?;', '')):
        rejected(lambda: sources.main(bad))
    original = (base / 'named.rs').read_text()
    adapted = sources.named(original)
    assert adapted.split('fn hex(')[1].split('pub(super) fn run(')[0] == original.split('fn hex(')[1].split('macro_rules! check_named')[0]
    assert adapted.count('check_named!(') == 6 and '../../../crates/' not in adapted
    for bad in ('', original + original, original.replace('check_named!(Sha224,', 'check_named!(Other,'),
                original.replace('nist-bit-selected.txt', 'wrong.txt')):
        rejected(lambda: sources.named(bad))
    for routes in (('Portable', 'Portable'), ('Static(X86Sha256)', 'Portable'),
                   ('Runtime(ArmSha256)', 'Runtime(ArmSha512)')):
        good = good_result(routes)
        acceptance.check_result(good, routes)
        for changed in ({'returncode': 1}, {'returncode': 101}, {'stderr': 'unexpected'},
                        {'stdout': ''}, {'stdout': good.stdout + good.stdout},
                        *({'stdout': good.stdout.replace(before, after)} for before, after in (
                            ('named=240', 'named=0'), ('general=4590', 'general=4589'), ('lifecycle=11', 'lifecycle=10'),
                            ('revocations=', 'revocations=99'), ('narrow=', 'wrong='), ('NO', 'YES')))):
            rejected(lambda: acceptance.check_result(SimpleNamespace(**(vars(good) | changed)), routes))
    orchestration()
    restoration()
    print('Scoped SHA-2 facade rejects corpus/source/route/population drift and surviving mutants; restores probes/mutations across failures')


def orchestration():
    shared = acceptance.shared
    for selected in (shared.probe_result(probe()), shared.probe_result(probe(native=True)),
                     shared.probe_result(probe('aarch64',True,True,True))):
        seen = []

        def run(command, consumer, env, **kwargs):
            if 'test' in command:
                return SimpleNamespace(stdout='test result: ok. 2 passed; 0 failed; 0 ignored;')
            if 'build' in command:
                return None
            mode, narrow = command[1], len(command) == 3
            routes, error = shared.expected(selected, mode, narrow)
            seen.append((mode,narrow))
            assert kwargs['success'] == (error is None)
            if not error:
                return good_result(routes)
            return SimpleNamespace(returncode=1, stdout='', stderr=
                'Error: Custom { kind: Other, error: "acceptance failed: ' + error + '" }\n')

        acceptance.campaign(SimpleNamespace(run=run), Path('/consumer'), ['cargo'], {'CARGO_TARGET_DIR':'/target'}, selected)
        assert seen == list(shared.MODES) * 2


def restoration():
    with TemporaryDirectory(prefix='facade-scoped-sha2-') as directory:
        root = Path(directory)
        for mutant in probes.MUTANTS:
            filename, before, _, count, _ = mutant
            path = root / 'src/hardened_execution' / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            original = ('\n' + before) * count
            for failure in ('compile', 'runtime', 'survived'):
                path.write_text(original)

                def run(command, *args, **kwargs):
                    assert path.read_text() != original
                    if failure == 'compile':
                        raise ValueError('synthetic compiler failure')
                    if 'build' in command:
                        return None
                    return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='', stderr='unrelated failure')

                with patch.object(probes, 'MUTANTS', (mutant,)):
                    rejected(lambda: probes.mutants(SimpleNamespace(run=run), root, {'brynja-hash-sha2': root}, [], {'CARGO_TARGET_DIR':str(root)}))
                assert path.read_text() == original
        path = root / 'src/lib.rs'
        path.write_text('original')

        def source(*args):
            path.write_text('probe')

        def fail(*args):
            raise ValueError('synthetic compiler failure')

        rejected(lambda: probes.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}))
        assert path.read_text() == 'original'
