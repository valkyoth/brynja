"""No-compiler regressions for single-state SHA-2 facade acceptance."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import facade_sha2_execution as acceptance
from test_facade_keccak import rejected


def probe(arch='x86_64', wide=False, native=False, hosted=False):
    return (f'ARCH:{arch}\nCPU:narrow:true\nCPU:wide:{str(wide).lower()}\n'
            f'STATIC:narrow:{"ready" if native else "MissingTargetFeatures"}\n'
            f'HOST:narrow:{"ready" if hosted else "MissingMigrationGuarantee"}\n'
            f'STATIC:wide:{"ready" if native and wide else "MissingTargetFeatures"}\n'
            f'HOST:wide:{"ready" if hosted and wide else "MissingFeaturesOrOsState"}\n')


def check():
    for package, namespace in (('brynja', 'facade::crypto'), ('brynja-crypto', 'facade')):
        text = acceptance.rewrite('use brynja_hash_sha2::*; use brynja_crypto_cpu::static_execution; use brynja_crypto_cpu_std::execution;', package)
        assert namespace + '::sha2::*' in text and namespace + '::cpu::static_execution' in text and 'host::execution' in text
    rejected(lambda: acceptance.rewrite('use brynja_core::*;', 'brynja'))
    rejected(lambda: acceptance.rewrite('', 'unknown'))
    original = (acceptance.ROOT / 'assurance/general-sha512-t/src/corpus.rs').read_text()
    adapted = acceptance.sources.corpus(original)
    assert adapted.count('#[test]') == original.count('#[test]') == 2
    assert adapted.split('pub(crate) fn visit', 1)[1].split('#[cfg(test)]')[0] == original.split('pub(crate) fn visit', 1)[1].split('#[cfg(test)]')[0]
    for bad in ('', original + original, original.replace('check_case', 'other')):
        rejected(lambda: acceptance.sources.corpus(bad))
    generic = acceptance.probe_result(probe())
    narrow = acceptance.probe_result(probe(native=True))
    full = acceptance.probe_result(probe('aarch64', True, True, True))
    assert acceptance.native_flags(generic) == '+sha,+sse2'
    assert acceptance.native_flags(full) == '+neon,+sha2,+sha3'
    assert acceptance.native_flags(acceptance.probe_result(probe(wide=True))) == '+sha,+sse2,+sha512,+avx2,+avx'
    assert acceptance.expected(generic, 'static', False) == (None, 'Backend(MissingTargetFeatures)')
    assert acceptance.expected(narrow, 'static', True) == (('Static(X86Sha256)', 'Portable'), None)
    assert acceptance.expected(narrow, 'static', False) == (None, 'Backend(MissingTargetFeatures)')
    assert acceptance.expected(full, 'hosted', False) == (('Runtime(ArmSha256)', 'Runtime(ArmSha512)'), None)
    assert acceptance.expected(full, 'prefer', False)[0] == ('Runtime(ArmSha256)', 'Runtime(ArmSha512)')
    assert acceptance.expected(generic, 'prefer', False) == (('Portable', 'Portable'), None)
    for bad in ('', probe() + probe(), probe().replace('CPU:wide', 'CPU:narrow'),
                probe().replace('HOST:wide', 'OTHER:wide'), probe().replace('ARCH:x86_64', 'ARCH:unknown'),
                probe().replace('CPU:narrow:true', 'CPU:narrow:yes'),
                probe(native=True).replace('CPU:narrow:true', 'CPU:narrow:false'),
                probe().replace('HOST:wide:MissingFeaturesOrOsState', 'HOST:wide:ready')):
        rejected(lambda: acceptance.probe_result(bad))
    rejected(lambda: acceptance.native_flags(generic | {('CPU', 'narrow'): 'false'}))
    rejected(lambda: acceptance.expected(generic, 'unknown', False))
    for hardened in (False, True):
        output = (f'SHA-2 {"hardened" if hardened else "ordinary"} execution acceptance: PASS; named=240; general=4590\n'
                  'narrow=Portable; wide=Portable\n' +
                  ('owned-memory cleanup; no register/spill guarantee' if hardened else 'public-only') +
                  '; independently verified: NO; FIPS validated: NO\n')
        good = SimpleNamespace(returncode=0, stdout=output, stderr='')
        acceptance.check_result(good, hardened, ('Portable', 'Portable'))
        for changes in ({'returncode': 1}, {'stderr': 'unexpected'}, {'stdout': ''},
                        {'stdout': output + output}, {'stdout': output.replace('240', '0')},
                        {'stdout': output.replace('4590', '4589')}, {'stdout': output.replace('Portable', 'Static(X86Sha256)')},
                        {'stdout': output.replace('NO', 'YES')}):
            rejected(lambda: acceptance.check_result(SimpleNamespace(**(vars(good) | changes)), hardened, ('Portable', 'Portable')))
    good = SimpleNamespace(returncode=1, stdout='', stderr='Error: Custom { kind: Other, error: ' + json.dumps('acceptance failed: mismatch') + ' }\n')
    acceptance.check_error(good, 'mismatch')
    for changes in ({'returncode': 0}, {'returncode': 101}, {'returncode': -9}, {'stdout': 'partial'}, {'stderr': 'error[E0308]'}):
        rejected(lambda: acceptance.check_error(SimpleNamespace(**(vars(good) | changes)), 'mismatch'))
    restoration()
    print('SHA-2 execution rejects corpus/import/probe/route/population/error drift and restores algorithm/native/ownership probes')


def restoration():
    regression = acceptance.regressions
    with TemporaryDirectory(prefix='facade-sha2-execution-harness-') as directory:
        root = Path(directory)
        for hardened, attr in ((False, 'ORDINARY'), (True, 'HARDENED')):
            base = root / 'src' / ('hardened_execution' if hardened else 'execution')
            base.mkdir(parents=True)
            for mutant in getattr(regression, attr):
                filename, before, _, count, _ = mutant
                path = base / filename
                original = (before + '\n') * count
                for failure in ('build', 'runtime', 'survived'):
                    path.write_text(original)

                    def run(command, *args, **kwargs):
                        assert path.read_text() != original
                        if failure == 'build':
                            raise ValueError('synthetic compile error')
                        if 'build' in command:
                            return None
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='', stderr='unrelated error')

                    with patch.object(regression, attr, (mutant,)):
                        rejected(lambda: regression.mutants(SimpleNamespace(run=run, require=acceptance.require), root,
                            {'brynja-hash-sha2': root}, [], {'CARGO_TARGET_DIR': str(root)}, hardened,
                            acceptance.check_error, acceptance.check_result))
                    assert path.read_text() == original
            for case in regression.native_cases(hardened, True):
                filename, replacements = case
                path = root / 'src' / filename
                original = '\n'.join((before + '\n') * count for before, _, count in replacements)
                for failure in ('build', 'runtime', 'survived'):
                    path.write_text(original)
                    with patch.object(regression, 'native_cases', return_value=(case,)):
                        rejected(lambda: regression.native_mutants(SimpleNamespace(run=run, require=acceptance.require), root,
                            {'brynja-hash-sha2': root}, [], {'CARGO_TARGET_DIR': str(root)}, hardened, True,
                            ('Static(X86Sha256)', 'Static(X86Sha512)'), acceptance.check_error, acceptance.check_result))
                    assert path.read_text() == original
        lib = root / 'src/lib.rs'
        lib.write_text('original')

        def source(*args):
            lib.write_text('temporary probe')

        def fail(*args, **kwargs):
            raise ValueError('synthetic failed check')

        for hardened in (False, True):
            rejected(lambda: regression.negatives(SimpleNamespace(source=source, run=fail), root, 'brynja', [], {}, hardened))
            assert lib.read_text() == 'original'
