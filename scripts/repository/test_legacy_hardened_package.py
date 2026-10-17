"""Hardened legacy orchestration regressions without compiler subprocesses."""
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import legacy_execution_package as shared
import legacy_hardened_package as hardened
import legacy_hardened_cases as cases
from test_legacy_execution_package import document
from test_facade_keccak import rejected


def check(api):
    corpus = 'let cases: &[(&[u8],u8,[u8;20])] = &[\n' + ',\n'.join(['(&[], 0, [0, 1])'] * 1135) + '];'
    hardened.validate_oracle(corpus)
    for bad in ('', corpus.replace('(&[], 0, [0, 1])', '', 1), corpus + '(&[], 0, [0, 1])'):
        rejected(lambda: hardened.validate_oracle(bad))
    for family in ('sha1', 'md5'):
        good, roots, consumer = document(family, Path('/hardened-legacy-graph'))
        nodes = good['resolve']['nodes']
        nodes[0]['features'] = ['hardened-execution', 'runtime-hardened-execution']
        nodes[3]['features'].append('hardened-execution')
        nodes[4]['features'] = ['runtime-hardened-execution', *(['runtime-execution'] if family == 'sha1' else [])]
        shared.graph(api, good, roots, consumer, family, hardened=True)
        rejected(lambda: shared.graph(api, good, roots, consumer, family))
        for index in range(len(nodes)):
            for values in ([], nodes[index]['features'] + ['cpu-evidence'], nodes[index]['features'] + ['strict-execution']):
                bad = copy.deepcopy(good)
                bad['resolve']['nodes'][index]['features'] = values
                rejected(lambda: shared.graph(api, bad, roots, consumer, family, hardened=True))
        tests = shared.test_counts(family, True)
        assert tests == [('execution', 4 if family == 'sha1' else 5), ('hosted', 1), ('selection', 1),
                         *([('oracle', 1)] if family == 'sha1' else []), ('scope', 1)]
        assert len(cases.owners(family)) == 5
        assert len(cases.negatives(family)) == (9 if family == 'sha1' else 6)
        assert len(cases.mutations(family, False)) == (7 if family == 'sha1' else 8)
        assert len(cases.mutations(family, True)) == (8 if family == 'sha1' else 10)
        for filename, before, _ in cases.mutations(family, True):
            assert (shared.ROOT / f'crates/brynja-legacy-{family}/src' / filename).read_text().count(before) == 1
    restoration()
    print('Hardened legacy rejects ordinary/protected/evidence feature drift; pins lifecycle/negative/mutation populations and restores every mutation/probe after failures')


def restoration():
    with TemporaryDirectory(prefix='legacy-hardened-mutations-') as directory:
        root = Path(directory)
        for family in ('sha1', 'md5'):
            for filename, before, after in cases.mutations(family, True):
                path = root / 'src' / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                for failure in ('compile', 'runtime', 'survived'):
                    path.write_text(before)

                    def run(command, *args, **kwargs):
                        assert path.read_text() == after and 'scope' in command
                        if before in ('scope.completed = true;', 'scope.complete = true;'):
                            assert 'execution' not in command
                        if failure == 'compile':
                            raise ValueError('synthetic build failure')
                        if '--no-run' in command:
                            return None
                        return SimpleNamespace(returncode=0 if failure == 'survived' else 101, stdout='unrelated failure', stderr='')

                    with patch.object(cases, 'mutations', return_value=[(filename, before, after)]):
                        rejected(lambda: shared.mutants(SimpleNamespace(run=run), root,
                                 {'brynja-legacy-' + family: root}, [], {}, family, True, hardened=True))
                    assert path.read_text() == before
        path = root / 'src/lib.rs'
        path.write_text('original')

        def fail(*args, **kwargs):
            assert path.read_text() != 'original'
            raise ValueError('synthetic negative build failure')

        rejected(lambda: hardened.negatives(SimpleNamespace(run=fail), root, [], {}, 'sha1'))
        assert path.read_text() == 'original'
