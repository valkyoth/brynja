"""Combined archive graph mutations; no crypto subprocesses needed here."""
import copy
from pathlib import Path
import re
import unittest

import hmac_combined_acceptance as combined


def fixture():
    modern = {'brynja-crypto': ['brynja-mac-hmac'], 'brynja-mac-hmac': ['brynja-core', 'brynja-hash-core'],
              'brynja-core': [], 'brynja-hash-core': []}
    legacy = {'brynja-legacy-hmac': ['brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-core'],
              'brynja-legacy-sha1': ['brynja-hash-core'], 'brynja-legacy-md5': ['brynja-hash-core']}
    roots = {name: Path('/private/extracted') / name for name in (*modern, *legacy)}
    consumer = Path('/private/consumer')
    versions = dict.fromkeys(roots, '0.1.0')

    def document(edges, paired):
        edges = {**edges, 'facade-consumer': ['brynja-crypto'] + (['brynja-legacy-hmac'] if paired else [])}
        packages, nodes = [], []
        for name, dependencies in edges.items():
            path = consumer if name == 'facade-consumer' else roots[name]
            packages.append({'id': name, 'name': name, 'source': None,
                'version': '0.0.0' if name == 'facade-consumer' else versions[name],
                'manifest_path': str(path / 'Cargo.toml'),
                'targets': [{'kind': ['lib'], 'src_path': str(path / 'src/lib.rs')}]})
            deps = [{'name': ('facade' if d == 'brynja-crypto' else 'legacy')
                     if name == 'facade-consumer' else d.replace('-', '_'),
                     'pkg': d, 'dep_kinds': [{'kind': None, 'target': None}]} for d in dependencies]
            nodes.append({'id': name, 'features': [], 'deps': deps, 'dependencies': dependencies.copy()})
        return {'packages': packages, 'resolve': {'root': 'facade-consumer', 'nodes': nodes}}
    return document({**modern, **legacy}, True), document(modern, False), roots, consumer, versions


class CombinedTests(unittest.TestCase):
    def test_baseline_and_complete_general_parameter_population(self):
        combined.graph(*fixture(), 'brynja-crypto')
        parameters = [int(t) for t in re.findall(r'identity::<Sha512T<(\d+)>>', combined.general_parameters())]
        self.assertEqual(parameters, [t for t in range(128, 512) if t != 384])
        self.assertEqual(len(parameters), 383)
        self.assertEqual(len(list(combined.negatives())), 12)

    def test_archive_binding_regressions(self):
        original, baseline, roots, consumer, versions = fixture()
        count = 0
        for field, value in (
            ('version', '9.9.9'), ('source', 'registry+untrusted'),
            ('manifest_path', '/checkout/Cargo.toml'), ('links', 'foreign'),
            ('targets', []), ('targets', [{'kind': ['custom-build'], 'src_path': '/private/build.rs'}]),
            ('targets', [{'kind': ['proc-macro'], 'src_path': '/private/lib.rs'}]),
            ('targets', [{'kind': ['lib'], 'src_path': '/checkout/src/lib.rs'}]),
        ):
            for index in range(len(original['packages'])):
                doc = copy.deepcopy(original)
                doc['packages'][index][field] = value
                with self.subTest(field=field, index=index), self.assertRaises(ValueError):
                    combined.graph(doc, baseline, roots, consumer, versions, 'brynja-crypto')
                count += 1
        self.assertEqual(count, 64)

    def test_identity_edge_feature_and_kind_regressions(self):
        original, baseline, roots, consumer, versions = fixture()
        mutants = []
        for key in ('packages', 'nodes'):
            for mode in ('missing', 'duplicate'):
                doc = copy.deepcopy(original)
                rows = doc['packages'] if key == 'packages' else doc['resolve']['nodes']
                rows.pop() if mode == 'missing' else rows.append(copy.deepcopy(rows[0]))
                mutants.append(doc)
        for kind in ([], [{'kind': 'invented', 'target': None}], [{'kind': 'dev', 'target': None}]):
            doc = copy.deepcopy(original)
            doc['resolve']['nodes'][-1]['deps'][-1]['dep_kinds'] = kind
            mutants.append(doc)
        for mutation in ('feature', 'legacy-edge', 'hidden-build-edge', 'dependencies', 'alias', 'root', 'legacy-cycle'):
            doc = copy.deepcopy(original)
            nodes = {n['id']: n for n in doc['resolve']['nodes']}
            if mutation == 'feature':
                nodes['brynja-core']['features'].append('secret-new-feature')
            elif mutation in ('legacy-edge', 'hidden-build-edge'):
                n = nodes['brynja-crypto']
                n['dependencies'].append('brynja-legacy-hmac')
                n['deps'].append({'name': 'hidden', 'pkg': 'brynja-legacy-hmac',
                                 'dep_kinds': [{'kind': 'build' if mutation == 'hidden-build-edge' else None,
                                               'target': 'cfg(windows)'}]})
            elif mutation == 'dependencies':
                nodes['brynja-crypto']['dependencies'] = []
            elif mutation == 'alias':
                nodes['facade-consumer']['deps'][-1]['name'] = 'implicit'
            elif mutation == 'root':
                doc['resolve']['root'] = 'brynja-crypto'
            else:
                n = nodes['brynja-legacy-sha1']
                n['dependencies'].append('brynja-crypto')
                n['deps'].append({'name': 'wrong', 'pkg': 'brynja-crypto',
                                 'dep_kinds': [{'kind': None, 'target': None}]})
            mutants.append(doc)
        for index, doc in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                combined.graph(doc, baseline, roots, consumer, versions, 'brynja-crypto')
        with self.assertRaises(ValueError):
            combined.graph(original, original, roots, consumer, versions, 'brynja-crypto')
        self.assertEqual(len(mutants), 14)


if __name__ == '__main__':
    unittest.main()
