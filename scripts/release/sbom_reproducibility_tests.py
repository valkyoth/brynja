"""Regression tests included in the scoped release suite."""
import json
import tempfile
import unittest
from pathlib import Path

from compare_sbom import normalized, stable_document


class ReproducibleSbom(unittest.TestCase):
    def test_reordered_documents_reproduce_but_content_changes_do_not(self):
        source = Path(__file__).resolve().parents[2] / 'sbom/brynja.spdx.json'
        doc = json.loads(source.read_text())
        with tempfile.TemporaryDirectory() as folder:
            generated = Path(folder) / 'generated.json'
            output = Path(folder) / 'stable.json'
            original = stable_document(source, '1700000000')
            for key in ('packages', 'relationships', 'files'):
                doc[key].reverse()
            doc['creationInfo']['created'] = 'ignored generator timestamp'
            doc['documentNamespace'] = 'ignored generator namespace'
            generated.write_text(json.dumps(doc))
            self.assertEqual(stable_document(generated, '1700000000'), original)
            output.write_text(original)
            self.assertEqual(normalized(generated), normalized(output))
            self.assertEqual(json.loads(original)['creationInfo']['created'], '2023-11-14T22:13:20Z')
            self.assertNotEqual(stable_document(generated, '1700000001'), original)
            with self.assertRaises(ValueError):
                stable_document(generated, '-1')
            doc['relationships'].pop()
            generated.write_text(json.dumps(doc))
            altered = json.loads(stable_document(generated, '1700000000'))
            self.assertNotEqual(altered['documentNamespace'], json.loads(original)['documentNamespace'])
            self.assertNotEqual(normalized(generated), normalized(output))


if __name__ == '__main__':
    unittest.main()
