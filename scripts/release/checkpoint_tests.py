"""Public closing-patch cadence and fail-closed publication regressions."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

import checkpoint_policy as checkpoints
import release_policy as policy
import release_crates as publisher


class Checkpoints(unittest.TestCase):
    def setUp(self):
        self.versions = ['0.20.0', '0.25.0', '0.25.1', '0.25.2', '0.30.0', '0.30.2']
        self.document = {'schema': 1, 'checkpoints': {'25': '0.25.2', '30': '0.30.2'}}

    def test_explicit_closure_and_historical_boundaries(self):
        for version in ('0.10.0', '0.15.0', '0.20.0', '0.25.2', '0.30.2', '1.0.0-rc.1', '1.0.0'):
            self.assertEqual(policy.milestone_class(version), 'public')
        for version in ('0.24.23', '0.25.0', '0.25.1', '0.25.3', '0.30.0', '0.30.1', '0.30.3'):
            self.assertEqual(policy.milestone_class(version), 'internal')

    def test_later_patch_does_not_implicitly_move_checkpoint(self):
        before = checkpoints.validate_catalog(self.document, self.versions)
        after = checkpoints.validate_catalog(self.document, self.versions + ['0.25.3'])
        self.assertEqual(before, after)
        self.assertNotIn('0.25.3', after)

    def test_invalid_catalogs_fail_closed(self):
        for edit in (
            lambda d: d.update(schema=True),
            lambda d: d.update(schema=2),
            lambda d: d.update(extra=[]),
            lambda d: d.pop('schema'),
            lambda d: d['checkpoints'].pop('25'),
            lambda d: d['checkpoints'].update({'26': '0.26.0'}),
            lambda d: d['checkpoints'].update({'25': '0.30.2'}),
            lambda d: d['checkpoints'].update({'25': '0.25.99'}),
            lambda d: d['checkpoints'].update({'25': '0.25.2-rc.1'}),
            lambda d: d['checkpoints'].update({'25': True}),
            lambda d: d['checkpoints'].update({'025': '0.25.2'}),
        ):
            document = copy.deepcopy(self.document)
            edit(document)
            with self.assertRaises(ValueError):
                checkpoints.validate_catalog(document, self.versions)
        with self.assertRaises(ValueError):
            checkpoints.validate_catalog(self.document, self.versions * 2)
        with self.assertRaises(ValueError):
            checkpoints.validate_catalog(self.document, self.versions + ['0.35.0'])

    def test_plan_validator_and_publisher_share_all_classifications(self):
        spec = importlib.util.spec_from_file_location('plan', Path(__file__).with_name('check-release-plan.py'))
        plan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plan)
        versions = checkpoints.ROW.findall((checkpoints.ROOT / 'docs/VERSION_PLAN.md').read_text())
        for version in versions:
            self.assertEqual(plan.is_scheduled_checkpoint('v' + version), policy.milestone_class(version) == 'public')

    def context(self, version, stage):
        return dict(version=version, milestone=version, baseline='0.20.0',
                    cumulative_milestones=policy.roadmap_range('0.20.0', version),
                    stage=stage, exceptional=False, exception_reason='')

    def test_early_dot_zero_cannot_publish_without_exception(self):
        with self.assertRaisesRegex(RuntimeError, 'exceptional=true'):
            policy.validate_release_context(self.context('0.25.0', 'public'), {'brynja': {'publish': True}})
        with self.assertRaisesRegex(RuntimeError, 'empty publication selection'):
            policy.validate_release_context(self.context('0.25.0', 'internal'), {'brynja': {'publish': True}})
        policy.validate_release_context(self.context('0.25.2', 'public'), {'brynja': {'publish': True}})
        with self.assertRaisesRegex(RuntimeError, 'non-checkpoint'):
            policy.validate_release_context(self.context('0.25.2', 'internal'), {})
        early = self.context('0.25.0', 'public')
        early.update(exceptional=True, exception_reason='Reviewed security correction')
        policy.validate_release_context(early, {'brynja': {'publish': True}})

    def test_cumulative_range_includes_the_closing_patches(self):
        first = policy.roadmap_range('0.20.0', '0.25.2')
        self.assertEqual(first[-3:], ['0.25.0', '0.25.1', '0.25.2'])
        second = policy.roadmap_range('0.25.2', '0.30.2')
        self.assertNotIn('0.25.2', second)
        self.assertEqual(second[-3:], ['0.30.0', '0.30.1', '0.30.2'])
        incomplete = self.context('0.25.2', 'public')
        incomplete['cumulative_milestones'].pop()
        with self.assertRaisesRegex(RuntimeError, 'exact roadmap delta'):
            policy.validate_release_context(incomplete, {})

    def test_patch_checkpoint_uses_full_tag_gate(self):
        with patch.object(publisher, 'run') as run:
            publisher.run_preflight('0.25.2', dry_run=False, release_tag_at_head=True)
        self.assertEqual(run.call_args_list[0].args[0], ['scripts/tag_gate.sh', 'v0.25.2'])
        self.assertEqual(run.call_args_list[0].kwargs['extra_env'], {'BRYNJA_RELEASE_PUBLISH_TAG': 'v0.25.2'})


def run_tests():
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Checkpoints))
    if not result.wasSuccessful():
        raise RuntimeError('closing-patch checkpoint regression')


if __name__ == '__main__':
    run_tests()
