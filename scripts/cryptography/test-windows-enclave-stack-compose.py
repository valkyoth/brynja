"""Cumulative depth, unresolved-boundary and complete saved-image regressions."""
import copy
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_enclave_stack_review as r

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'release-reports/windows-local-20261004'
DISASSEMBLY=ROOT/'release-reports/windows-worker-review-20261006/stack-disassembly-20261012'


def node(low,calls=(),incoming=32):
    return dict(incoming_bytes=incoming,scans=[dict(entry_residue=v,local_low=low,calls=list(calls))
        for v in (8,24)])


def call(target,offset=-48,kind='call',capacity=32):
    return dict(site=5,kind=kind,targets=[target],entry_offset=offset,allocated_outgoing_bytes=capacity)


class CompositionTests(unittest.TestCase):
    def test_nested_return_addresses_not_sum_of_metadata(self):
        nodes={'a':node(-40,[call('b')]),'b':node(-24)}
        report=r.composition.compose(nodes)['a']['8']
        self.assertEqual(report['complete_stack_bytes'],72)
        self.assertTrue(report['finite_transitive_bound_proven'])
        self.assertEqual(report['deepest_known_path'][0]['entry_offset'],-48)

    def test_tail_has_no_second_return_slot(self):
        nodes={'a':node(-40,[call('b',0,'tail',None)]),'b':node(-64)}
        self.assertEqual(r.composition.compose(nodes)['a']['8']['complete_stack_bytes'],64)

    def test_unknown_boundary_remains_symbolic_through_descendants(self):
        nodes={'a':node(-40,[call('b')]),'b':node(-40,[call('boundary:SDK')])}
        report=r.composition.compose(nodes)['a']['8']
        self.assertIsNone(report['complete_stack_bytes'])
        self.assertFalse(report['finite_transitive_bound_proven'])
        self.assertEqual(report['unresolved_boundaries']['boundary:SDK']['prefix_low'],-96)
        self.assertTrue(report['unresolved_boundaries']['boundary:SDK']['unknown_suffix_depth'])

    def test_unknown_callee_is_not_an_empty_node(self):
        with self.assertRaises(ValueError):r.composition.compose({'a':node(0,[call('missing')])})

    def test_recursion_and_recursive_tail_reject(self):
        for edge in (call('a'),call('a',0,'tail',None)):
            with self.assertRaises(ValueError):r.composition.compose({'a':node(-40,[edge])})

    def test_incoming_fifth_argument_propagates_through_tail(self):
        nodes={'a':node(-40,[call('b')]),'b':node(0,[call('leaf',0,'tail',None)]),
            'leaf':node(0,incoming=36)}
        with self.assertRaises(ValueError):r.composition.compose(nodes)
        for scan in nodes['a']['scans']:scan['calls']=[call('b',capacity=48)]
        self.assertEqual(r.composition.compose(nodes)['b']['8']['incoming_argument_bytes'],36)

    def test_entry_residue_changes_child_alignment(self):
        nodes={'a':node(-40,[call('b')]),'b':node(-32)}
        nodes['b']['scans'][1]['local_low']=-48
        result=r.composition.compose(nodes)['a']
        self.assertEqual([result[v]['complete_stack_bytes'] for v in ('8','24')],[96,80])

    def test_empty_ambiguous_or_unassigned_target_population_reject(self):
        for targets in ([],['b','b']):
            edge=call('b');edge['targets']=targets
            with self.assertRaises(ValueError):r.composition.compose({'a':node(-40,[edge]),'b':node(0)})
        bad=node(0);bad['scans'].append(copy.deepcopy(bad['scans'][0]))
        with self.assertRaises(ValueError):r.composition.compose({'a':bad})

    def test_worst_path_not_sum_of_sequential_calls(self):
        nodes={'a':node(-40,[call('b'),call('c')]),'b':node(-80),'c':node(-160)}
        self.assertEqual(r.composition.compose(nodes)['a']['8']['complete_stack_bytes'],208)

    def test_tail_cannot_hide_unrestored_frame(self):
        with self.assertRaises(ValueError):
            r.composition.compose({'a':node(-40,[call('b',-8,'tail')]),'b':node(0)})


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report=r.collect(SAVED,ROOT,DISASSEMBLY)

    def test_complete_original_population(self):
        rows=self.report['records']
        self.assertEqual(len(rows),19)
        self.assertEqual(sum(v['normal_functions'] for v in rows),925)
        self.assertEqual(sum(len(v['excluded_cleanup_funclets']) for v in rows),98)
        self.assertEqual(sum(len(v['leaf_accesses']) for v in rows),132)
        self.assertEqual(sum(v['indirect_sites'] for v in rows),44)
        self.assertFalse(self.report['whole_image_qualified'])
        self.assertFalse(self.report['completion_package_closed'])

    def test_whole_window_not_inferred_from_known_prefix(self):
        largest=0
        for row in self.report['records']:
            self.assertFalse(row['complete_protected_window_bound_proven'])
            for name,variants in row['roots'].items():
                for result in variants.values():
                    largest=max(largest,-result['known_prefix_low'])
                    if name not in ('RetainedTokenWord','PrivateWaveLeaf'):
                        self.assertIsNone(result['complete_stack_bytes'])
                        self.assertTrue(result['unresolved_boundaries'])
        self.assertEqual(largest,25048)

    def test_all_leaf_reads_and_runtime_tail_saves_retained(self):
        reads=0
        for row in self.report['records']:
            self.assertEqual(row['runtime_summaries']['memcpy']['bytes'],16)
            self.assertEqual(row['runtime_summaries']['memset']['bytes'],8)
            for leaf in row['leaf_accesses'].values():
                reads+=len(leaf['explicit_stack_accesses'])
                if leaf['explicit_stack_accesses']:self.assertEqual(leaf['incoming_bytes'],36)
        self.assertGreater(reads,0)

    def test_each_live_transfer_has_explicit_targets(self):
        for row in self.report['records']:
            for node in row['function_geometry'].values():
                for scan in node['scans']:
                    for edge in scan['calls']:
                        self.assertTrue(edge['targets'])
                        for target in edge['targets']:
                            self.assertTrue(target in row['function_geometry'] or target.startswith('boundary:'))

    def test_family_review_replayed_and_indirect_target_bytes_required(self):
        rows=[v for v in self.report['records'] if v['callback_review']]
        self.assertEqual(len(rows),3)
        for row in rows:
            self.assertTrue(row['callback_review']['family_provenance_replayed'])
            self.assertEqual(len(row['callback_review']['targets']),2)
        unknown={'function':node(0,[dict(target=None,operand='*%rax')])}
        with self.assertRaises(ValueError):r.callbacks.inspect(SAVED,ROOT,'unexpected','',{},unknown)

    def test_frozen_image_cannot_be_relabelled(self):
        row=r.workers.catalog.catalog()[0]
        text=(DISASSEMBLY/(row['sha256']+'.txt')).read_text()
        with self.assertRaises(ValueError):r.inspect(SAVED,ROOT,row|{'sha256':'0'*64},text)
        changed=re.sub(r'\bc3[ \t]+retq','cc\tint3',text)
        self.assertTrue(changed!=text)
        with self.assertRaises(ValueError):r.inspect(SAVED,ROOT,row,changed)


if __name__=='__main__':unittest.main()
