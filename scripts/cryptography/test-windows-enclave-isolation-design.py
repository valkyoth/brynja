"""Admission criterion for a future SDK-free secret phase; not current closure."""
import copy
import unittest

import windows_enclave_isolation_design as r


def node(*targets):
    return dict(scans=[dict(entry_residue=residue,calls=[dict(targets=list(targets))]
        if targets else []) for residue in (8,24)])


class Tests(unittest.TestCase):
    def test_known_pure_closure_does_not_claim_stack_or_implementation_proof(self):
        result=r.compute_closure({'root':node('leaf'),'leaf':node()},['root'])
        self.assertEqual(result['functions'],['leaf','root'])
        self.assertTrue(result['sdk_free_call_graph'])
        self.assertFalse(result['stack_bound_proven'])
        self.assertFalse(result['implementation_qualified'])

    def test_every_sdk_import_and_unknown_edge_rejects_transitively(self):
        for target in ('sdk:EnclaveCopyIntoEnclave','import:EnclaveCopyOutOfEnclave',
                       'sdk:CallEnclave','boundary:os:copy_syscall_stub'):
            with self.subTest(target=target),self.assertRaises(ValueError):
                r.compute_closure({'root':node('helper'),'helper':node(target),target:node()},['root'])

    def test_unassigned_target_cannot_be_hidden_by_removing_its_node(self):
        with self.assertRaises(ValueError):r.compute_closure({'root':node('helper')},['root'])

    def test_fatal_trap_not_general_exception_whitelist(self):
        result=r.compute_closure({'root':node('boundary:fatal:int29')},['root'])
        self.assertTrue(result['fatal_trap_possible'])
        for target in ('boundary:fatal:other','boundary:os:debug_trap','sdk:RaiseException'):
            with self.assertRaises(ValueError):r.compute_closure({'root':node(target)},['root'])

    def test_each_residue_and_indirect_alternative_required(self):
        nodes={'root':node('a','b'),'a':node(),'b':node()}
        self.assertEqual(r.compute_closure(nodes,['root'])['functions'],['a','b','root'])
        for index in (0,1):
            for targets in ([],['a','a'],['a',None],['a','sdk:VirtualAlloc']):
                bad=copy.deepcopy(nodes);bad['root']['scans'][index]['calls'][0]['targets']=targets
                with self.assertRaises(ValueError):r.compute_closure(bad,['root'])
        for scans in ([],[node()['scans'][0]],node()['scans']*2):
            with self.assertRaises(ValueError):r.compute_closure({'root':dict(scans=scans)},['root'])

    def test_empty_unknown_or_duplicate_roots_reject(self):
        for roots in ([],['missing'],['root','root']):
            with self.assertRaises(ValueError):r.compute_closure({'root':node()},roots)

    def test_cycle_is_not_misrepresented_as_stack_bound(self):
        result=r.compute_closure({'root':node('a'),'a':node('root')},['root'])
        self.assertTrue(result['sdk_free_call_graph'])
        self.assertFalse(result['stack_bound_proven'])

    def test_reviewed_runtime_summaries_have_four_distinct_residues(self):
        summary=dict(runtime_summary=True,scans=[dict(entry_residue=r,calls=[]) for r in (0,8,16,24)])
        self.assertTrue(r.compute_closure({'runtime':summary},['runtime'])['sdk_free_call_graph'])
        for bad in (summary|{'runtime_summary':False},summary|{'scans':summary['scans']*2}):
            with self.assertRaises(ValueError):r.compute_closure({'runtime':bad},['runtime'])


if __name__=='__main__':unittest.main()
