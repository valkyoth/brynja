"""Narrow authority/admission callsite and full helper-body regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_narrow_admission as a


class NarrowAdmissionSavedTests:
    def narrow_admission_fixture(self):return self.normal_effect_fixture('simd256')

    def test_actual_narrow_admission_interfaces_keep_shared_limits(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.narrow_admission_fixture();proof=a.inspect(row[-1],asm,prior)
        self.assertEqual(sorted(v['line'] for v in proof['assigned']),[21,35,135,161,171,342,374,1542,1622])
        self.assertEqual(len(proof['remaining_narrow_calls']),30)
        self.assertEqual(proof['normal_callee_count'],5);self.assertEqual(proof['normal_stack_span'],[-104,0])
        self.assertEqual(proof['helpers']['cleared_owner_output'],[16,272])
        self.assertEqual(proof['assigned_narrow_returning_interfaces'],32)
        self.assertFalse(proof['whole_frame_qualified'])
        probe=next(v for v in proof['assigned'] if v['target']=='__chkstk')
        self.assertNotIn('footprints',probe);self.assertFalse(probe['stack_effects_qualified'])
        with patch.object(a,'inspect',side_effect=ValueError('narrow admission failed')) as check:
            with self.assertRaisesRegex(ValueError,'narrow admission failed'):
                main.inspect_route(self.saved,self.root,'simd256',row[1],False)
            check.assert_called_once()

    def test_actual_narrow_admission_complete_helper_bodies_and_wrong_layout(self):
        row,asm,prior=self.narrow_admission_fixture();bodies=row[-1]
        compiled=prior['simd_control_call_effects']['leaf_targets']['compiled']
        helpers=a.shared.contracts(bodies,compiled,'simd256');count=0
        for role in ('operation','check','compiled'):
            name=helpers[role];lines=a.p.storage.instructions(bodies[name])
            for i in range(len(lines)):
                with self.assertRaises(ValueError):
                    a.shared.contracts(bodies|{name:'\n'.join(lines[:i]+lines[i+1:])},compiled,'simd256')
                count+=1
        self.assertEqual(count,125)
        for lane in ('simd512','simd128',None):
            with self.assertRaises(ValueError):a.shared.contracts(bodies,compiled,lane)
        name=a.s.one(bodies,r'mask_is_zero$');lines=a.p.storage.instructions(bodies[name])
        for i in range(len(lines)):
            with self.assertRaises(ValueError):a.predicate(bodies|{name:'\n'.join(lines[:i]+lines[i+1:])},asm)
            count+=1
        self.assertEqual(count,132)
        print('Narrow admission complete helper/predicate deletions rejected:',count)

    def test_actual_narrow_admission_original_arguments_and_bypasses(self):
        row,asm,prior=self.narrow_admission_fixture();bodies=row[-1]
        proof=a.inspect(bodies,asm,prior);name=proof['function'];lines=a.s.lines(bodies[name]);count=0
        helpers=proof['helpers']
        changes={33:'leaq 6689(%rbx), %rcx',34:'movl $1, %r9d',
            154:'movq 16(%rax), %r15',158:'movzbl 16(%r15), %ecx',
            169:'movzbl 16(%r15), %ecx',339:'movzbl 16(%r15), %ecx',
            1538:'movq 16(%rax), %rcx',1619:'movq 16(%rax), %rcx',
            372:'leaq 17(%rsi), %rcx',373:'movl $255, %edx'}
        for site,text in changes.items():
            bad=lines[:];bad[site]=text
            with self.assertRaises(ValueError):a.callsites(bodies|{name:'\n'.join(bad)},asm,helpers)
            count+=1
        for at,text in [(33,'xorl %r8d, %r8d'),(33,'xorl %edx, %edx'),
                        (153,'movb $0, 159(%rbx)'),(165,'movb $0, 95(%rbx)')]:
            bad=lines[:at]+[text]+lines[at:]
            with self.assertRaises(ValueError):a.callsites(bodies|{name:'\n'.join(bad)},asm,helpers)
            count+=1
        for call in (v for v in proof['assigned'] if v['role'] not in ('shared_stack_probe','bounded_tail_predicate')):
            at=call['line'];bad=lines[:1]+['jne admission_bypass']+lines[1:at]+['admission_bypass:']+lines[at:]
            with self.assertRaises(ValueError):a.callsites(bodies|{name:'\n'.join(bad)},asm,helpers)
            count+=1
        self.assertEqual(count,21)

    def test_actual_narrow_admission_predicate_cursor_and_bounds(self):
        row,asm,_=self.narrow_admission_fixture();bodies=row[-1]
        name=a.s.one(bodies,r'Resident6digest$');lines=a.s.lines(bodies[name]);count=0
        replacements={112:'addq $25, %r15',113:'addq $41, %r12',115:'cmpq $210, %r15',
            117:'movq -8(%rdi,%r15), %rsi',118:'cmpq $1025, %rsi',119:'jb .B27',
            120:'movq -16(%rdi,%r15), %r13',121:'movzbl (%rdi,%r15), %r14d',
            122:'testq %r13, %r13',123:'jne .B11',125:'cmpb $8, %al',126:'jb .B13',
            127:'cmpb $8, %r14b',128:'jb .B3',129:'leaq (%rsi), %rax',130:'movb $0, %dl',
            131:'movl %esi, %ecx',132:'shlb %cl, %dl',133:'addq %rsi, %rax',134:'movq %r13, %rcx'}
        for site,text in replacements.items():
            bad=lines[:];bad[site]=text
            with self.assertRaises(ValueError):a.predicate(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        for at in (117,124,129,135):
            bad=lines[:1]+['jne mask_bypass']+lines[1:at]+['mask_bypass:']+lines[at:]
            with self.assertRaises(ValueError):a.predicate(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        self.assertEqual(count,24)

    def test_actual_narrow_admission_prerequisites_inventory_and_probe(self):
        row,asm,prior=self.narrow_admission_fixture();count=0
        for key,field in a.PREREQUISITES:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):a.inspect(row[-1],asm,bad)
            count+=1
        for role in ('unassigned_calls','assigned'):
            bad=copy.deepcopy(prior)
            if role=='unassigned_calls':bad['simd_descriptor_normal_effects'][role]=[]
            else:bad['simd_descriptor_normal_effects'][role].append(dict(line=35,target=a.s.one(row[-1],r'Owner9operation$')))
            with self.assertRaises(ValueError):a.inspect(row[-1],asm,bad)
            count+=1
        name=a.s.one(row[-1],r'Resident6digest$');lines=a.s.lines(row[-1][name])
        for at,text in [(20,'movl $11993, %eax'),(21,'callq wrong'),(22,'subq $4096, %rsp')]:
            bad=lines[:];bad[at]=text
            with self.assertRaises(ValueError):a.inspect(row[-1]|{name:'\n'.join(bad)},asm,prior)
            count+=1
        self.assertEqual(count,11)
