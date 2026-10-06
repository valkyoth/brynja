"""Positive clear-length call-site regressions, independent of body hash pins."""
from unittest.mock import patch
import windows_enclave_sha2_zero_calls as z


class ZeroCallTests:
    def test_clear_length_literals_are_representable_and_not_clobbered(self):
        for length in (1,8,128,640,8192,(1<<32)-1):
            lines=[f'movl ${length}, %edx','movq %rsi, %rcx','callq '+z.s.ZERO]
            self.assertEqual(z.site(lines,2)['length'],length)
            for inserted in ('xorl %edx, %edx','movb $0, %dl','movq $0, %rdx',
                             'popq %rdx','callq opaque','entry:', 'jmp entry'):
                with self.assertRaises(ValueError): z.site(lines[:2]+[inserted]+lines[2:],3)
        for length in (0,-1,1<<32,1<<63):
            with self.assertRaises(ValueError):z.site([f'movl ${length}, %edx','callq '+z.s.ZERO],1)

    def test_clear_length_dynamic_guard_requires_full_width_and_no_entry_or_clobber(self):
        lines=['movq 8(%rsi,%rdi), %rdx','testq %rdx, %rdx','je .B3',
               'vzeroupper','callq '+z.s.ZERO,'.B3:','retq']
        self.assertEqual(z.site(lines,4)['kind'],'guarded_descriptor')
        for at,new in ((0,'movq 7(%rsi,%rdi), %rdx'),(1,'testl %edx, %edx'),
                       (1,'testq %rcx, %rcx'),(2,'jne .B3'),(2,'je .B4'),
                       (3,'xorl %edx, %edx'),(3,'.B4:')):
            bad=list(lines);bad[at]=new
            with self.assertRaises(ValueError):z.site(bad,4)
        with self.assertRaises(ValueError):z.site(lines+['.B3:'],4)


class ZeroCallSavedTests:
    def test_all_zeroizer_callers_reject_invalid_lengths_bypasses_and_population_drift(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            report=z.inspect(bodies,lane)
            self.assertEqual(report['total'],53 if lane=='simd256' else 51)
            for record in report['calls']:
                name=record['function'];lines=z.s.lines(bodies[name]);start=record['start'];at=record['transfer']
                replacements=((start,'movl $0, %edx'),(start,'movl $4294967296, %edx'),
                              (start,'movq $-1, %rdx')) if record['kind']=='constant' else (
                              (start+1,'testl %edx, %edx'),(start+1,'testq %rcx, %rcx'),
                              (start+2,'jne '+record['zero_target']))
                for offset,line in replacements:
                    bad=list(lines);bad[offset]=line
                    with self.assertRaises(ValueError):z.inspect(bodies|{name:'\n'.join(bad)},lane)
                    count+=1
                for line in ('xorl %edx, %edx','.injected_entry:','callq opaque'):
                    bad=lines[:at]+[line]+lines[at:]
                    with self.assertRaises(ValueError):z.inspect(bodies|{name:'\n'.join(bad)},lane)
                    count+=1
                bad=lines[:at]+lines[at+1:]
                with self.assertRaises(ValueError):z.inspect(bodies|{name:'\n'.join(bad)},lane)
                count+=1
            with self.assertRaises(ValueError):z.inspect(bodies|{'extra':'movl $1, %edx\ncallq '+z.s.ZERO},lane)
            count+=1
        self.assertEqual(count,730)
        print('SIMD clearing length/guard/population mutations rejected: '+str(count))

    def test_zeroizer_call_review_is_required_by_primitive_composition(self):
        import windows_enclave_sha2_simd_reuse as r
        for lane,_,_,_,ir,functions,bodies in self.routes:
            if not lane.startswith('simd'):continue
            with patch.object(r,'helpers',return_value={}), patch.object(z,'inspect',side_effect=ValueError('call review failed')) as check:
                with self.assertRaisesRegex(ValueError,'call review failed'):
                    r.inspect(self.saved,lane,functions,ir,bodies,{})
                check.assert_called_once()
