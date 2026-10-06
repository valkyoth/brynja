"""Caller/callee argument-region composition regressions, not whole-frame proof."""
import re
from unittest.mock import patch
import windows_enclave_sha2_call_effects as c
from windows_enclave_sha2_transfer_effects_tests import TransferEffectTests, TransferEffectSavedTests


class CallEffectTests(TransferEffectTests):
    def test_primitive_regions_reject_unknown_wrapping_and_aliased_pointers(self):
        value=c.e.Value
        for pointer,length in ((None,8),(value(None,0,0),8),(value('w',0,1),8),
                (value('w',(1<<64)-4,(1<<64)-4),8),(value('w',0,0),0)):
            with self.assertRaises(ValueError):c.region(pointer,0,length)
        for lane in ('simd256','simd512'):
            regs={'rcx':value('w',1024,1024),'rdx':value('w',768,768),'r8':value('w',0,0)}
            self.assertEqual(c.footprint('compress',regs,lane)['writes'][1]['span'],[0,640])
            for reg in ('rcx','rdx'):
                with self.assertRaises(ValueError):c.footprint('compress',regs|{reg:value('w',0,0)},lane)
            with self.assertRaises(ValueError):c.footprint('compress',regs|{'rdx':value('unplaced',768,768)},lane)
        for length in (value('pointer',8,8),value(None,1,8),value(None,0,0)):
            with self.assertRaises(ValueError):c.footprint('zero',{'rcx':value('w',0,0),'rdx':length},'simd256')

    def test_multiple_call_snapshots_forget_clobbers_but_keep_nonvolatile_arguments(self):
        value=c.e.Value;seen=[]
        c.e.evaluate(['movq %rbx, %rcx','callq compress','movq %rbx, %rcx',
                      'movl $640, %edx','callq zero'],{'rbx':value('w',0,0)},
                     {},{'compress','zero'},seen)
        self.assertEqual([name for name,_ in seen],['compress','zero'])
        self.assertEqual(seen[1][1]['rcx'],value('w',0,0))
        self.assertEqual(seen[1][1]['rdx'],value(None,640,640))
        lost=[]
        c.e.evaluate(['callq compress','callq zero'],{'rcx':value('w',0,0)},
                     {},{'compress','zero'},lost)
        with self.assertRaises(ValueError):c.footprint('zero',lost[1][1],'simd256')


class CallEffectSavedTests(TransferEffectSavedTests):
    def test_twelve_scalar_helper_calls_reject_argument_and_population_mutations(self):
        import windows_enclave_sha2_frame_cell as f
        total=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            frame=f.inspect(bodies,lane);result=c.inspect(bodies,lane,frame)
            self.assertEqual(result['conditional_argument_call_count'],6)
            self.assertEqual(len(result['other_call_effects_pending']),12)
            self.assertFalse(result['complete_saved_pointer_lifetime_qualified'])
            name=frame['function'];full=c.s.lines(bodies[name]);start=full.index(frame['begin']+':')
            changes=set()
            for effect in result['calls']:
                at=start+effect['line']
                prefix=5 if effect['role']=='compress' else (1 if effect['role']=='wipe' and lane=='simd256' else 2)
                for i in range(at-prefix,at):
                    line=full[i]
                    m=re.match(r'(?:leaq|movq) (\d+)\(%\w+\)',line)
                    if m:
                        changes.add((i,line[:m.start(1)]+str(int(m[1])+1)+line[m.end(1):]))
                    m=re.fullmatch(r'movl \$(\d+), %edx',line)
                    if m:
                        for size in (0,int(m[1])-1,int(m[1])+1):changes.add((i,f'movl ${size}, %edx'))
                    if line=='movq %rbx, %rcx':changes.add((i,'movq %rax, %rcx'))
                changes.add((at,'callq unreviewed_helper'))
            for at,line in sorted(changes):
                changed=full[:];changed[at]=line
                # Deliberately call the effect check directly: earlier literal
                # finish contracts cannot mask address-composition failures.
                with self.assertRaises(ValueError):c.inspect(bodies|{name:'\n'.join(changed)},lane,frame)
                total+=1
            at=start+result['calls'][0]['line']
            for line in ('callq unreviewed_helper','movq %rax, 184(%rbx)'):
                with self.assertRaises(ValueError):
                    c.inspect(bodies|{name:'\n'.join(full[:at]+[line]+full[at:])},lane,frame)
                total+=1
        self.assertEqual(total,47)
        print('SIMD scalar-helper pointer/extent/call mutations rejected: '+str(total))

    def test_scalar_call_composition_is_required_in_parent(self):
        import windows_enclave_sha2_batch_chains as parent
        for lane,pin,_,_,_,_,_ in self.routes:
            if not lane.startswith('simd'):continue
            with patch.object(c,'inspect',side_effect=ValueError('call composition failed')) as check:
                with self.assertRaisesRegex(ValueError,'call composition failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
