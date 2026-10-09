"""Receiver source/ABI binding and independent wire-policy boundary tests."""
import copy
from hashlib import sha256
from unittest.mock import patch
import windows_enclave_sha3_simd_receive as t


def oracle(operation,words):
    if operation not in (100,101,102) or words[0]!=22 or not words[1] or words[3]!=2:return False
    if operation!=100 and words[2]:return False
    for lane in range(4):
        identity,output,*parts=words[4+lane*11:15+lane*11]
        if operation==102:
            if any((identity,output,*parts)):return False
            continue
        if identity not in range(1,9) or output>2048:return False
        fixed={1:224,2:256,3:384,4:512}
        if identity in fixed and output!=fixed[identity]:return False
        for part in range(3):
            length,last,address=parts[3*part:3*part+3]
            if operation==101 or length==0:
                if (length,last,address)!=(0,0,0):return False
            elif not (length<=1024 and 1<=last<=8 and address>0 and
                address+length<1<<64 and (part==0 or identity in (7,8))):return False
    return True


def header(operation,identity=7):
    if operation==102:return [22,1,0,2]+[0]*44
    width={1:224,2:256,3:384,4:512}.get(identity,2048)
    part=[1024,8,0x100000] if operation==100 else [0,0,0]
    return [22,1,77 if operation==100 else 0,2]+(
        [identity,width]+part+(part*2 if identity>=7 else [0]*6))*4


class SimdReceiveModelTests:
    def test_simd_receive_wire_boundaries_against_independent_policy(self):
        count=0
        values=(0,1,2,3,4,5,6,7,8,9,22,100,101,102,224,256,384,512,1024,1025,2048,2049,t.MASK-1024,t.MASK)
        for operation in (100,101,102):
            for identity in range(1,9):
                base=header(operation,identity);self.assertTrue(t.metadata(operation,base))
                for index in range(48):
                    for value in values:
                        bad=base.copy();bad[index]=value
                        self.assertEqual(t.metadata(operation,bad),oracle(operation,bad),(operation,index,value))
                        count+=1
        for operation in (0,1,3,99,100,101,102,103,t.MASK):
            base=header(100)
            self.assertEqual(t.metadata(operation,base),oracle(operation,base))
        self.assertEqual(count,27648)
        print('Keccak wire predicate differential comparisons:',count)

    def test_simd_receive_transfer_and_twelve_slot_geometry(self):
        moved=t.decoded_transfer();self.assertEqual(moved['bytes'],288)
        self.assertFalse(moved['padding_initialization_or_erasure_claimed'])
        geometry=t.geometry();slots=geometry['slots']
        self.assertEqual([x['copy_kind'] for x in slots],list(range(1,13)))
        for index,slot in enumerate(slots):
            lane,part=divmod(index,3)
            self.assertEqual(slot['payload'],[index*1024,(index+1)*1024])
            self.assertEqual(slot['descriptor'],[1064+112*lane+32*part,1096+112*lane+32*part])
        self.assertEqual(geometry['lane_array'],[1064,1512])


class SimdReceiveSavedTests:
    def simd_receive_fixture(self):
        bodies,ir,construction,checked=self.simd_worker_fixture()
        retained=t.worker.inspect(bodies,ir,construction,checked)
        import windows_enclave_sha3_batch_chains as c
        data,image,_,_,functions,_=self.routes['simd']
        records=c.binding.bind_all(data,image,functions)
        runtime={'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort'}|{
            'PublicKeccakSimd'+part for part in ('Input','Output','Source','Observe')}
        constants=c.binding.data_bindings(data,image,records,functions,runtime,'simd')[0]
        return bodies,ir,constants,retained,checked

    def test_simd_receive_every_instruction_and_early_return(self):
        args=self.simd_receive_fixture();bodies,ir,constants,retained,checked=args
        report=t.inspect(*args);name=report['functions']['receive'];lines=t.life.code(bodies[name]);count=0
        for at in range(len(lines)):
            for replacement in ([],['ud2'],['retq',lines[at]]):
                bad=lines[:at]+replacement+lines[at+1:]
                with self.assertRaises(ValueError):
                    t.inspect(bodies|{name:name+':\n'+'\n'.join(bad)},ir,constants,retained,checked)
                count+=1
        self.assertEqual(count,1215)
        print('Keccak receiver instruction/label mutations rejected:',count)

    def test_simd_receive_linked_constants_and_abis(self):
        args=self.simd_receive_fixture();bodies,ir,constants,retained,checked=args
        n=t.names(bodies);count=0
        for label,raw in ((t.shape.ZERO88,bytes(88)),('switch.table.'+n['receive'],
                b''.join(x.to_bytes(8,'little') for x in (224,256,384,512)))):
            for at in range(len(raw)):
                bad=copy.deepcopy(constants);mutant=bytearray(raw);mutant[at]^=1
                bad[label]['sha256']=sha256(mutant).hexdigest()
                with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,retained,checked)
                count+=1
            for size in (0,len(raw)-1,len(raw)+1):
                bad=copy.deepcopy(constants);bad[label]['bytes']=size
                with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,retained,checked)
            bad=copy.deepcopy(constants);del bad[label]
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,retained,checked)
        self.assertEqual(count,120);count=0
        for role in ('receive','array','bits','digest'):
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[role]+'(' in l)
            for token in ('noundef','noalias','nofree','nonnull','readonly','writeonly','writable',
                'captures(none)','captures(address, read_provenance)','dead_on_return','align 8',
                'dereferenceable(12672)','dereferenceable(448)','dereferenceable(32)','dereferenceable(64)',
                'range(i64 0, 1025)','initializes((0, 441))','initializes((0, 9))','fastcc'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace(token,'')),constants,retained,checked)
                count+=1
        print('Keccak receiver/helper ABI mutations rejected:',count)

    def test_simd_receive_export_cleanup_and_copy_pointer_mutations(self):
        args=self.simd_receive_fixture();bodies,ir,constants,retained,checked=args
        n=t.names(bodies);name=n['receive'];body=name+':\n'+'\n'.join(t.life.code(bodies[name]))
        for old,new in (('movq %rax, %r8','movq %rsi, %r8'),('leaq (%rsi,%rbx), %rdx','movq %r8, %rdx'),
            ('movl $279, %r8d','movl $278, %r8d'),('movq %rcx, -2032','movq %rdx, -2032'),
            ('movq %rdx, -1936','movq %rcx, -1936'),('movzbl 366','movzbl 367'),
            ('leaq 1064(%rsp), %r9','leaq 784(%rsp), %r9'),('movq 440(%rsp), %rax','movq 432(%rsp), %rax'),
            ('movl $1024, %edx','movl $1023, %edx'),('cmpq %rcx, 48(%rdi)','cmpq %rcx, 32(%rdi)'),
            ('callq '+n['check'],'nop')):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.inspect(bodies|{name:body.replace(old,new,1)},ir,constants,retained,checked)
        event=t.L(f'''movl $1024, %edx|movq %rsi, %rcx|callq {t.life.ZERO}|
            movb $-1, 8(%rdi)|movb $0, 1104(%rdi)''')
        self.assertEqual(t.s.normal_returns(body,'.B82',event),1)
        for bad in (body.replace('.B82:','.B82:\nretq'),body.replace('callq '+t.life.ZERO,'nop'),
                    body.replace('movb $0, 1104(%rdi)','nop')):
            with self.assertRaises(ValueError):t.s.normal_returns(bad,'.B82',event)

    def test_simd_receive_prerequisites_and_unfinished_claims(self):
        args=self.simd_receive_fixture();report=t.inspect(*args)
        for index,key in ((3,'live_identity_checked_before_receive'),(3,'return_after_buffer_drop_on_all_normal_request_paths'),
            (3,'bounds_readback_and_observe_failure_quarantine_then_drop'),(3,'buffers_bytes'),
            (4,'rejected_operation_clears_output_and_quarantines'),(4,'cancellation_clears_output_then_sets_empty')):
            bad=copy.deepcopy(list(args));bad[index][key]=None
            with self.assertRaises(ValueError):t.inspect(*bad)
        for index,roles in ((3,('receive','live','identity')),(4,('operation','cancel','check'))):
            for role in roles:
                bad=copy.deepcopy(list(args));bad[index]['functions'][role]='wrong'
                with self.assertRaises(ValueError):t.inspect(*bad)
        for key in ('array_constructor_bitstring_and_digest_bodies_qualified','nested_pointer_preservation_and_nonretention_qualified',
            'decoder_padding_or_private_frame_erasure_qualified','export_host_rollback_claimed','fatal_abort_cleanup_claimed'):
            self.assertFalse(report[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('receiver review failed')) as call:
            with self.assertRaisesRegex(ValueError,'receiver review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
