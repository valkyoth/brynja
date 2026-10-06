"""Accelerated route inventory, dispatch, admission and erasure regressions."""
import copy
import json
import unittest
from unittest.mock import patch

import windows_enclave_sha3_avx2_chain as c

s=c.s


def kernel():
    before=[s.KERNEL+':','.Lfunc_begin15:','.seh_proc '+s.KERNEL,'subq $168, %rsp','.seh_stackalloc 168']
    for r in range(15,5,-1):
        before += [f'vmovaps %xmm{r}, {s.scalar.mem((r-6)*16,"%rsp")}',f'.seh_savexmm %xmm{r}, {(r-6)*16}']
    before += ['.seh_endprologue','movq %rdx, %r9','movq %rcx, %r10',f'leaq {s.CONSTANT}(%rip), %r11',
               '#APP','# BRYNJA_SECRET_BEGIN']
    after=['# BRYNJA_SECRET_END','#NO_APP']
    after += [f'vmovaps {s.scalar.mem((r-6)*16,"%rsp")}, %xmm{r}' for r in range(6,16)]
    after += ['.seh_startepilogue','addq $168, %rsp','.seh_endepilogue','retq']
    return '\n'.join(before+s.kernel_shape()[:-10]+['# BRYNJA_REGISTER_ERASE']+s.kernel_shape()[-10:]+after)


class Tests(unittest.TestCase):
    def test_review_population_is_frozen(self):
        raw=c.SPEC.read_bytes();spec=c.specification(raw)
        self.assertEqual(len(spec['functions']),61)
        self.assertEqual(sum(k.startswith('?') for k in spec['functions']),8)
        for key in ('image_sha256','object_sha256','assembly_sha256','ir_sha256','build_sha256'):
            changed=copy.deepcopy(spec);changed[key]='0'*64
            with self.assertRaises(ValueError): c.specification(json.dumps(changed).encode())
        for name in spec['functions']:
            changed=copy.deepcopy(spec);del changed['functions'][name]
            with self.assertRaises(ValueError): c.specification(json.dumps(changed).encode())

    def test_body_identity_includes_relocation_and_runtime_kind(self):
        code=b'\xe8\0\0\0\0';refs=[dict(offset=1,symbol='target',trailing=0,addend=0)]
        pin=dict(bytes=5,sha256=c.digest(code),references=refs,runtime=True)
        c.body_check(code,refs,True,pin)
        for altered in ([],[refs[0]|dict(symbol='other')],[refs[0]|dict(offset=0)],
                        [refs[0]|dict(addend=4)],[refs[0]|dict(trailing=1)]):
            with self.assertRaises(ValueError): c.body_check(code,altered,True,pin)
        with self.assertRaises(ValueError): c.body_check(code,refs,False,pin)
        for at in range(5):
            bad=bytearray(code);bad[at]^=1
            with self.assertRaises(ValueError): c.body_check(bad,refs,True,pin)

    def test_independent_constants_and_rotation_schedule(self):
        self.assertEqual(s.zero_permutation()[:32].hex(),
            'e7dde140798f25f18a47c033f9ccd584eea95aa61e2698d54d49806f304715bd')
        self.assertEqual(s.zero_permutation()[-8:].hex(),'49a2ec5c7bfff1ea')
        self.assertEqual([r for _,r,_ in s.scalar.rho_pi()],
            [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14])
        # Last vector row reads [440,472), [448,480); scalar tail uses 472.
        for row in range(5):
            self.assertLessEqual(288+40*row+32,480)
        self.assertIn('cmpq $576, %rcx',s.kernel_shape())

    def test_all_kernel_instructions_and_markers_are_load_bearing(self):
        text=kernel();result=s.kernel(text)
        self.assertEqual(result['scratch_bytes'],576)
        lines=text.splitlines()
        for index,line in enumerate(lines):
            if line in s.kernel_shape() or line.startswith(('vmovaps ','movq ','leaq ','subq ','addq ')):
                bad=lines.copy();bad[index]='int3'
                with self.assertRaises(ValueError): s.kernel('\n'.join(bad))
        for token in ('BRYNJA_SECRET_BEGIN','BRYNJA_REGISTER_ERASE','BRYNJA_SECRET_END'):
            with self.assertRaises(ValueError): s.kernel(text.replace(token,'missing'))
        for inserted in ('pushq %rax','movq %rax, 32(%rsp)','callq helper','jmp outside',
                         'vmovdqu %ymm0, (%rsp)','vzeroupper'):
            with self.assertRaises(ValueError): s.kernel(text.replace('# BRYNJA_REGISTER_ERASE',inserted+'\n# BRYNJA_REGISTER_ERASE'))

    def test_restore_only_incoming_nonvolatile_vectors(self):
        text=kernel()
        for i in range(6,16):
            old=f'vmovaps {s.scalar.mem((i-6)*16,"%rsp")}, %xmm{i}'
            with self.assertRaises(ValueError): s.kernel(text.replace(old,'vmovdqu (%r10), %ymm0'))
        self.assertTrue(s.kernel(text)['saved_vectors_require_outer_window_clearing'])

    def test_buffer_exit_cannot_skip_destruction(self):
        text='\n'.join(('.LBB0_27:','jne .LBB0_51','.LBB0_51:',
            'leaq 64(%rsp), %rcx','callq '+s.DROP,'jmp .LBB0_52','.LBB0_52:','retq'))
        self.assertTrue(s.buffer_exits(text)['destructor_dominates_returns'])
        for bad in (text.replace('callq '+s.DROP,'nop'),text.replace('jne .LBB0_51','jne .LBB0_52'),
                    text.replace('jne .LBB0_51','jmpq *%rax'),text.replace('jne .LBB0_51','je external')):
            with self.assertRaises(ValueError): s.buffer_exits(bad)

    def test_jump_table_subtable_base_and_every_destination(self):
        source=b''.join(v.to_bytes(4,'little') for v in (24,36,48))
        pin=dict(object_hex=source.hex(),subtable_bytes=[8,4])
        # object cell address includes +4; linked signed offsets are relative
        # to the respective dispatch subtable base, not its individual cell.
        destinations=[20,28,44]
        raw=b''.join((1000+d-2000-base).to_bytes(4,'little',signed=True)
                     for d,base in zip(destinations,(0,0,8)))
        self.assertEqual(s.scalar.ops.table_destinations(raw,2000,1000,pin),destinations)
        for at in range(len(raw)):
            bad=bytearray(raw);bad[at]^=1
            with self.assertRaises(ValueError): s.scalar.ops.table_destinations(bad,2000,1000,pin)

    def test_no_unbounded_or_unassigned_frame(self):
        records={n:dict(reference_targets={}) for n in ('RetainedWork',s.KERNEL,s.KAT)}
        records['RetainedWork']['reference_targets']={n:100+i for i,n in enumerate(c.RUNTIME)}
        records['RetainedWork']['reference_targets'][s.KERNEL]=1000
        assembly={'RetainedWork':'.seh_stackalloc 64',s.KERNEL:'.seh_stackalloc 168\n.seh_savexmm %xmm6, 0',
                  s.KAT:'.seh_stackalloc 1216\n.seh_savexmm %xmm6, 1056'}
        _,_,external,_,geometry=c.frames_and_edges(records,assembly)
        self.assertEqual(geometry['local_rsp_bound_from_window_high'],-344)
        self.assertTrue(geometry['shared_runtime_frames_excluded'])
        for item in external.values(): self.assertEqual(item['assigned_completion_package'],8)
        for bad in ('subq %rax, %rsp','andq $-64, %rsp'):
            with self.assertRaises(ValueError): c.frames_and_edges(records,assembly|{'RetainedWork':bad})

    def test_semantic_sequence_mutations_not_just_hashes(self):
        for sequence in ('cmpq 584(%rcx), %r9|jne .LBB16_7',
                         'movb $2, 8(%rax)|movq $3, (%rax)|jmp .LBB52_14'):
            s.contains(sequence.replace('|','\n'),[sequence],'test')
            for at,line in enumerate(sequence.split('|')):
                lines=sequence.split('|');lines[at]='nop'
                with self.assertRaises(ValueError): s.contains('\n'.join(lines),[sequence],'test')

    def test_ambiguous_assembly_labels_fail(self):
        text='\nentry:\nretq\n.Lfunc_end0:'
        self.assertIn('entry',s.bodies(text,['entry']))
        with self.assertRaises(ValueError): s.bodies(text+text,['entry'])
        with self.assertRaises(ValueError): s.bodies(text,['missing'])


if __name__=='__main__': unittest.main()
