"""Scalar route closure, full opaque schedule, and cleanup regression tests."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_enclave_sha3_chain as c

p=c.p


def assembly():
    before=[p.PERMUTE+':','.Lfunc_begin27:','.seh_proc '+p.PERMUTE,
        'pushq %rsi','.seh_pushreg %rsi','pushq %rdi','.seh_pushreg %rdi',
        'pushq %rbx','.seh_pushreg %rbx','.seh_endprologue','movq %rdx, %rsi',
        'movq %rcx, %rdi','leaq '+p.CONSTANT+'(%rip), %rbx','#APP','# BRYNJA_SCALAR_BEGIN']
    after=['# BRYNJA_SCALAR_END','#NO_APP','.seh_startepilogue',
        'popq %rbx','popq %rdi','popq %rsi','.seh_endepilogue','retq','.Lfunc_end27:']
    return '\n'.join(before+p.opaque_shape()[:-5]+['# BRYNJA_SCALAR_ERASE']+p.opaque_shape()[-5:]+after)


def synthetic():
    names=['RetainedWork']+['body'+str(i) for i in range(54)]
    records={n:dict(entry=n,rva=4096+64*i,image_sha256='same',reference_targets={},
        unwind=[dict(stack_bytes=40,frame=0,chain=None,saved_registers=[])]) for i,n in enumerate(names)}
    for i,n in enumerate(names[:-1]): records[n]['reference_targets'][names[i+1]]=records[names[i+1]]['rva']
    records[names[0]]['reference_targets'].update({n:100000+i*100 for i,n in enumerate(c.SHARED)})
    return set(names),records,{n:'reviewed' for n in names}


class Tests(unittest.TestCase):
    def test_constants_and_coordinate_recurrence(self):
        self.assertEqual(p.digest(p.round_constants()),'f8e6964adffc257265537256d21e93496a17b9271dc5d64f40869eeeaaff6fbb')
        self.assertEqual([r for _,r,_ in p.rho_pi()],
            [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14])
        self.assertEqual(sorted(d for _,_,d in p.rho_pi()),list(range(25)))
        for source,_,destination in p.rho_pi():
            self.assertEqual(destination,source//5+5*((2*(source%5)+3*(source//5))%5))
            self.assertTrue(0<=8*source<=192 and 0<=8*destination<=192)

    def test_every_instruction_is_load_bearing_without_hash_check(self):
        text=assembly();p.permutation_assembly(text)
        # Mutate each occurrence individually, including all branch and wipe
        # loops. Exact schedule checks must work without the whole-file hash.
        lines=text.splitlines()
        for i,line in enumerate(lines):
            if line in p.opaque_shape() or line.startswith(('pushq ','popq ','movq ','leaq ')):
                changed=lines.copy();changed[i]='int3'
                with self.assertRaises(ValueError): p.permutation_assembly('\n'.join(changed))
        for bad in ('pushq %rax','movq %rax, 32(%rsp)','callq helper','jmp external','vmovdqu %ymm0, (%rdi)'):
            with self.assertRaises(ValueError): p.permutation_assembly(text.replace('# BRYNJA_SCALAR_ERASE',bad+'\n# BRYNJA_SCALAR_ERASE'))
        for marker in ('BEGIN','ERASE','END'):
            with self.assertRaises(ValueError): p.permutation_assembly(text.replace('BRYNJA_SCALAR_'+marker,'missing'))

    def test_constants_must_match_object_and_linked_readonly_image(self):
        raw=p.round_constants();row=dict(code=raw,flags=0x40000000,nrelocs=0)
        symbols={1:dict(name=p.CONSTANT,value=0,section=1)}
        record=dict(reference_targets={p.CONSTANT:123})
        with patch.object(p.ops.obj,'tables',return_value=([row],symbols)),patch.object(p.ops,'readonly',return_value=raw):
            self.assertEqual(p.constants(b'object',b'image',record)['bytes'],192)
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at] ^= 1;row['code']=bytes(bad)
                with self.assertRaises(ValueError): p.constants(b'object',b'image',record)
            row['code']=raw
            for key,bad in (('flags',0xc0000000),('nrelocs',1)):
                old=row[key];row[key]=bad
                with self.assertRaises(ValueError): p.constants(b'object',b'image',record)
                row[key]=old
            with patch.object(p.ops,'readonly',return_value=bytes(192)):
                with self.assertRaises(ValueError): p.constants(b'object',b'image',record)

    def test_buffer_destructor_clears_both_extents_before_return(self):
        lines=[p.DROP+':','.Lfunc_begin2:','.seh_proc '+p.DROP,'pushq %rsi',
            '.seh_pushreg %rsi','subq $32, %rsp','.seh_stackalloc 32','.seh_endprologue',
            'movq %rcx, %rsi','addq $1024, %rcx','movl $96, %edx','callq '+p.ZERO,
            'movl $1024, %edx','movq %rsi, %rcx','.seh_startepilogue','addq $32, %rsp',
            'popq %rsi','.seh_endepilogue','jmp '+p.ZERO,'.Lfunc_end2:']
        p.destructor_assembly('\n'.join(lines))
        for i in range(3,len(lines)-1):
            bad=lines.copy();bad[i]='retq'
            with self.assertRaises(ValueError): p.destructor_assembly('\n'.join(bad))

    def test_inventory_fails_on_unassigned_code_sections(self):
        row=dict(flags=0x20000000,code=b'body')
        symbol=dict(section=1,kind=32,value=0,name='body')
        with patch.object(c.ops.obj,'tables',return_value=([row],{1:symbol})),patch.object(c.shared.caller,'function',return_value=(b'body',[])):
            self.assertEqual(c.inventory(b'object'),{'body'})
            symbol['value']=1
            with self.assertRaises(ValueError): c.inventory(b'object')
            symbol['value']=0
            with patch.object(c.ops.obj,'tables',return_value=([row,row],{1:symbol})):
                with self.assertRaises(ValueError): c.inventory(b'object')
            with patch.object(c.shared.caller,'function',return_value=(b'partial',[])):
                with self.assertRaises(ValueError): c.inventory(b'object')

    def test_all_constructed_worker_exits_destroy_buffers(self):
        body='\n'.join(('.LBB0_11:','jne .LBB0_28','callq '+p.DROP,'jmp .LBB0_29',
                        '.LBB0_28:','callq '+p.DROP,'.LBB0_29:','retq'))
        self.assertTrue(p.buffer_exits(body)['post_construction_paths_checked'])
        for bad in (body.replace('callq '+p.DROP,'nop',1),body.replace('jne .LBB0_28','jne .LBB0_29'),
                    body.replace('jne .LBB0_28','jne external'),body.replace('jne .LBB0_28','jmpq *%rax'),
                    body.replace('jne .LBB0_28','callq *%rax')):
            with self.assertRaises(ValueError): p.buffer_exits(bad)

    def test_complete_graph_and_shared_assignments(self):
        names,records,groups=synthetic();edges,frames,external=c.reconcile(names,records,groups)
        self.assertEqual(set(external),set(c.SHARED))
        self.assertTrue(all(v['assigned_completion_package']==8 for v in external.values()))
        for name in names:
            bad=copy.deepcopy(records);del bad[name]
            with self.assertRaises(ValueError): c.reconcile(names,bad,groups)
        for symbol in records['RetainedWork']['reference_targets']:
            bad=copy.deepcopy(records);del bad['RetainedWork']['reference_targets'][symbol]
            with self.assertRaises(ValueError): c.reconcile(names,bad,groups)
        bad=copy.deepcopy(records);bad['RetainedWork']['reference_targets']['unknown_runtime']=77
        with self.assertRaises(ValueError): c.reconcile(names,bad,groups)
        bad=copy.deepcopy(records);bad['body0']['image_sha256']='other'
        with self.assertRaises(ValueError): c.reconcile(names,bad,groups)
        bad=copy.deepcopy(records);bad['body0']['rva']+=1
        with self.assertRaises(ValueError): c.reconcile(names,bad,groups)
        bad=copy.deepcopy(records);bad['body0']['reference_targets']['__umodti3']=77
        with self.assertRaises(ValueError): c.reconcile(names,bad,groups)

    def test_depth_is_conservative_local_only_and_rejects_cycles(self):
        names,records,groups=synthetic();edges,frames,_=c.reconcile(names,records,groups)
        value=c.contributions(edges,frames)
        self.assertEqual(value['local_bytes_below_worker_entry'],55*40+54*8)
        self.assertFalse(value['maximum_whole_image_depth_qualified'])
        self.assertTrue(value['shared_runtime_frames_excluded'])
        edges['body53']=['RetainedWork']
        with self.assertRaises(ValueError): c.contributions(edges,frames)
        edges['body53']=[];frames['body53']=65536
        with self.assertRaises(ValueError): c.contributions(edges,frames)
        records['body0']['unwind'][0]['chain']=123
        with self.assertRaises(ValueError): c.reconcile(names,records,groups)

    def test_source_manifest_rejects_drift_and_unsafe_paths(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'source').write_bytes(b'bytes')
            source={'source':p.digest(b'bytes')}
            for i in range(157):
                (root/f'other{i}').write_bytes(b'bytes');source[f'other{i}']=p.digest(b'bytes')
            raw=json.dumps(dict(target='x86_64-pc-windows-msvc',source_sha256=source)).encode()
            with patch.object(c,'BUILD_HASH',p.digest(raw)):
                self.assertEqual(c.sources(raw,root),source)
                (root/'source').write_bytes(b'changed')
                with self.assertRaises(ValueError): c.sources(raw,root)
            with self.assertRaises(ValueError): c.sources(raw,root)
            (root/'source').write_bytes(b'bytes')
            for bad in ('folder/../source','/source','C:/source','C:source'):
                changed=source.copy();changed[bad]=changed.pop('source')
                raw=json.dumps(dict(target='x86_64-pc-windows-msvc',source_sha256=changed)).encode()
                with patch.object(c,'BUILD_HASH',p.digest(raw)):
                    with self.assertRaises(ValueError): c.sources(raw,root)


if __name__=='__main__': unittest.main()
