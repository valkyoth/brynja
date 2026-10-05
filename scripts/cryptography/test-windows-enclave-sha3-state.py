"""Nonvacuous drift/semantic regressions for the saved scalar state review."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha3_state as r


def sequence_body(role):
    body = '\n'.join(v.replace('|','\n') for v in r.s.SEQUENCES[role])
    if role=='finish_fixed':
        body += '\n'+'\n'.join(f'cmpq ${w}, %rsi\njne .LBB50_128' for w in (28,32,48,64))
        body += '\n'+('addq 96(%rsp), %rax\nmovq 104(%rsp), %rax\nadcq $0, %rax\nmovb $1, %r15b\njb .LBB50_128\n')*4
        body += ('callq '+r.s.OUTPUT+'\nmovq 40(%rsp), %r12\nleaq 96(%rsp), %rcx\ncallq '+r.s.WIPE+'\n')*2
    return body


def permutation_body():
    lines = []
    for width,rate,last in ((28,144,655),(48,104,615),(64,72,583)):
        for i in range(5):
            lines += [f'movl ${rate}, %ebp','callq '+r.s.PERMUTE]
            for size,reg in ((40,'%r12'),(40,'%r14'),(200,'%r15' if i<4 else '%rbp'),(168,'%r13')):
                lines += [f'movl ${size}, %edx',f'movq {reg}, %rcx','callq '+r.s.ZERO]
        lines += [f'leaq {last}(%rsp), %rcx','movb $-1, %dl','movb $-128, %r8b','callq '+r.s.MASK,
                  f'movl ${width}, %edx',f'movl ${width}, %r9d']
    return '\n'.join(lines)


class Tests(unittest.TestCase):
    def setUp(self):
        self.spec = r.specification(r.SPEC.read_bytes())

    def test_spec_identity_and_complete_population(self):
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        for key in ('functions','tables'):
            bad = copy.deepcopy(self.spec);bad[key].pop(next(iter(bad[key])))
            raw = r.shared.encoded(bad)
            with patch.object(r,'SPEC_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.specification(raw)
        bad = copy.deepcopy(self.spec);bad['functions']['new']['name'] = 'other'
        raw = r.shared.encoded(bad)
        with patch.object(r,'SPEC_HASH',r.digest(raw)):
            with self.assertRaises(ValueError): r.specification(raw)

    def test_sequences_without_body_hashes(self):
        for role,sequences in r.s.SEQUENCES.items():
            body = sequence_body(role);r.s.sequences(role,body)
            for sequence in sequences:
                bad = body.replace(sequence.replace('|','\n'),'int3')
                with self.subTest(role=role,sequence=sequence):
                    with self.assertRaises(ValueError): r.s.sequences(role,bad)

    def test_all_widths_and_admission_branches(self):
        body = sequence_body('finish_fixed')
        for width in (28,32,48,64):
            with self.assertRaises(ValueError):
                r.s.sequences('finish_fixed',body.replace(f'cmpq ${width}, %rsi',f'cmpq ${width+1}, %rsi'))
        for old,new in (('jb .LBB50_128','jmp .LBB50_128'),('adcq $0, %rax','addq $0, %rax'),
                        ('callq '+r.s.OUTPUT,'callq other'),('callq '+r.s.WIPE,'callq other')):
            with self.assertRaises(ValueError): r.s.sequences('finish_fixed',body.replace(old,new,1))

    def test_every_inlined_permutation_clears_before_branch(self):
        body = permutation_body();v = r.s.permutation_cleanup(body)
        self.assertEqual(v['inlined_permutation_calls'],15)
        self.assertFalse(v['permutation_internals_qualified'])
        lines = body.splitlines()
        starts = [i for i,l in enumerate(lines) if l=='callq '+r.s.PERMUTE]
        for at in starts:
            for after in range(1,13):
                bad = list(lines);bad[at+after] = 'jmp skip_cleanup'
                with self.assertRaises(ValueError): r.s.permutation_cleanup('\n'.join(bad))
            bad = list(lines);bad[at] = 'callq other'
            with self.assertRaises(ValueError): r.s.permutation_cleanup('\n'.join(bad))
        with self.assertRaises(ValueError): r.s.permutation_cleanup(body+body)
        for rate in (72,104,144):
            with self.assertRaises(ValueError):
                r.s.permutation_cleanup(body.replace(f'movl ${rate}, %ebp',f'movl ${rate+1}, %ebp',1))
        with self.assertRaises(ValueError): r.s.permutation_cleanup(body.replace('movb $-128, %r8b','movb $0, %r8b',1))

    def test_private_preconditions(self):
        text = (f'define internal fastcc void @{r.s.NAMES["new"]}(i8 noundef range(i8 0, 8), ptr dereferenceable(1136))\n'
                f'define internal fastcc i8 @{r.s.NAMES["finish_fixed"]}(i64 noundef range(i64 28, 65), ptr dereferenceable(1136))')
        with patch.object(r.ops.s,'IR_HASH',r.digest(text.encode())):
            v = r.preconditions(text.encode());self.assertFalse(v['arbitrary_private_abi_calls_qualified'])
        for old,new in (('0, 8','0, 9'),('28, 65','0, 1025'),('1136','1135')):
            bad = text.replace(old,new).encode()
            with patch.object(r.ops.s,'IR_HASH',r.digest(bad)):
                with self.assertRaises(ValueError): r.preconditions(bad)

    def test_dispatch_tables_and_all_bytes(self):
        for role,pin in self.spec['tables'].items():
            source = bytes.fromhex(pin['object_hex']);dest = [int.from_bytes(source[i:i+4],'little')-i-4 for i in range(0,len(source),4)]
            raw = b''.join((2000+n-10000).to_bytes(4,'little',signed=True) for n in dest)
            self.assertEqual(r.ops.table_destinations(raw,10000,2000,pin),dest)
            for at in range(len(raw)):
                bad = bytearray(raw);bad[at] ^= 1
                with self.assertRaises(ValueError): r.ops.table_destinations(bad,10000,2000,pin)
            with self.assertRaises(ValueError): r.ops.table_destinations(raw[:-4],10000,2000,pin)
            self.assertEqual(len(dest),8 if role=='new' else 4)

    def test_actual_owner_and_cleanup_connections(self):
        records = {k:dict(rva=100+20*i,image_sha256='image',reference_targets={'cleanup':1000}) for i,k in enumerate(r.s.NAMES)}
        parent = dict(image_sha256='image',records={c:dict(reference_targets={}) for c,_ in r.EDGES})
        for c,k in r.EDGES: parent['records'][c]['reference_targets'][r.s.NAMES[k]] = records[k]['rva']
        tables = {k:dict(rva=2000+i*40) for i,k in enumerate(self.spec['tables'])}
        for k in tables: records[k]['reference_targets']['.rdata'] = tables[k]['rva']
        targets = {'cleanup':1000};r.connections(parent,records,targets,tables)
        for c,k in r.EDGES:
            bad = copy.deepcopy(parent);del bad['records'][c]['reference_targets'][r.s.NAMES[k]]
            with self.assertRaises(ValueError): r.connections(bad,records,targets,tables)
        for k,rec in records.items():
            for edge in rec['reference_targets']:
                bad = copy.deepcopy(records);bad[k]['reference_targets'][edge] += 1
                with self.assertRaises(ValueError): r.connections(parent,bad,targets,tables)
            bad = copy.deepcopy(records);bad[k]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.connections(parent,bad,targets,tables)

    def test_complete_frames_and_geometry(self):
        pins = self.spec['functions'];owners = r.ops.specification(r.ops.SPEC.read_bytes())['functions']
        g = r.geometry(r.life.bounded.Window(0,65536),pins,owners)
        self.assertEqual(g['paths']['rehash -> finish_fixed']['rsp_from_high'],-8320)
        self.assertEqual(g['paths']['begin -> new']['rsp_from_high'],-6672)
        self.assertFalse(g['maximum_whole_image_depth_qualified'])
        self.assertFalse(g['all_moved_copies_individually_erased'])
        self.assertTrue(g['outer_window_clearing_required'])
        self.assertEqual(g,r.geometry(r.life.bounded.Window(4096,69632),pins,owners))
        with self.assertRaises(ValueError): r.geometry(r.life.bounded.Window(0,4096),pins,owners)
        records = {k:dict(unwind=[dict(stack_bytes=p['stack_bytes'],saved_registers=[],chain=None,frame=0)]) for k,p in pins.items()}
        r.ops.frames(records,pins)
        for k in pins:
            bad = copy.deepcopy(records);bad[k]['unwind'][0]['stack_bytes'] += 8
            with self.assertRaises(ValueError): r.ops.frames(bad,pins)


if __name__=='__main__': unittest.main()
