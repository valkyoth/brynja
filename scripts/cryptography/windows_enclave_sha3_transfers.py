"""Saved SHA-3 transfer/output/public-length helpers; not whole-image assurance."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_state as state

ops,life,shared,obj = state.ops,state.life,state.shared,state.obj
require,digest = state.require,state.digest
SPEC = shared.CATALOG.with_name('sha3-transfers-20261005.json')
SPEC_HASH = '5c55c765bc344c3487d1fb5f90bea7f189563c480f2ef3018551fd3404eb357b'
FRAMES = dict(copy=40,xor=56,predicate=40,output=40,encode=344)
LEAVES = ('copy_bytes','xor_bits','mask','mask_byte','predicate_leaf')
EDGES = dict(copy={'copy_bytes'},copy_bytes=set(),xor={'xor_bits'},xor_bits=set(),mask={'mask_byte'},
             mask_byte=set(),predicate={'predicate_leaf'},predicate_leaf=set(),output={'zero'},encode={'memcpy','memset'})


def specification(raw):
    require(digest(raw)==SPEC_HASH,'reviewed helper specification identity')
    result = json.loads(raw)
    require(result['schema']==1 and set(result['functions'])==set(EDGES),'complete ten-helper population')
    require(all(p['stack_bytes']==FRAMES.get(k,0) for k,p in result['functions'].items()),'declared frame population')
    return result


def instructions(code,refs,pin):
    require(code==bytes.fromhex(pin['code_hex']),'complete reviewed helper instructions')
    require(refs==pin['references'],'complete helper relocation operands')


def preconditions(raw,pins):
    require(digest(raw)==ops.s.IR_HASH,'same private compiler IR')
    checks = {'copy':'range(i64 0, 1025)','copy_bytes':'range(i64 0, 1025)',
              'xor':'range(i8 0, 9)','xor_bits':'range(i32 0, 9)',
              'output':'dereferenceable(32)','encode':'dereferenceable(258)'}
    for role,token in checks.items():
        lines = [l for l in raw.decode().splitlines() if l.startswith('define internal fastcc ') and '@'+pins[role]['name']+'(' in l]
        require(len(lines)==1 and token in lines[0],'private helper argument contract: '+role)
        if role=='xor': require(lines[0].count(token)==2,'count and destination offset bounds')
    return dict(copy_length_half_open_range=[0,1025],xor_count_and_destination_offset_half_open_range=[0,9],
                valid_borrows_and_typed_layout_required=True,standalone_arbitrary_abi_calls_qualified=False)


def output_contract(present,has_region,length,initialized):
    """Inspected branch model, not forged-layout admission or dereference proof."""
    require(type(present) is bool and type(has_region) is bool,'typed optional region flags')
    require(all(type(n) is int and 0<=n<1<<64 for n in (length,initialized)),'u64 region metadata')
    if not present: return dict(tag=0,clear_bytes=0,publish=False)
    if not has_region: return dict(tag=2,clear_bytes=0,publish=False)
    if initialized!=length: return dict(tag=2,clear_bytes=length,publish=False)
    return dict(tag=1,clear_bytes=0,publish=True)


def copy_accesses(length):
    require(type(length) is int and 0<=length<=1024,'private copy length')
    offset = 0;remaining = length;spans = []
    while remaining>=8:
        spans.append((offset,8));offset += 8;remaining -= 8
    while remaining:
        spans.append((offset,1));offset += 1;remaining -= 1
    return spans


def xor_contract(source,right,count,left):
    require(type(source) is int and 0<=source<=255 and type(right) is int and 0<=right<=255,'byte/offset domain')
    require(all(type(n) is int and 0<=n<=8 for n in (count,left)),'private count/left compiler bounds')
    remaining = 8-count
    if count==0 or right>remaining or left>remaining: return None
    return ((source>>right) & (255>>remaining))<<left


def encoded_layout(value):
    """Model the emitted leading-byte scan and initialized 258-byte result."""
    require(type(value) is int and 0<=value<1<<128,'u128 public integer')
    raw = value.to_bytes(16,'big');first = 0
    while first<15 and raw[first]==0: first += 1
    width = 16-first
    return bytes([width])+raw[first:]+bytes(255-width)+(width+1).to_bytes(2,'little')


def assembly(raw,pins):
    require(digest(raw)==life.ASM_HASH,'same saved helper assembly')
    text = raw.decode();bodies = {}
    for role,pin in pins.items():
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique helper assembly body')
        start = text.index(label);end = text.index('.Lfunc_end',start)
        bodies[role] = text[start:end]
    # Raw byte identity also covers every opcode, branch and erasure. These
    # landmarks make the semantic interpretation independently regressionable.
    landmarks(bodies,pins)
    return {k:digest(v.encode()) for k,v in bodies.items()}


def sequences(pins):
    return {
        'output':('cmpl $1, (%rdx)|jne .LBB33_1',
                  'movq 8(%rdx), %rax|testq %rax, %rax|je .LBB33_5',
                  'movq 16(%rdx), %r8|cmpq %r8, 24(%rdx)|jne .LBB33_4',
                  'movq %rax, 8(%rcx)|movq %r8, 16(%rcx)|movl $1, %eax',
                  'movq %rax, %rcx|movq %r8, %rdx|callq '+state.s.ZERO),
        'copy':('cmpq %r9, %rdx|jne .LBB6_2','callq '+pins['copy_bytes']['name']+'|movb $-1, %al'),
        'xor':('movb $8, %al|subb %r9b, %al|testb %r9b, %r9b|sete %r9b',
               'cmpb %al, %r8b|seta %bl|cmpb %al, %r11b|seta %r10b|orb %r9b, %bl|orb %r10b, %bl|jne .LBB7_2'),
        'predicate':('callq '+pins['predicate_leaf']['name']+'|cmpl $1, %eax|sete %al',),
        'encode':('movq %r8, %rax|bswapq %rax|bswapq %rdx','movl $16, %edi|subq %r8, %rdi',
                  'movb %dil, (%rsi)|leaq 1(%rsi), %rcx|movl $255, %r8d|movq %r14, %rdx|callq memcpy|incl %edi|movw %di, 256(%rsi)'),
    }


ERASURES = (('copy_bytes','COPY','xorl %eax, %eax|xorl %ecx, %ecx|xorl %edx, %edx'),
            ('xor_bits','XOR','xorl %eax, %eax|xorl %ecx, %ecx'),
            ('mask_byte','MASK','xorl %eax, %eax'),('predicate_leaf','PREDICATE','xorl %r10d, %r10d'))


def landmarks(bodies,pins):
    def check(role,sequence):
        require(sequence.replace('|','\n') in state.s.normalized(bodies[role]),'helper semantic landmark: '+role)
    for role,items in sequences(pins).items():
        for sequence in items: check(role,sequence)
    for role,marker,erase in ERASURES:
        require(bodies[role].count('BRYNJA_'+marker+'_ERASE')==1,'one opaque erasure marker')
        check(role,erase)


def reconcile(records,anchors,pins,external):
    require(set(records)==set(EDGES),'all helpers bound')
    byname = {p['name']:k for k,p in pins.items()};targets = external | {k:r['rva'] for k,r in records.items()}
    image_hash = records['output']['image_sha256'];reached = set()
    for role,rec in records.items():
        expected = {pins[k]['name'] if k in pins else state.s.ZERO if k=='zero' else k for k in EDGES[role]}
        require(set(rec['reference_targets'])==expected,'complete helper reference closure')
        if role in FRAMES:
            f = rec['unwind'];require(len(f)==1 and f[0]['stack_bytes']==FRAMES[role] and not f[0]['saved_registers'] and
                                     f[0]['frame']==0 and f[0]['chain'] is None,'exact helper fixed frame')
    for rec in (*records.values(),*anchors):
        require(rec['image_sha256']==image_hash,'same helper/caller image')
        for name,addr in rec['reference_targets'].items():
            key = byname.get(name,'zero' if name==state.s.ZERO else name)
            if key not in targets: continue
            require(targets[key]==addr,'actual helper/caller target')
            if key in records: reached.add(key)
    require(reached==set(records),'every helper reached by reproduced callers')


def geometry(window,parent):
    start = window.high+parent['geometry']['paths']['rehash -> finish_fixed']['rsp_from_high']
    xor = life.bounded.Frame.enter(window,start,56);copy = life.bounded.Frame.enter(window,start,40)
    output = life.bounded.Frame.enter(window,start,40)
    return dict(xor_rsp_from_high=xor.current-window.high,xor_leaf_entry_from_high=xor.current-8-window.high,
        copy_leaf_entry_from_high=copy.current-8-window.high,
        spans=[xor.slot('public fifth argument',96,8),xor.slot('public mask outgoing argument',32,8),
               window.span('XOR leaf public fifth argument',xor.current+32,8),
               output.slot('saved caller RSI',-8,8,'entry')],
        output_clear_entry=output.unknown_callee('volatile clearer entry/home'),
        outer_window_clearing_required=True,maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    parent = state.inspect(base);owners = ops.inspect(base);lifecycle = life.inspect(base)
    pins = specification(SPEC.read_bytes())['functions'];row = shared.catalog(shared.CATALOG.read_bytes())[3]
    profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2];directory = (base/row['object']).parent
    data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']];image = (base/row['image']).read_bytes()
    require(digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],'same reviewed helper image/object')
    asm = assembly((directory/'normal_rust.s').read_bytes(),pins);pre = preconditions((directory/'normal_rust.ll').read_bytes(),pins)
    records = {};mutants = 0;anchors = [*parent['records'].values(),*owners['records'].values()]
    for role,pin in pins.items():
        code,refs = shared.caller.function(data,pin['name']);instructions(code,refs,pin)
        if role in FRAMES: records[role] = shared.caller.bind(data,image,pin['name'])
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted helper instruction mutation')
    for role in LEAVES:
        records[role] = life.bounded.leaf.bind(data,image,pins[role]['name'],[*anchors,*records.values()])
    external = {'zero':lifecycle['records'][state.s.ZERO]['rva']} | ops.memory.inspect(data,image,55)['runtime_targets']
    reconcile(records,anchors,pins,external)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_TRANSFER_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=asm,compiler_preconditions=pre,geometry=geometry(life.bounded.Window(0,65536),parent),
        actual_body_byte_mutations_rejected=mutants,whole_image_qualified=False,arbitrary_exception_cleanup_qualified=False,
        prefix_packer_and_sponge_semantics_qualified=False,native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-transfers.py')))
    result['source_sha256'] = {p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes());return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path);a = p.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
