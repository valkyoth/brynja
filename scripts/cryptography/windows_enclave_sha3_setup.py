"""Saved streamed cSHAKE setup review; not full image/runtime qualification."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha3_update as u

t,state,ops,life,shared = u.t,u.state,u.ops,u.life,u.shared
require,digest = u.require,u.digest
ZERO,WIPE = u.ZERO,life.s.WIPE
SPEC = shared.CATALOG.with_name('sha3-setup-20261005.json')
SPEC_HASH = '859903371fa040478bb0f8ea7dfad654c5d72b7165d641b5ead51110b8410263'
ROLES = tuple(kind+str(rate) for kind in ('push','bits','advance') for rate in (136,168))
REMAINDER136 = ('movq %r14, %rax|shldq $61, %rbx, %rax|movq %r14, %rcx|shrq $3, %rcx|'
    'addq %rax, %rcx|adcq $0, %rcx|movabsq $-1085102592571150095, %rdx|movq %rcx, %rax|'
    'mulq %rdx|shrq $4, %rdx|movl %edx, %eax|shll $4, %eax|addl %edx, %eax|subl %eax, %ecx|'
    'shll $3, %ecx|movl %ebx, %eax|andl $7, %eax|orq %rcx, %rax')


def name(kind,rate):
    return ('_RNvMs_NtNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened6cshake5setupINtB4_5SetupKj'
            +format(rate,'x')+'_E'+str(len(kind))+kind+'Ba_')


def specification(raw):
    require(digest(raw)==SPEC_HASH,'saved setup specification identity')
    result = json.loads(raw);pins = result['functions']
    require(result['schema']==1 and set(pins)==set(ROLES),'six setup bodies')
    for role,pin in pins.items():
        kind,rate = role[:-3],int(role[-3:]);frame = 120 if kind=='push' else 104 if kind=='bits' else 344 if rate==136 else 376
        require(pin['name']==name(kind,rate) and pin['stack_bytes']==frame and not pin['saved_registers'],
                'exact setup identity/frame')
    return result


def sequences(kind,rate,h):
    update = state.s.UPDATE+format(rate,'x')+'_E6updateB6_'
    if kind=='push':
        return (
            'cmpb %dl, 66(%rcx)|jne .LBBX_3',
            'cmpq %r14, %r12|movq %r13, %rax|sbbq $0, %rax|jb .LBBX_4|subq %r14, %r12|sbbq $0, %r13',
            'shrq $3, %r14|movq 8(%r8), %rbp|cmpq %rbp, %r14|jbe .LBBX_9',
            'cmpb $1, 67(%rsi)|jne .LBBX_7|leaq 68(%rsi), %rbx|movq %rbx, %rcx|callq '+WIPE,
            'cmpb $0, 67(%rsi)|je .LBBX_7|movq %rbx, %rcx|callq '+WIPE,
            'movb $0, 67(%rsi)|leaq 64(%rsi), %rcx|movl $1, %edx|callq '+ZERO+
            '|movw $768, 65(%rsi)|movb $0, 1108(%rsi)|xorps %xmm0, %xmm0|movaps %xmm0, (%rsi)|movaps %xmm0, 16(%rsi)|movaps %xmm0, 32(%rsi)|movaps %xmm0, 48(%rsi)',
            'cmpb $0, 65(%rsi)|je .LBBX_14',
            'callq '+name('bits',rate)+'|cmpb $-1, %al|jne .LBBX_21',
            'addq %r14, %rbx|adcq $0, %r15|jb .LBBX_4|cmpb $1, 67(%rsi)|jne .LBBX_3',
            'callq '+update+'|testb %al, %al|jne .LBBX_4|movq %rbx, (%rsi)|movq %r15, 8(%rsi)',
            'leal -1(%r8), %eax|cmpb $6, %al|ja .LBBX_22|cmpq %rbp, %r14|jae .LBBX_3',
            'movq %r12, 16(%rsi)|movq %r13, 24(%rsi)|movq %rsi, %rcx|callq '+name('advance',rate)+
            '|cmpb $-1, %al|je .LBBX_25|.LBBX_21:|movl %eax, %edi|jmp .LBBX_4')
    if kind=='bits':
        return (
            'leal -1(%rsi), %eax|cmpb $8, %al|setb %cl|movzbl 65(%rbx), %eax|cmpb $8, %al|setb %dl|andb %cl, %dl|cmpb $1, %dl|jne .LBBX_1',
            'movl %esi, %ecx|subb %bpl, %cl|movb $8, %dl|subb %al, %dl|movzbl %dl, %edx|movzbl %cl, %r12d|cmpb %r12b, %dl|cmovbl %edx, %r12d',
            'movb %al, 32(%rsp)|movq %r14, %rcx|movq %rdi, %rdx|movl %ebp, %r8d|movl %r12d, %r9d|callq '+h['xor']['name'],
            'testb %al, %al|jne .LBBX_1|addb %r12b, %bpl|jb .LBBX_1|addb 65(%rbx), %r12b|jb .LBBX_1|movb %r12b, 65(%rbx)|cmpb $8, %r12b|jne .LBBX_13',
            'addq $1, %r13|adcq $0, %r15|movb $1, %r12b|jb .LBBX_2|cmpb $1, 67(%rbx)|jne .LBBX_1',
            'callq '+update+'|testb %al, %al|je .LBBX_12|jmp .LBBX_2',
            '.LBBX_12:|movl $1, %edx|movq %r14, %rcx|callq '+ZERO+
            '|movq %r15, 8(%rbx)|movq %r13, (%rbx)|movb $0, 65(%rbx)|xorl %r12d, %r12d')
    offset = 32 if rate==136 else 64
    return (
        'movq 16(%rcx), %rcx|movb $-1, %al|orq 24(%rsi), %rcx|je .LBBX_2',
        'testb %dl, %dl|jne .LBBX_12|movq 32(%rsi), %rdx|movq 40(%rsi), %r8|'+f'leaq {offset}(%rsp), %r14|movq %r14, %rcx|callq '+h['encode']['name'],
        f'movzwl {offset+256}(%rsp), %eax|xorl %edi, %edi|cmpl $257, %eax|movl $1, %ebx|cmovbq %r14, %rbx|cmovbl %eax, %edi',
        'addq %rdi, %r15|adcq $0, %r14|movb $1, %al|jb .LBBX_27|cmpb $1, 67(%rsi)|jne .LBBX_26',
        'movq 32(%rsi), %rax|movq 40(%rsi), %rcx|movq %rcx, 24(%rsi)|movq %rax, 16(%rsi)|movb $1, 66(%rsi)',
        'addq $1, %rbx|adcq $0, %r14|movb $1, %al|jb .LBBX_1|cmpb $1, 67(%rsi)|jne .LBBX_25',
        'movl $1, %edx|movq %rdi, %rcx|callq '+ZERO+'|movq %r14, 8(%rsi)|movq %rbx, (%rsi)|movb $0, 65(%rsi)',
        REMAINDER136 if rate==136 else 'movq %rbx, 48(%rsp)|movq %r14, 56(%rsp)|movq $168, 32(%rsp)|movq $0, 40(%rsp)|leaq 48(%rsp), %rcx|leaq 32(%rsp), %rdx|callq __umodti3',
        f'movl ${rate}, %r8d|subq %rax, %r8|addq %r8, %rbx|adcq $0, %r14|movb $1, %al|jb .LBBX_1',
        f'leaq {offset}(%rsp), %rdx|callq '+update+'|movl %eax, %ecx|movb $1, %al|testb %cl, %cl|jne .LBBX_1|movq %rbx, (%rsi)|movq %r14, 8(%rsi)',
        'xorq 48(%rsi), %rbx|xorq 56(%rsi), %r14|orq %rbx, %r14|jne .LBBX_25|movb $2, 66(%rsi)')


def landmarks(kind,rate,body,helpers):
    text = u.normalized(body)
    for sequence in sequences(kind,rate,helpers):
        require(sequence.replace('|','\n') in text,'setup admission/commit/cleanup sequence')
    if kind=='advance':
        offset = 32 if rate==136 else 64
        vector,store = ('%xmm0','movaps') if rate==136 else ('%xmm1','movdqa')
        for at in range(offset,offset+160,16): require(f'{store} {vector}, {at}(%rsp)' in text,'complete public zero padding')
        require(f'movq $0, {offset+160}(%rsp)' in text,'final public padding word')


def common_shape(rate,body):
    text = re.sub(r'\.Lfunc_(begin|end)\d+',r'.Lfunc_\1X',u.normalized(body))
    return text.replace('Kj'+format(rate,'x')+'_E','KjRATE_E')


def remainder136(value):
    """Model the emitted u128 remainder reduction, including machine-width folds."""
    require(type(value) is int and 0<=value<1<<128,'u128 public emitted count')
    mask = (1<<64)-1;low,high = value & mask,value>>64
    cross = ((high<<61)|(low>>3)) & mask
    combined = (high>>3)+cross;folded = (combined & mask)+(combined>>64)
    quotient = (folded*((1<<64)-1085102592571150095)>>64)>>4
    residue = ((folded & 0xffffffff)-17*(quotient & 0xffffffff)) & 0xffffffff
    return (residue<<3)|(low & 7)


def push_bits(pending,used,emitted,source,valid,owner=True,fail_update=False):
    """Inspected fragment model; enclosing Operation owns failed-pending cleanup."""
    require(all(type(n) is int and 0<=n<=255 for n in (pending,used,source,valid)),'byte domain')
    require(type(emitted) is int and 0<=emitted<1<<128,'u128 emitted domain')
    calls = [];clears = 0
    def result(error): return dict(error=error,pending=pending,used=used,emitted=emitted,calls=calls,clears=clears)
    if not 1<=valid<=8 or used>=8: return result('StateConsumed')
    position = 0
    while position<valid:
        count = min(valid-position,8-used)
        pending ^= t.xor_contract(source,position,count,used);position += count;used += count
        if used==8:
            next_count = u.counter_admit(emitted,1)
            if next_count is None: return result('MessageTooLong')
            if not owner: return result('StateConsumed')
            calls.append(pending)
            if fail_update: return result('MessageTooLong')
            pending = 0;used = 0;emitted = next_count;clears += 1
    return result(None)


def connections(records,owners,callees,pins):
    require(set(records)==set(ROLES),'six setup connections')
    targets = {r['entry']:r['rva'] for r in (*records.values(),*callees.values())}
    runtime = owners['runtime_boundaries_pending']['__umodti3'];targets['__umodti3'] = runtime
    for role,r in records.items():
        kind,rate = role[:-3],role[-3:]
        keys = ('zero','wipe','update'+rate) if kind=='push' else ('zero','xor','update'+rate) if kind=='bits' else ('zero','encode','update'+rate)
        expected = {callees[k]['entry'] for k in keys}
        if kind!='bits': expected.add(pins['bits'+rate]['name'])
        if kind=='push': expected.add(pins['advance'+rate]['name'])
        if role=='advance168': expected.add('__umodti3')
        require(set(r['reference_targets'])==expected,'complete setup callee population')
        for symbol,address in r['reference_targets'].items(): require(targets[symbol]==address,'exact setup callee address')
        source = 'setup_chunk' if kind=='push' else 'setup'
        require(owners['records'][source]['reference_targets'].get(pins[role]['name'])==r['rva'],'actual incoming setup call')
    for r in (*records.values(),*callees.values()): require(r['image_sha256']==owners['image_sha256'],'same setup/helper image')
    return dict(symbol='__umodti3',rva=runtime,public_counts_only=True,internals_qualified=False)


def geometry(window,owners):
    paths = {}
    for rate in (136,168):
        caller = window.high+owners['geometry']['paths']['setup_chunk']['rsp_from_high']
        push = life.bounded.Frame.enter(window,caller,120)
        advance = life.bounded.Frame.enter(window,push.current,344 if rate==136 else 376)
        bits = life.bounded.Frame.enter(window,advance.current,104)
        update = life.bounded.Frame.enter(window,bits.current,136)
        offset = 32 if rate==136 else 64
        paths[str(rate)] = dict(push_rsp=push.current-window.high,advance_rsp=advance.current-window.high,
            bits_rsp=bits.current-window.high,update_rsp=update.current-window.high,
            public_encoded_length=advance.slot('public encoded length',offset,258),
            public_zero_padding=advance.slot('overlapping public padding',offset,168),
            bit_offset=bits.slot('public destination bit offset',32,1),
            deeper_entry=update.unknown_callee('deeper sponge call'))
    return dict(paths=paths,outer_window_clearing_required=True,maximum_whole_image_depth_qualified=False)


def inspect(base,mutate=False):
    owners=ops.inspect(base);updates=u.inspect(base);transfer=t.inspect(base);lifecycle=life.inspect(base)
    pins=specification(SPEC.read_bytes())['functions'];helpers=t.specification(t.SPEC.read_bytes())['functions']
    row=shared.catalog(shared.CATALOG.read_bytes())[3];profile=life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory=(base/row['object']).parent;data=life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image=(base/row['image']).read_bytes();raw=(directory/'normal_rust.s').read_bytes()
    require(digest(raw)==life.ASM_HASH and digest(data)==owners['object_sha256'] and digest(image)==owners['image_sha256'],'same saved setup artifacts')
    text=raw.decode();rows,funcs=shared.caller.pe.linked(image);records={};bodies={};shapes={};mutants=0
    for role,pin in pins.items():
        kind,rate=role[:-3],int(role[-3:]);code,refs=shared.caller.function(data,pin['name']);t.instructions(code,refs,pin)
        label='\n'+pin['name']+':\n';require(text.count(label)==1,'unique setup assembly body')
        start=text.index(label);body=text[start:text.index('.seh_endproc',start)]
        landmarks(kind,rate,body,helpers);bodies[role]=digest(body.encode());shapes[role]=common_shape(rate,body)
        record=ops.memory.handlers.bind(data,image,pin['name'],owners['records'].values())
        record['unwind']=shared.caller.unwind.extent(rows,funcs,record['rva'],len(code));records[role]=record
        if mutate:
            for at in range(len(code)):
                bad=bytearray(code);bad[at] ^= 1
                try: t.instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted actual setup instruction mutation')
    for kind in ('push','bits'): require(shapes[kind+'136']==shapes[kind+'168'],'identical reviewed push/bit pair shapes')
    ops.frames(records,pins)
    callees={k:transfer['records'][k] for k in ('xor','encode')}
    callees.update(zero=lifecycle['records'][ZERO],wipe=lifecycle['records'][WIPE])
    callees.update({'update'+rate:updates['records'][rate] for rate in ('136','168')})
    runtime=connections(records,owners,callees,pins)
    result=dict(schema=1,status='SAVED_SCALAR_SHA3_STREAMED_SETUP_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=bodies,geometry=geometry(life.bounded.Window(0,65536),owners),
        public_runtime_boundary_pending=runtime,actual_body_byte_mutations_rejected=mutants,
        whole_image_qualified=False,arbitrary_exception_cleanup_qualified=False,permutation_internals_qualified=False,
        native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths={Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-setup.py')))
    result['source_sha256']={p.name:digest(p.read_bytes()) for p in sorted(paths)}
    result['spec_sha256']=digest(SPEC.read_bytes());return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path);a=parser.parse_args()
    text=json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
