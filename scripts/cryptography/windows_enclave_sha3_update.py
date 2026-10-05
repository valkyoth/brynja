"""Saved scalar sponge-update review; excludes permutation/finalize internals."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha3_prefix as p

t,state,ops,life,shared = p.t,p.state,p.ops,p.life,p.shared
require,digest = p.require,p.digest
SPEC = shared.CATALOG.with_name('sha3-update-20261005.json')
SPEC_HASH = '61dee22293eadc9bff252a53a7c8bcf8ccc1525c31e7c0c1064cba9ff091fad4'
RATES = (72,104,136,144,168)
PERMUTE,ZERO = state.s.PERMUTE,state.s.ZERO
DIV = {
 72:'movabsq $-2049638230412172401, %rcx|movq %r8, %rax|mulq %rcx|shrq $3, %rdx|andq $-8, %rdx|leaq (%rdx,%rdx,8), %rdi',
 104:'movabsq $5675921253449092805, %rcx|movq %r8, %rax|mulq %rcx|shrq $5, %rdx|imulq $104, %rdx, %rdi',
 136:'movabsq $-1085102592571150095, %rcx|movq %r8, %rax|mulq %rcx|movq %rdx, %rax|shrq $7, %rax|andq $-128, %rdx|leaq (%rdx,%rax,8), %rdi',
 144:'movabsq $-2049638230412172401, %rcx|movq %r8, %rax|mulq %rcx|shrq $3, %rdx|andq $-16, %rdx|leaq (%rdx,%rdx,8), %rdi',
 168:'movq %r8, %rax|shrq $3, %rax|movabsq $878416384462359601, %rcx|mulq %rcx|imulq $168, %rdx, %rdi',
}


def specification(raw):
    require(digest(raw)==SPEC_HASH,'reviewed sponge update specification')
    result = json.loads(raw);pins = result['functions']
    require(result['schema']==1 and set(pins)=={str(n) for n in RATES},'five rate specializations')
    for rate in RATES:
        pin = pins[str(rate)]
        require(pin['name']==state.s.UPDATE+format(rate,'x')+'_E6updateB6_' and
                pin['stack_bytes']==136 and not pin['saved_registers'],'exact update identity/frame')
    return result


def sequences(rate,helpers):
    return (
        'movq 8(%rcx), %rbx|movq (%rcx), %rdx|addq %r8, %rdx|adcq $0, %rbx|movb $1, %bpl|jb .LBBX_11',
        f'movl ${rate}, %eax|subq %rcx, %rax|cmovaeq %rax, %r12|cmpq %r12, %r8|cmovbq %r8, %r12|leaq (%r12,%rcx), %rdi|cmpq $168, %rdi|ja .LBBX_11',
        'callq '+helpers['copy']['name']+f'|cmpb $-1, %al|jne .LBBX_11|movb %dil, 1038(%rsi)|cmpq ${rate}, %rdi|jne .LBBX_10',
        'leaq -200(%r13), %rcx|movb $0, 32(%rsp)|movq %r13, %rdx|xorl %r8d, %r8d|movb $8, %r9b|callq '+helpers['xor']['name'],
        DIV[rate],
        f'cmpq ${rate}, %rbx|jne .LBBX_6|addq ${rate}, %r14|addq $-{rate}, %rdi',
        'movq %rdi, %r9|callq '+helpers['copy']['name']+'|cmpb $-1, %al|movb $1, %bpl|jne .LBBX_11|movb %dil, 1038(%rsi)',
        'movb %al, 7(%rsi)|movb %bl, 8(%rsi)|movb %bh, 9(%rsi)|movb %r11b, 10(%rsi)|movb %cl, 11(%rsi)|movb %dl, 12(%rsi)|movb %r8b, 13(%rsi)|movb %r9b, 14(%rsi)|movb %r10b, 15(%rsi)|xorl %ebp, %ebp',
    )


def normalized(body):
    return re.sub(r'\.LBB\d+_', '.LBBX_',state.s.normalized(body))


def erasures(body):
    lines = normalized(body).splitlines();sites = [i for i,v in enumerate(lines) if v=='callq '+PERMUTE]
    require(len(sites)==2,'partial and direct-block permutation population')
    for index,at in enumerate(sites):
        regs = ('%r13','%rbp','%r12') if index==0 else ('%r13','%rbp','%r15')
        expected = []
        for size,reg in zip((40,40,200),regs): expected += [f'movl ${size}, %edx',f'movq {reg}, %rcx','callq '+ZERO]
        if index==0: expected += ['movl $168, %edx','movq %r15, %rcx','callq '+ZERO,'movb $0, 1038(%rsi)']
        require(lines[at+1:at+1+len(expected)]==expected,'immediate complete permutation scratch erasure')
    return dict(permutation_sites=2,per_site_scratch_lengths=[40,40,200],partial_input_clear_bytes=168)


def landmarks(rate,body,helpers):
    text = normalized(body)
    for sequence in sequences(rate,helpers):
        require(sequence.replace('|','\n') in text,'update admission/transfer/commit sequence')


def common_shape(rate,body,name):
    text = normalized(body).replace(name,'UPDATE')
    text = re.sub(r'\.Lfunc_(begin|end)\d+',r'.Lfunc_\1X',text)
    divide = DIV[rate].replace('|','\n');require(text.count(divide)==1,'one reviewed rate division')
    text = text.replace(divide,'REVIEWED_RATE_DIVISION')
    for branch in ('jne .LBBX_10','jb .LBBX_8'):
        text = text.replace(f'cmpq ${rate}, %rdi\n'+branch,'cmpq $RATE, %rdi\n'+branch)
    for instruction in ('movl ${}, %eax','movl ${}, %edi','cmpq ${}, %rbx','addq ${}, %r14','addq $-{}, %rdi'):
        text = text.replace(instruction.format(rate),instruction.format('RATE'))
    return text.replace(f'cmpq ${rate-1}, %rdi','cmpq $RATE_MINUS_ONE, %rdi')


def block_bytes(rate,length):
    """Exact unsigned multiply-high/shift arithmetic from these emitted bodies."""
    require(rate in RATES and type(length) is int and 0<=length<1<<64,'rate/u64 domain')
    if rate in (72,144):
        high = (length*((1<<64)-2049638230412172401))>>64
        return ((high>>3) & (-8 if rate==72 else -16))*9
    if rate==104: return ((length*5675921253449092805>>64)>>5)*104
    if rate==136:
        high = length*((1<<64)-1085102592571150095)>>64
        return (high & -128)+(high>>7)*8
    return ((length>>3)*878416384462359601>>64)*168


def partition(rate,buffered,length):
    require(rate in RATES and type(buffered) is int and 0<=buffered<rate,'valid owner buffer invariant')
    require(type(length) is int and 0<=length<1<<64,'u64 input length')
    copied = min(rate-buffered,length) if buffered else 0
    used = buffered+copied
    if buffered and used!=rate:
        return dict(copied=copied,partial_permutations=0,direct_bytes=0,tail=0,used=used)
    remaining = length-copied;complete = block_bytes(rate,remaining)
    return dict(copied=copied,partial_permutations=int(bool(buffered)),direct_bytes=complete,
                tail=remaining-complete,used=remaining-complete)


def counter_admit(counter,length):
    require(type(counter) is int and 0<=counter<1<<128 and type(length) is int and 0<=length<1<<64,'counter/input domain')
    low = (counter & ((1<<64)-1))+length;high = (counter>>64)+(low>>64)
    return None if high>=1<<64 else (high<<64)|(low & ((1<<64)-1))


def connections(records,anchors,callees,pins):
    require(set(records)=={str(n) for n in RATES},'all update bodies')
    targets = {pin['name']:records[k]['rva'] for k,pin in pins.items()}
    targets.update({c['entry']:c['rva'] for c in callees.values()});expected = {c['entry'] for c in callees.values()}
    image_hash = records['72']['image_sha256'];reached = set()
    for r in records.values(): require(set(r['reference_targets'])==expected,'complete update reference closure')
    for r in (*records.values(),*anchors,*callees.values()):
        require(r['image_sha256']==image_hash,'same update/caller/callee image')
        for name,address in r['reference_targets'].items():
            if name in targets:
                require(targets[name]==address,'actual update/callee address');reached.add(name)
    require({pin['name'] for pin in pins.values()}<=reached,'all rates reached from reviewed callers')


def inspect(base,mutate=False):
    prefix = p.inspect(base);parent = state.inspect(base);transfer = t.inspect(base);lifecycle = life.inspect(base)
    pins = specification(SPEC.read_bytes())['functions'];helpers = t.specification(t.SPEC.read_bytes())['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3];profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory = (base/row['object']).parent;data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();raw = (directory/'normal_rust.s').read_bytes()
    require(digest(raw)==life.ASM_HASH and digest(data)==parent['object_sha256'] and digest(image)==parent['image_sha256'],
            'same saved update assembly/object/image')
    text = raw.decode();records = {};bodies = {};cleanups = {};shapes = [];mutants = 0
    for rate in RATES:
        role = str(rate);pin = pins[role];code,refs = shared.caller.function(data,pin['name']);t.instructions(code,refs,pin)
        label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique update assembly label')
        start = text.index(label);body = text[start:text.index('.seh_endproc',start)]
        landmarks(rate,body,helpers);cleanups[role] = erasures(body);shapes.append(common_shape(rate,body,pin['name']))
        bodies[role] = digest(body.encode());records[role] = shared.caller.bind(data,image,pin['name'])
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: t.instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted update instruction mutation')
    require(len(set(shapes))==1,'all five bodies differ only by reviewed rate arithmetic')
    ops.frames(records,pins);anchors = [*parent['records'].values(),*prefix['records'].values()]
    callees = {k:transfer['records'][k] for k in ('copy','xor')};callees['zero'] = lifecycle['records'][ZERO]
    callees['permutation'] = ops.memory.handlers.bind(data,image,PERMUTE,records.values())
    connections(records,anchors,callees,pins)
    window = life.bounded.Window(0,65536)
    update = life.bounded.Frame.enter(window,window.high+parent['geometry']['paths']['rehash -> finish_fixed']['rsp_from_high'],136)
    xor = life.bounded.Frame.enter(window,update.current,56)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_UPDATE_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=bodies,cleanup=cleanups,permutation_identity_only=callees['permutation'],
        geometry=dict(selected_update_rsp=update.current-window.high,xor_leaf_entry=xor.current-8-window.high,
            spans=[update.slot('counter low/high and tail pointer',48,24),update.slot('remaining count',40,8)],
            permutation_entry=update.unknown_callee('scalar permutation entry/home')),
        actual_body_byte_mutations_rejected=mutants,valid_buffer_invariant_required=True,whole_image_qualified=False,
        permutation_internals_qualified=False,maximum_whole_image_depth_qualified=False,arbitrary_exception_cleanup_qualified=False,
        native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-update.py')))
    result['source_sha256'] = {f.name:digest(f.read_bytes()) for f in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes());return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path);a = parser.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
