"""Saved cSHAKE terminal-output adapter review; not complete image qualification."""
import argparse
import json
from pathlib import Path
import re
import sys

import windows_enclave_sha3_finalize as f

t,u,state,ops,life,shared = f.t,f.u,f.state,f.ops,f.life,f.shared
require,digest = f.require,f.digest
ZERO,PERMUTE,WIPE = u.ZERO,u.PERMUTE,life.s.WIPE
SPEC = shared.CATALOG.with_name('sha3-terminal-20261005.json')
SPEC_HASH = '6bf8c2fb45280e0538d54aaf3db6f7f55311b0ca4f948259bff072d86a8daeb9'


def specification(raw):
    require(digest(raw)==SPEC_HASH,'terminal adapter specification identity')
    value = json.loads(raw);pins = value['functions']
    require(value['schema']==1 and set(pins)=={'136','168'},'both terminal adapters')
    for rate,pin in pins.items():
        name = (state.s.ENTER256 if rate=='136' else state.s.ENTER128).replace('24enter_squeezing_in_place','34squeeze_final_bits_secret_in_place')
        require(pin['name']==name and pin['stack_bytes']==136 and not pin['saved_registers'],'exact adapter identity/frame')
    return value


def sequences(rate,helpers,squeeze):
    return (
        'cmpb $1, (%rdx)|jne .LBBX_31|movq %rdx, %rbx|movb $2, (%rdx)|leaq 1(%rdx), %rsi',
        'movq %r15, %rcx|movq %r14, %rdx|callq '+ZERO,
        'movq $0, 64(%rsp)|movq $1, 40(%rsp)',
        'testb $-9, %bpl|je .LBBX_4|cmpq $1, %r14|movq %r14, %r15|adcq $-1, %r15',
        'addq %r15, %rax|setb %cl|addq 17(%rbx), %rax|adcq 25(%rbx), %rcx|movb $2, %al|jb .LBBX_17',
        'callq '+squeeze+'|cmpb $-1, %al|je .LBBX_6',
        '.LBBX_17:|movb %al, 8(%rdi)|cmpq $0, 40(%rsp)|movq $2, (%rdi)|je .LBBX_30|movq 48(%rsp), %rcx|testq %rcx, %rcx|je .LBBX_30|movq 56(%rsp), %rdx|callq '+ZERO+'|jmp .LBBX_30',
        '.LBBX_31:|movb $0, 8(%rdi)|movq $2, (%rdi)',
        'cmpq $1, 40(%rsp)|jne .LBBX_23|movq 48(%rsp), %rcx|testq %rcx, %rcx|je .LBBX_27|cmpq %rbx, %r15|jne .LBBX_26|movq %rcx, 8(%rdi)|movq %r15, 16(%rdi)|movl $1, %eax',
        '.LBBX_26:|movq %rbx, %rdx|callq '+ZERO+'|.LBBX_27:|movb $4, 8(%rdi)|movl $2, %eax',
        f'movzbl 1040(%rbx), %r12d|cmpb ${rate-256}, %r12b|jbe .LBBX_10|xorl %eax, %eax|jmp .LBBX_17',
        'callq '+helpers['copy']['name']+'|movl %eax, %ecx|movb $4, %al|cmpb $-1, %cl|jne .LBBX_17|incb %r12b|movb %r12b, 1040(%rbx)',
        'movb $-1, %dl|shrb %cl, %dl|cmpb $8, %cl|movzbl %dl, %edx|cmovael %eax, %edx|movq %r14, %rcx|xorl %r8d, %r8d|callq '+helpers['mask']['name'],
        'movq 48(%rsp), %rcx|testq %rcx, %rcx|je .LBBX_16|movq 64(%rsp), %rax|movq %rax, %r15|incq %r15|je .LBBX_16|movq 56(%rsp), %rbx|cmpq %rbx, %r15|jbe .LBBX_20',
        '.LBBX_16:|movl $168, %edx|movq %r14, %rcx|callq '+ZERO+'|movb $4, %al|jmp .LBBX_17',
        'movl $1, %r8d|movq %r14, %rdx|callq '+helpers['copy_bytes']['name']+'|movl $168, %edx|movq %r14, %rcx|callq '+ZERO+'|jmp .LBBX_22')


def wipe_epilogue():
    return '.LBBX_30:|movq %rsi, %rcx|.seh_startepilogue|addq $72, %rsp|popq %rbx|popq %rbp|popq %rdi|popq %rsi|popq %r12|popq %r13|popq %r14|popq %r15|.seh_endepilogue|jmp '+WIPE


def erasure():
    return ['movl $40, %edx','movq %r12, %rcx','callq '+ZERO,
            'movl $40, %edx','movq %r13, %rcx','callq '+ZERO,
            'movl $200, %edx','leaq 833(%rbx), %rcx','callq '+ZERO,'movb $0, 1040(%rbx)']


def landmarks(rate,body,helpers,squeeze):
    text = u.normalized(body)
    for seq in (*sequences(rate,helpers,squeeze),wipe_epilogue()):
        require(seq.replace('|','\n') in text,'terminal admission/output/cleanup sequence')
    lines = text.splitlines();sites = [i for i,line in enumerate(lines) if line=='callq '+PERMUTE]
    require(len(sites)==1,'one terminal tail permutation site')
    require(lines[sites[0]+1:sites[0]+1+len(erasure())]==erasure(),'tail scratch erasure before cursor reset')


def common_shape(rate,body,name,squeeze):
    text = u.normalized(body).replace(name,'TERMINAL').replace(squeeze,'RATE_SQUEEZE')
    text = re.sub(r'\.Lfunc_(begin|end)\d+',r'.Lfunc_\1X',text)
    return text.replace(f'cmpb ${rate-256}, %r12b','cmpb $RATE_BYTE, %r12b')


def disposition(phase,length,valid,total,complete_error=False,tail_error=False,initialized=None):
    """Control-flow disposition model, not forged-pointer admission or hashing."""
    require(phase in (0,1,2) and type(length) is int and 0<=length<=1024,'reviewed phase/owner output domain')
    require((length==0 and valid==0) or (length>0 and 1<=valid<=8),'canonical output shape')
    require(type(total) is int and 0<=total<1<<128,'owned output count')
    if phase!=1: return dict(error='StateConsumed',phase=phase,clear_destination=0,wipe_owner=False,publish=False)
    complete = length-int(length>0 and valid!=8)
    error = None
    if u.counter_admit(total,complete) is None: error = 'OutputTooLong'
    elif (length>0 and complete_error) or (valid not in (0,8) and tail_error): error = 'InjectedOutputFailure'
    elif initialized is not None and initialized!=length: error = 'SecretMemory'
    return dict(error=error,phase=2,clear_destination=length,wipe_owner=True,publish=error is None,
                clear_failed_output_again=length if error else 0,complete_bytes=complete,
                tail_mask=(1<<valid)-1 if valid not in (0,8) else None)


def connections(records,owners,callees,pins):
    require(set(records)=={'136','168'},'both terminal connections')
    image_hash = owners['image_sha256'];targets = {r['entry']:r['rva'] for r in (*records.values(),*callees.values())}
    for rate,r in records.items():
        keys = ('zero','wipe','copy','copy_bytes','mask','permutation','squeeze'+rate)
        require(set(r['reference_targets'])=={callees[k]['entry'] for k in keys},'complete terminal callee closure')
        require(owners['records']['squeeze']['reference_targets'].get(pins[rate]['name'])==r['rva'],
                'actual owner-to-terminal call')
    for r in (*records.values(),*callees.values(),owners['records']['squeeze']):
        require(r['image_sha256']==image_hash,'same adapter/callee image')
        for name,address in r['reference_targets'].items():
            if name in targets: require(address==targets[name],'actual terminal helper address')


def geometry(window,owners):
    caller = window.high+owners['geometry']['paths']['squeeze']['rsp_from_high']
    frame = life.bounded.Frame.enter(window,caller,136)
    squeeze = life.bounded.Frame.enter(window,frame.current,168)
    return dict(adapter_rsp=frame.current-window.high,squeeze_rsp=squeeze.current-window.high,
        initialization=frame.slot('typed output initialization',40,32),
        permutation_entry=frame.unknown_callee('tail permutation entry/home'),
        tail_wipe_entry=window.span('restored-frame wipe entry/home',frame.entry,40),
        maximum_whole_image_depth_qualified=False,outer_window_clearing_required=True)


def inspect(base,mutate=False):
    owners = ops.inspect(base);final = f.inspect(base);transfer = t.inspect(base);lifecycle = life.inspect(base);updates = u.inspect(base)
    pins = specification(SPEC.read_bytes())['functions'];hp = t.specification(t.SPEC.read_bytes())['functions']
    row = shared.catalog(shared.CATALOG.read_bytes())[3];profile = life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory = (base/row['object']).parent;data = life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image = (base/row['image']).read_bytes();raw = (directory/'normal_rust.s').read_bytes()
    require(digest(raw)==life.ASM_HASH and digest(data)==owners['object_sha256'] and digest(image)==owners['image_sha256'],
            'same saved terminal image/object/assembly')
    text = raw.decode();rows,functions = shared.caller.pe.linked(image);records = {};bodies = {};shapes = [];mutants = 0
    for rate in ('136','168'):
        pin = pins[rate];squeeze = final['records']['squeeze'+rate]['entry'];code,refs = shared.caller.function(data,pin['name'])
        t.instructions(code,refs,pin);label = '\n'+pin['name']+':\n';require(text.count(label)==1,'unique terminal assembly label')
        start = text.index(label);body = text[start:text.index('.seh_endproc',start)]
        landmarks(int(rate),body,hp,squeeze);shapes.append(common_shape(int(rate),body,pin['name'],squeeze));bodies[rate] = digest(body.encode())
        r = ops.memory.handlers.bind(data,image,pin['name'],owners['records'].values())
        r['unwind'] = shared.caller.unwind.extent(rows,functions,r['rva'],len(code));records[rate] = r
        if mutate:
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                try: t.instructions(bad,refs,pin)
                except ValueError: mutants += 1
                else: raise AssertionError('accepted terminal instruction mutation')
    require(shapes[0]==shapes[1],'only reviewed rate/callee differences');ops.frames(records,pins)
    callees = {k:transfer['records'][k] for k in ('copy','copy_bytes','mask')}
    callees.update(zero=lifecycle['records'][ZERO],wipe=lifecycle['records'][WIPE],permutation=updates['permutation_identity_only'])
    callees.update({'squeeze'+rate:final['records']['squeeze'+rate] for rate in ('136','168')})
    connections(records,owners,callees,pins)
    result = dict(schema=1,status='SAVED_SCALAR_SHA3_TERMINAL_REVIEW',image_sha256=digest(image),object_sha256=digest(data),
        records=records,assembly_body_sha256=bodies,geometry=geometry(life.bounded.Window(0,65536),owners),
        actual_body_byte_mutations_rejected=mutants,canonical_output_and_valid_borrows_required=True,
        whole_image_qualified=False,permutation_internals_qualified=False,arbitrary_exception_cleanup_qualified=False,
        native_run_added=False,release_gate_changed=False,independently_verified=False)
    paths = {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-terminal.py')))
    result['source_sha256'] = {path.name:digest(path.read_bytes()) for path in sorted(paths)}
    result['spec_sha256'] = digest(SPEC.read_bytes());return result


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path);a = parser.parse_args()
    text = json.dumps(inspect(a.saved_directory,a.mutate),indent=2)+'\n'
    if a.output: a.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
