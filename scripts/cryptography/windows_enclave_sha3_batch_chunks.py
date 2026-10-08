"""Sequential setup fragments, descriptor lifetimes and saved unwind selection.

Full instruction expectations are reviewed independently of candidate text.
This is not setup finalization, an OS exception dispatcher, or frame erasure.
"""
import re
import windows_enclave_sha3_batch_receive as receive

life=receive.life
s=life.s
L=receive.L


def names(bodies,lane):
    n={k:s.one(bodies,'Owner'+str(len(k))+k+'$') for k in ('operation','setup_chunk')}
    n.update(state=s.one(bodies,r'State11setup_chunk$'),mask=s.one(bodies,r'24secret_byte_mask_is_zero$'))
    if lane=='scalar':
        n.update({rate:s.one(bodies,r'SetupKj'+rate+r'_E4push') for rate in ('a8','88')})
    else:
        n.update(glue=s.one(bodies,r'drop_glue.*9OperationE'),
                 funclet=s.one(bodies,r'^\?dtor\$22@.*Owner11setup_chunk@'))
    return n


def scalar(n):
    saves=['r15','r14','r13','r12','rsi','rdi','rbp','rbx']
    result=[f'pushq %{r}' for r in saves]+L(f'''subq $88, %rsp
        movl %r9d, %ebx|movq %r8, %rdi|movq %rdx, %r8|movq %rcx, %rdx
        leaq 40(%rsp), %rcx|movb $2, %sil|movb $2, %r9b|callq {n['operation']}
        movzbl 48(%rsp), %ebp|cmpb $2, %bpl|jne .B2|movzbl 40(%rsp), %eax|jmp .B18
        .B2:|movq 40(%rsp), %r14|cmpl $1, (%r14)|jne .B15|cmpq %rdi, 8(%r14)|jne .B15
        movq 200(%rsp), %r15|movq 2376(%r14), %rax|movb $3, %sil|subq %r15, %rax
        jb .B15|movq %rax, 2376(%r14)|cmpq $7, %rdi|ja .B15
        leaq (%rdi,%rdi,2), %rax|movq 1152(%r14,%rax,8), %rax|addq $-7, %rax
        cmpq $1, %rax|ja .B7|movzbl 208(%rsp), %edi|xorl %eax, %eax
        movl %edi, %ecx|subb $1, %cl|setb %al|xorl %edx, %edx|cmpb $8, %cl|setb %dl
        testq %r15, %r15|cmovel %eax, %edx|movb $4, %sil|cmpb $1, %dl|jne .B15
        movq 192(%rsp), %r12|testq %r15, %r15|je .B10|movzbl %dil, %eax
        leaq (%rax,%r15,8), %r13|addq $-8, %r13|cmpb $7, %dil|ja .B13
        movb $-1, %dl|movl %edi, %ecx|shlb %cl, %dl|leaq (%r12,%r15), %rcx|decq %rcx
        callq {n['mask']}|testb %al, %al|je .B15|jmp .B13|.B7:|xorl %esi, %esi
        .B15:|testb $1, %bpl|jne .B17''')
    result+=life.clear('scalar','r14')+life.quarantine('scalar','r14')
    result+=L('.B17:|movl %esi, %eax|.B18:|addq $88, %rsp')+[f'popq %{r}' for r in reversed(saves)]+['retq']
    return result+L(f'''.B10:|xorl %r13d, %r13d|.B13:|movq %r15, %rax|shrq $8, %rax
        movl %r15d, %ecx|movq %r15, %rdx|shrq $56, %rdx|movb %dl, 71(%rsp)
        shrq $40, %r15|movw %r15w, 69(%rsp)|movl %eax, 65(%rsp)|movq %r13, 72(%rsp)
        movb %dil, 80(%rsp)|movq %r12, 56(%rsp)|movb %cl, 64(%rsp)
        movb $-1, %al|testq %r13, %r13|je .B18|leaq 16(%r14), %rcx
        leaq 56(%rsp), %r8|movl %ebx, %edx|callq {n['state']}
        movl %eax, %esi|movb $-1, %al|cmpb $-1, %sil|jne .B15|jmp .B18''')


def avx2(n):
    saves=['rbp','r15','r14','r13','r12','rsi','rdi','rbx']
    result=[f'pushq %{r}' for r in saves]+L(f'''subq $104, %rsp|leaq 96(%rsp), %rbp
        movq $-2, (%rbp)|movl %r9d, %ebx|movq %r8, %rsi|movq %rdx, %r8|movq %rcx, %rdx
        leaq -32(%rbp), %rcx|movb $2, %dil|movb $2, %r9b|callq {n['operation']}
        movzbl -24(%rbp), %r15d|cmpb $2, %r15b|jne .B2|movzbl -32(%rbp), %eax|jmp .B21
        .B2:|movq -32(%rbp), %r13|cmpl $1, 2232(%r13)|jne .B16|cmpq %rsi, 2240(%r13)|jne .B16
        movq 120(%rbp), %r14|movq 2216(%r13), %rax|movb $3, %dil|subq %r14, %rax
        jb .B16|movq %rax, 2216(%r13)|cmpq $7, %rsi|ja .B16
        leaq (%rsi,%rsi,2), %rax|movq 1024(%r13,%rax,8), %rax|addq $-7, %rax
        cmpq $1, %rax|ja .B7|movzbl 128(%rbp), %esi|xorl %eax, %eax
        movl %esi, %ecx|subb $1, %cl|setb %al|xorl %edx, %edx|cmpb $8, %cl|setb %dl
        testq %r14, %r14|cmovel %eax, %edx|movb $4, %dil|cmpb $1, %dl|jne .B16
        movq 112(%rbp), %r9|testq %r14, %r14|je .B10|movzbl %sil, %eax
        leaq (%rax,%r14,8), %r12|addq $-8, %r12|cmpb $7, %sil|ja .B13
        movb $-1, %dl|movl %esi, %ecx|shlb %cl, %dl|leaq (%r9,%r14), %rcx|decq %rcx
        callq {n['mask']}|movq 112(%rbp), %r9|testb %al, %al|je .B16|jmp .B13
        .B7:|xorl %edi, %edi|.B16:|testb $1, %r15b|jne .B20''')
    result+=life.clear('avx2','r13')+life.quarantine('avx2','r13',label=19)
    result+=L('.B20:|movl %edi, %eax|.B21:|addq $104, %rsp')+[f'popq %{r}' for r in reversed(saves)]+['retq']
    return result+L(f'''.B10:|xorl %r12d, %r12d|.B13:|movq %r14, %rax|shrq $8, %rax
        movl %r14d, %ecx|movq %r14, %rdx|shrq $56, %rdx|movb %dl, -49(%rbp)
        shrq $40, %r14|movw %r14w, -51(%rbp)|movl %eax, -55(%rbp)|movq %r12, -48(%rbp)
        movb %sil, -40(%rbp)|movq %r9, -64(%rbp)|movb %cl, -56(%rbp)
        movb $-1, %al|testq %r12, %r12|je .B21|movb %r15b, -1(%rbp)
        movq %r13, -16(%rbp)|leaq 1216(%r13), %rcx|leaq -64(%rbp), %r8
        movl %ebx, %edx|callq {n['state']}|nop|movb $6, %dil|cmpb $-1, %al
        movb $-1, %al|movq -16(%rbp), %r13|movzbl -1(%rbp), %r15d|jne .B16|jmp .B21''')


def bridge(n):
    return L(f'''subq $40, %rsp|movzbl (%rcx), %r9d|cmpl $8, %r9d|je .B4
        movb $2, %al|cmpl $7, %r9d|jne .B11|addq $16, %rcx|testb %dl, %dl|je .B6
        xorl %edx, %edx|jmp .B7|.B4:|addq $16, %rcx|testb %dl, %dl|je .B8
        xorl %edx, %edx|jmp .B9|.B6:|movb $1, %dl|.B7:|callq {n['a8']}|jmp .B10
        .B8:|movb $1, %dl|.B9:|callq {n['88']}|.B10:|cmpb $-1, %al|sete %al
        negb %al|orb $6, %al|.B11:|addq $40, %rsp|retq''')


def funclet(n):
    saves=['rbp','r15','r14','r13','r12','rsi','rdi','rbx']
    return L('.B22:|movq %rdx, 16(%rsp)')+[f'pushq %{r}' for r in saves]+L(f'''
        subq $40, %rsp|leaq 96(%rdx), %rbp|movq -16(%rbp), %rcx
        movzbl -1(%rbp), %edx|callq {n['glue']}|nop|addq $40, %rsp''')+[
            f'popq %{r}' for r in reversed(saves)]+['retq']


def check_shapes(bodies,lane):
    s.require(lane in life.LAYOUT,'sequential setup fragment lane');n=names(bodies,lane)
    expected={n['setup_chunk']:scalar(n) if lane=='scalar' else avx2(n)}
    if lane=='scalar':expected[n['state']]=bridge(n)
    else:expected.update({n['funclet']:funclet(n),n['glue']:life.guard('avx2')})
    for name,want in expected.items():
        s.require(life.code(bodies[name])==want,'complete setup fragment/bridge/cleanup contract')
    return n,expected


def cleanup_tables(assembly,bodies,n):
    name=n['setup_chunk'];prefix={p:p+name for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    expected={prefix['$cppxdata$']:['429065506','1',prefix['$stateUnwindMap$']+'@IMGREL',
                '0','0','3',prefix['$ip2state$']+'@IMGREL','96','0','1'],
        prefix['$stateUnwindMap$']:['-1','"'+n['funclet']+'"@IMGREL'],
        prefix['$ip2state$']:['.Lfunc_begin37@IMGREL','-1','.Ltmp10@IMGREL','0','.Ltmp11@IMGREL','-1']}
    for label,want in expected.items():
        definitions=re.findall(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',assembly,re.M)
        s.require(len(definitions)==1,'one setup cleanup table')
        s.require([l.strip().split(None,1)[1] for l in definitions[0].splitlines()]==want,'exact setup cleanup state selection')
    actual=set(re.findall(r'^(\$(?:cppxdata|stateUnwindMap|ip2state)\$'+re.escape(name)+r'[^:\n]*):',assembly,re.M))
    s.require(actual==set(expected),'complete setup cleanup table population')
    lines=s.lines(bodies[name])
    start=lines.index('.Ltmp10:');end=lines.index('.Ltmp11:')
    s.require(lines.count('.Ltmp10:')==lines.count('.Ltmp11:')==1 and lines[start+1:end]==L(
        f'leaq -64(%rbp), %r8|movl %ebx, %edx|callq {n["state"]}|nop'),
        'exact protected call interval, not just an unwind table label')
    s.require('.seh_handler __CxxFrameHandler3, @unwind, @except' in lines and
        '.long $cppxdata$'+name+'@IMGREL' in lines,'actual setup function selects its own handler metadata')
    return dict(expected_tables=expected,guard_frame_pointer_offset=96,
        guard_owner_offset=-16,guard_complete_offset=-1,protected_call=n['state'],
        cleanup_funclet=n['funclet'],bound_object_and_image_metadata_required=True,
        selected_guard_cleanup_composed=True,os_dispatcher_qualified=False)


def arguments(ir,bodies,lane):
    n=names(bodies,lane);receive.arguments(ir,receive.names(bodies,lane),lane)
    bits='ptr dead_on_return noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(32) %2)'
    a=life.LAYOUT[lane];extent=1136 if lane=='scalar' else 992
    s.require(f'(ptr noalias nofree noundef nonnull align {a["align"]} dereferenceable({extent}) %0, i1 noundef zeroext %1, '+bits in
        life.reuse.abi(ir,n['state']),'full live state and nonescaping readonly setup descriptor')
    mask=life.reuse.abi(ir,n['mask'])
    s.require('(ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) dereferenceable(1) %0, '
        'i8 noundef range(i8 -128, 0) %1)' in mask and 'nounwind' in mask,'valid last-byte pointer and high-bit mask ABI')
    if lane=='scalar':
        for rate in ('a8','88'):
            s.require('(ptr noalias nofree noundef nonnull align 16 dereferenceable(1120) %0, i8 noundef range(i8 0, 2) %1, '+bits in
                life.reuse.abi(ir,n[rate]),'complete scalar setup object and name/custom selector ABI')
    else:
        s.require('(ptr nonnull %.0.val, i8 range(i8 0, 2) %.8.val)' in life.reuse.abi(ir,n['glue']),
                  'live unwinding owner and Boolean guard completion')


def fragment(length,last,tail=0):
    """Public arithmetic model for the pinned emitted fragment-validation path."""
    s.require(0<=length<=1024 and 0<=last<=255 and 0<=tail<=255,'bounded fragment model inputs')
    carry=last==0;below=((last-1)&255)<8
    if not (carry if length==0 else below):return None
    bits=0 if length==0 else length*8+last-8
    mask=(255<<(last&31))&255 if length and last<=7 else 0
    if tail&mask:return None
    return dict(bits=bits,mask=mask,read_tail=bool(mask),tail_offset=length-1 if mask else None)


def inspect(bodies,assembly,ir,lane,prior,storage,transitions,receiver):
    s.require(prior['prior_semantics_replayed'] and storage['state_destructor']['typed_payload_cleanup_composed'] and
        storage['state_pointer_inside_owner'],'setup requires replayed helpers and placed typed cleanup')
    s.require(transitions['checked_next_sequence'] and transitions['phase_match_before_admission'] and
        transitions['unfinished_guard_clears_and_quarantines'],'setup requires composed operation guard')
    s.require(receiver['payload_pointer_retained_from_worker_buffer'] and receiver['payload_limit']==1024,
        'setup descriptor must refer to bounded copied worker input')
    n,expected=check_shapes(bodies,lane);arguments(ir,bodies,lane)
    s.require(n['setup_chunk']==receiver['functions']['setup_chunk'] and n['operation']==transitions['functions']['operation'],
        'actual receiver setup target and reviewed admission target')
    helpers=[n['mask'],life.ZERO]+([n['a8'],n['88']] if lane=='scalar' else [n['state']])
    s.require(set(helpers)<=set(prior['exact_body_reference_extent_and_abi']),'all setup lower helpers freshly replayed and exact')
    cleanup=cleanup_tables(assembly,bodies,n) if lane=='avx2' else None
    frame=88 if lane=='scalar' else 104
    regions=([[40,56],[56,88]] if lane=='scalar' else [[32,64],[64,80],[80,96],[96,104]])
    s.require(all(32<=lo<hi<=frame for lo,hi in regions) and all(a[1]<=b[0] for a,b in zip(regions,regions[1:])),
        'disjoint descriptor, result, saved guard and exception-state slots outside callee home area')
    base=0 if lane=='scalar' else 96
    incoming=[192,200,208] if lane=='scalar' else [112,120,128]
    s.require([base+x for x in incoming]==[frame+64+x for x in (40,48,56)],
        'actual incoming pointer, length and terminal-bit positions match prologue geometry')
    descriptor=56 if lane=='scalar' else 32
    s.require(descriptor%8==0 and descriptor+32<=frame,'complete aligned setup descriptor allocation')
    state=life.LAYOUT[lane]['state'];size=1136 if lane=='scalar' else 992
    s.require(state%life.LAYOUT[lane]['align']==0 and state+size<=life.LAYOUT[lane]['size'],
        'setup state argument stays inside the actual exclusive owner')
    if lane=='scalar':s.require(state+16+1120==state+size,'scalar setup payload fits the placed state')
    return dict(functions=n,instructions_and_labels={k:len(v) for k,v in expected.items()},
        exact_replayed_helpers=helpers,phase_required=2,slot_upper_bound=7,setup_identities=[7,8],
        maximum_fragment_bytes=1024,maximum_fragment_bits=8192,checked_budget_before_fragment=True,
        last_byte_read_only_after_nonempty_and_partial_checks=True,empty_fragment_skips_lower_setup=True,
        input_pointer_and_length_preserved=True,descriptor_bytes=32,descriptor_semantic_bytes=25,
        descriptor_pointer_captured=False,descriptor_referenced_input_capture_claimed=False,
        frame_bytes=frame,saved_register_bytes=64,disjoint_local_regions=regions,
        incoming_arguments_from_rsp=[base+x for x in incoming],descriptor_from_rsp=descriptor,
        normal_rejection_typed_cleanup_and_quarantine_composed=True,selected_call_unwind=cleanup,
        valid_initialized_state_required=True,setup_finalization_qualified=False,
        descriptor_padding_erased=False,private_frame_erasure_qualified=False,
        all_unwind_paths_qualified=False,whole_image_qualified=False)
