"""Explicit saved-helper reuse; equality of code alone is insufficient."""
import re
import windows_enclave_sha3_avx2_chain as accelerated
import windows_enclave_sha3_chain as scalar
import windows_enclave_kmac_shapes as shapes

w=accelerated.w
require=accelerated.require


def abi(ir,name):
    definitions=[l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l]
    require(len(definitions)==1,'unique helper ABI')
    line=definitions[0]
    # Attribute group numbering is compilation-local. Resolve contents instead
    # of dropping attributes, which could silently discard target contracts.
    def expand(match):
        key=match[0]
        groups=[l for l in ir.splitlines() if l.startswith('attributes '+key+' = ')]
        require(len(groups)==1,'unique resolved attribute group')
        return groups[0].split(' = ',1)[1]
    return re.sub(r'#\d+\b',expand,line)


def exact_reuse(current,prior,current_ir,prior_ir):
    reused={};changed={}
    for name,values in current.items():
        if name not in prior or values!=prior[name]: continue
        now=abi(current_ir,name);before=abi(prior_ir,name)
        if now==before: reused[name]=dict(abi_sha256=accelerated.digest(now.encode()))
        else: changed[name]=dict(prior_abi=before,current_abi=now)
    return reused,changed


def renamed_reuse(current,prior,current_ir,prior_ir,lane):
    roles=[(r'worker7BuffersE',r'worker7BuffersE','same bounded header/payload storage')]
    if lane=='scalar':
        roles.append((r'HardenedFips202OwnerKj88_E4wipe',r'HardenedFips202OwnerKj48_E4wipe',
                      'same full owner allocation erasure, independent of sponge rate'))
    else:
        roles += [(r'workerNtB2_7Buffers5clear$',r'workerNtB2_7Buffers5clear$',
                   'same bounded header/payload storage'),
                  (r'15check_authority$',r'15check_authority$','same X86Keccak authority/session contract'),
                  (r'drop_glueNtCsc.*sha3_accelerated_state5StateE',
                   r'drop_glueNtCsc.*sha3_accelerated_state5StateE',
                   'same borrowed cSHAKE state layout and exclusive ownership')]
    out={}
    for now_pattern,old_pattern,context in roles:
        now=shapes.one(current,now_pattern);old=shapes.one(prior,old_pattern)
        require(current[now]==prior[old],'renamed helper complete body/references/kind')
        actual=abi(current_ir,now);expected=abi(prior_ir,old).replace('@'+old+'(','@'+now+'(')
        require(actual==expected,'renamed helper exact resolved ABI')
        out[now]=dict(prior_name=old,context=context,abi_sha256=accelerated.digest(actual.encode()))
    return out


def inspect(base,root,lane,functions,ir,current_bodies):
    # Reproduce the previous semantic reviews and their complete source/image
    # bindings. Never accept an old report merely because it contains PASS.
    report=(scalar if lane=='scalar' else accelerated).inspect(base,root)
    row=next(r for r in w.shared.catalog(w.shared.CATALOG.read_bytes()) if r['route']==report['route'])
    profile=next(p for p in w.specification(w.SPEC.read_bytes())['profiles'] if p['route']==row['route'])
    directory=(base/row['object']).parent
    data=w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    require(accelerated.digest(data)==report['object_sha256'],'reproduced prior object')
    prior=accelerated.inventory(data)
    prior_ir=(directory/'normal_rust.ll').read_text()
    reused,changed=exact_reuse(functions,prior,ir,prior_ir)
    renamed=renamed_reuse(functions,prior,ir,prior_ir,lane)
    bodies=accelerated.s.bodies((directory/'normal_rust.s').read_text(),prior)
    specialized=prefix_specializations(current_bodies,bodies,ir,prior_ir,lane)
    expected=22 if lane=='scalar' else 20
    require(len(reused)==expected,'exact context-compatible helper population')
    expected_changed=set() if lane=='scalar' else {shapes.CORE+'17secret_memory_xor8xor_bits',
                                                  shapes.CORE+'13secret_memory20xor_secret_byte_bits'}
    require(set(changed)==expected_changed,'only explicitly reviewed helper ABI changes')
    for item in changed.values():
        require(item['current_abi']==item['prior_abi'].replace('range(i32 0, 8)','range(i32 0, 9)')
                .replace('range(i8 0, 8)','range(i8 0, 9)'), 'only checked eight-bit range broadening')
    return dict(prior_route=report['route'],prior_image_sha256=report['image_sha256'],
                reproduced_semantic_review=True,exact_body_reference_and_abi_reuse=reused,
                explicitly_rebound_renamed_helpers=renamed,
                changed_abi_checked_by_widened_xor_review=changed,
                explicitly_compared_prefix_specializations=specialized,
                callee_addresses_rebound_in_current_image=True,
                renamed_or_changed_helpers_implicitly_accepted=False)


def prefix_specializations(current,prior,current_ir,prior_ir,lane):
    """Only enumerated instruction changes; no general 'similar code' waiver.

    The old semantic review is replayed before this comparison. The current
    encoder is separately checked for left/right encoding, and renamed wipes
    for complete body/reference/ABI identity. EDI/EBX are callee-preserved in
    this Windows ABI, so moving their zero initialization across the encoding
    call preserves both the selected left encoding and the subsequent offset.
    """
    patterns=([r'19push_encoded_string',r'hardened6cshake5setup.*E4push',
               r'hardened6cshake5setup.*E7advance'] if lane=='scalar' else [r'Prefix7advance$'])
    names=[n for n in current if any(re.search(p,n) for p in patterns)]
    require(len(names)==(6 if lane=='scalar' else 1),'exact prefix specialization population')
    result={}
    def normalized(body):
        return '\n'.join(re.sub(r'\.Lfunc_begin\d+', '.Lfunc_begin',l) for l in shapes.lines(body))
    for name in names:
        require(name in prior,'previously reviewed prefix helper')
        require(abi(current_ir,name)==abi(prior_ir,name),'unchanged prefix helper ABI')
        expected=normalized(prior[name]);actual=normalized(current[name])
        if 'E4push' in name:
            require(expected.count('HardenedFips202OwnerKj48_E4wipe')==2,'both former owner wipes')
            expected=expected.replace('HardenedFips202OwnerKj48_E4wipe','HardenedFips202OwnerKj88_E4wipe')
            reason='two calls to separately rebound full-allocation wipe'
        else:
            if lane=='avx2':
                old=shapes.ENCODE.replace('11encode_u128','16left_encode_u128')
                require(expected.count('callq '+old)==1,'one former left encoder call')
                expected=expected.replace('callq '+old,'callq '+shapes.ENCODE)
            require(expected.count('callq '+shapes.ENCODE)==1,'one public encoder call')
            expected=expected.replace('callq '+shapes.ENCODE,'xorl %r9d, %r9d\ncallq '+shapes.ENCODE)
            reason='explicit false (left) selector for generic public encoder'
            if 'advance' in name:
                register='edi' if lane=='scalar' else 'ebx'
                zero=f'xorl %{register}, %{register}\n'
                require(expected.count(zero)==1,'one preserved-register initialization')
                expected=expected.replace(zero,'')
                anchor='movq 40(%rsi), %r8\n' if lane=='scalar' else 'movq 24(%rsi), %r8\n'
                require(expected.count(anchor)==1,'one exact public length preparation')
                expected=expected.replace(anchor,anchor+zero)
                reason+='; callee-preserved offset initialization moved before call'
        require(actual==expected,'only enumerated prefix specialization changes')
        result[name]=dict(reason=reason,abi_sha256=accelerated.digest(abi(current_ir,name).encode()))
    return result


def widened_xor(bodies):
    leaf=shapes.CORE+'17secret_memory_xor8xor_bits'
    wrapper=shapes.CORE+'13secret_memory20xor_secret_byte_bits'
    # The leaf performs no bounds checking: the wrapper's zero-count return
    # and offset <= 8-count checks must precede its only actual call.
    expected=['movq %rcx, %r10','movl 40(%rsp), %r11d','movzbl (%rdx), %eax',
        'movl %r8d, %ecx','shrl %cl, %eax','andl %r11d, %eax','movl %r9d, %ecx',
        'shll %cl, %eax','xorb %al, (%r10)','xorl %eax, %eax','xorl %ecx, %ecx','retq']
    require(shapes.lines(bodies[leaf])[2:]==expected,'complete widened-range XOR leaf')
    shapes.sequences(bodies[wrapper],[
        'cmpb $8, %r9b|ja .B5|movzbl 96(%rsp), %r11d|movb $8, %r10b|subb %r9b, %r10b|'
        'cmpb %r10b, %r11b|ja .B5|testb %r9b, %r9b|je .B5|cmpb %r10b, %r8b|ja .B5',
        'movb $-1, %bl|movq %rcx, %rax|movl %r10d, %ecx|shrb %cl, %bl',
        'callq '+leaf+'|xorl %eax, %eax|.B5:'])
    require(shapes.lines(bodies[wrapper]).count('callq '+leaf)==1,'one guarded XOR leaf call')
    return dict(count_maximum=8,zero_count_skips_leaf=True,
                source_and_destination_offsets_bounded_by_remaining_width=True,
                source_load_bytes=1,destination_store_bytes=1)


def encoder(bodies,lane):
    body=bodies[shapes.ENCODE];s=shapes.sequences
    s(body,['bswapq %r8|bswapq %rdx|movq %rcx, %rsi|movq %rdx, 40(%rsp)|movq %r8, 32(%rsp)',
        'movl $16, %edi|subq %rax, %rdi|leaq (%rsp,%rax), %rdx|addq $32, %rdx',
        'testb %r9b, %r9b|je .B17|leaq 48(%rsp), %rcx|movq %rdi, %r8',
        'callq memcpy|movb %dil, 48(%rsp,%rdi)|jmp .B19|.B17:|movb %dil, 48(%rsp)|leaq 49(%rsp), %rcx',
        'incl %edi|movw %di, 256(%rsi)'])
    if lane=='scalar':
        initialization=['xorps %xmm0, %xmm0']+[f'movaps %xmm0, {n}(%rsp)' for n in range(288,47,-16)]
        s(body,['|'.join(initialization),'movl $256, %r8d|movq %rsi, %rcx|callq memcpy'])
    else:
        initialization=['vxorps %xmm0, %xmm0, %xmm0']+[f'vmovups %ymm0, {n}(%rsp)' for n in range(272,47,-32)]
        s(body,['|'.join(initialization)])
        # Complete initialized buffer is copied to the returned public encoding.
        for src,dst in ((272,224),(240,192),(208,160),(176,128)):
            s(body,[f'vmovups {src}(%rsp), %ymm0|vmovups %ymm0, {dst}(%rsi)'])
        s(body,['vmovups 48(%rsp), %ymm0|vmovups 80(%rsp), %ymm1|vmovups 112(%rsp), %ymm2|'
                'vmovups 144(%rsp), %ymm3|vmovups %ymm3, 96(%rsi)|vmovups %ymm2, 64(%rsi)|'
                'vmovups %ymm1, 32(%rsi)|vmovups %ymm0, (%rsi)'])
    return dict(input='declared public u128 length',integer_byte_width=[1,16],
                maximum_encoded_width=17,initialized_buffer_bytes=256,
                left_and_right_encoding=True,secret_integer_input_qualified=False)


def scalar_construction(bodies,ir):
    """Distinct KMAC constructor/reader paths, not inherited by name alone."""
    prefix=shapes.ENCODE.replace('11encode_u128','19cshake_prefix_bytes')
    require('range(i64 136, 169)' in abi(ir,prefix),'nonzero specialized prefix rate')
    s=shapes.sequences
    for offset,source in ((34,'rsi'),(292,'rdi'),(550,'rbx')):
        s(bodies[prefix],[f'leaq {offset}(%rsp), %rcx|movq %{source}, %rdx|'
                         'xorl %r8d, %r8d|xorl %r9d, %r9d|callq '+shapes.ENCODE])
    s(bodies[prefix],[
        'addq %rbx, %rdi|setb %cl|addq %rax, %rdi|adcq $0, %rcx|addq $7, %rdi|'
        'adcq $0, %rcx|shldq $61, %rdi, %rcx',
        'divq %rsi|testq %rdx, %rdx|je .B5',
        'divl %esi|testq %rdx, %rdx|jne .B4|jmp .B5'])
    wipe=shapes.one(bodies,r'HardenedFips202OwnerKj88_E4wipe')
    constructors={}
    for strength,rate in ((128,168),(256,136)):
        name=shapes.one(bodies,rf'HardenedCshake{strength}.*8new_kmac$')
        body=bodies[name]
        s(body,[f'movl ${rate}, %ecx|movl $32, %edx|callq '+prefix,
            'movl $1040, %r8d|movq %rbx, %rcx|xorl %edx, %edx|callq memset',
            '.B14:|cmpq %r14, %'+('rbx' if strength==128 else 'rdi')+'|jne .B15',
            'leaq 408(%rsp), %rdi|movq 48(%rsp), %rcx|movl $1, %edx|callq '+shapes.ZERO,
            'movb $1, 1412(%rsp)|leaq 1(%rsi), %rcx|leaq 376(%rsp), %rdx|'
            'movl $1040, %r8d|callq memcpy|xorl %eax, %eax|jmp .B17'])
        count=shapes.normal_returns(body,'.B16',['leaq 376(%rsp), %rcx','callq '+wipe])
        shapes.normal_returns(body,'.B15',['movq 48(%rsp), %rcx','movl $1, %edx','callq '+shapes.ZERO])
        constructors[name]=dict(rate=rate,function_name_bits=32,
            failure_return_sites=count,success_copy_bytes=1040,success_copy_stack_offset=376,
            moved_from_stack_reclamation_package=8)
    reader=shapes.one(bodies,r'26take_reader_erasing_source$')
    s(bodies[reader],[
        'movq %rcx, %rsi|movb $2, (%rdx)|leaq 1(%rdx), %rdi|incq %rcx|'
        'movl $1040, %r8d|movq %rdi, %rdx|callq memcpy|movl $1040, %r8d|'
        'movq %rdi, %rcx|xorl %edx, %edx|callq memset|movq %rdi, %rcx|callq '+wipe+
        '|movb $1, (%rsi)'])
    shapes.normal_returns(bodies[reader],reader,['callq '+wipe])
    require(abi(ir,reader).count('dereferenceable(1041)')==2,'distinct full reader/source extents')
    return dict(constructors=constructors,reader_transfer=reader,reader_bytes=1041,
                source_vacated_before_transfer=True,source_wiped_after_transfer=True,
                constructor_stack_copy_individually_erased=False)
