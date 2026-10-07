"""Reproduced SHA-NI fallback leaves and explicit fail-stop assignments.

Unreachable conclusions require valid typed state and the reviewed caller
admission/preservation contracts. Fatal abort never becomes successful cleanup.
"""
import re
import windows_enclave_sha2_batch_reuse as reuse
s=reuse.c.shapes
FEATURES='+cx16,+sse,+sse2,+sse3,+sahf'
SHA_FEATURES=FEATURES+(',+sha,+sse,+sse2,+sse,+sse2,+avx,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3'
    ',+avx,+avx2,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3')


def fallback_contracts(functions,previous,ir,old_ir,constants):
    result={}
    for width,offset,table in ((32,14,'anon.144b56272d44fa5dac32539943e266ef.3'),
                              (64,17,'anon.a32f23ba6f3a2c5c704bb4c9a5b3a9e4.8')):
        name=s.one(functions,r'hardened10compress'+str(width)+r'6native6scalar$')
        code,refs,kind=functions[name];old,old_refs,old_kind=previous[name]
        original=getattr(reuse.scalar.shapes,'ROUND'+str(width))
        ref=dict(offset=offset,symbol=table,trailing=0,addend=0)
        s.require(code==old and kind==old_kind and refs==[ref] and
                  old_refs==[ref|{'symbol':original}],'exact scalar fallback bytes with one named table rebind')
        before=reuse.reuse.abi(old_ir,name);after=reuse.reuse.abi(ir,name)
        token='"target-features"="'+FEATURES+'"'
        s.require(before.count(token)==1 and after==before.replace(token,'"target-features"="'+SHA_FEATURES+'"'),
                  'only explicit SHA-NI fallback target-feature ABI substitution')
        size,sha=reuse.scalar.CONSTANTS[original]
        s.require(constants[table]['bytes']==size and constants[table]['sha256']==sha,
                  'fallback round table equals reproduced scalar constants')
        result[name]=dict(bytes=len(code),sha256=reuse.digest(code),abi_sha256=reuse.digest(after.encode()),
            table=table,table_sha256=sha,explicit_feature_substitution=True)
    return result


def fallbacks(base,functions,ir,constants):
    _,old,old_ir,report=reuse.prior(base,'scalar')
    result=fallback_contracts(functions,reuse.c.previous.inventory(old),ir,old_ir,constants)
    return result,report['image_sha256']


def sha_ni_lengths(bodies):
    name=s.one(bodies,r'Engine6finish$');body=bodies[name]
    # The original width flag is a private boolean. Narrow uses 8 length
    # bytes and wide 16; the mismatch exits detect disagreement between the
    # retained flag and its later reload. Update/padding preserve that field.
    s.sequences(body,[
        '.B32:|movzbl 1970(%rcx), %r15d|testl %r15d, %r15d|movl $112, %eax|movl $56, %edi|cmovneq %rax, %rdi',
        '.B48:|cmpb $0, 1970(%rcx)|je .B51|movzbl %r15b, %eax|bswapq %r13|bswapq %r12|'
        'leaq 8(,%rax,8), %r8|movq %r12, 56(%rsp)|movq %r13, 48(%rsp)|testb %r15b, %r15b|jne .B54',
        '.B53:|movzbl %r15b, %eax|leaq 8(,%rax,8), %r8|bswapq %r12|movq %r12, 48(%rsp)|'
        'testb %al, %al|jne .B58|.B54:|addq %rdi, %rbx|leaq 48(%rsp), %rdx|movq %rbx, %rcx|callq memcpy',
        'cmpb $7, %bpl|ja .B60|movb $-128, %dl|movl %ebp, %ecx|shrb %cl, %dl'])
    rows=[]
    for wide in (0,1):
        width=8+8*wide;expected=16 if wide else 8
        s.require(width==expected,'both valid width flags match the serialized length extent')
        rows.append(dict(width_flag=wide,length_bytes=width,copy_start=112 if wide else 56,
                         block_bytes=128 if wide else 64))
    return dict(function=name,cases=rows,partial_bits=list(range(1,8)),
        private_typed_width_flag_and_helper_preservation_required=True,
        copied_length_never_exceeds_block=True,abort_cleanup_claim=False)


def inspect(bodies,lane,semantics):
    fmt=s.one(bodies,r'panicking9panic_fmt$');abort=s.one(bodies,r'rust_begin_unwind$')
    roots=[n for n in bodies if re.search(r'(?:panic_const_(?:shr|add)_overflow|len_mismatch_fail|slice_index_fail)$',n)]
    for caller,callee in [(n,fmt) for n in roots]+[(fmt,abort),(abort,'PublicProbeAbort')]:
        s.sequences(bodies[caller],['callq '+callee+'|ud2'])
        s.require('retq' not in s.lines(bodies[caller]),'fatal path is not a cleanup return')
    calls=[]
    for name,body in bodies.items():
        if name in roots+[fmt,abort]:continue
        for line in s.lines(body):
            if line.startswith(('callq ','jmp ')) and line.split(' ',1)[1] in roots+[fmt,abort]:
                calls.append((name,line.split(' ',1)[1]))
    if lane=='scalar':
        expected=[(s.one(bodies,r'10finalize'+str(w)+r'$'),s.one(bodies,r'panic_const_shr_overflow$')) for w in (32,64)]
        s.require(semantics['state_transitions']['scalar_finish']['canonical_tail_checked'] is True,
                  'scalar partial bits admitted before reproduced finalizers')
        reason='reproduced finalizers with caller-admitted canonical partial bits';lengths=None
    elif lane=='sha_ni':
        engine=s.one(bodies,r'Engine6finish$')
        expected=[(engine,s.one(bodies,p)) for p in (r'len_mismatch_fail$',r'panic_const_shr_overflow$')]
        s.require(semantics['finalizer_caller']['canonical_tail_checked'] is True and
                  semantics['finalizer']['exact_variant_widths']==[28,32],'admitted SHA-NI finalizer arguments')
        reason='stable typed width flag and caller-admitted partial bits';lengths=sha_ni_lengths(bodies)
    else:
        overflow=semantics['simd_admitted_overflow_paths']
        s.require(overflow['selected_overflow_unreachable_for_admitted_preserved_inputs'] is True,
                  'actual SIMD overflow caller proof is complete')
        expected=[(overflow['function'],s.one(bodies,r'panic_const_(?:shr|add)_overflow$'))]
        if lane=='simd256':
            s.require(semantics['simd_worker']['input_copies']['narrow_slice_failstop_precluded_by_unchanged_validated_lengths'] is True,
                      'bounded unchanged narrow worker lengths')
            expected.append((s.one(bodies,r'try_from_fn.*worker7receive'),s.one(bodies,r'slice_index_fail$')))
        reason='existing admitted-input overflow and fixed worker-slice bounds';lengths=None
    s.require(sorted(calls)==sorted(expected),'every retained private fail-stop caller assigned exactly once')
    return dict(calls=sorted(calls),basis=reason,sha_ni_length_cases=lengths,
        valid_typed_state_and_existing_caller_contracts_required=True,
        fatal_abort_is_cleanup_success=False,arbitrary_corrupted_state_guarantee=False)
