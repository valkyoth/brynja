"""Explicit broadened AVX2 copy-helper ABI and full loop review.

The leaf invariant is offset + remaining = n. Each qword iteration requires
remaining >= 8; the byte loop requires remaining > 0. Thus every access stays
within [0,n), offset never exceeds n <= isize::MAX, and zero length does not
dereference either pointer. Actual live allocations/non-overlap at each batch
call site are NOT established here; the leaf itself has no such checks.
"""
import windows_enclave_kmac_reuse as reuse

s=reuse.shapes
LEAF=s.CORE+'22secret_memory_transfer10copy_bytes'
WRAPPER=s.CORE+'13secret_memory18copy_secret_region'
OLD='range(i64 0, 1025)'
NEW='range(i64 0, -9223372036854775808)'
LEAF_CODE='''movq %rdx, %r9
movq %rcx, %r10
xorl %ecx, %ecx
movq %r8, %rdx
cmpq $8, %rdx
jb .Ltmp0
.Ltmp1:
movq (%r9,%rcx), %rax
movq %rax, (%r10,%rcx)
addq $8, %rcx
subq $8, %rdx
cmpq $8, %rdx
jae .Ltmp1
.Ltmp0:
testq %rdx, %rdx
je .Ltmp2
.Ltmp3:
movzbl (%r9,%rcx), %eax
movb %al, (%r10,%rcx)
incq %rcx
decq %rdx
jne .Ltmp3
.Ltmp2:
xorl %eax, %eax
xorl %ecx, %ecx
xorl %edx, %edx
retq'''.splitlines()
WRAPPER_CODE=['subq $40, %rsp','movb $2, %al','cmpq %r9, %rdx','jne .B2',
    'movq %rdx, %r10','movq %r8, %rdx','movq %r10, %r8','callq '+LEAF,
    'movb $-1, %al','.B2:','addq $40, %rsp','retq']


def code(body):
    return [l for l in s.lines(body)[1:]
            if not l.startswith('.') or l.startswith(('.B','.Ltmp'))]


def inspect(bodies,ir,changed):
    s.require(set(changed)=={LEAF,WRAPPER},'both and only broadened copy helpers')
    for name,expected in ((LEAF,LEAF_CODE),(WRAPPER,WRAPPER_CODE)):
        s.require(code(bodies[name])==expected,'complete broadened copy loop/wrapper')
        before,now=changed[name]['prior_abi'],reuse.abi(ir,name)
        s.require(before.count(OLD)==(1 if name==LEAF else 2),'former bounded copy lengths')
        s.require(now==changed[name]['current_abi']==before.replace(OLD,NEW),
                  'only enumerated copy length ABI broadening')
    return dict(functions=[LEAF,WRAPPER],length_min=0,length_max=(1<<63)-1,
        full_loop_and_wrapper_checked=True,zero_length_no_load_or_store=True,
        equal_lengths_checked_by_wrapper=True,offset_plus_remaining_invariant=True,
        other_abi_attributes_unchanged=True,leaf_checks_allocation_bounds=False,
        caller_allocation_lifetime_and_nonoverlap_qualified=False,
        destination_eventual_erasure_qualified=False)
