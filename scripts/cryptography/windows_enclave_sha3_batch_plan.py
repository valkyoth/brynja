"""Complete emitted sequential public-plan validator and identity dispatch."""
import re
import windows_enclave_kmac_reuse as reuse

s=reuse.shapes
EXPECTED='''pushq %rsi
pushq %rbx
movl $16, %r8d
xorl %edx, %edx
leaq TABLE(%rip), %r9
.B1:
cmpq $208, %r8
je .B16
movq -16(%rcx,%r8), %rax
cmpq $8, %rax
ja .B20
movq -8(%rcx,%r8), %r10
movzbl (%rcx,%r8), %r11d
movslq (%r9,%rax,4), %rax
addq %r9, %rax
jmpq *%rax
.B4:
cmpq $1024, %r10
jbe .B12
jmp .B18
.B5:
movl $64, %esi
jmp .B10
.B6:
movl $32, %esi
jmp .B10
.B7:
movl $48, %esi
jmp .B10
.B8:
orq %r10, %r11
je .B14
jmp .B20
.B9:
movl $28, %esi
.B10:
movb $3, %al
cmpq %rsi, %r10
jne .B21
cmpl $8, %r11d
jne .B21
.B12:
movb $4, %al
cmpb $8, %r11b
ja .B21
testq %r10, %r10
sete %bl
testb %r11b, %r11b
sete %r11b
xorb %bl, %r11b
jne .B21
.B14:
addq $24, %r8
addq %r10, %rdx
jae .B1
movb $3, %al
jmp .B21
.B16:
movb $3, %al
cmpq $1024, %rdx
ja .B21
movq 24(%rcx), %rax
orq (%rcx), %rax
movq 72(%rcx), %rdx
orq 48(%rcx), %rdx
orq 96(%rcx), %rdx
orq 120(%rcx), %rdx
orq 144(%rcx), %rdx
orq %rax, %rdx
orq 168(%rcx), %rdx
sete %al
decb %al
orb $3, %al
jmp .B21
.B18:
movb $4, %al
jmp .B21
.B20:
xorl %eax, %eax
.B21:
popq %rbx
popq %rsi
retq'''.splitlines()
TARGETS=[8,9,6,7,5,4,4,4,4]


def inspect(bodies,assembly,ir):
    name=s.one(bodies,r'Owner13validate_plan$');body=bodies[name]
    tables=re.findall(r'leaq (\.LJTI\d+_0)\(%rip\), %r9','\n'.join(s.lines(body)))
    s.require(len(tables)==1,'one sequential plan dispatch table')
    table=tables[0]
    code=[l.replace(table,'TABLE') for l in s.lines(body)[1:]
          if not l.startswith('.') or l.startswith('.B')]
    s.require(code==EXPECTED,'complete sequential plan validator including every rejection and return')
    definitions=re.findall(r'^'+re.escape(table)+r':\n((?:\s*\.long[^\n]+\n)+)',assembly,re.M)
    s.require(len(definitions)==1,'one complete identity dispatch definition')
    index=table.split('_')[0].removeprefix('.LJTI')
    actual=[re.sub(r'\s+','',l) for l in definitions[0].splitlines()]
    s.require(actual==[f'.long.LBB{index}_{n}-{table}' for n in TARGETS],
              'exact inactive/SHA-3/SHAKE/cSHAKE identity dispatch')
    abi=reuse.abi(ir,name)
    s.require('(ptr noalias nofree noundef nonnull readonly align 8 captures(none) dereferenceable(192) %0)' in abi,
              'eight exclusive public slot descriptors with full extent')
    return dict(function=name,slots=8,slot_bytes=24,total_plan_bytes=192,
        fixed_widths={'1':28,'2':32,'3':48,'4':64},xof_identities=[5,6,7,8],
        total_output_limit=1024,individual_xof_limit=1024,canonical_last_bits=[0,8],
        inactive_shape=[0,0,0],nonempty_required=True,checked_total=True,
        all_instructions_and_dispatch_cases_checked=True,batch_caller_lifetimes_qualified=False)
