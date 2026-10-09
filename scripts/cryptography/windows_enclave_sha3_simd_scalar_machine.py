"""Finite scalar-caller instruction replay, not a CPU or permutation emulator."""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_scalar_shape as shape
from windows_enclave_sha3_simd_vector_machine import STACK,WORK,INPUT,EXEC,AUTH,CONTROL,CONTEXT,CALL,MASK,transform
s=shape.s
REVALIDATE=0x90000
EXITS=('.B87','.B207','.B215','.B216','.B217','.B218','.B244')


def run(code,n,memory,writable,poison=0xa5,cancel_at=None,revoke_at=None,
        copy_failure=None,max_steps=2048):
    regs={name:poison*0x0101010101010101 for name,_ in index.REGS.values()}
    regs.update(rbp=STACK,rbx=WORK,rdi=EXEC,r12=CONTROL,r14=INPUT,r13=19)
    mem=dict(memory);cf=zf=None;events=[];polls=validations=copies=0;exit_label=None
    def get(at,size):
        s.require(all(at+i in mem for i in range(size)),'initialized scalar caller read')
        return int.from_bytes(bytes(mem[at+i] for i in range(size)),'little')
    def put(at,size,value):
        s.require(all(at+i in writable for i in range(size)),'assigned scalar caller write')
        mem.update(enumerate(value.to_bytes(size,'little'),at))
    def read(operand,size):
        if operand.startswith('$'):return int(operand[1:])&((1<<(size*8))-1)
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'scalar read width')
            return regs[index.REGS[operand][0]]&((1<<(size*8))-1)
        return get(index.address(operand,regs),size)
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'scalar write width')
            key,_=index.REGS[operand];regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:put(index.address(operand,regs),size,value)
    labels={line[:-1]:i for i,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique scalar caller labels')
    pc=0
    for steps in range(max_steps):
        if exit_label:return dict(memory=mem,registers=regs,events=events,exit=exit_label,steps=steps)
        s.require(0<=pc<len(code),'bounded scalar caller control')
        line=code[pc];pc+=1
        if line.endswith(':') or line in ('vzeroupper','nop'):continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne'):
            if op!='jmp':s.require(zf is not None,'initialized scalar flags')
            if op=='jmp' or (zf if op=='je' else not zf):
                if a[0] in EXITS:exit_label=a[0];continue
                s.require(a[0] in labels,'assigned scalar branch');pc=labels[a[0]]
            continue
        if op=='callq':
            result=None
            if a==['*912(%rbp)']:
                s.require(get(STACK+912,8)==CALL and regs['rcx']==CONTEXT,'original scalar poll/context')
                polls+=1;events.append(('poll',));result=int(polls==cancel_at)
            elif a==['*8(%rax)']:
                s.require(regs['rax']==AUTH and get(AUTH+8,8)==REVALIDATE and
                    regs['rcx']==get(AUTH+17,1),'same scalar authority revalidator and kernel')
                validations+=1;events.append(('revalidate',));result=int(validations!=revoke_at)
            elif a==[n['copy']]:
                dst,length,src,other=(regs[k] for k in ('rcx','rdx','r8','r9'))
                s.require(length==other==200 and (dst==WORK+4256 and WORK+1920<=src<=WORK+2520 or
                    src==WORK+4256 and WORK+1920<=dst<=WORK+2520),'bounded state/scalar copy')
                s.require(src+200<=dst or dst+200<=src,'disjoint scalar copy')
                copies+=1;events.append(('copy',dst,src));result=0 if copies==copy_failure else 255
                if result==255:put(dst,200,get(src,200))
            elif a==[n['scalar']]:
                s.require(tuple(regs[k] for k in ('rcx','rdx','r8','r9'))==
                    tuple(WORK+i for i in (4256,4960,5000,5040)),'four distinct scalar kernel regions')
                events.append(('scalar',));raw=get(WORK+4256,200).to_bytes(200,'little')
                put(WORK+4256,200,int.from_bytes(transform(raw),'little'))
                # Callee contract: scratch is zero on normal return. Caller
                # explicit wipes remain separately checked by the event oracle.
                put(WORK+4960,280,0)
            elif a==[shape.life.ZERO]:
                at,size=regs['rcx'],regs['rdx']
                s.require((at-WORK,size) in ((4960,40),(5000,40),(5040,200)),'scalar scratch wipe geometry')
                put(at,size,0);events.append(('wipe',at,size))
            elif a==[n['scalar_wipe']]:
                s.require(regs['rcx']==WORK+4208,'whole scalar owner wipe pointer')
                put(WORK+4208,1040,0);events.append(('owner_wipe',))
            else:raise ValueError('unassigned scalar caller callee')
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            if result is not None:regs['rax']=(regs['rax']&~255)|result
            cf=zf=None;continue
        if op=='movzbl':write(a[1],4,read(a[0],1));continue
        size={'q':8,'l':4,'b':1}.get(op[-1],0)
        if op in ('movq','movl','movb'):write(a[1],size,read(a[0],size));continue
        if op=='imulq':write(a[2],8,read(a[0],8)*read(a[1],8));cf=zf=None;continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,y&x==0);continue
        s.require(op in ('xorl','addq','incq','decq'),'assigned scalar instruction: '+op)
        dst=a[-1];y=read(dst,size);mask=(1<<(size*8))-1
        x=1 if op in ('incq','decq') else read(a[0],size)
        value=y^x if op=='xorl' else y-x if op=='decq' else y+x
        write(dst,size,value);zf=value&mask==0
    raise ValueError('bounded scalar caller instruction budget exhausted')
