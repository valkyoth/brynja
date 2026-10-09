"""Bounded vector-caller replay; permutation is an abstract reviewed callee.

The synthetic transform is ONLY a lane-provenance marker, not Keccak evidence.
The real session/transpose/kernel review must be replayed independently.
"""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_vector_shape as shape
s=shape.s
STACK,WORK,INPUT,EXEC,AUTH,CONTROL,CONTEXT,CALL=range(0x10000,0x90000,0x10000)
MASK=(1<<64)-1
EXITS=('.B190','.B219','.B214','.B224','.B225','.B226','.B227','.B228','.B233')


def transform(data):return bytes(value^((i*29+0x5b)&255) for i,value in enumerate(reversed(data)))


def run(code,n,memory,writable,vector_calls=0,poison=0xa5,cancel=False,copy_failure=None,
        session_error=None,counter_delta=1,selection_only=False,max_steps=4096):
    regs={name:poison*0x0101010101010101 for name,_ in index.REGS.values()}
    regs.update(rbp=STACK,rbx=WORK,rdi=EXEC,r12=CONTROL,r14=INPUT,r11=WORK+5248,r13=vector_calls)
    mem=dict(memory);cf=zf=None;events=[];copies=0;vectors={};exit_label=None
    def get(at,size):
        s.require(all(at+i in mem for i in range(size)),'initialized vector caller read')
        return int.from_bytes(bytes(mem[at+i] for i in range(size)),'little')
    def put(at,size,value):
        s.require(all(at+i in writable for i in range(size)),'assigned vector caller write')
        mem.update(enumerate(value.to_bytes(size,'little'),at))
    def read(operand,size):
        if operand.startswith('$'):return int(operand[1:])&((1<<(size*8))-1)
        if operand.startswith('%'):
            if operand.startswith(('%ymm','%xmm')):
                s.require(operand[2:] in vectors,'initialized vector temporary');return vectors[operand[2:]]
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'vector caller read width')
            return regs[index.REGS[operand][0]]&((1<<(size*8))-1)
        return get(index.address(operand,regs),size)
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'vector caller write width')
            key,_=index.REGS[operand];regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:put(index.address(operand,regs),size,value)
    def condition(op):
        s.require(cf is not None and zf is not None,'initialized vector caller flags')
        return {'e':zf,'ne':not zf,'b':cf,'ae':not cf,'a':not cf and not zf}[op]
    labels={line[:-1]:i for i,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique vector caller labels')
    pc=0
    for steps in range(max_steps):
        if exit_label or selection_only and pc==labels['.B148']:
            return dict(memory=mem,registers=regs,events=events,exit=exit_label or '.B148',steps=steps)
        s.require(0<=pc<len(code),'bounded vector caller control')
        line=code[pc];pc+=1
        if line.endswith(':') or line in ('vzeroupper','nop'):continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne','jb','jae','ja'):
            if op=='jmp' or condition(op[1:]):
                if a[0] in EXITS:exit_label=a[0];continue
                s.require(a[0] in labels,'assigned vector caller branch');pc=labels[a[0]]
            continue
        if op=='vxorps':
            s.require(a==['%xmm0']*3,'only zero vector initialization');vectors['mm0']=0;continue
        if op=='vmovups':write(a[1],32,read(a[0],32));continue
        if op=='callq':
            result=None
            if a==['*912(%rbp)']:
                s.require(get(STACK+912,8)==CALL and regs['rcx']==CONTEXT,'original internal poll target/context')
                events.append(('poll',));result=int(cancel)
            elif a==[shape.life.ZERO]:
                s.require(regs['rcx']==WORK+2720 and regs['rdx']==800,'entire separate group wipe')
                put(WORK+2720,800,0);events.append(('wipe',))
            elif a==[n['copy']]:
                dst,length,src,other=(regs[k] for k in ('rcx','rdx','r8','r9'))
                s.require(length==other==200 and WORK+1920<=min(src,dst) and max(src,dst)+200<=WORK+3520,
                          'bounded state/group copy lengths')
                s.require(src+200<=dst or dst+200<=src,'nonoverlap state/group copy')
                copies+=1;events.append(('copy',dst,src));result=0 if copies==copy_failure else 255
                if result==255:put(dst,200,get(src,200))
            elif a==[n['session']]:
                s.require(regs['rcx']==AUTH and regs['rdx']==WORK+2720 and regs['r8']==WORK,
                          'same authority; disjoint group and CPU scratch')
                events.append(('session',));counter=get(AUTH,8);kernel=get(AUTH+17,1)
                result=session_error if session_error is not None else 0 if kernel else 3 if counter==MASK else 255
                put(WORK,1920,0)
                if result==255:
                    for i in range(4):
                        at=WORK+2720+200*i;data=get(at,200).to_bytes(200,'little')
                        put(at,200,int.from_bytes(transform(data),'little'))
                    put(AUTH,8,(counter+counter_delta)&MASK)
                else:put(AUTH+16,1,0)
            else:raise ValueError('unassigned vector caller callee')
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            if result is not None:regs['rax']=(regs['rax']&~255)|result
            cf=zf=None;vectors={};continue
        if op=='movzbl':write(a[1],4,read(a[0],1));continue
        size={'q':8,'l':4,'b':1}.get(op[-1],0)
        if op in ('movq','movl','movb'):write(a[1],size,read(a[0],size));continue
        if op in ('leaq','leal'):write(a[1],size,index.address(a[0],regs));continue
        if op=='imulq':write(a[2],8,read(a[0],8)*read(a[1],8));cf=zf=None;continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,y&x==0);continue
        s.require(op in ('xorl','addq','subq','incq','shlb','orb'),'assigned vector caller instruction: '+op)
        dst=a[-1];y=read(dst,size);mask=(1<<(size*8))-1
        x=1 if op=='incq' else read(a[0],1 if a[0]=='%cl' else size)
        if op=='xorl':value=y^x;cf=False
        elif op=='orb':value=y|x;cf=False
        elif op=='subq':value=y-x;cf=y<x
        elif op=='shlb':
            shift=x&31
            if not shift:continue
            s.require(shift<=8,'defined vector bitmask shift');value=y<<shift;cf=bool(y>>(8-shift)&1)
        else:
            value=y+x
            if op!='incq':cf=value>mask
        write(dst,size,value);zf=value&mask==0
    raise ValueError('bounded vector caller instruction budget exhausted')
