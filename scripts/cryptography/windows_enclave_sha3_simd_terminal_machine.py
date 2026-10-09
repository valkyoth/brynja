"""Bounded public terminal-region replay. Not a general x86 emulator."""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_terminal_shape as shape
from windows_enclave_sha3_simd_reject_model import STACK,WORK,EXEC,AUTH,STAGING,RESULT,CONTROL,CONTEXT,CALLBACK,MASK
s=shape.s
INPUT,REVALIDATE=0xd0000,0xc0000
REGS=index.REGS|{'%si':('rsi',2)}


def run(code,n,memory,writable,regs,entry,exits,*,cancel=False,revalidate=True,
        poison=0xa5,helper=None,max_steps=2048):
    mem=dict(memory);regs=dict(regs);events=[];vectors={};cf=zf=None
    def get(at,size):
        s.require(all(at+i in mem for i in range(size)),'initialized terminal memory read')
        return int.from_bytes(bytes(mem[at+i] for i in range(size)),'little')
    def put(at,size,value):
        s.require(all(at+i in writable for i in range(size)),'assigned terminal write')
        mem.update(enumerate(value.to_bytes(size,'little'),at))
        if at in (EXEC+16,AUTH+16):events.append(('quarantine',at,value))
    def read(arg,size):
        if arg.startswith('$'):return int(arg[1:])&((1<<(size*8))-1)
        if arg.startswith('%'):
            if arg.startswith(('%ymm','%xmm')):
                s.require(arg in vectors,'initialized terminal vector');return vectors[arg]
            s.require(arg in REGS and REGS[arg][1]==size,'terminal register width')
            return regs[REGS[arg][0]]&((1<<(size*8))-1)
        return get(index.address(arg,regs),size)
    def write(arg,size,value):
        mask=(1<<(size*8))-1;value&=mask
        if arg.startswith('%'):
            if arg.startswith(('%ymm','%xmm')):vectors[arg]=value;return
            s.require(arg in REGS and REGS[arg][1]==size,'terminal register write width')
            key,_=REGS[arg];regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:put(index.address(arg,regs),size,value)
    def condition(op):
        s.require(cf is not None and zf is not None,'initialized terminal flags')
        return dict(e=zf,ne=not zf,b=cf,ae=not cf,a=not cf and not zf)[op]
    labels={line[:-1]:i for i,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code) and entry in labels,'unique terminal labels/entry')
    pc=labels[entry];external=None
    for steps in range(max_steps):
        if external or pc==len(code) and 'fallthrough' in exits or any(labels.get(e)==pc for e in exits):
            edge=external or next((e for e in exits if labels.get(e)==pc),'fallthrough')
            return dict(memory=mem,registers=regs,events=events,exit=edge,steps=steps)
        s.require(0<=pc<len(code),'bounded terminal control flow')
        line=code[pc];pc+=1
        if line.endswith(':') or line in ('nop','vzeroupper'):continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne','jb','jae','ja'):
            if op=='jmp' or condition(op[1:]):
                if a[0] in exits:external=a[0];continue
                s.require(a[0] in labels,'assigned terminal branch');pc=labels[a[0]]
            continue
        if op=='callq':
            result=None
            if a==['*912(%rbp)']:
                s.require(get(STACK+912,8)==CALLBACK and regs['rcx']==CONTEXT,'final original poll target/context')
                events.append(('poll',));result=int(cancel)
            elif a==['*8(%rdx)']:
                s.require(regs['rdx']==AUTH and get(AUTH+8,8)==REVALIDATE and
                    regs['rcx']==get(AUTH+17,1),'final authority callback/kernel')
                events.append(('revalidate',));result=int(revalidate)
            elif a==[n['check']]:
                s.require(regs['rcx']==EXEC,'final health original executor')
                events.append(('check',))
                child=run(helper if helper is not None else ['.entry:']+shape.check_shape()[4:-3],
                    n,mem,writable,regs|{'rbp':STACK+4096},'.entry',{'.B7'},
                    revalidate=revalidate,poison=poison)
                mem=child['memory'];events+=child['events'];result=child['registers']['rax']&255
            elif a==[n['validate']]:
                s.require(regs['rcx']==INPUT and regs['rdx']==STACK+592,'final validator original inputs/descriptors')
                result=255
                for i in range(4):
                    tag=get(INPUT+104+112*i,1);ptr=get(STACK+592+16*i,8);size=get(STACK+600+16*i,8)
                    bits=get(INPUT+96+112*i,8)
                    if (ptr!=0 if tag==255 else ptr==0 or size!=(bits+7)//8):result=8
                events.append(('validate',))
            elif a in ([n['workspace_wipe']],[shape.life.ZERO]):
                at,size=regs['rcx'],5260 if a==[n['workspace_wipe']] else regs['rdx']
                allowed=[(WORK,5260),(STAGING,1024),(STACK+688,4),(STACK+656,32)]
                allowed += [(get(STACK+592+16*i,8),get(STACK+600+16*i,8)) for i in range(4)]
                s.require((at,size) in allowed and (a!=[n['workspace_wipe']] or at==WORK),
                    'terminal exact live wipe extent')
                put(at,size,0);events.append(('wipe',at,size))
            elif a==[n['panic']]:external='panic';events.append(('panic',));continue
            else:raise ValueError('unassigned terminal callee')
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            if result is not None:regs['rax']=(regs['rax']&~255)|result
            cf=zf=None;vectors={};continue
        if op=='vmovups':
            size=32 if any(x.startswith('%ymm') for x in a) else 16
            write(a[1],size,read(a[0],size));continue
        if op=='movzbl':write(a[1],4,read(a[0],1));continue
        if op in ('setb','sete'):write(a[0],1,int(condition(op[3:])));continue
        size={'q':8,'l':4,'w':2,'b':1}.get(op[-1],0)
        if op in ('movq','movl','movw','movb','movabsq'):write(a[1],size,read(a[0],size));continue
        if op=='leal':
            # This is public error-tag arithmetic, not a pointer calculation:
            # valid error 4 deliberately computes -2 modulo 2**32.
            s.require(a==['-6(%r13)','%ecx'],'assigned terminal tag arithmetic')
            write(a[1],4,regs['r13']-6);continue
        if op=='leaq':write(a[1],size,index.address(a[0],regs));continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,y&x==0);continue
        s.require(op in ('xorl','andl','addq','sbbq','incb','shrq','shlb','shrb'),'assigned terminal instruction: '+op)
        dst=a[-1];y=read(dst,size);mask=(1<<(size*8))-1
        x=1 if op=='incb' else read(a[0],1 if a[0]=='%cl' else size)
        if op=='xorl':value=y^x;cf=False
        elif op=='andl':value=y&x;cf=False
        elif op=='sbbq':
            s.require(cf is not None,'initialized subtract-borrow flag');value=y-x-int(cf);cf=value<0
        elif op.startswith('sh'):
            shift=x&(63 if size==8 else 31)
            if not shift:continue
            value=y<<shift if op=='shlb' else y>>shift;cf=False
        else:
            value=y+x
            if op!='incb':cf=value>mask
        write(dst,size,value);zf=value&mask==0
    raise ValueError('bounded terminal instruction budget exhausted')
