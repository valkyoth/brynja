"""Replay saved output-copy/clear instructions, recording exact public extents.

Only metadata is interpreted. Callee bodies, allocation lifetimes and the
platform ABI are prerequisites, not inferred from synthetic addresses.
"""
import windows_enclave_sha3_simd_output_model as prepare
machine,s=prepare.machine,prepare.s
STACK,STAGING,OUTPUT=4096,16384,32768
VOLATILE=('rax','rcx','rdx','r8','r9','r10','r11')


def seed(present,lengths):
    s.require(len(present)==len(lengths)==4 and all(type(v) is bool for v in present) and
        all(type(v) is int and 0<=v<=256 for v in lengths),'four caller-bounded destination descriptors')
    mem={}
    for lane in range(4):
        for offset,value in ((592+16*lane,OUTPUT+256*lane if present[lane] else 0),(600+16*lane,lengths[lane])):
            mem.update(enumerate(value.to_bytes(8,'little'),STACK+offset))
    return mem


def execute(code,n,regs,memory,entry,exits,copy_fail=None):
    regs=dict(regs);mem=dict(memory);events=[];cf=zf=None;poison=0xb7b7b7b7b7b7b7b7
    labels={line[:-1]:at for at,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique transfer labels')
    pc=labels[entry]
    def read(arg,size):
        if arg.startswith('$'):return int(arg[1:])&((1<<(8*size))-1)
        if arg.startswith('%'):
            key,width=machine.REGS[arg]
            s.require(width==size and key in regs,'initialized transfer register')
            return regs[key]&((1<<(8*size))-1)
        at=machine.address(arg,regs)
        s.require(all(at+i in mem for i in range(size)),'initialized transfer descriptor')
        return int.from_bytes(bytes(mem[at+i] for i in range(size)),'little')
    def write(reg,size,value):
        s.require(reg in machine.REGS and machine.REGS[reg][1]==size and size in (4,8),'full transfer register write')
        regs[machine.REGS[reg][0]]=value&((1<<(8*size))-1)
    for _ in range(160):
        s.require(0<=pc<len(code),'bounded transfer control flow')
        line=code[pc];pc+=1
        if line.endswith(':') or line=='nop':continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne'):
            s.require(op=='jmp' or zf is not None,'initialized transfer branch flags')
            if op=='jmp' or (zf if op=='je' else not zf):
                if a[0] in exits:return events,a[0]
                s.require(a[0] in labels,'assigned transfer branch');pc=labels[a[0]]
            continue
        if op=='callq':
            if a==[n['copy']]:
                dst,src,size=regs['rcx'],regs['r8'],regs['rdx']
                s.require(size==regs['r9'] and 0<=size<=256,'same bounded source/destination length')
                lane=(dst-OUTPUT)//256
                s.require(0<=lane<4 and dst==OUTPUT+256*lane and
                    STAGING<=src<=src+size<=STAGING+1024,'copy in original staging and one original output slot')
                events.append(('copy',lane,src-STAGING,size))
                result=8 if lane==copy_fail else 255
            else:
                s.require(a==[n['zero']],'only assigned clearing or copy callee')
                at,size=regs['rcx'],regs['rdx']
                s.require((at,size) in ((STACK+688,4),(STACK+656,32)) or
                    at in range(OUTPUT,OUTPUT+1024,256) and 0<size<=256,'clear one original output or metadata region')
                events.append(('clear',at,size));result=None
            for key in VOLATILE:regs[key]=poison
            if result is not None:regs['rax']=(poison&~255)|result
            cf=zf=None;continue
        if op in ('movq','movl'):
            size=8 if op=='movq' else 4;write(a[1],size,read(a[0],size));continue
        if op=='leaq':write(a[1],8,machine.address(a[0],regs));continue
        if op in ('testq','cmpq','cmpb'):
            size=1 if op=='cmpb' else 8;x,y=read(a[0],size),read(a[1],size)
            cf,zf=(False,(x&y)==0) if op=='testq' else (y<x,y==x);continue
        if op=='xorl':
            s.require(a[0]==a[1],'transfer zero idiom');write(a[1],4,0);cf,zf=False,True;continue
        if op=='addq':
            value=read(a[0],8)+read(a[1],8);write(a[1],8,value);cf,zf=value>prepare.MASK,value&prepare.MASK==0;continue
        raise ValueError('unassigned transfer instruction: '+line)
    raise ValueError('transfer instruction budget exhausted')


def copies(code,n,present,lengths,fail=None):
    seed(present,lengths)
    initial=prepare.evaluate(code[1482:1542],present,lengths)
    s.require(initial['accepted'],'caller lengths fit staging')
    events,edge=execute(['.entry:']+code[1542:1586]+['jmp .B269'],n,initial['registers'],initial['memory'],
        '.entry',{'.B269','.B270'},fail)
    expected=[];prefix=0
    for lane,(active,length) in enumerate(zip(present,lengths)):
        if active:
            expected.append(('copy',lane,prefix,length));prefix+=length
            if lane==fail:break
    s.require(events==expected and edge==('.B269' if fail is not None and present[fail] else '.B270'),
        'all copy arguments preserve exact lane, prefix sum, length and first failure')
    return events


def clears(code,n,present,lengths):
    regs={'rbp':STACK,'rsi':0,'rdi':STACK+656,'rbx':STACK+688}
    events,edge=execute(['.entry:']+code[549:574]+['jmp .done'],n,regs,seed(present,lengths),'.entry',{'.done'})
    want=[('clear',OUTPUT+256*i,lengths[i]) for i in range(4) if present[i] and lengths[i]]
    want += [('clear',STACK+688,4),('clear',STACK+656,32)]
    s.require(events==want and edge=='.done','four guarded descriptor clears then both metadata clears exactly once')
    return events
