"""Execute the saved integer-only output preflight over public descriptor shapes.

Not an x86 emulator. Unknown instructions, uninitialized reads and off-region
writes fail. No cryptographic bytes or callbacks are interpreted.
"""
import windows_enclave_sha2_index_machine as machine
import windows_enclave_sha3_simd_output as output
s=output.s
MASK=(1<<64)-1


def evaluate(code,present,lengths):
    s.require(len(present)==len(lengths)==4 and all(type(v) is bool for v in present) and
        all(type(v) is int and 0<=v<=MASK for v in lengths),'four typed output slots')
    labels={l[:-1]:i for i,l in enumerate(code) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique preflight labels')
    regs={'rbp':4096,'r12':16384};memory={};writes=[]
    def put(at,value):
        for j,b in enumerate(value.to_bytes(8,'little')):memory[at+j]=b
    for i in range(4):
        put(4096+592+16*i,32768+256*i if present[i] else 0)
        put(4096+600+16*i,lengths[i])
    writable={4096+offset+j for offset in (824,912,928,936,944,960) for j in range(8)}
    def read(arg,size):
        if arg.startswith('$'):return int(arg[1:])&((1<<(size*8))-1)
        if arg.startswith('%'):
            name,width=machine.REGS[arg]
            s.require(name in regs and width==size,'initialized public preflight register')
            return regs[name]&((1<<(size*8))-1)
        at=machine.address(arg,regs)
        s.require(all(at+j in memory for j in range(size)),'initialized public preflight memory')
        return int.from_bytes(bytes(memory[at+j] for j in range(size)),'little')
    def write(arg,size,value):
        value&=(1<<(size*8))-1
        if arg.startswith('%'):
            name,width=machine.REGS[arg];s.require(width==size and size in (4,8),'public register write width')
            regs[name]=value
        else:
            at=machine.address(arg,regs)
            s.require(size==8 and all(at+j in writable for j in range(8)),'bounded source descriptor spill')
            put(at,value);writes.append(at)
    pc=0;cf=zf=None
    for _ in range(128):
        s.require(0<=pc<len(code),'no escaped public preflight')
        line=code[pc];pc+=1
        if line=='.B257:':
            sources=[regs['r8'],read('944(%rbp)',8),read('960(%rbp)',8),regs['rbx']]
            prefix=0
            for i in range(4):
                s.require(sources[i]==(16384+prefix if present[i] else 0),'exact contiguous original staging source')
                if present[i]:
                    s.require(prefix+lengths[i]<=1024,'source bounded by complete staging')
                    prefix+=lengths[i]
            return dict(accepted=True,sources=sources,used=prefix,writes=writes,
                registers=dict(regs),memory=dict(memory))
        if line.endswith(':'):continue
        op,_,args=line.partition(' ');args=args.split(', ')
        if op in ('jmp','je','ja','jb','jbe'):
            s.require(op=='jmp' or cf is not None and zf is not None,'initialized public branch flags')
            take=op=='jmp' or dict(je=zf,ja=not cf and not zf,jb=cf,jbe=cf or zf)[op]
            if take:
                if args[0]=='.B269':return dict(accepted=False)
                s.require(args[0] in labels,'assigned local preflight target');pc=labels[args[0]]
            continue
        if op=='leaq':write(args[1],8,machine.address(args[0],regs));continue
        if op in ('movq','movl'):
            size=8 if op=='movq' else 4;write(args[1],size,read(args[0],size));continue
        if op=='xorl':
            s.require(args[0]==args[1],'assigned zero idiom');write(args[1],4,0);cf=False;zf=True;continue
        s.require(op in ('testq','cmpq','subq','addq'),'assigned public preflight instruction '+op)
        a,b=read(args[0],8),read(args[1],8)
        if op=='testq':cf=False;zf=(a&b)==0
        elif op=='cmpq':cf=b<a;zf=b==a
        else:
            value=b-a if op=='subq' else b+a
            cf=b<a if op=='subq' else value>MASK;zf=(value&MASK)==0
            write(args[1],8,value)
    raise ValueError('bounded public preflight exceeded step limit')
