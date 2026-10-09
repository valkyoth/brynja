"""Independent grouping/charge/transfer oracle, not a permutation oracle."""
import itertools
import windows_enclave_sha3_simd_vector_machine as machine
s=machine.s
STACK,WORK,INPUT,EXEC,AUTH,CONTROL=machine.STACK,machine.WORK,machine.INPUT,machine.EXEC,machine.AUTH,machine.CONTROL
MASK=machine.MASK


def prepare(ready=(1,1,1,1),eligible=(1,1,1,1),authority=True,kernel=0,budget=20,
            charged=10,counter=17,blocks=20,accelerated=0,poison=0xa5):
    s.require(len(ready)==len(eligible)==4 and all(0<=v<256 for v in (*ready,*eligible)),
              'four public flag bytes')
    s.require(kernel in (0,1) and all(0<=v<=MASK for v in (budget,charged,counter,blocks,accelerated)),
              'bounded vector metadata')
    mem={WORK+i:(i*73+i//200+poison)&255 for i in range(5260)}
    def seed(at,size,value):mem.update(enumerate(value.to_bytes(size,'little'),at))
    for i,(r,e) in enumerate(zip(ready,eligible)):seed(WORK+5248+i,1,r);seed(WORK+5252+i,1,e)
    values={480:WORK+5252,800:AUTH if authority else 0,936:4 if kernel==0 else 2,
        928:machine.CONTEXT,912:machine.CALL,776:WORK+2720,960:WORK+1920,728:WORK+2920,
        736:WORK+3120,752:WORK+3320,1104:WORK,968:INPUT,1120:CONTROL,888:WORK+5248,
        744:blocks,856:accelerated,991:2}
    for offset,value in values.items():seed(STACK+offset,1 if offset==991 else 8,value)
    seed(EXEC,8,AUTH if authority else 0);seed(AUTH,8,counter);seed(AUTH+16,1,1);seed(AUTH+17,1,kernel)
    seed(CONTROL+16,8,budget);seed(CONTROL+24,8,charged)
    seed(STACK+176,32,int.from_bytes(bytes([poison])*32,'little'))
    writable=set(range(WORK,WORK+3520))|set(range(WORK+5248,WORK+5252))
    writable|=set(range(CONTROL+16,CONTROL+32))|set(range(AUTH,AUTH+8))|{AUTH+16,STACK+991}
    for offset,size in ((-80,8),(176,32),(520,8),(784,8),(744,8),(856,8)):writable.update(range(STACK+offset,STACK+offset+size))
    return mem,writable


def word(mem,at):return int.from_bytes(bytes(mem[at+i] for i in range(8)),'little')


def selected(ready,eligible,width):return [i for i in range(4) if ready[i]==eligible[i]==1][:width]


def check_selection(code,n,ready,eligible,authority=True,kernel=0,poison=0xa5):
    mem,writable=prepare(ready,eligible,authority,kernel,poison=poison)
    r=machine.run(code,n,mem,writable,poison=poison,selection_only=True);width=4 if kernel==0 else 2
    indices=selected(ready,eligible,width)
    exit_label='.B219' if not any(ready) else '.B190' if not authority or len(indices)<width else '.B148'
    s.require(r['exit']==exit_label and not r['events'],'selection dispatch before effects')
    if any(ready) and authority:
        s.require([word(r['memory'],STACK+176+8*i) for i in range(4)]==indices+[0]*(4-len(indices)),
                  'stable unique ready-and-eligible compaction')
    s.require(all(r['memory'][at]==value for at,value in mem.items() if not STACK<=at<STACK+208),
              'selection has no work/control/state effects')
    return r


def check(code,n,ready=(1,1,1,1),eligible=(1,1,1,1),authority=True,kernel=0,
          budget=20,charged=10,counter=17,blocks=20,accelerated=0,vector_calls=5,
          poison=0xa5,cancel=False):
    mem,writable=prepare(ready,eligible,authority,kernel,budget,charged,counter,blocks,accelerated,poison)
    r=machine.run(code,n,mem,writable,vector_calls,poison,cancel)
    want=dict(mem);events=[];width=4 if kernel==0 else 2;indices=selected(ready,eligible,width);calls=vector_calls
    def seed(at,size,value):want.update(enumerate(value.to_bytes(size,'little'),at))
    if not any(ready):exit_label='.B219'
    elif not authority or len(indices)<width:exit_label='.B190'
    else:
        events.append(('poll',))
        if cancel:exit_label='.B224'
        elif budget<width:exit_label='.B225'
        elif charged+width>MASK:exit_label='.B227'
        else:
            seed(CONTROL+16,8,budget-width);seed(CONTROL+24,8,charged+width)
            seed(WORK+2720,800,0);events.append(('wipe',))
            for slot,i in enumerate(indices):
                dst,src=WORK+2720+200*slot,WORK+1920+200*i
                for j in range(200):want[dst+j]=mem[src+j]
                events.append(('copy',dst,src))
            events.append(('session',));seed(WORK,1920,0)
            if kernel or counter==MASK:
                seed(AUTH+16,1,0);exit_label='.B226'
            else:
                seed(AUTH,8,counter+1)
                for slot,i in enumerate(indices):
                    src,dst=WORK+2720+200*slot,WORK+1920+200*i
                    raw=bytes(mem[dst+j] for j in range(200));changed=machine.transform(raw)
                    want.update(enumerate(changed,src));want.update(enumerate(changed,dst));events.append(('copy',dst,src))
                seed(STACK+856,8,accelerated|sum(1<<i for i in indices));calls=(vector_calls+1)&MASK
                if vector_calls==MASK:exit_label='.B228'
                else:
                    seed(STACK+744,8,(blocks+width)&MASK)
                    if blocks+width>MASK:exit_label='.B228'
                    else:
                        seed(STACK+991,1,kernel)
                        for i in indices:seed(WORK+5248+i,1,0)
                        exit_label='.B190'
    s.require(r['exit']==exit_label and r['events']==events,'independent vector selection/effect/error order')
    for at,value in want.items():
        if STACK-80<=at<STACK+1100 and at not in (*range(STACK+744,STACK+752),*range(STACK+856,STACK+864),STACK+991):continue
        s.require(r['memory'][at]==value,'exact vector work/state/counter/ready effect')
    s.require(r['registers']['r13']==calls,'checked vector-call report counter')
    if exit_label in ('.B190','.B219'):
        expected=dict(r14=INPUT,r12=CONTROL,rdi=EXEC,rbx=WORK,r11=WORK+5248)
        s.require(all(r['registers'][key]==value for key,value in expected.items()),
                  'vector continuation retains original input/control/executor/work pointers')
    return r


def selections():
    flags=list(itertools.product((0,1),repeat=4))
    for ready,eligible,kernel,authority in itertools.product(flags,flags,(0,1),(False,True)):
        yield ready,eligible,authority,kernel
