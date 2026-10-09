"""Independent scalar-lane effect oracle; synthetic bytes are not crypto evidence."""
import windows_enclave_sha3_simd_scalar_machine as m
s,MASK=m.s,m.MASK


def prepare(ready=(1,1,1,1),budget=10,charged=5,blocks=8,authority=True,
            healthy=True,quarantined=False,kernel=0,poison=0xa5):
    s.require(len(ready)==4 and all(type(v) is int and 0<=v<256 for v in ready),'four scalar ready bytes')
    s.require(all(type(v) is int and 0<=v<=MASK for v in (budget,charged,blocks)) and kernel in (0,1),
              'bounded scalar public accounting')
    mem={m.WORK+i:(i*73+i//200+poison)&255 for i in range(5260)}
    def seed(at,size,value):mem.update(enumerate(value.to_bytes(size,'little'),at))
    for i,value in enumerate(ready):seed(m.WORK+5248+i,1,value)
    values={888:m.WORK+5248,928:m.CONTEXT,912:m.CALL,960:m.WORK+1920,704:m.WORK+4256,
        488:m.WORK+4960,712:m.WORK+5000,720:m.WORK+5040,496:m.WORK+4208,
        808:blocks,1104:m.WORK,504:m.WORK+3624,952:poison*0x0101010101010101}
    for offset,value in values.items():seed(m.STACK+offset,8,value)
    seed(m.EXEC,8,m.AUTH if authority else 0);seed(m.EXEC+16,1,int(quarantined))
    seed(m.AUTH,8,77);seed(m.AUTH+8,8,m.REVALIDATE);seed(m.AUTH+16,1,int(healthy));seed(m.AUTH+17,1,kernel)
    seed(m.CONTROL+16,8,budget);seed(m.CONTROL+24,8,charged)
    writable=set(range(m.WORK+1920,m.WORK+2720))|set(range(m.WORK+4208,m.WORK+5248))
    writable|=set(range(m.CONTROL+16,m.CONTROL+32))
    for offset in (808,952):writable.update(range(m.STACK+offset,m.STACK+offset+8))
    return mem,writable


def check(code,n,ready=(1,1,1,1),budget=10,charged=5,blocks=8,authority=True,
          healthy=True,quarantined=False,kernel=0,poison=0xa5,cancel_at=None,
          revoke_at=None,copy_failure=None):
    mem,writable=prepare(ready,budget,charged,blocks,authority,healthy,quarantined,kernel,poison)
    result=m.run(code,n,mem,writable,poison,cancel_at,revoke_at,copy_failure)
    want=dict(mem);events=[];polls=copies=0;exit_label='.B87'
    def seed(at,size,value):want.update(enumerate(value.to_bytes(size,'little'),at))
    for slot,flag in enumerate(ready):
        if flag!=1:continue
        polls+=1;events.append(('poll',))
        if polls==cancel_at:exit_label='.B216';break
        if budget==0:exit_label='.B217';break
        if charged==MASK:exit_label='.B207';break
        budget-=1;charged+=1;seed(m.CONTROL+16,8,budget);seed(m.CONTROL+24,8,charged)
        if quarantined:exit_label='.B218';break
        if authority:
            if not healthy:exit_label='.B215';break
            events.append(('revalidate',))
            if polls==revoke_at:exit_label='.B215';break
        state=m.WORK+1920+200*slot;owner=m.WORK+4256
        copies+=1;events.append(('copy',owner,state))
        if copies==copy_failure:exit_label='.B207';break
        raw=bytes(want[state+i] for i in range(200));want.update(enumerate(raw,owner))
        events.append(('scalar',));want.update(enumerate(m.transform(raw),owner))
        for at,size in ((4960,40),(5000,40),(5040,200)):
            seed(m.WORK+at,size,0);events.append(('wipe',m.WORK+at,size))
        copies+=1;events.append(('copy',state,owner))
        if copies==copy_failure:exit_label='.B207';break
        want.update(enumerate(m.transform(raw),state));seed(m.WORK+4208,1040,0)
        events.append(('owner_wipe',))
        if blocks==MASK:exit_label='.B244';break
        blocks+=1;seed(m.STACK+808,8,blocks)
    s.require(result['exit']==exit_label and result['events']==events,'independent scalar failure/effect ordering')
    for at,value in want.items():
        if m.STACK+952<=at<m.STACK+960:continue
        s.require(result['memory'][at]==value,'scalar state/work/scratch/readiness/accounting exact effect')
    s.require(result['registers']['rdi']==m.EXEC and result['registers']['r12']==m.CONTROL and
        result['registers']['r14']==m.INPUT and result['registers']['r13']==19,'scalar preserves enclosing vector state')
    if exit_label=='.B87':
        expected=dict(rbx=m.WORK,rsi=m.WORK+3624,r11=m.WORK+5248,rax=blocks)
        s.require(all(result['registers'][k]==v for k,v in expected.items()),'scalar absorption continuation pointers')
    if exit_label=='.B215':s.require(result['registers']['rax']==m.AUTH,'failed authority retained for rejection latch')
    return result
