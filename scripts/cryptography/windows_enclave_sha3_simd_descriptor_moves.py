"""Byte provenance of the resident's actual four-lane input repacking.

Only moves and public address arithmetic execute. Payload bytes never enter
this model: source bytes are descriptor-field tokens, including opaque padding.
"""
import re
import windows_enclave_sha3_simd_digest as digest
import windows_enclave_sha2_index_machine as machine
s,life=digest.s,digest.life
SOURCE,FRAME=131072,65536
REGS=machine.REGS|{'%r8w':('r8',2),'%r9w':('r9',2)}


def transfer(code,lane):
    s.require(type(lane) is int and 0<=lane<4,'one bounded descriptor lane')
    start=code.index('.B4:')+1;stop=code.index('addq $112, %rax',start)
    memory={SOURCE+i:('descriptor',i) for i in range(448)};registers={};written=set()
    def number(v):return list(v.to_bytes(8,'little'))
    for key,value in dict(rdi=SOURCE,rbp=FRAME,rcx=FRAME-33,rax=104+112*lane).items():registers[key]=number(value)
    def address(arg):
        used=set(re.findall(r'%(\w+)',arg));values={}
        for key in used:
            s.require(key in registers and all(type(v) is int for v in registers[key]),'descriptor address has only public numeric provenance')
            values[key]=int.from_bytes(bytes(registers[key]),'little')
        return machine.address(arg,values)
    def get(arg,width):
        if arg.startswith('%'):
            key=arg[1:] if arg.startswith(('%ymm','%xmm')) else REGS[arg][0]
            s.require(key in registers and len(registers[key])>=width,'complete descriptor move source register')
            return registers[key][:width].copy()
        at=address(arg)
        s.require(all(at+i in memory for i in range(width)),'descriptor move reads initialized bytes')
        return [memory[at+i] for i in range(width)]
    def put(arg,width,value):
        s.require(len(value)==width,'exact byte-transfer width')
        if arg.startswith('%'):
            key=arg[1:] if arg.startswith(('%ymm','%xmm')) else REGS[arg][0]
            if width>=8 or arg.startswith(('%ymm','%xmm')):registers[key]=value.copy()
            elif width==4:registers[key]=value+[0]*4
            else:
                s.require(key in registers,'partial descriptor register was defined')
                registers[key][:width]=value
            return
        at=address(arg)
        allowed=((-64,-17),(5200,5247),(8144+112*lane,8249+112*lane))
        s.require(any(FRAME+lo<=at<at+width<=FRAME+hi for lo,hi in allowed),'only original temporary or selected-lane descriptor written')
        memory.update(enumerate(value,at));written.update(range(at,at+width))
    # These are the actual scalar field loads in B5, before identity dispatch.
    expected={
        'r8':'movq -56(%rdi,%rax), %r8','r15':'movq -24(%rdi,%rax), %r15',
        'r10':'movq -8(%rdi,%rax), %r10','r11':'movzbl (%rdi,%rax), %r11d',
        'rbx':'movzbl -104(%rdi,%rax), %ebx','r14':'movq -48(%rdi,%rax), %r14',
        'r12':'movq -16(%rdi,%rax), %r12'}
    suffix=code[code.index('.B5:'):code.index('.B11:')]
    for key,line in expected.items():
        s.require(suffix.count(line)==1,'actual typed field load before resident identity dispatch')
        op,rest=line.split(' ',1);src,dst=rest.split(', ');width=1 if op=='movzbl' else 8
        registers[key]=get(src,width)+([0]*7 if width==1 else [])
    for line in code[start:stop]:
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op=='leaq':put(a[1],8,number(address(a[0])));continue
        if op=='addq':
            s.require(a==['$-72','%r13'],'only fixed public descriptor address adjustment')
            put(a[1],8,number(int.from_bytes(bytes(get(a[1],8)),'little')-72));continue
        if op in ('movzbl','movzwl'):
            width=1 if op=='movzbl' else 2;put(a[1],4,get(a[0],width)+[0]*(4-width));continue
        s.require(op in ('vmovups','vmovaps','movq','movl','movw','movb'),'closed descriptor move instruction')
        width=(32 if any(v.startswith('%ymm') for v in a) else 16) if op.startswith('v') else {'movq':8,'movl':4,'movw':2,'movb':1}[op]
        put(a[1],width,get(a[0],width))
    begin=FRAME+8144+112*lane
    s.require([memory.get(begin+i) for i in range(105)]==[('descriptor',112*lane+i) for i in range(105)],
        'all three pointer/length/bit/last fields and identity/output width preserve exact original bytes')
    s.require(not any(begin+i in written for i in range(105,112)),'unwritten trailing padding is not claimed initialized')
    return dict(lane=lane,semantic_and_copied_bytes=105,unwritten_tail_padding=7,
        source=[112*lane,112*lane+105],destination=[8144+112*lane,8249+112*lane])
