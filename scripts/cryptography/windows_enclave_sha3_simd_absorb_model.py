"""Independent bitstream oracle; permutation is deliberately not modeled."""
import windows_enclave_sha3_simd_absorb_machine as machine
import windows_enclave_sha3_simd_frame_model as framing
s=machine.s
STACK,WORK,INPUT=machine.STACK,machine.WORK,machine.INPUT


def payload(length,kind,poison):
    return bytes((i*43+(i//256)*17+kind*31+poison)&255 for i in range((length+7)//8))


def parts(tag,message,name,custom,poison):
    rate=framing.RATES[tag];customized=tag>=6 and (name or custom)
    result=[(b'',0)]*6
    if customized:
        result=[(framing.integer(rate),8*len(framing.integer(rate))),
            (framing.integer(name),8*len(framing.integer(name))),
            (payload(name,1,poison),name),
            (framing.integer(custom),8*len(framing.integer(custom))),
            (payload(custom,2,poison),custom)]
        result.append((b'',(-sum(n for _,n in result))%(rate*8)))
    result+=[(payload(message,0,poison),message),
             (bytes([4 if customized else 6 if tag<4 else 31]),3 if customized or tag<4 else 5)]
    result.append((b'',rate*8-sum(n for _,n in result)%(rate*8)))
    return result


def cursor(parts,position):
    if position==0:return 0,0
    for i,(_,length) in enumerate(parts):
        if length and position<=length:return i,position
        position-=length
    raise ValueError('bit position outside independent framing')


def prepare(tag,message,name,custom,lane,block=0,poison=0xa5):
    s.require(0<=tag<8 and 0<=lane<4 and all(0<=v<=8192 for v in (message,name,custom)),
              'bounded absorption model inputs')
    output=framing.FIXED[tag] if tag<4 else 2048
    lanes=[None]*4;lanes[lane]=(tag,message,name,custom,output)
    work=bytearray(framing.expected(lanes,1)['workspace']);base=3584+156*lane
    for i in range(800):work[1920+i]=(i*73+i//200+poison)&255
    ps=parts(tag,message,name,custom,poison);width=framing.RATES[tag]*8
    total=sum(length for _,length in ps)//width
    s.require(0<=block<total,'valid independent block position')
    part,offset=cursor(ps,block*width)
    for at,value in ((base,part),(base+8,offset),(base+16,total-block)):
        work[at:at+8]=value.to_bytes(8,'little')
    mem=dict(enumerate(work,WORK));writable=set(range(WORK+1920+200*lane,WORK+2120+200*lane))
    writable.update(range(WORK+base,WORK+base+24))
    writable.update((WORK+5248+lane,WORK+5256+lane))
    def seed(at,size,value):mem.update(enumerate(value.to_bytes(size,'little'),at))
    for slot,value in ((824,WORK+3584),(960,WORK+1920),(976,0x90000),
                       (1104,WORK),(888,WORK+5248),(968,INPUT),(1120,machine.CONTROL)):
        seed(STACK+slot,8,value)
    for slot in (512,528,536,544,552,560,568,576,584,760,768,816,832,840,848,864,872,880,896,904,920,952):
        writable.update(range(STACK+slot,STACK+slot+8))
    writable.update((STACK+176,STACK-96))
    sources=[]
    for j,(offset,length) in enumerate(((0,message),(32,name),(64,custom))):
        at=0x70000+j*0x1000;sources.append(at);data=payload(length,j,poison)
        mem.update(enumerate(data,at));seed(INPUT+112*lane+offset,8,at)
        seed(INPUT+112*lane+offset+8,8,len(data))
    for i,v in enumerate(machine.shape.TARGETS):seed(machine.TABLE+4*i,4,0x100+16*v)
    for i,v in enumerate(framing.RATES):seed(machine.RATES+8*i,8,v)
    return mem,writable,ps,total,sources


def expected(mem,ps,total,sources,tag,lane,block):
    want=dict(mem);base=WORK+3584+156*lane;rate=framing.RATES[tag];position=block*rate*8
    bitstream=[]
    for i,(data,length) in enumerate(ps):
        bitstream.extend([int(i==8 and j==length-1) if i in (5,8) else data[j//8]>>(j%8)&1
                          for j in range(length)])
    for bit,value in enumerate(bitstream[position:position+rate*8]):
        want[WORK+1920+200*lane+bit//8]^=value<<(bit%8)
    # Expected call segmentation follows logical bits, not emitted registers.
    events=[];part,offset=cursor(ps,position);used=0
    while used<rate*8:
        while offset==ps[part][1]:part+=1;offset=0
        take=min(8-used%8,ps[part][1]-offset);dest=WORK+1920+200*lane+used//8
        if part not in (5,8):
            source={0:base+104,1:base+121,2:sources[1],3:base+138,4:sources[2],
                    6:sources[0],7:base+155}[part]
            done=0
            while done<take:
                right=(offset+done)%8;count=min(take-done,8-right)
                events.append((dest,source+(offset+done)//8,right,count,used%8+done,False))
                done+=count
        elif part==8:events.append((dest,STACK+176,0,take,used%8,False))
        used+=take;offset+=take
    for at,value in ((base,part),(base+8,offset),(base+16,total-block-1)):
        want.update(enumerate(value.to_bytes(8,'little'),at))
    want[WORK+5248+lane]=1;want[WORK+5256+lane]=int(block+1<total)
    return want,events


def check(code,n,tag,message,name,custom,lane,block=0,poison=0xa5):
    mem,writable,ps,total,sources=prepare(tag,message,name,custom,lane,block,poison)
    result=machine.run(code,n,mem,writable,tag,lane,poison)
    want,events=expected(mem,ps,total,sources,tag,lane,block)
    s.require(result['failure'] is None,'valid absorb block must succeed')
    s.require(result['calls']==events,'independent source-byte/bit/call segmentation')
    s.require(all(result['memory'][at]==want[at] for at in mem if not STACK-128<=at<STACK+1000),
              'exact full workspace and readonly-input absorption effects')
    expected_regs=dict(r9=lane,r8=112*lane,rdx=WORK+3624+156*lane,r14=INPUT,r12=machine.CONTROL,rbx=WORK)
    s.require(all(result['registers'][k]==v for k,v in expected_regs.items()),'absorption continuation pointers')
    return result


def cases():
    for tag,rate in enumerate(framing.RATES):
        for message,name,custom in ((0,0,0),(1,0,0),(7,0,0),(8,0,0),
            (rate*8-6,0,0),(rate*8-3,0,0),(rate*8+1,0,0),
            (17,7,9),(255,255,256),(8192,8192,8192)):
            if tag<6:name=custom=0
            total=sum(n for _,n in parts(tag,message,name,custom,0xa5))//(rate*8)
            # Walk every block for maximum-size inputs, including the middle
            # of name/customization/message; other cases cover both boundaries.
            blocks=range(total) if message==8192 else sorted({0,total-1})
            for block in blocks:
                yield dict(tag=tag,message=message,name=name,custom=custom,lane=(message+tag)%4,block=block)
