"""Independent SP 800-185/public framing arithmetic oracle for bounded callers."""
import itertools
import windows_enclave_sha3_simd_frame_machine as machine
RATES=(144,136,104,72,168,136,168,136)
FIXED=(224,256,384,512)


def integer(value):
    width=max(1,(value.bit_length()+7)//8)
    return bytes([width])+value.to_bytes(width,'big')


def expected(lanes,threshold):
    work=bytearray(5260);offset=0
    def word(at,value):work[at:at+8]=value.to_bytes(8,'little')
    for i,lane in enumerate(lanes):
        if lane is None:continue
        tag,message,name,custom,output=lane;rate=RATES[tag];block=rate*8
        base=3584+i*156;lengths=[0]*9
        customized=tag>=6 and (name or custom)
        if customized:
            for j,value in enumerate((rate,name,custom)):
                encoding=integer(value)
                at=base+104+j*17;work[at:at+len(encoding)]=encoding
            lengths[:5]=[8*len(integer(rate)),8*len(integer(name)),name,
                         8*len(integer(custom)),custom]
            lengths[5]=(-sum(lengths[:5]))%block
        lengths[6]=message
        lengths[7]=3 if customized or tag<4 else 5
        lengths[8]=block-sum(lengths[:8])%block
        absorbs=sum(lengths)//block
        output_bytes=(output+7)//8
        permutations=absorbs+max(output_bytes-1,0)//rate
        word(base+16,absorbs);word(base+24,permutations)
        for j,length in enumerate(lengths):word(base+32+8*j,length)
        work[base+155]=4 if customized else 6 if tag<4 else 31
        word(3520+8*i,offset);offset+=output_bytes
        work[5252+i]=int(permutations>=threshold);work[5256+i]=1
    return dict(workspace=bytes(work),output_bytes=offset,lanes=4)


def check(lines,n,lanes,threshold=1,poison=0xa5):
    actual=machine.run(lines,n,lanes,threshold,poison)
    want=expected(lanes,threshold)
    machine.s.require(all(actual[key]==value for key,value in want.items()),
                      'emitted public framing matches independent oracle')
    return actual


def cases():
    yield [None]*4,1
    for tag,rate in enumerate(RATES):
        messages=sorted({0,1,7,8,255,256,8192,rate*8-6,rate*8-5,rate*8-4,
                         rate*8-3,rate*8-2,rate*8-1,rate*8,rate*8+1})
        outputs=[FIXED[tag]] if tag<4 else [0,1,7,8,rate*8-1,rate*8,rate*8+1,2048]
        customs=[(0,0)] if tag<6 else [(0,0),(0,1),(1,0),(255,256),(256,255),
                                      (8192,8192),(0,rate*8-57),
                                      (0,rate*8-56),(0,rate*8-55)]
        for message,output,(name,custom) in itertools.product(messages,outputs,customs):
            lane=(tag,message,name,custom,output)
            # Rotate active lanes: absence before and after a present lane must
            # retain physical indices, not compact framing/output slots.
            slot=(message+name+output)%4;lanes=[None]*4;lanes[slot]=lane
            yield lanes,1
    for threshold in (0,1,2,10,100,(1<<64)-1):
        yield [(0,1149,0,0,224),(4,0,0,0,0),(6,8192,255,256,2048),
               (7,1,8192,1,1089)],threshold
