"""Selected entry geometry/observation models, conditional on C admission."""
import windows_enclave_parallel_lifecycle_models as lifecycle

require,operand,MASK=lifecycle.require,lifecycle.operand,lifecycle.MASK


def buffers(code,lane):
    scalar=lane=='scalar';require(lane in ('scalar','avx2'),'sequential lane')
    frame=operand(code,0xa if scalar else 8,'4881ec',4)
    payload=operand(code,0x159 if scalar else 0x218,'4c8d7424' if scalar else '488d5c24',1)
    total=operand(code,0x16c if scalar else 0x22b,'41b8',4)
    endpoint=operand(code,0x1b3 if scalar else 0x277,'488d8c24',4)
    require(total==(1136 if scalar else 1152) and payload==(32 if scalar else 64) and
        endpoint==payload+total<=frame,'exact adjacent buffers fit actual allocated frame')
    require(payload>=32,'buffers exclude outgoing ABI home space')
    return dict(frame_bytes=frame,payload=[payload,payload+1024],
        header=[payload+1024,endpoint],header_bytes=total-1024,
        original_window_admission_proved=False,
        full_frame_erasure_proved=False,shared_cumulative_stack_package=8)


def entry_admits(lane,page,low,high):
    require(lane in ('scalar','avx2') and all(type(x) is int and 0<=x<=MASK
        for x in (page,low,high)),'machine address domains')
    common=bool(page and page%4096==0 and high>=low and high-low==65536)
    if lane=='scalar':return common
    return common and page<=MASK-4096 and (page+4096<=low or page>=high)


def within(address,size,low,high):
    require(all(type(x) is int and 0<=x<=MASK for x in (address,size,low,high)),
        'checked buffer address domains')
    # Mirrors unsigned no-overflow and both endpoint comparisons.
    end=(address+size)&MASK
    return address>=low and address+size<=MASK and end<=high


def observed_offsets(lane):
    """Enumerate the actual unrolled comparison loops, not just buffer length."""
    if lane=='scalar':
        index=0x403;header=[]
        while index!=0x473:
            header.extend(index+d for d in (0x1d,0x1e,0x1f,0x20));index+=4
        index=4;payload=[]
        while True:
            payload.extend(index+d for d in (0x1c,0x1d,0x1e,0x1f))
            if index==0x400:break
            payload.append(index+0x20);index+=5
        base=0x20;width=112
    else:
        require(lane=='avx2','known comparison-loop lane')
        index=0x402;header=[]
        while True:
            header.extend(index+d for d in (0x3e,0x3f))
            if index==0x480:break
            header.append(index+0x40);index+=3
        index=4;payload=[]
        while True:
            payload.extend(index+d for d in (0x3c,0x3d,0x3e,0x3f))
            if index==0x400:break
            payload.append(index+0x40);index+=5
        base=0x40;width=128
    require(payload==list(range(base,base+1024)) and header==list(range(base+1024,base+1024+width)),
        'volatile observations cover exactly both buffers without gaps or overread')
    return header+payload


def scalar_page_erase(code):
    require(code[0xbb:0xbd]==b'\x31\xd2','zero original-page erase index')
    require(code[0xd0:0xd4]==bytes.fromhex('c6041100'),'first original-page byte store')
    for offset in range(1,8):
        at=0xd4+5*(offset-1)
        require(code[at:at+5]==bytes((0xc6,0x44,0x11,offset,0)),
            'same original-page base and exact byte offset')
    require(operand(code,0xf7,'4883c2',1)==8 and operand(code,0xfb,'4881fa',4)==4096,
        'complete page erasure stride and bound')
    require(code[0x102:0x104]==bytes.fromhex('75cc'),'all iterations return to first store')
    return dict(bytes_cleared=4096,iterations=512,typed_lifetime_ends_before_clear=True,
        ordinary_return_only=True)
