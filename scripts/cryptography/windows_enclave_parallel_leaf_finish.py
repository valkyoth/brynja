"""Actual COFF completion arithmetic, not the separately emitted .s listing.

Fixed saved-image author contracts. Offsets are instruction starts in the
bound Input::finish bodies. No generic disassembler or compiler proof is
claimed. The external __udivti3 implementation remains in package 8.
"""
import windows_enclave_parallel_inventory as inventory

require=inventory.require
MASK=(1<<64)-1
LIMIT=(1<<128)-1

# Loads/add/adc and zero-divisor rejection; construction of the full 67-bit
# B*8 divisor; q*divisor and remainder; exact used==0 and leaves==ceil(bits/B8).
# The second group is the actual right_encode loop, including its counter
# register allocation (different from the independently emitted listing).
ANCHORS={
    'scalar':[
        (0x13,'4889d74889ce498b5810488b8998040000488b96900400004801da4883d100b003'),
        (0x36,'4889969004000048898e9804000048c1eb034d8b6808b0044939dd'),
        (0x59,'4889f14889fa4d89f04989d9'),
        (0x1a0,'488b9ea0040000b0034885db'),
        (0x1b2,'4c8bb6980400004c8bae900400004989dc49c1ec3d48c1e30348895c24604c896424684c897424784c896c2470488d4c2470488d542460'),
        (0x1ee,'660f70c8ee66490f7ecf66480f7ec14c0fafe14889c848f7e34c01e2490fafdf4801d34929c54919de4531e44d09ee410f95c44901cc4983d700488b8670040000480b8678040000b002'),
        (0x23e,'488b8e800400004c31e1488b96880400004c31fa4809ca'),
        (0x293,'4981fc000100004c89f84883d800'),
        (0x2a3,'31c9b8ffff00004d89e04d89f94c89fa'),
        (0x2c0,'4d89c24d89c84d0fa4d0384989cd48c1ea0848ffc14c39d041ba000000004d19ca4989d1'),
        (0x301,'4983c5024c8d74242048bafeffffffffffff1f46886c2c204d8d45ff4a8d04edf8ffffff4531c9'),
        (0x330,'483d80000000'),
        (0x33c,'4d89e289c14d0fadfa4d89fb49d3eba8404d0f44da46885c0c204d39c8'),
        (0x35b,'4c89c94831d14c01e948c1e1034883f97f'),
        (0x378,'4d89e24d0fadfa4d89fb49d3ebf6c1404d0f44da46885c0c214983c1024883c0f04d39cd'),
        (0x39e,'418d4d01884c2431b0024983fd10'),
        (0x3ae,'440fb6c1488d5424204889f9'),
        (0x3bf,'3cff'),
        (0x3c3,'4889f1e8000000004c89f1e800000000b0ff'),
        (0x3dc,'488d4c2420ba1100000089c6e800000000ba010000004889d9e80000000089f0e96dfcffff')],
    'avx2':[
        (0x23,'4889d74889ce498b5810488b8908040000488b96000400004801da4883d100b003'),
        (0x46,'4889960004000048898e0804000048c1eb034d8b6808b0044939dd'),
        (0x69,'4889f14889fa4d89f04989d9'),
        (0x19b,'488b9e18040000b0034885db'),
        (0x1ad,'4c8ba6080400004c8bae000400004989df49c1ef3d48c1e30348895dd04c897dd84c8965c84c896dc0488d4dc0488d55d0'),
        (0x1e3,'c4c3f916c601c4e1f97ec14c0faff94889c848f7e34c01fa490fafde4801d34929c54919dc4531ff4d09ec410f95c74901cf4983d600488b86e0030000480b86e8030000b002'),
        (0x22f,'488b8ef00300004c31f9488b96f80300004c31f24809ca'),
        (0x27f,'4981ff000100004c89f04883d800'),
        (0x28f,'31c0b9ffff00004d89f84d89f14c89f2'),
        (0x2a0,'4d89c24d89c84d0fa4d0384989c448c1ea0848ffc04c39d141ba000000004d19ca4989d1'),
        (0x2e2,'4983c4024889ea46886425004d8d4424ff4a8d04e5f8ffffff4531d249b9feffffffffffff1f'),
        (0x310,'483d80000000'),
        (0x31c,'4d89fb89c14d0fadf34d89f549d3eda8404d0f44eb46886c15004d39d0'),
        (0x33b,'4c89d14c31c94c01e148c1e1034883f97f'),
        (0x358,'4d89fb4d0fadf34d89f549d3edf6c1404d0f44eb46886c15014983c2024883c0f04d39d4'),
        (0x37e,'418d44240188451141b0024983fc10'),
        (0x39b,'440fb6c04889f9'),
        (0x3a7,'41b0063cff'),
        (0x3ae,'4889f1e800000000904889e9e800000000b0ff'),
        (0x3c9,'4889e9ba110000004489c6e800000000ba010000004889d9e80000000089f0')],
}

# Explicit destinations: arithmetic, absent block, pending input and unequal
# leaf count all return an error before suffix construction or root absorption.
BRANCHES={
    'scalar':[(0x34,'72',0x6e),(0x51,'72',0x6e),(0x6c,'74',0x82),
        (0x19a,'0f85',0x6e),(0x1ac,'0f84',0x6e),(0x238,'0f85',0x6e),
        (0x255,'0f85',0x6e),(0x2a1,'72',0x305),(0x2e4,'72',0x2c0),
        (0x2ef,'0f87',0x3dc),(0x2fb,'0f87',0x3dc),(0x336,'0f83',0x401),
        (0x359,'74',0x39e),(0x36c,'0f87',0x401),(0x376,'74',0x3da),
        (0x39c,'75',0x330),(0x3ac,'77',0x3dc),(0x3c1,'75',0x3dc),
        (0x3d5,'e9',0x6e),(0x3fc,'e9',0x6e)],
    'avx2':[(0x44,'72',0x7e),(0x61,'72',0x7e),(0x7c,'74',0x92),
        (0x195,'0f85',0x7e),(0x1a7,'0f84',0x7e),(0x229,'0f85',0x7e),
        (0x246,'0f85',0x7e),(0x28d,'72',0x2e6),(0x2c4,'72',0x2a0),
        (0x2cf,'0f87',0x3c9),(0x2dc,'0f87',0x3c9),(0x316,'0f83',0x3ed),
        (0x339,'74',0x37e),(0x34c,'0f87',0x3ed),(0x356,'74',0x3c6),
        (0x37c,'75',0x310),(0x38d,'77',0x3c9),(0x399,'74',0x3c9),
        (0x3ac,'75',0x3c9),(0x3c1,'e9',0x7e),(0x3e8,'e9',0x7e)],
}


def windows(code,anchors,branches):
    for at,text in anchors:
        value=bytes.fromhex(text)
        require(code[at:at+len(value)]==value,'ParallelHash actual instruction landmark')
    for at,text,target in branches:
        op=bytes.fromhex(text);width=4 if len(op)==2 or op==b'\xe9' else 1
        end=at+len(op)+width
        require(code[at:at+len(op)]==op and len(code[at:end])==len(op)+width and
            end+int.from_bytes(code[end-width:end],'little',signed=True)==target,
            'ParallelHash actual branch destination')


def checked_total(total,additional):
    require(type(total) is int and 0<=total<=LIMIT and type(additional) is int and
        0<=additional<=MASK,'u128 total and u64 bit-string length')
    low=(total&MASK)+additional
    high=(total>>64)+(low>>64)
    require(high<=MASK,'checked adc rejects total-bit overflow')
    return (high<<64)|(low&MASK)


def completion(total,block,used,leaves):
    require(all(type(n) is int and 0<=n<=LIMIT for n in (total,used,leaves)) and
        type(block) is int and 0<block<=MASK,'completion domains and positive B')
    # Match the machine's split divisor, multiply/subtract remainder, then
    # add/adc round-up. Independent tests compare to mathematical ceil.
    divisor=((block>>61)<<64)|((block<<3)&MASK)
    quotient=total//divisor  # conditional on the separately owned runtime ABI
    lo,hi=quotient&MASK,quotient>>64
    dlo,dhi=divisor&MASK,divisor>>64
    product=lo*dlo
    product_hi=((product>>64)+lo*dhi+hi*dlo)&MASK
    remainder=(total-((product_hi<<64)|(product&MASK)))&LIMIT
    low=lo+int(remainder!=0)
    expected=(((hi+(low>>64))&MASK)<<64)|(low&MASK)
    require(used==0 and leaves==expected,'no pending bytes and exact leaf count')
    return expected


def right_encoded(value):
    require(type(value) is int and 0<=value<=LIMIT,'right-encoded u128')
    # Actual optimized counter starts at zero for values >=256, compares the
    # pre-shift value to 65535, then uses previous_counter+2.
    width=1
    if value>=256:
        shifted=value;counter=0
        while True:
            before=shifted;shifted>>=8;previous=counter;counter+=1
            if before<=65535:break
        width=previous+2
    require(1<=width<=16,'bounded encoding width')
    out=bytearray(17);out[width]=width
    index=0;shift=(width-1)*8
    while True:
        require(0<=shift<128 and index<width,'first encoding shift/store')
        out[index]=(value>>shift)&255
        if index==width-1:break
        second=(((index^((1<<61)-2))+width)<<3)&MASK
        require(0<=second<128 and index+1<width,'second encoding shift/store')
        out[index+1]=(value>>second)&255
        index+=2;shift-=16
        if index==width:break
    return bytes(out[:width+1])
