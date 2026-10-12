"""Actual PE instruction/COFF-table inputs for an offline stack review.

LLVM is the instruction decoder, not a separately emitted assembler listing.
Every decoded byte is rebound to the original signed PE. Retained disassembly
may be replayed on a second host; that is not an independent decoder claim.
"""
import re
import subprocess

import windows_enclave_runtime_workers as workers
import windows_enclave_sha3_operations as tables

require=workers.require
IMAGE_BASE=0x180000000


def parse(text):
    result={}
    for line in text.splitlines():
        match=re.fullmatch(r'\s*([0-9a-f]+): ((?:[0-9a-f]{2}[ \t]+)+)(\S.*)',line)
        if not match:continue
        address=int(match[1],16)-IMAGE_BASE
        require(0<=address<1<<32 and address not in result,'unique decoded image address')
        raw=bytes.fromhex(match[2]);operation=match[3].split('#',1)[0].strip()
        operation=re.sub(r'\s+',' ',operation)
        require(0<len(raw)<=15 and '(bad)' not in operation and '<unknown>' not in operation,
            'complete supported decoded instruction')
        result[address]=(raw,operation)
    require(result,'nonempty decoded image')
    return result


def disassemble(path):
    command=['llvm-objdump','-d',str(path)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=30,check=True)
    require(len(result.stdout)<32*1024*1024,'bounded disassembly output')
    return result.stdout


def body(image,record,instructions):
    pe=int.from_bytes(image[0x3c:0x40],'little');optional=pe+24
    require(image[pe:pe+4]==b'PE\0\0' and image[optional:optional+2]==b'\x0b\x02' and
        int.from_bytes(image[optional+24:optional+32],'little')==IMAGE_BASE,
        'actual PE32+ image base matches disassembler addresses')
    rows,_=workers.catalog.sdk.pe.linked(image)
    start,end=record['rva'],record['rva']+record['size'];cursor=start;result={}
    while cursor<end:
        require(cursor in instructions,'no omitted or truncated instruction')
        raw,text=instructions[cursor]
        require(cursor+len(raw)<=end and
            workers.catalog.sdk.mapped(rows,cursor,len(raw))==raw,'decoded bytes match exact signed image')
        result[cursor-start]=(raw,text);cursor+=len(raw)
    require(cursor==end,'complete decoded function extent')
    return result


def destinations(data,image,name,record,refs):
    selected=[v for v in refs if v['symbol']=='.rdata']
    if not selected:return []
    _,_,_,_,original=workers.chain.obj.select(data,name)
    selected=[v for v in original if v['symbol']=='.rdata']
    rows,symbols=workers.chain.obj.tables(data)
    indices={v['symbol_index'] for v in selected}
    require(len(indices)==1,'one combined function dispatch section')
    symbol=symbols[indices.pop()];row=rows[symbol['section']-1]
    starts=sorted({v['addend'] for v in selected})
    require(starts[0]==0 and starts[-1]<len(row['code']),'complete table extents')
    sizes=[b-a for a,b in zip(starts,starts[1:]+[len(row['code'])])]
    pin=dict(operands=[[v['offset'],v['addend']] for v in selected],
        object_hex=row['code'].hex(),subtable_bytes=sizes)
    _,bound=tables.table(data,image,record|{'entry':name},pin)
    require(all(0<=v<record['size'] for v in bound['destinations']),'local table destinations only')
    return sorted(set(bound['destinations']))


def relative(raw,address):
    if raw[:1] in (b'\xe8',b'\xe9') and len(raw)==5:width=4
    elif len(raw)==2 and (raw[0]==0xeb or 0x70<=raw[0]<=0x7f):width=1
    elif len(raw)==6 and raw[0]==0x0f and 0x80<=raw[1]<=0x8f:width=4
    else:raise ValueError('stack decode: unsupported direct control encoding')
    return address+len(raw)+int.from_bytes(raw[-width:],'little',signed=True)


def indirect(raw,extension):
    at=1 if raw and 0x40<=raw[0]<=0x4f else 0
    require(len(raw)>=at+2 and raw[at]==0xff and (raw[at+1]>>3)&7==extension,
        'exact indirect near CALL/JMP ModRM extension')


def graph(code,rva,table_targets):
    edges={};transfers={}
    require(code and min(code)==0,'nonempty entry-zero decoded function')
    end=max(at+len(raw) for at,(raw,_) in code.items())
    for at,(raw,text) in code.items():
        op,_,operand=text.partition(' ');after=at+len(raw)
        if op=='retq':
            require(raw==b'\xc3' and not operand,'plain normal return');edges[at]=[]
        elif op in ('ud2','int3'):
            require(raw==(b'\x0f\x0b' if op=='ud2' else b'\xcc'),'explicit terminal trap');edges[at]=[]
        elif op=='callq':
            target=None if operand.startswith('*') else relative(raw,rva+at)
            if target is None:indirect(raw,2)
            else:require(raw[0]==0xe8,'direct CALL encoding')
            transfers[at]=dict(kind='call',target=target,operand=operand);edges[at]=[after]
        elif op.startswith('j'):
            if operand.startswith('*'):
                require(op=='jmpq' and table_targets,'assigned local indirect dispatch')
                indirect(raw,4)
                edges[at]=list(table_targets)
            else:
                require((op in ('jmp','jmpq') and raw[0] in (0xe9,0xeb)) or
                    (op not in ('jmp','jmpq') and
                        (0x70<=raw[0]<=0x7f or raw[:1]==b'\x0f')),
                    'direct branch text agrees with branch encoding class')
                target=relative(raw,at)
                if target in code:edges[at]=[target]
                else:
                    require(not 0<=target<end,'no branch into middle of an instruction')
                    require(op in ('jmp','jmpq'),'no conditional branch escaping function')
                    edges[at]=[];transfers[at]=dict(kind='tail',target=rva+target,operand=operand)
                if op not in ('jmp','jmpq'):edges[at].append(after)
        else:
            require(not op.startswith(('ret','iret','loop','call','lcall','sys','int')),
                'no unassigned control transfer')
            edges[at]=[after]
        require(all(v in code for v in edges[at]),'all CFG edges land on instruction starts')
    return edges,transfers
