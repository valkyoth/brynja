"""Exact static x86 startup boundary. libc bcmp and its loader remain trusted.

Bindings use actual ELF dynamic metadata, not disassembler symbol guesses.
All startup bytes and operands stay pinned except validated link relocations.
"""
import importlib.util
import json
from pathlib import Path
import re
import struct


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


kernels=module('aes_accelerated_linked_kernels')
expansion=module('aes_accelerated_linked_expansion')
mix=module('aes_linked_mix')
require=kernels.require
TARGET='x86_64-unknown-linux-gnu'
POLICY=json.loads(Path(__file__).with_name('startup-x86-review.json').read_text())
REFERENCE={k:bytes.fromhex(v) for k,v in json.loads(Path(__file__).with_name('startup-arm-reference.json').read_text()).items()}
REGISTERS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',*(f'r{i}' for i in range(8,16)))


def candidate(table):
    pattern=r'(?:_ZN30brynja_aes_accelerated_fixture7startup17h[0-9a-f]{16}E|_RNvC\w+_30brynja_aes_accelerated_fixture7startup)'
    rows=[line for line in table.splitlines() if 'fixture7startup' in line]
    require(len(rows)==1,'startup symbol population changed')
    match=re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] ('+pattern+')',rows[0])
    require(match is not None and int(match[2],16)>0,'startup symbol changed')
    return match[3],int(match[1],16),int(match[2],16)


def bcmp_import(image):
    """Bind the GOT slot through loader-consumed PT_DYNAMIC/RELA/SYMTAB."""
    loads=mix.segments(image)
    phoff=struct.unpack_from('<Q',image,32)[0];count=struct.unpack_from('<H',image,56)[0]
    dynamic=[]
    for i in range(count):
        row=struct.unpack_from('<IIQQQQQQ',image,phoff+56*i)
        if row[0]==2:dynamic.append(row)
    require(len(dynamic)==1,'startup dynamic segment population changed')
    _,_,pos,address,_,size,_,_=dynamic[0]
    require(size>0 and size%16==0 and mix.file_offset(loads,address,size,6)==pos,
            'startup dynamic extent changed')
    tags={};metadata=[(pos,size)];ended=False
    for i in range(pos,pos+size,16):
        tag,value=struct.unpack_from('<qQ',image,i)
        if tag==0:
            require(value==0 and not any(image[i+16:pos+size]),'startup dynamic terminator changed')
            ended=True;break
        require(tag not in (17,18,19,35,36,37),'unsupported startup relocation table')
        if tag in (2,5,6,7,8,9,10,11,20,23):
            require(tag not in tags,'duplicate startup dynamic tag')
            tags[tag]=value
    require(ended and {5,6,7,8,9,10,11}<=set(tags) and tags[9]==tags[11]==24,
            'startup dynamic tables changed')
    require(tags[8]>0 and tags[8]%24==0,'startup relocation extent changed')
    rel=mix.file_offset(loads,tags[7],tags[8],4)
    strings=mix.file_offset(loads,tags[5],tags[10],4)
    metadata.extend(((rel,tags[8]),(strings,tags[10])))
    matches=[];slots=set()
    for i in range(rel,rel+tags[8],24):
        slot,info,addend=struct.unpack_from('<QQq',image,i)
        require(slot not in slots,'duplicate startup relocation slot');slots.add(slot)
        index,kind=info>>32,info&0xffffffff
        if index==0:continue
        sym=mix.file_offset(loads,tags[6]+24*index,24,4)
        name,binding,visibility,section,value,extent=struct.unpack_from('<IBBHQQ',image,sym)
        require(name<tags[10],'startup symbol string outside table')
        end=image.find(b'\0',strings+name,strings+tags[10])
        require(end>=0,'unterminated startup symbol')
        if image[strings+name:end]!=b'bcmp':continue
        require(kind==6 and addend==0 and binding==0x12 and visibility==section==value==extent==0,
                'startup bcmp import changed')
        got=mix.file_offset(loads,slot,8,6)
        require(slot%8==0 and image[got:got+8]==b'\0'*8,'startup bcmp slot changed')
        matches.append(slot);metadata.extend(((sym,24),(got,8)))
    if {2,20,23}&set(tags):
        require({2,20,23}<=set(tags) and tags[20]==7 and tags[2]>0 and tags[2]%24==0,
                'startup PLT relocation table changed')
        plt=mix.file_offset(loads,tags[23],tags[2],4)
        metadata.append((plt,tags[2]))
        for i in range(plt,plt+tags[2],24):
            slot,info,addend=struct.unpack_from('<QQq',image,i)
            require(slot not in slots and info&0xffffffff==7 and addend==0,
                    'startup PLT relocation overlap/type changed')
            slots.add(slot)
    require(len(matches)==1,'startup bcmp import population changed')
    return matches[0],metadata


def reference_at(image,loads,address,schedule):
    matches=[]
    for role,expected in REFERENCE.items():
        if role.startswith('schedule')!=schedule:continue
        try:pos=mix.file_offset(loads,address,len(expected),4)
        except ValueError:continue
        if image[pos:pos+len(expected)]==expected:matches.append((role,pos,len(expected)))
    require(len(matches)==1,'startup reference changed or not uniquely read-only mapped')
    return matches[0]


def observe(lines,raw,sizes,row,image,targets):
    require(len(lines)==len(sizes) and sum(sizes)==len(raw)==row[2]
            and all(type(n)is int and 1<=n<=15 for n in sizes),'startup instruction partition changed')
    loads=mix.segments(image);pos=mix.file_offset(loads,row[1],len(raw),5)
    require(image[pos:pos+len(raw)]==raw,'startup decoded bytes differ from executable')
    got,metadata=bcmp_import(image)
    text=list(lines);data=bytearray(raw);refs={};constants=[];cursor=0;import_register=None;import_calls=0
    vector_loads=0;addresses=0
    for i,(line,n) in enumerate(zip(lines,sizes)):
        code=raw[cursor:cursor+n]
        if '%rip' in line:
            match=re.fullmatch(r'(leaq|movq|movaps|movups|movdqa|pcmpeqb) (-?\d+)\(%rip\), %(\w+) # 0x([0-9a-f]+) <[^>]+>',line)
            require(match is not None,'unreviewed startup RIP operand')
            op,delta,register,address=match.groups();address=int(address,16)
            require(n>=5 and int.from_bytes(code[-4:],'little',signed=True)==int(delta)
                    and row[1]+cursor+n+int(delta)==address,'startup RIP destination mismatch')
            if op in ('leaq','movq'):
                require(register in REGISTERS,'startup address register changed')
                reg=REGISTERS.index(register)
                prefix=bytes((0x4c if reg>=8 else 0x48,0x8d if op=='leaq' else 0x8b,5|((reg%8)<<3)))
                if op=='leaq':
                    ref=reference_at(image,loads,address,True);addresses+=1
                    require(ref[0] not in refs or refs[ref[0]]==ref,'startup reference aliases changed')
                    refs[ref[0]]=ref;identity=ref[0]
                else:
                    require(import_register is None and address==got,'startup bcmp GOT binding changed')
                    import_register=register;identity='bcmp-import'
            else:
                require(re.fullmatch(r'xmm(?:[0-9]|1[0-5])',register) is not None,'startup vector register changed')
                reg=int(register[3:]);opcode={'movaps':0x28,'movups':0x10,'movdqa':0x6f,'pcmpeqb':0x74}[op]
                prefix=(b'\x66' if op in ('movdqa','pcmpeqb') else b'')+(b'\x44' if reg>=8 else b'')+bytes((0x0f,opcode,5|((reg%8)<<3)))
                p=mix.file_offset(loads,address,16,4);block=image[p:p+16]
                keys={bytes(range(16)):'key-first16',bytes(range(16,32)):'key-last16'}
                if block in keys:identity=keys[block]
                else:
                    ref=reference_at(image,loads,address,False)
                    require(ref[0] not in refs or refs[ref[0]]==ref,'startup reference aliases changed')
                    refs[ref[0]]=ref;identity=ref[0]
                constants.append((p,16));vector_loads+=1
            require(code[:-4]==prefix,'startup RIP encoding/operand mismatch')
            data[cursor+n-4:cursor+n]=b'\0'*4
            text[i]=f'{op} @reference[{identity}], %{register}'
        elif line.startswith('callq *'):
            require(import_register is not None and line=='callq *%'+import_register,
                    'startup imported call register changed')
            reg=REGISTERS.index(import_register)
            expected=(b'\x41' if reg>=8 else b'')+bytes((0xff,0xd0+(reg%8)))
            require(code==expected,'startup imported call encoding mismatch')
            text[i]='bound-import-call bcmp, %'+import_register;import_calls+=1
        cursor+=n
    require(import_calls==3 and set(refs)==set(REFERENCE),'startup import/reference population changed')
    shadow=image[:pos]+data+image[pos+len(data):]
    actual,other=mix.observe(text,bytes(data),sizes,row[0],row[1],shadow,targets)
    require(not other,'unconsumed startup constants')
    actual.update(reference_addresses=addresses,vector_references=vector_loads,import_calls=import_calls)
    return actual,[*constants,*[(p,n) for _,p,n in refs.values()]],list(refs.values()),metadata


def check(lines,raw,sizes,row,image,targets,compiler,panic):
    require(compiler in POLICY and panic in ('abort','unwind'),'unreviewed x86 startup configuration')
    require(set(targets)=={k+str(b) for k in ('expand','round') for b in (128,192,256)},'startup call population changed')
    ordered=sorted([row,*targets.values()],key=lambda r:r[1])
    require(all(r[2]>0 for r in ordered) and all(a[1]+a[2]<=b[1] for a,b in zip(ordered,ordered[1:])),
            'startup overlapping body extents')
    actual,_,_,_=observe(lines,raw,sizes,row,image,targets)
    require(actual==POLICY[compiler][panic],'startup stream changed; explicit review required')
    return actual


def inspect(table,assembly,image,compiler,panic):
    require(compiler in POLICY and panic in ('abort','unwind'),'unreviewed x86 startup configuration')
    row=candidate(table)
    dependencies={'rounds':kernels.inspect(table,assembly,image,TARGET),
                  'expansion':expansion.inspect(table,assembly,image,TARGET)}
    targets={}
    for kind,reviewer in (('round',kernels),('expand',expansion)):
        for target in reviewer.select(table,TARGET):
            bits=reviewer.check(*kernels.decode(assembly,target,TARGET),target,image,TARGET)['bits']
            require(kind+str(bits) not in targets,'duplicate startup kernel width')
            targets[kind+str(bits)]=target
    args=(*kernels.decode(assembly,row,TARGET),row,image,targets,compiler,panic)
    result=check(*args)
    lines,raw,sizes=args[:3];pos=mix.file_offset(mix.segments(image),row[1],row[2],5)
    rejected=0
    for i in range(len(lines)+len(raw)):
        text,data,binary=list(lines),raw,image
        if i<len(lines):text[i]='unreviewed-instruction'
        else:
            j=i-len(lines);data=raw[:j]+bytes([raw[j]^1])+raw[j+1:]
            binary=image[:pos]+data+image[pos+len(data):]
        try:check(text,data,sizes,row,binary,targets,compiler,panic)
        except ValueError:rejected+=1
        else:raise ValueError('startup code mutation accepted')
    _,constants,refs,metadata=observe(*args[:-2])
    offsets=sorted({p+i for p,n in constants for i in range(n)})
    for p in offsets:
        binary=image[:p]+bytes([image[p]^1])+image[p+1:]
        try:check(*args[:4],binary,*args[5:])
        except ValueError:pass
        else:raise ValueError('startup constant mutation accepted')
    return dict(body=result,rejected_code_mutations=rejected,rejected_constant_mutations=len(offsets),
                references=[dict(role=r,offset=p,size=n) for r,p,n in refs],dependencies=dependencies,
                runtime_dependency='libc bcmp and the dynamic loader are trusted; import binding is not libc qualification',
                scope='static x86 startup and selected kernels on this native host, not hosted admission, other CPUs or physical qualification')


def corruption_cases(image,references):
    require(len(references)==len(REFERENCE) and {r['role'] for r in references}==set(REFERENCE),
            'startup corruption population changed')
    for ref in references:
        role,pos,size=ref['role'],ref['offset'],ref['size'];expected=REFERENCE[role]
        require(type(pos)is int and pos>=0 and size==len(expected) and image[pos:pos+size]==expected,
                'startup corruption reference changed')
        for i in range(size if role.startswith('schedule') else 1):
            yield f'{role}:{i}',image[:pos+i]+bytes([image[pos+i]^1])+image[pos+i+1:]
