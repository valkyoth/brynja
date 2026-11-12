"""Inspected Apple static startup instructions, with immutable KAT bindings.

No policy learning or disassembler trust. System memcmp/dyld are explicit trusted
dependencies; this does not qualify their implementation or hosted admission.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


c = module('apple_startup_body', 'aes_apple_linked_constructors.py')
imports = module('apple_startup_import', 'aes_apple_unwind_import.py')
mapping, require, Body = c.mapping, c.require, c.Body
REFERENCE = {k: bytes.fromhex(v) for k, v in json.loads(
    Path(__file__).with_name('startup-arm-reference.json').read_text()).items()}
REFERENCE.update(key16=bytes(range(16)), tail8=bytes(range(16,24)), tail16=bytes(range(16,32)))


def template(compiler, start, targets, addresses):
    require(compiler in ('1.90.0','1.99.1'), 'unreviewed Apple startup compiler')
    require(set(targets) == {'memcmp', *(k+str(b) for k in ('expand','transform') for b in (128,192,256))},
            'startup target population changed')
    require(set(addresses) == set(REFERENCE), 'startup reference population changed')
    old = compiler == '1.90.0'
    b, relocations = Body(start), []

    def ref(role, reg, kind='address'):
        address = addresses[role]
        require(type(address) is int and 0 <= address < 2**64, 'invalid startup reference address')
        pc = start+4*len(b.words)
        delta = (address//4096)-(pc//4096)
        require(-(2**20) <= delta < 2**20, 'startup reference out of range')
        immediate = delta & ((1<<21)-1)
        page = 0x90000000 | ((immediate & 3)<<29) | ((immediate>>2)<<5) | reg
        offset = address & 4095
        relocations.append((len(b.words),role,reg,kind))
        if kind == 'address':
            follow = 0x91000000 | offset<<10 | reg<<5 | reg
        else:
            scale,opcode = (16,0x3dc00000) if kind == 'q' else (8,0xfd400000)
            require(offset % scale == 0, 'misaligned startup vector constant')
            follow = opcode | (offset//scale)<<10 | reg<<5  # v0/d0
        b.emit(page,follow)

    def zero_schedule(n):
        b.emit(0x6f00e400)
        for offset in range(64+n-32,64,-32):
            b.emit(0xad0003e0 | (offset//16)<<15)
        b.emit(0x3d8013e0)

    def mov64(reg, data):
        value = int.from_bytes(data,'little')
        b.emit(0xd2800000 | (value & 65535)<<5 | reg)
        for shift in (1,2,3):
            b.emit(0xf2800000 | shift<<21 | ((value>>(16*shift)) & 65535)<<5 | reg)

    def ccmp(left,right):
        b.emit(0xfa400000 | right<<16 | left<<5)  # eq, false NZCV=0 (Z clear)

    b.emit(0xd10683ff,0xa9146ffc,0xa91567fa,0xa9165ff8,0xa91757f6,
           0xa9184ff4,0xa9197bfd,0x910643fd,0xaa0003f3)
    b.branch(0x36000001 if old else 0x34000001,'wrong',14 if old else 19)
    ref('key16',8,'q'); b.emit(0xad0083e0)
    zero_schedule(176)
    b.emit(0x910083e0,0x910103e1); b.call(targets['expand128'])
    r128,r192,r256 = (22,24,25) if old else (20,22,1)
    ref('schedule128',r128)
    b.emit(0x910103e0,0xaa0003e1 | r128<<16,0x52801602); b.call(targets['memcmp'])
    b.emit(0xb9000fe0 if old else 0xaa0003f5,0x3dc007e0,0x3d800be0)
    ref('tail8',8,'d'); b.emit(0xfd001be0)
    zero_schedule(208)
    b.emit(0x910083e0,0x910103e1); b.call(targets['expand192'])
    ref('schedule192',r192)
    b.emit(0x910103e0,0xaa0003e1 | r192<<16,0x52801a02); b.call(targets['memcmp'])
    if old: b.emit(0xb9000be0)
    ref('tail16',8,'q')
    if not old: b.emit(0x2a150008,0xb9000fe8)
    b.emit(0x3dc007e1,0xad0103e1)
    zero_schedule(240)
    b.emit(0x910083e0,0x910103e1); b.call(targets['expand256'])
    ref('schedule256',r256)
    b.emit(0x910103e0)
    if old: b.emit(0xaa1903e1)
    b.emit(0x52801e02); b.call(targets['memcmp'])
    b.emit(0xb90007e0 if old else 0xb9000be0)
    ref('plain',8); b.emit(0x3dc00100,0xad0083e0)
    for bits,register in ((128,r128),(192,r192),(256,25 if old else 20)):
        if bits != 128: b.emit(0x3dc007e0,0x3d800be0)
        ref('cipher'+str(bits),8); b.emit(0x3dc00100,0x3d8013e0,0x910083e0)
        if not old and bits == 256: ref('schedule256',20)
        b.emit(0xaa0003e1 | register<<16,0x52800002); b.call(targets['transform'+str(bits)])
        if not old and bits == 128: b.emit(0x52800039)
        b.emit(0x910103e0,0xaa0003e1 | register<<16,0x52800022)
        b.call(targets['transform'+str(bits)])
        if bits == 128:
            b.emit(*( (0xa9426ff6,0xa94453fc) if old else (0xa9426be8,0xf90003e8,0xa94473fb)))
        elif bits == 192:
            b.emit(*( (0xa94257f8,0xa9445ffa) if old else (0xa94263f6,0xa9445ff5)))
        else: b.emit(0xa94227e8,0xa9442fea)
    # Every half of six independent answers contributes to Z; no result is
    # compared only to another computed result. Constants come from fixed KATs.
    mov64(12,REFERENCE['plain'][8:]); b.emit(0xeb0c017f)
    mov64(11,REFERENCE['plain'][:8]); ccmp(10,11)
    mov64(10,REFERENCE['cipher256'][8:]); ccmp(9,10)
    mov64(9,REFERENCE['cipher256'][:8]); ccmp(8,9)
    ccmp(23,12); ccmp(26 if old else 21,11)
    mov64(8,REFERENCE['cipher192'][8:]); ccmp(21 if old else 24,8)
    mov64(8,REFERENCE['cipher192'][:8]); ccmp(24 if old else 22,8)
    ccmp(20 if old else 28,12); ccmp(28 if old else 27,11)
    mov64(8,REFERENCE['cipher128'][8:]); ccmp(27 if old else 26,8)
    mov64(8,REFERENCE['cipher128'][:8])
    if not old: b.emit(0xf94003e9)
    ccmp(22 if old else 9,8)
    b.emit(0x294123e9)
    if old: b.emit(0x2a080128,0xb94007e9)
    b.emit(0x2a090108,0x7a400900)
    if old: b.emit(0x5280002a,0x1a8a0548)
    else: b.emit(0x1a990728)
    b.emit(0x52800049,0xf9000269,0x39002268)  # generation 2; health 1 or 2
    if old:
        b.emit(0x3900266a,0xb94043e8,0xb800a268,0x79408be8,0x79001e68)
    b.jump('epilogue' if old else 'discriminant')
    b.label('wrong'); b.emit(0x52800048 if old else 0x52800059)
    b.label('discriminant'); b.emit(0x39002668 if old else 0x39002679)
    b.label('epilogue')
    b.emit(0xa9597bfd,0xa9584ff4,0xa95757f6,0xa9565ff8,0xa95567fa,
           0xa9546ffc,0x910683ff,0xd65f03c0)
    return b.finish(),relocations


def selected(image):
    code,functions,symbols,layout = mapping.parse(image,
        symbol_filter=lambda name: b'fixture7startup' in name, include_layout=True)
    require(len(symbols)==1,'startup symbol population changed')
    symbol,address = symbols[0]
    pattern = r'__(?:ZN30brynja_aes_accelerated_fixture7startup17h[0-9a-f]{16}E|RNvC\w+_30brynja_aes_accelerated_fixture7startup)'
    require(re.fullmatch(pattern,symbol) is not None,'unreviewed startup symbol')
    ends = dict(zip(functions,functions[1:]))
    require(address in ends,'startup lacks complete function boundaries')
    return symbol,address,ends[address]-address,code['offset']+address-code['address'],layout


def inspect(image,compiler,panic,admission='static'):
    require(panic in ('abort','unwind') and admission=='static','requires static Apple startup configuration')
    require(compiler in ('1.90.0','1.99.1'),'unreviewed Apple startup compiler')
    dependencies = mapping.inspect(image)
    comparison = imports.inspect(image,b'_memcmp')
    targets = {r['role']+str(r['bits']):int(r['address'],16) for r in dependencies['bodies']}
    targets['memcmp'] = int(comparison['stub_address'],16)
    symbol,start,size,pos,layout = selected(image)
    require(symbol.startswith('__ZN') == (compiler=='1.90.0'),'startup compiler/symbol mismatch')
    dummy,relocations = template(compiler,start,targets,{r:start & ~4095 for r in REFERENCE})
    require(size==len(dummy),'startup encoding/extent changed')
    raw = image[pos:pos+size]
    addresses,refs = {},[]
    for index,role,reg,kind in relocations:
        page,follow = struct.unpack_from('<2I',raw,4*index)
        immediate = ((page>>5)&0x7ffff)<<2 | (page>>29)&3
        base = ((start+4*index)&~4095)+imports.signed(immediate,21)*4096
        scale = 1 if kind=='address' else 16 if kind=='q' else 8
        address = base+((follow>>10)&4095)*scale
        matches = [s for s in layout['segments'] if s['initial'] in (1,5)
                   and s['maximum']==s['initial'] and s['base']<=address
                   and address+len(REFERENCE[role])<=s['base']+s['filesz']]
        require(len(matches)==1,'startup constant not uniquely immutable mapped')
        s = matches[0]; offset = s['pos']+address-s['base']
        require(image[offset:offset+len(REFERENCE[role])]==REFERENCE[role],'startup reference changed: '+role)
        require(role not in addresses or addresses[role]==address,'startup repeated reference disagrees')
        addresses[role] = address
        refs.append(dict(role=role,offset=offset,size=len(REFERENCE[role]),address=hex(address)))
    expected,_ = template(compiler,start,targets,addresses)
    require(raw==expected,'startup encoding/extent changed; explicit review required')
    return {'binary_sha256':hashlib.sha256(image).hexdigest(),
            'compiler':compiler,'panic':panic,'admission':admission,
            'startup':dict(symbol=symbol,address=hex(start),file_offset=pos,size=size,
                           instructions=size//4,sha256=hashlib.sha256(raw).hexdigest()),
            'references':refs,'comparison_import':comparison,'kernels':dependencies,
            'scope':'Retained static Apple startup body and constants, width-bound kernels and system memcmp import. '
                    'Not memcmp/dyld implementation, hosted detection/lifetime admission, other callers or physical qualification.'}
