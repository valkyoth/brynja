"""Inspected Apple hosted startup boundary; std_detect and OS remain trusted.

Exact instruction templates bind the system comparison, six AES kernels, cold
detector and zero-filled feature cache. No policy is learned from an input.
"""
import hashlib
import re
import struct

import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('apple_hosted_static',Path(__file__).with_name('aes_apple_startup_static.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
mapping,require,Body,REFERENCE=s.mapping,s.require,s.Body,s.REFERENCE


def template(compiler,start,targets,addresses,cache):
    require(compiler in ('1.90.0','1.99.1'),'unreviewed hosted Apple compiler')
    require(set(targets)=={'detect','memcmp',*(k+str(b) for k in ('expand','transform') for b in (128,192,256))},
            'hosted target population changed')
    require(set(addresses)==set(REFERENCE),'hosted reference population changed')
    old=compiler=='1.90.0';b=Body(start);relocations=[]
    def ref(role,reg,kind='address'):
        address=cache if role=='cache' else addresses[role]
        require(type(address) is int and 0<=address<2**64,'invalid hosted reference')
        pc=start+4*len(b.words);delta=address//4096-pc//4096
        require(-(2**20)<=delta<2**20,'hosted reference out of range')
        immediate=delta&((1<<21)-1);offset=address&4095
        page=0x90000000|((immediate&3)<<29)|(immediate>>2)<<5|reg
        relocations.append((len(b.words),role,reg,kind))
        if kind=='address':follow=0x91000000|offset<<10|reg<<5|reg
        else:
            scale,opcode,out={'q':(16,0x3dc00000,0),'d':(8,0xfd400000,0),'x':(8,0xf9400000,reg)}[kind]
            require(offset%scale==0,'misaligned hosted reference')
            follow=opcode|(offset//scale)<<10|reg<<5|(8 if role=='cache' else out)
        b.emit(page,follow)
    def cache_read():
        b.emit(0xf9400288|((cache&4095)//8)<<10)
    def zero(n):
        b.emit(0x6f00e400)
        for offset in range(80+n-32,80,-32):b.emit(0xad0003e0|(offset//16)<<15)
        b.emit(0x3d8017e0)
    def mov64(reg,data):
        value=int.from_bytes(data,'little');b.emit(0xd2800000|(value&65535)<<5|reg)
        for shift in (1,2,3):b.emit(0xf2800000|shift<<21|((value>>(16*shift))&65535)<<5|reg)
    def ccmp(left,right):b.emit(0xfa400000|right<<16|left<<5)
    # Portable bypasses detector and AES; wrong architecture precedes cache load.
    b.emit(0x72001c5f);b.branch(0x54000000,'portable')
    b.emit(0xd106c3ff,0xa9156ffc,0xa91667fa,0xa9175ff8,0xa91857f6,0xa9194ff4,0xa91a7bfd,0x910683fd)
    b.branch(0x34000001,'wrong');ref('cache',20,'x');b.branch(0xb4000008,'cold_aes')
    b.emit(0xd3430d13);cache_read();b.branch(0xb4000008,'cold_pmull')
    b.label('pmull');b.emit(0xd3410508)
    if old:
        b.emit(0x0a080268,0x52800039,0x7100051f);b.branch(0x54000001,'unavailable')
    else:
        b.emit(0x52800039,0x6a08027f);b.branch(0x54000000,'unavailable')
    b.label('admitted');ref('key16',8,'q');b.emit(0xad0103e0);zero(176)
    b.emit(0xf9000fe0,0x9100c3e0,0xb90017e1,0x910143e1);b.call(targets['expand128'])
    ref('schedule128',21);b.emit(0x910143e0,0xaa1503e1,0x52801602);b.call(targets['memcmp'])
    b.emit(0xb90013e0,0x3dc00be0,0x3d800fe0);ref('tail8',8,'d');b.emit(0xfd0023e0);zero(208)
    b.emit(0x9100c3e0,0x910143e1);b.call(targets['expand192'])
    ref('schedule192',22);b.emit(0x910143e0,0xaa1603e1,0x52801a02);b.call(targets['memcmp'])
    b.emit(0xb9000fe0);ref('tail16',8,'q');b.emit(0x3dc00be1,0xad0183e1);zero(240)
    b.emit(0x9100c3e0,0x910143e1);b.call(targets['expand256'])
    ref('schedule256',24);b.emit(0x910143e0,0xaa1803e1,0x52801e02);b.call(targets['memcmp'])
    b.emit(0xb9000be0);ref('plain',8);b.emit(0x3dc00100,0xad0103e0)
    for bits,register in ((128,21),(192,22),(256,24)):
        if bits!=128:b.emit(0x3dc00be0,0x3d800fe0)
        ref('cipher'+str(bits),8);b.emit(0x3dc00100,0x3d8017e0,0x9100c3e0,0xaa0003e1|register<<16,0x52800002)
        b.call(targets['transform'+str(bits)])
        b.emit(0x910143e0,0xaa0003e1|register<<16,0x52800022);b.call(targets['transform'+str(bits)])
        if bits==128:b.emit(0xa94373f5,0xa9456bf3 if old else 0xa9454ffa)
        elif bits==192:b.emit(0xa9436ff6,0xa9455ff4)
    b.emit(0xb94017e1,0xf9400fe0,0xa94327e8,0xa9452fea)
    # Both variants compare every answer half to an independent fixed KAT.
    mov64(12,REFERENCE['plain'][8:]);b.emit(0xeb0c017f if old else 0xeb0c027f)
    if old:
        mov64(11,REFERENCE['plain'][:8]);ccmp(10,11)
        mov64(10,REFERENCE['cipher256'][8:]);ccmp(9,10)
        mov64(9,REFERENCE['cipher256'][:8]);ccmp(8,9)
        ccmp(26,12);ccmp(19,11)
        mov64(8,REFERENCE['cipher128'][8:]);ccmp(28,8)
        mov64(8,REFERENCE['cipher128'][:8]);ccmp(21,8)
        b.emit(0x2941a3e9,0x2a090108,0xb9400be9,0x2a090108,0x7a400900)
        ccmp(23,12);ccmp(20,11)
        mov64(8,REFERENCE['cipher192'][8:]);ccmp(27,8)
        mov64(8,REFERENCE['cipher192'][:8]);ccmp(22,8)
    else:
        mov64(13,REFERENCE['plain'][:8]);ccmp(26,13)
        mov64(14,REFERENCE['cipher128'][8:]);ccmp(28,14)
        mov64(14,REFERENCE['cipher128'][:8]);ccmp(21,14)
        b.emit(0x2941bbef,0x2a0f01ce,0xb9400bef,0x2a0f01ce,0x7a4009c0)
        ccmp(23,12);ccmp(20,13)
        mov64(14,REFERENCE['cipher192'][8:]);ccmp(27,14)
        mov64(14,REFERENCE['cipher192'][:8]);ccmp(22,14)
        ccmp(11,12);ccmp(10,13)
        mov64(10,REFERENCE['cipher256'][8:]);ccmp(9,10)
        mov64(9,REFERENCE['cipher256'][:8]);ccmp(8,9)
    # Generation 2, health 1/2, accelerated route; neither result can fallback.
    b.emit(0x1a990728,0x52800049,0xf9002be9,0x390163e8,0x390167f9,0xf84523e9,0x52800028,0x528000b9)
    b.jump('owner')
    b.label('portable');b.emit(0x52800048,0x39002808,0x52800068,0x39004008,0x39004401,0xd65f03c0)
    b.label('wrong');b.emit(0x52800019)
    b.label('unavailable');b.emit(0x12001c48,0x7100051f);b.branch(0x54000001,'error')
    b.emit(0x52800048)
    b.label('owner');b.emit(0x5280004a,0x7900000a,0xf8002009,0x39002808,0x39004019);b.jump('epilogue')
    b.label('error');b.emit(0x3900001f,0x39000419,0x52800041)
    b.label('epilogue');b.emit(0xa95a7bfd,0xa9594ff4,0xa95857f6,0xa9575ff8,0xa95667fa,0xa9556ffc,0x9106c3ff,0x39004401,0xd65f03c0)
    b.label('cold_aes');b.emit(0xaa0003f3,0xaa0103f6,0xaa0203f5);b.call(targets['detect'])
    b.emit(0xaa1503e2,0xaa1603e1,0xaa0003e8,0xaa1303e0,0xd3430d13);cache_read()
    b.branch(0xb5000008,'pmull')
    b.label('cold_pmull');b.emit(0xaa0003f4,0xaa0103f6,0xaa0203f5);b.call(targets['detect'])
    b.emit(0xaa1503e2,0xaa1603e1,0xaa0003e8,0xaa1403e0,0xd3410508)
    if old:
        b.emit(0x0a080268,0x52800039,0x7100051f);b.branch(0x54000000,'admitted')
    else:
        b.emit(0x52800039,0x6a08027f);b.branch(0x54000001,'admitted')
    b.jump('unavailable')
    return b.finish(),relocations


def platform(image,compiler):
    detector_pattern=r'__(?:ZN10std_detect6detect5cache21detect_and_initialize17h[0-9a-f]{16}E|RNvNtNtC\w+_10std_detect6detect5cache21detect_and_initialize)'
    cache_pattern=r'__(?:ZN10std_detect6detect5cache5CACHE17h[0-9a-f]{16}E|RNvNtNtC\w+_10std_detect6detect5cache5CACHE)\.0'
    code,functions,symbols,layout=mapping.parse(image,symbol_filter=lambda n:b'21detect_and_initialize' in n,include_layout=True)
    require(len(symbols)==1,'hosted detector population changed')
    symbol,address=symbols[0];ends=dict(zip(functions,[*functions[1:],code['address']+code['size']]))
    require(re.fullmatch(detector_pattern,symbol) is not None and address in ends,'unbound hosted detector')
    require(symbol.startswith('__ZN')==(compiler=='1.90.0'),'hosted detector compiler mismatch')
    pos=code['offset']+address-code['address'];size=ends[address]-address
    detector=dict(symbol=symbol,address=hex(address),size=size,file_offset=pos,
                  sha256=hashlib.sha256(image[pos:pos+size]).hexdigest())
    symoff,count,stroff,strsize=layout['commands'][2];strings=image[stroff:stroff+strsize]
    caches=[];defined=[]
    for i in range(count):
        index,kind,section,desc,value=struct.unpack_from('<IBBHQ',image,symoff+16*i)
        if kind&0xe0:continue
        if kind&0x1e==0xe:defined.append((section,value))
        name=strings[index:strings.find(b'\0',index)]
        if b'5cache5CACHE' not in name:continue
        require(re.fullmatch(cache_pattern.encode(),name) is not None,'unreviewed hosted cache symbol')
        require(name.startswith(b'__ZN')==(compiler=='1.90.0'),'hosted cache compiler mismatch')
        require(kind&0x1e==0xe and 1<=section<=len(layout['sections']) and desc==0,'invalid hosted cache definition')
        sec=layout['sections'][section-1];seg=next(row for row in layout['segments'] if row['name']==sec['segment'])
        require(sec['name']=='__bss' and sec['flags']&255==1 and sec['offset']==0
                and seg['initial']==seg['maximum']==3 and value%8==0
                and sec['address']<=value and value+8<=sec['address']+sec['size'],
                'hosted cache not uniquely zero-fill RW mapped')
        # Apple linkers may include zero-filled segment padding covering __bss
        # in filesize. Any such initial bytes must also be zero, not a warm
        # fabricated feature value hidden behind the section's zero-fill flag.
        backed=max(0,min(8,seg['base']+seg['filesz']-value));offset=seg['pos']+value-seg['base']
        require(not any(image[offset:offset+backed]),'hosted cache has nonzero initial padding')
        caches.append(dict(symbol=name.decode(),address=hex(value),size=8,section=section))
    require(len(caches)==1,'hosted cache population changed')
    cache=caches[0];value=int(cache['address'],16)
    require(sum(sec==cache['section'] and value<=a<value+8 for sec,a in defined)==1,'hosted cache alias/overlap')
    return detector,cache


def inspect(image,compiler,panic,admission='hosted'):
    require(compiler in ('1.90.0','1.99.1') and panic in ('abort','unwind') and admission=='hosted',
            'requires reviewed hosted Apple configuration')
    dependencies=mapping.inspect(image);comparison=s.imports.inspect(image,b'_memcmp')
    detector,cache=platform(image,compiler)
    targets={r['role']+str(r['bits']):int(r['address'],16) for r in dependencies['bodies']}
    targets.update(memcmp=int(comparison['stub_address'],16),detect=int(detector['address'],16))
    symbol,start,size,pos,layout=s.selected(image)
    require(symbol.startswith('__ZN')==(compiler=='1.90.0'),'hosted startup compiler mismatch')
    mapping.nonoverlap([(start,size),(int(detector['address'],16),detector['size']),
                        (targets['memcmp'],12),
                        *((int(row['address'],16),row['size']) for row in dependencies['bodies'])])
    dummy,relocations=template(compiler,start,targets,{r:start&~4095 for r in REFERENCE},int(cache['address'],16))
    require(size==len(dummy),'hosted startup encoding/extent changed')
    raw=image[pos:pos+size];addresses={};refs=[]
    for index,role,reg,kind in relocations:
        if role=='cache':continue # exact symbol address is encoded into template
        page,follow=struct.unpack_from('<2I',raw,4*index)
        immediate=((page>>5)&0x7ffff)<<2|(page>>29)&3
        base=((start+4*index)&~4095)+s.imports.signed(immediate,21)*4096
        scale=1 if kind=='address' else 16 if kind=='q' else 8
        address=base+((follow>>10)&4095)*scale
        matches=[row for row in layout['segments'] if row['initial'] in (1,5) and row['maximum']==row['initial']
                 and row['base']<=address and address+len(REFERENCE[role])<=row['base']+row['filesz']]
        require(len(matches)==1,'hosted constant not uniquely immutable mapped')
        row=matches[0];offset=row['pos']+address-row['base']
        require(image[offset:offset+len(REFERENCE[role])]==REFERENCE[role],'hosted reference changed: '+role)
        require(role not in addresses or addresses[role]==address,'hosted repeated reference disagrees')
        addresses[role]=address;refs.append(dict(role=role,offset=offset,size=len(REFERENCE[role]),address=hex(address)))
    expected,_=template(compiler,start,targets,addresses,int(cache['address'],16))
    require(raw==expected,'hosted startup encoding/extent changed; explicit review required')
    return dict(binary_sha256=hashlib.sha256(image).hexdigest(),compiler=compiler,panic=panic,admission=admission,
        startup=dict(symbol=symbol,address=hex(start),file_offset=pos,size=size,instructions=size//4,sha256=hashlib.sha256(raw).hexdigest()),
        references=refs,comparison_import=comparison,kernels=dependencies,detector=detector,cache=cache,
        scope='Apple hosted startup branches, KATs, kernels and declared memcmp/cache/detector bindings. '
              'std_detect and libc/dyld implementations, OS capabilities and lifetime guarantees remain trusted, not qualified here.')


def admission_cases(image,compiler,panic):
    """Temporary observation substitutions, not real missing-feature hardware."""
    report=inspect(image,compiler,panic)
    pos=report['startup']['file_offset']
    words=struct.unpack_from('<'+str(report['startup']['instructions'])+'I',image,pos)
    reads=[i for i,w in enumerate(words) if w&0xffc003ff==0xf9400288]
    cold=[i for i,w in enumerate(words) if w==0xaa0003e8]
    require(len(reads)==3 and len(cold)==2,'hosted observation population changed')
    # Preserve the OTHER feature in each negative. Cold paths execute the real
    # detector and replace its returned observation; branches/KATs stay intact.
    for feature,mask in (('aes',2),('pmull',8)):
        value=0xd2800008|(mask<<5)
        for temperature in ('warm','cold'):
            edits={i:value if temperature=='warm' else 0xd2800008 for i in reads}
            if temperature=='cold':edits.update({i:value for i in cold})
            changed=bytearray(image)
            for index,word in edits.items():struct.pack_into('<I',changed,pos+index*4,word)
            yield temperature+'-'+feature+'-absent',bytes(changed)
