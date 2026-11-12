"""Linux ARM hosted startup boundary; std_detect/OS remain trusted dependencies.

The mutable cache is bound to its exact symbol and zero-filled RW ELF extent.
Only its validated relocation is normalized. No policy is learned by a run.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('hosted_startup_static',
        Path(__file__).with_name('aes_accelerated_startup_arm.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
c, arm, require, TARGET = s.c, s.arm, s.require, s.TARGET
POLICY = json.loads(Path(__file__).with_name('startup-hosted-review.json').read_text())
corruption_cases = s.corruption_cases


def platform_rows(table):
    result = {}
    patterns = {
        'detect': r'(?:_ZN10std_detect6detect5cache21detect_and_initialize17h[0-9a-f]{16}E|_RNvNtNtC\w+_10std_detect6detect5cache21detect_and_initialize)',
        'cache': r'(?:_ZN10std_detect6detect5cache5CACHE17h[0-9a-f]{16}E|_RNvNtNtC\w+_10std_detect6detect5cache5CACHE)\.0',
    }
    for role, pattern in patterns.items():
        rows = re.findall(r'^([0-9a-f]+) ([0-9a-f]+) '+('[tT]' if role=='detect' else '[bB]')+
                          ' ('+pattern+r')$', table, re.M)
        require(len(rows)==1, 'hosted platform symbol population changed: '+role)
        address, size, name = rows[0]
        result[role] = name, int(address,16), int(size,16)
    require(result['cache'][2]==8 and result['cache'][1]%8==0, 'hosted cache extent changed')
    c.cleanup.disjoint(result.values())
    return result


def observe(lines, raw, row, image, targets, cache):
    require(len(lines)*4 == len(raw) == row[2] and len(lines)>42, 'hosted instruction partition changed')
    loads = arm.segments(image)
    pos = arm.mapped(loads,row[1],row[2],5)
    require(image[pos:pos+len(raw)]==raw, 'hosted decoded bytes differ from executable')
    require(cache[2]==8 and cache[1]%8==0, 'hosted cache extent changed')
    require(sum(mode==6 and base+filesz<=cache[1] and cache[1]+8<=base+memsz
                for base,memsz,_,filesz,mode in loads)==1, 'hosted cache not uniquely zero-fill RW mapped')
    # Both inspected compilers materialize the cache page at this position.
    # The whole-body policy fixes the Portable/wrong-architecture guards before
    # these reads, both cold calls and AES/PMULL checks before every kernel call.
    page = re.fullmatch(r'adrp x20, 0x([0-9a-f]+) <[^>]+>',lines[11])
    load = re.fullmatch(r'ldr x8, \[x20, #(\d+)\]',lines[12])
    require(page is not None and load is not None, 'hosted cache load changed')
    first, second = (int.from_bytes(raw[i*4:i*4+4],'little') for i in (11,12))
    require(first & 0x9f00001f == 0x90000014, 'hosted cache ADRP encoding mismatch')
    immediate = ((first>>5)&0x7ffff)<<2 | (first>>29)&3
    address = int(page[1],16); offset = int(load[1])
    require(address == ((row[1]+44)&~4095)+arm.signed(immediate,21)*4096,
            'hosted cache ADRP destination mismatch')
    require(second & 0xffc003ff == 0xf9400288 and offset == ((second>>10)&0xfff)*8,
            'hosted cache LDR encoding mismatch')
    require(address+offset == cache[1], 'hosted cache destination mismatch')
    text, data = list(lines), bytearray(raw)
    reads=[i for i,line in enumerate(lines) if line==lines[12]]
    require(len(reads)==3 and reads[:2]==[12,15], 'hosted cache read population changed')
    for i in reads:
        require(raw[i*4:i*4+4]==raw[48:52], 'hosted cache read encoding mismatch')
    for i in (11,*reads): text[i]='nop'; data[i*4:i*4+4]=s.NOP
    shadow=image[:pos]+data+image[pos+len(data):]
    actual, constants, normalized, refs = s.observe(text,bytes(data),row,shadow,targets)
    normalized[11]='adrp x20, @std_detect_cache_page; encoding=90000014'
    for i in reads:
        normalized[i]='ldr x8, [x20, @std_detect_cache]; encoding=f9400288'
    actual['text_sha256']=hashlib.sha256(('\n'.join(normalized)+'\n').encode()).hexdigest()
    actual['mutable_caches']=1
    return actual, constants, normalized, refs


def check(lines, raw, row, image, targets, cache, compiler):
    require(compiler in POLICY, 'unreviewed hosted startup compiler')
    require(set(targets)=={'detect','bcmp',*(k+str(b) for k in ('expand','round') for b in (128,192,256))},
            'hosted startup call population changed')
    c.cleanup.disjoint([row,cache,*targets.values()])
    actual,_,_,_=observe(lines,raw,row,image,targets,cache)
    require(actual==POLICY[compiler], 'hosted startup stream changed; explicit review required')
    return actual


def inspect(table, assembly, image, compiler, panic):
    require(compiler in POLICY and panic in ('abort','unwind'), 'unreviewed hosted startup configuration')
    rows=s.candidates(table); platform=platform_rows(table)
    dependencies={'rounds':c.kernels.inspect(table,assembly,image,TARGET),
                  'expansion':c.expansion.inspect(table,assembly,image,TARGET)}
    targets={'bcmp':rows['bcmp'],'detect':platform['detect']}
    for kind,reviewer in (('round',c.kernels),('expand',c.expansion)):
        for row in reviewer.select(table,TARGET):
            bits=reviewer.check(*c.kernels.decode(assembly,row,TARGET),row,image,TARGET)['bits']
            role=kind+str(bits)
            require(role not in targets,'duplicate hosted startup kernel width')
            targets[role]=row
    c.cleanup.disjoint([*rows.values(),platform['cache'],*(r for k,r in targets.items() if k!='bcmp')])
    rejected, reports=0,{}
    for role in ('bcmp','memcmp'):
        args=(*c.decode(assembly,rows[role]),rows[role],image,
              {'memcmp':rows['memcmp']} if role=='bcmp' else {},compiler,role)
        reports[role]=s.compare_check(*args)
        rejected+=s.mutations(s.compare_check,*args)
    args=(*c.decode(assembly,rows['startup']),rows['startup'],image,targets,platform['cache'],compiler)
    reports['startup']=check(*args)
    rejected+=s.mutations(check,*args)
    _,constants,_,refs=observe(*args[:-1])
    offsets=sorted({p+i for p,n in constants for i in range(n)})
    for pos in offsets:
        binary=image[:pos]+bytes([image[pos]^1])+image[pos+1:]
        try: check(*args[:3],binary,*args[4:])
        except ValueError as error:
            require('reference changed' in str(error) or 'stream changed' in str(error),'unrelated hosted constant rejection')
        else: raise ValueError('hosted constant mutation accepted')
    detector=platform['detect']; pos=arm.mapped(arm.segments(image),detector[1],detector[2],5)
    return dict(bodies=reports,rejected_code_mutations=rejected,rejected_constant_mutations=len(offsets),
                references=[dict(role=r,offset=p,size=n) for r,p,n in refs],dependencies=dependencies,
                platform_dependency=dict(symbol=detector[0],size=detector[2],
                    sha256=hashlib.sha256(image[pos:pos+detector[2]]).hexdigest(),
                    trust='std_detect and Linux capability reporting are trusted, not independently qualified here'),
                scope='Linux ARM hosted startup, runtime AES/PMULL admission and terminal startup health; '
                      'NEON is a target baseline; not macOS, native, OS or physical qualification')


def admission_cases(table, assembly, image, compiler, panic):
    # Call only after the complete inspect succeeds; independently enforce the
    # fixed startup policy again before changing its detector observations.
    require(compiler in POLICY and panic in ('abort','unwind'), 'unreviewed admission control')
    rows=s.candidates(table); platform=platform_rows(table)
    targets={'bcmp':rows['bcmp'],'detect':platform['detect']}
    for kind,reviewer in (('round',c.kernels),('expand',c.expansion)):
        for row in reviewer.select(table,TARGET):
            bits=reviewer.check(*c.kernels.decode(assembly,row,TARGET),row,image,TARGET)['bits']
            targets[kind+str(bits)]=row
    lines,raw=c.decode(assembly,rows['startup'])
    check(lines,raw,rows['startup'],image,targets,platform['cache'],compiler)
    cold=[i for i,line in enumerate(lines) if line=='mov x8, x0']
    reads=[i for i,line in enumerate(lines) if re.fullmatch(r'ldr x8, \[x20, #\d+\]',line)]
    require(len(cold)==2 and len(reads)==3, 'hosted detector observation population changed')
    require(all(raw[i*4:i*4+4]==bytes.fromhex('e80300aa') for i in cold),
            'hosted cold detector observation changed')
    pos=arm.mapped(arm.segments(image),rows['startup'][1],len(raw),5)
    # Each negative preserves the OTHER feature. A cached nonzero observation
    # avoids initialization; cold controls execute the real detector but replace
    # its returned observation. Neither control changes a branch or AES body.
    for feature,mask in (('aes',2),('pmull',8)):
        value=0xd2800008|(mask<<5)
        for temperature in ('warm','cold'):
            edits={i:value if temperature=='warm' else 0xd2800008 for i in reads}
            if temperature=='cold': edits.update({i:value for i in cold})
            changed=bytearray(image)
            for i,word in edits.items(): changed[pos+i*4:pos+i*4+4]=word.to_bytes(4,'little')
            yield temperature+'-'+feature+'-absent',bytes(changed)
