#!/usr/bin/env python3
"""Constructed hosted Mach-O tests; no native-execution claims."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
f=module('apple_hosted_fixture','test-aes-apple-startup-static.py')
runner=module('apple_hosted_cli','check-aes-apple-linked.py')
r=runner.hosted_startup_review
BASE=f.BASE

def fixture(compiler='1.99.1'):
    image,meta=f.fixture(compiler);_,functions,_=r.mapping.parse(image)
    cursor=32;commands={}
    for _ in range(struct.unpack_from('<I',image,16)[0]):
        cmd,size=struct.unpack_from('<II',image,cursor);commands[cmd]=cursor;cursor+=size
    header=cursor
    struct.pack_into('<II16sQQQQiiII',image,header,0x19,152,b'__BSS',BASE+0x6000,0x1000,0,0,3,3,1,0)
    struct.pack_into('<16s16sQQ8I',image,header+72,b'__bss',b'__BSS',BASE+0x6000,8,0,3,0,0,1,0,0,0)
    count,length=struct.unpack_from('<II',image,16);struct.pack_into('<II',image,16,count+1,length+152)
    targets={**meta['targets'],'detect':BASE+0xd00}
    raw,relocations=r.template(compiler,meta['start'],targets,meta['addresses'],BASE+0x6000)
    image[meta['offset']:meta['offset']+len(raw)]=raw
    for pos in (meta['offset']+len(raw),0xd00,0xd04):struct.pack_into('<I',image,pos,0xd65f03c0)
    struct.pack_into('<Q',image,144,0xd08-0x400)
    symcmd=commands[2];symoff,count,stroff,strsize=struct.unpack_from('<4I',image,symcmd+8)
    image[symoff+9*16:symoff+10*16]=image[symoff+7*16:symoff+8*16]
    names=[('__ZN10std_detect6detect5cache21detect_and_initialize17h0000000000000000E',
            '__ZN10std_detect6detect5cache5CACHE17h0000000000000000E.0'),
           ('__RNvNtNtCtest_10std_detect6detect5cache21detect_and_initialize',
            '__RNvNtNtCtest_10std_detect6detect5cache5CACHE.0')][compiler=='1.99.1']
    for i,(name,section,value) in enumerate(zip(names,(1,5),(BASE+0xd00,BASE+0x6000)),7):
        image[stroff+strsize:stroff+strsize+len(name)+1]=name.encode()+b'\0'
        struct.pack_into('<IBBHQ',image,symoff+i*16,strsize,0xe,section,0,value)
        strsize+=len(name)+1
    struct.pack_into('<I',image,symcmd+12,10);struct.pack_into('<I',image,symcmd+20,strsize)
    struct.pack_into('<I',image,commands[0xb]+12,9);struct.pack_into('<I',image,commands[0xb]+24,9)
    struct.pack_into('<2I',image,0x3a00,9,9)
    encoded=bytearray();previous=BASE
    for address in [*functions[:7],meta['start']+len(raw),BASE+0xd00,BASE+0xd04]:
        encoded.extend(f.f.fixture_module.uleb(address-previous));previous=address
    encoded.append(0);image[0x3800:0x3800+len(encoded)]=encoded
    struct.pack_into('<I',image,commands[0x26]+12,len(encoded))
    return image,{**meta,'size':len(raw),'targets':targets,'relocations':relocations,
                  'bss':header,'cache_symbol':symoff+8*16,'detect_symbol':symoff+7*16}

class AppleHostedStartupTests(unittest.TestCase):
    def test_missing_feature_controls_change_only_reviewed_observations(self):
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            cases=list(r.admission_cases(image,compiler,'abort'))
            self.assertEqual([name for name,_ in cases],['warm-aes-absent','cold-aes-absent',
                                                        'warm-pmull-absent','cold-pmull-absent'])
            reads=(12,15,238 if compiler=='1.90.0' else 237)
            cold=(235,246) if compiler=='1.90.0' else (234,245)
            edits_by_case=[]
            for value in (0xd2800048,0xd2800108):
                edits_by_case.extend(({i:value for i in reads},
                                     {**{i:0xd2800008 for i in reads},**{i:value for i in cold}}))
            for (_,changed),edits in zip(cases,edits_by_case):
                expected=bytearray(image)
                for index,word in edits.items():struct.pack_into('<I',expected,meta['offset']+4*index,word)
                self.assertEqual(changed,expected)
                with self.assertRaises(ValueError):list(r.admission_cases(changed,compiler,'abort'))

    def test_profiles_and_dependencies(self):
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            for panic in ('abort','unwind'):
                report=r.inspect(image,compiler,panic)
                self.assertEqual(report['startup']['size'],1016 if compiler=='1.90.0' else 1008)
                self.assertEqual(len(report['kernels']['bodies']),6)
                self.assertEqual(len(report['references']),10)
                self.assertEqual(report['cache']['address'],hex(BASE+0x6000))
                self.assertEqual(report['detector']['size'],4)
                self.assertEqual(sum(w>>26==0x25 for w in struct.unpack('<'+str(meta['size']//4)+'I',image[meta['offset']:meta['offset']+meta['size']])),14)

    def test_every_code_byte_and_reference_byte_rejected(self):
        total=0
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            for offset in range(meta['offset'],meta['offset']+meta['size']):
                changed=bytearray(image);changed[offset]^=255
                with self.subTest(compiler=compiler,offset=offset),self.assertRaises(ValueError):r.inspect(changed,compiler,'abort')
                total+=1
            for role,(pos,size) in meta['positions'].items():
                for offset in range(pos,pos+size):
                    changed=bytearray(image);changed[offset]^=1
                    with self.subTest(role=role,offset=offset),self.assertRaisesRegex(ValueError,'reference changed'):
                        r.inspect(changed,compiler,'abort')
        self.assertEqual(total,2024)

    def test_mode_architecture_feature_branch_and_terminal_health_controls(self):
        image,meta=fixture();words=list(struct.unpack('<252I',image[meta['offset']:meta['offset']+meta['size']]))
        # Portable/architecture, both cache misses, feature conjunction, both
        # extracted bits, terminal state and cold path are pinned byte-for-byte.
        for index in (0,1,10,13,14,16,17,19,20,190,191,197,207,249,250,251):
            changed=bytearray(image);struct.pack_into('<I',changed,meta['offset']+index*4,0xd503201f)
            with self.subTest(index=index),self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        for index,bit in ((14,3),(17,1)):
            self.assertEqual((words[index]>>16)&63,bit)
            changed=bytearray(image);struct.pack_into('<I',changed,meta['offset']+index*4,words[index]^(1<<16))
            with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')

    def test_cache_definition_extent_permissions_alias_and_warm_data(self):
        image,meta=fixture();bss=meta['bss'];symbol=meta['cache_symbol']
        for offset,fmt,value in ((symbol+4,'B',0),(symbol+5,'B',1),(symbol+6,'H',1),
            (symbol+8,'Q',BASE+0x6001),(symbol+8,'Q',BASE+0x6008),
            (bss+60,'I',1),(bss+56,'I',7),(bss+72+64,'I',0),(bss+72+40,'Q',7)):
            changed=bytearray(image);struct.pack_into('<'+fmt,changed,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        changed=bytearray(image)
        # An unrelated defined symbol may not alias any byte in the cache slot.
        struct.pack_into('<B',changed,0x3000+5,5)
        struct.pack_into('<Q',changed,0x3000+8,BASE+0x6004)
        with self.assertRaisesRegex(ValueError,'alias/overlap'):r.platform(changed,'1.99.1')
        # Native linker-style zero padding may cover a S_ZEROFILL section.
        image.extend(b'\0'*8);struct.pack_into('<QQ',image,bss+40,0x5000,8)
        r.inspect(image,'1.99.1','abort')
        image[0x5000]=8
        with self.assertRaisesRegex(ValueError,'nonzero initial'):r.inspect(image,'1.99.1','abort')

    def test_relocations_and_detector_binding_not_implementation_qualification(self):
        image,meta=fixture();original=r.inspect(image,'1.99.1','abort')
        # Detector implementation stays explicitly trusted; record its hash.
        changed=bytearray(image);struct.pack_into('<I',changed,0xd00,0xd503201f)
        self.assertNotEqual(original['detector']['sha256'],r.inspect(changed,'1.99.1','abort')['detector']['sha256'])
        changed=bytearray(image)
        struct.pack_into('<Q',changed,meta['detect_symbol']+8,meta['start'])
        with self.assertRaisesRegex(ValueError,'overlapping ranges'):r.inspect(changed,'1.99.1','abort')
        for targets,cache in (({**meta['targets'],'detect':BASE+0xd04},BASE+0x6000),
                              (meta['targets'],BASE+0x2000)):
            changed=bytearray(image);raw,_=r.template('1.99.1',meta['start'],targets,meta['addresses'],cache)
            changed[meta['offset']:meta['offset']+meta['size']]=raw
            with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        addresses={**meta['addresses'],'tail8':meta['addresses']['schedule192']+16}
        raw,_=r.template('1.99.1',meta['start'],meta['targets'],addresses,BASE+0x6000)
        image[meta['offset']:meta['offset']+meta['size']]=raw
        r.inspect(image,'1.99.1','abort')

    def test_configuration_and_identity_fail_before_review(self):
        image,_=fixture()
        for config in (('1.90.0','abort','hosted'),('1.99.1','bad','hosted'),('1.99.1','abort','static')):
            with self.assertRaises(ValueError):r.inspect(image,*config)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'fixture';path.write_bytes(image)
            with patch.object(runner.hosted_startup_review,'inspect') as inspect:
                with self.assertRaisesRegex(ValueError,'capture hash mismatch'):
                    runner.check(path,'0'*64,hosted_startup=('1.99.1','abort','hosted'))
                inspect.assert_not_called()
            report=runner.check(path,r.hashlib.sha256(image).hexdigest(),hosted_startup=('1.99.1','abort','hosted'))
            self.assertEqual(report['admission'],'hosted')
            with self.assertRaises(ValueError):runner.check(path,'0'*64,static_startup=('1.99.1','abort','static'),hosted_startup=('1.99.1','abort','hosted'))

    def test_cli_missing_config_and_conflicting_modes(self):
        for extra in ([],['--review-static-startup']):
            result=subprocess.run([sys.executable,str(Path(runner.__file__)),'missing','--sha256','0'*64,
                                   '--review-hosted-startup',*extra],capture_output=True,text=True)
            self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'')

if __name__=='__main__':unittest.main()
