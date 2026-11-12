#!/usr/bin/env python3
"""Hosted startup negative controls; synthetic code never approves real code."""
import importlib.util
from pathlib import Path
import re
import struct
import tomllib
import unittest
from unittest.mock import patch


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


h=module('hosted_startup_review_tests','aes_accelerated_startup_hosted.py')
static=module('hosted_startup_fixtures','test-aes-accelerated-startup.py')


def synthetic():
    args,refs=static.synthetic();old,raw,row,image,targets=args
    image=bytearray(image);start=row[1];lines=['nop']*43;data=bytearray(h.s.NOP*43)
    targets={k:(name,address+0x100,size) for k,(name,address,size) in targets.items()}
    targets['detect']=('detect',0x17c0,4)
    cache=('cache',0x2000,8)
    struct.pack_into('<H',image,56,2)
    struct.pack_into('<IIQQQQQQ',image,120,1,6,len(image),0x2000,0,0,8,0x1000)
    def put(i,line,word):lines[i]=line;data[i*4:i*4+4]=word.to_bytes(4,'little')
    put(0,'bl 0x17c0 <detect>',0x94000000|((0x17c0-start)//4))
    put(11,'adrp x20, 0x2000 <cache>',0xb0000014)
    for i in (12,15,36):
        put(i,'ldr x8, [x20, #0]',0xf9400288)
    put(14,'ubfx x19, x8, #3, #1',0xd3430d13)
    put(17,'ubfx x8, x8, #1, #1',0xd3410508)
    put(31,'mov x8, x0',0xaa0003e8)
    put(40,'mov x8, x0',0xaa0003e8)
    for i,line in enumerate(old):
        word=int.from_bytes(raw[i*4:i*4+4],'little')
        if line.startswith('bl '):
            name=re.search(r'<([^>]+)>',line)[1];address=targets[name][1]
            line=f'bl 0x{address:x} <{name}>';word=0x94000000|(((address-start-len(data))//4)&0x3ffffff)
        elif line.startswith('adr '):
            address=int(re.search(r'0x([0-9a-f]+)',line)[1],16);delta=address-start-len(data)
            word=0x10000014|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
        lines.append(line);data.extend(word.to_bytes(4,'little'))
    image[0x500:0x500+len(data)]=data
    return (lines,bytes(data),('startup',start,len(data)),bytes(image),targets,cache),refs


class HostedStartupTests(unittest.TestCase):
    def test_complete_policies_and_synthetic_rejection(self):
        self.assertEqual(set(h.POLICY),{'1.90.0','1.99.1'})
        args,_=synthetic()
        for compiler,p in h.POLICY.items():
            self.assertEqual(p['instructions'],254 if compiler=='1.90.0' else 251)
            self.assertEqual((p['branches'],p['calls'],p['constants'],p['address_constants'],p['mutable_caches']),(11,14,3,7,1))
            for field in ('text_sha256','encoding_sha256'):self.assertRegex(p[field],r'^[0-9a-f]{64}$')
            with self.assertRaisesRegex(ValueError,'stream changed'):h.check(*args,compiler)

    def test_all_instruction_bytes_and_cache_relocations_checked(self):
        args,_=synthetic();lines,raw,row,image,targets,cache=args
        actual=h.observe(*args)[0]
        with patch.dict(h.POLICY,{'1.99.1':actual}):
            self.assertEqual(h.s.mutations(h.check,*args,'1.99.1'),len(lines)+len(raw))
            for bad in ((cache[0],cache[1]+8,8),(cache[0],0x1800,8),(cache[0],cache[1],16)):
                with self.assertRaises(ValueError):h.check(*args[:-1],bad,'1.99.1')
            for role,(name,address,size) in targets.items():
                changed={**targets,role:(name,address+4,size)}
                with self.assertRaises(ValueError):h.check(*args[:4],changed,cache,'1.99.1')
            for i in (11,12,14,15,17,36):
                changed=lines.copy();changed[i]=changed[i].replace('x8','x9').replace('x20','x21')
                with self.assertRaises(ValueError):h.check(changed,*args[1:],'1.99.1')

    def test_bss_mapping_must_be_unique_zero_filled_and_writable(self):
        args,_=synthetic()
        for offset,value in ((124,5),(152,8),(160,4),(56,1)):
            image=bytearray(args[3]);struct.pack_into('<H' if offset==56 else '<I',image,offset,value)
            with self.assertRaises(ValueError):h.observe(*args[:3],bytes(image),*args[4:])
        for n in (0,12,42):
            with self.assertRaises(ValueError):h.observe(args[0][:n],args[1][:4*n],('startup',args[2][1],4*n),*args[3:])

    def test_platform_symbols_strict(self):
        for detect,cache in (
            ('_ZN10std_detect6detect5cache21detect_and_initialize17h0000000000000000E',
             '_ZN10std_detect6detect5cache5CACHE17h0000000000000000E.0'),
            ('_RNvNtNtCs123_10std_detect6detect5cache21detect_and_initialize',
             '_RNvNtNtCs123_10std_detect6detect5cache5CACHE.0')):
            table=f'000017c0 00000004 t {detect}\n00002000 00000008 b {cache}'
            self.assertEqual(set(h.platform_rows(table)),{'detect','cache'})
            for bad in ('',table+'\n'+table,table.replace('00000008','00000004'),
                        table.replace('00002000','00002001'),table.replace(' b ',' d '),table.replace('CACHE','OTHER')):
                with self.assertRaises(ValueError):h.platform_rows(bad)

    def test_admission_controls_only_replace_detector_observations(self):
        args,_=synthetic();lines,raw,row,image,targets,cache=args
        with patch.object(h.s,'candidates',return_value={'startup':row,'bcmp':targets['bcmp'],'memcmp':('memcmp',0x17e0,4)}), \
             patch.object(h,'platform_rows',return_value={'detect':targets['detect'],'cache':cache}), \
             patch.object(h.c,'decode',return_value=(lines,raw)), \
             patch.object(h.c.kernels,'select',return_value=[]), \
             patch.object(h.c.expansion,'select',return_value=[]), \
             patch.object(h,'check') as checked:
            cases=list(h.admission_cases('','',image,'1.99.1','abort'))
            checked.assert_called_once()
            self.assertEqual([n for n,_ in cases],['warm-aes-absent','cold-aes-absent',
                                                 'warm-pmull-absent','cold-pmull-absent'])
            edits_by_case=[]
            for value in (0xd2800048,0xd2800108):
                edits_by_case.extend(({12:value,15:value,36:value},
                                      {12:0xd2800008,15:0xd2800008,36:0xd2800008,31:value,40:value}))
            for (_,changed),edits in zip(cases,edits_by_case):
                expected=bytearray(image)
                for i,word in edits.items():expected[0x500+4*i:0x504+4*i]=word.to_bytes(4,'little')
                self.assertEqual(changed,bytes(expected))
            with patch.object(h,'check',side_effect=ValueError('baseline rejected')):
                with self.assertRaisesRegex(ValueError,'baseline rejected'):list(h.admission_cases('','',image,'1.99.1','abort'))

    def test_registry_hosted_scope(self):
        registry=tomllib.loads((static.runner.ROOT/'verification/checks.toml').read_text())
        checks={c['id']:c for c in registry['checks'] if c.get('category')=='aes-linked-arm-hosted-startup'}
        self.assertEqual(set(checks),{'accelerated-arm-hosted-startup-msrv','accelerated-arm-hosted-startup-current'})
        for endpoint,compiler in (('msrv','1.90.0'),('current','1.99.1')):
            check=checks['accelerated-arm-hosted-startup-'+endpoint]
            self.assertEqual(check['command'],['python3','scripts/aes/check-aes-accelerated-startup.py','--toolchain',compiler,'--admission','hosted'])
            self.assertEqual(check['success']['unique_lines'],[f'AES_ARM_HOSTED_STARTUP_LINKED_PASS: {compiler}; four hosted emulated consumers'])
            self.assertTrue({'aes-accelerated-startup','aes-accelerated-hosted-startup','hosted-cpu-source','aes-kernel-qemu'}<=set(check['inputs']))
        self.assertEqual(set(registry['groups']['aes-accelerated-hosted-startup']['paths']),{
            'assurance/aes-accelerated-campaigns/startup-hosted.rs','scripts/aes/aes_accelerated_startup_hosted.py',
            'scripts/aes/startup-hosted-review.json','scripts/aes/test-aes-accelerated-startup-hosted.py',
            'docs/assurance/aes-accelerated-hosted-startup.md'})


if __name__=='__main__':unittest.main()
