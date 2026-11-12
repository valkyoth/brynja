#!/usr/bin/env python3
"""Synthetic image controls for x86 startup review; no production policy learning."""
import importlib.util
from pathlib import Path
import struct
import tomllib
import unittest
from types import SimpleNamespace
from unittest.mock import patch


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


x=module('x86_startup_test_review','aes_accelerated_startup_x86.py')
runner=module('x86_startup_test_runner','check-aes-accelerated-startup-x86.py')


def synthetic():
    image=bytearray(0x2000);image[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',image,16,3,62,1)
    struct.pack_into('<Q',image,32,64);struct.pack_into('<HHH',image,52,64,56,4)
    for i,(kind,mode,pos,base,size) in enumerate(((1,4,0,0x1000,0x1000),
            (1,5,0x1000,0x3000,0x800),(1,6,0x1800,0x4000,0x800),(2,6,0x1800,0x4000,128))):
        struct.pack_into('<IIQQQQQQ',image,64+56*i,kind,mode,pos,base,0,size,size,8)
    for i,(tag,value) in enumerate(((5,0x1280),(6,0x1200),(7,0x1300),(8,24),(9,24),(10,6),(11,24),(0,0))):
        struct.pack_into('<qQ',image,0x1800+16*i,tag,value)
    image[0x280:0x286]=b'\0bcmp\0'
    struct.pack_into('<IBBHQQ',image,0x218,1,0x12,0,0,0,0)
    struct.pack_into('<QQq',image,0x300,0x4200,(1<<32)|6,0)
    targets={k+str(b):(k+str(b),0x3400+i*16,1) for i,(k,b) in enumerate((k,b) for k in ('expand','round') for b in (128,192,256))}
    lines=[];raw=bytearray();sizes=[];refs=[];start=0x3100
    def emit(text,data):lines.append(text);raw.extend(data);sizes.append(len(data))
    def rip(op,reg,address,prefix):
        delta=address-(start+len(raw)+len(prefix)+4)
        emit(f'{op} {delta}(%rip), %{reg} # 0x{address:x} <data>',prefix+delta.to_bytes(4,'little',signed=True))
    for role,(_,address,_) in targets.items():
        delta=address-(start+len(raw)+5)
        emit(f'callq 0x{address:x} <{role}>',b'\xe8'+delta.to_bytes(4,'little',signed=True))
    rip('movq','r12',0x4200,bytes.fromhex('4c8b25'))
    pos=0x500
    for role,data in x.REFERENCE.items():
        image[pos:pos+len(data)]=data;refs.append(dict(role=role,offset=pos,size=len(data)))
        if role.startswith('schedule'):
            rip('leaq','rsi',0x1000+pos,bytes.fromhex('488d35'))
            emit('callq *%r12',bytes.fromhex('41ffd4'))
        else:rip('movups','xmm0',0x1000+pos,bytes.fromhex('0f1005'))
        pos+=len(data)
    emit('retq',b'\xc3');image[0x1100:0x1100+len(raw)]=raw
    return (lines,bytes(raw),sizes,('startup',start,len(raw)),bytes(image),targets),refs


class X86StartupTests(unittest.TestCase):
    def test_policies_and_synthetic_never_approve_production(self):
        self.assertEqual(set(x.POLICY),{'1.90.0','1.99.1'})
        args,_=synthetic()
        for compiler,profiles in x.POLICY.items():
            self.assertEqual(set(profiles),{'abort','unwind'})
            for panic,p in profiles.items():
                self.assertEqual((p['instructions'],p['symbol_bytes']),(185,913) if compiler=='1.90.0' else (172,845))
                self.assertEqual((p['calls'],p['import_calls']),(9,3))
                for field in ('text_sha256','encoding_sha256'):self.assertRegex(p[field],r'^[0-9a-f]{64}$')
                with self.assertRaisesRegex(ValueError,'stream changed'):x.check(*args,compiler,panic)

    def test_import_uses_actual_dynamic_metadata_and_undefined_function(self):
        args,_=synthetic();image=args[4]
        self.assertEqual(x.bcmp_import(image)[0],0x4200)
        # Header/segment, dynamic table, relocation, symbol, name and GOT data.
        for pos,fmt,value in ((16,'H',1),(18,'H',183),(56,'H',3),(64+3*56+32,'Q',127),
                (0x1800,'q',6),(0x1808,'Q',0x3280),(0x1848,'Q',8),(0x1858,'Q',999999),
                (0x1870,'q',1),(0x300,'Q',0x3200),(0x308,'Q',(1<<32)|7),(0x310,'q',1),
                (0x218,'I',6),(0x21c,'B',0x22),(0x21d,'B',1),(0x21e,'H',1),(0x220,'Q',1),
                (0x228,'Q',1),(0x281,'B',ord('a')),(0x285,'B',ord('x')),(0x1a00,'Q',1)):
            changed=bytearray(image);struct.pack_into('<'+fmt,changed,pos,value)
            with self.subTest(pos=pos,value=value):
                with self.assertRaises(ValueError):x.bcmp_import(bytes(changed))

    def test_duplicate_and_conflicting_loader_relocations_fail(self):
        args,_=synthetic();image=bytearray(args[4])
        struct.pack_into('<Q',image,0x1838,48)
        image[0x318:0x330]=image[0x300:0x318]
        with self.assertRaisesRegex(ValueError,'duplicate'):x.bcmp_import(bytes(image))
        image=bytearray(args[4])
        struct.pack_into('<Q',image,64+3*56+32,176);struct.pack_into('<Q',image,64+3*56+40,176)
        for i,(tag,value) in enumerate(((2,24),(20,7),(23,0x1340),(0,0))):
            struct.pack_into('<qQ',image,0x1870+16*i,tag,value)
        struct.pack_into('<QQq',image,0x340,0x4210,(1<<32)|7,0)
        self.assertEqual(x.bcmp_import(bytes(image))[0],0x4200)
        struct.pack_into('<Q',image,0x340,0x4200)
        with self.assertRaisesRegex(ValueError,'overlap'):x.bcmp_import(bytes(image))
        for tag in (17,18,19,35,36,37):
            changed=bytearray(args[4]);struct.pack_into('<q',changed,0x1800,tag)
            with self.assertRaisesRegex(ValueError,'unsupported'):x.bcmp_import(bytes(changed))

    def test_each_instruction_byte_operand_and_call_target_is_checked(self):
        args,_=synthetic();lines,raw,sizes,row,image,targets=args
        actual=x.observe(*args)[0]
        with patch.dict(x.POLICY,{'1.99.1':{'abort':actual}}):
            x.check(*args,'1.99.1','abort')
            for i in range(len(lines)+len(raw)):
                text,code,binary=list(lines),raw,image
                if i<len(lines):text[i]='unreviewed-instruction'
                else:
                    j=i-len(lines);code=raw[:j]+bytes([raw[j]^1])+raw[j+1:]
                    binary=image[:0x1100]+code+image[0x1100+len(code):]
                with self.assertRaises(ValueError):x.check(text,code,sizes,row,binary,targets,'1.99.1','abort')
            for role,(name,address,size) in targets.items():
                for bad in ((name,address+1,size),('wrong',address,size),row):
                    with self.assertRaises(ValueError):x.check(*args[:5],{**targets,role:bad},'1.99.1','abort')
            for i,l in enumerate(lines):
                if '%rip' in l:
                    text=list(lines);text[i]=l.replace('%rsi','%rdi').replace('%r12','%r13').replace('%xmm0','%xmm1')
                    with self.assertRaises(ValueError):x.check(text,*args[1:],'1.99.1','abort')

    def test_every_reference_byte_and_read_only_extent_is_bound(self):
        args,refs=synthetic();actual=x.observe(*args)[0]
        with patch.dict(x.POLICY,{'1.99.1':{'abort':actual}}):
            for ref in refs:
                for i in range(ref['size']):
                    p=ref['offset']+i;image=args[4];changed=image[:p]+bytes([image[p]^1])+image[p+1:]
                    with self.assertRaises(ValueError):x.check(*args[:4],changed,*args[5:],'1.99.1','abort')
        with self.assertRaises(ValueError):x.reference_at(args[4],[(0x1000,0x1000,0,0x1000,6)],0x1500,True)
        with self.assertRaises(ValueError):x.observe(args[0],args[1][:-1],*args[2:])

    def test_corruption_cases_are_bounded_single_byte_edits(self):
        args,refs=synthetic();image=args[4];cases=list(x.corruption_cases(image,refs))
        self.assertEqual(len(cases),628);self.assertEqual(len({n for n,_ in cases}),628)
        for name,changed in cases:
            role,index=name.split(':');ref=next(r for r in refs if r['role']==role)
            expected=bytearray(image);expected[ref['offset']+int(index)]^=1
            self.assertEqual(changed,bytes(expected))
        for bad in (refs[:-1],refs+[refs[0]],[{**r,'offset':-1} for r in refs],[{**r,'size':0} for r in refs]):
            with self.assertRaises(ValueError):list(x.corruption_cases(image,bad))

    def test_symbols_and_invalid_compiler_fail_closed(self):
        for name in ('_ZN30brynja_aes_accelerated_fixture7startup17h0000000000000000E',
                     '_RNvCs123_30brynja_aes_accelerated_fixture7startup'):
            table=f'00003100 00000010 t {name}'
            self.assertEqual(x.candidate(table),(name,0x3100,16))
            for bad in ('',table+'\n'+table,table.replace(' t ',' D '),table.replace('00000010','00000000')):
                with self.assertRaises(ValueError):x.candidate(bad)
            with patch.object(x.kernels,'inspect',side_effect=ValueError('rounds rejected')),patch.object(x,'check') as checked:
                with self.assertRaisesRegex(ValueError,'rounds rejected'):x.inspect(table,'',b'','1.99.1','abort')
                checked.assert_not_called()
        with patch.object(runner.packaged,'package_sources') as package:
            with self.assertRaises(ValueError):runner.check('unknown')
            package.assert_not_called()

    def test_registry_pins_runtime_probe_and_review_inputs(self):
        registry=tomllib.loads((runner.ROOT/'verification/checks.toml').read_text())
        checks={c['id']:c for c in registry['checks'] if c.get('category')=='aes-linked-x86-startup'}
        self.assertEqual(set(checks),{'accelerated-x86-startup-msrv','accelerated-x86-startup-current'})
        for endpoint,compiler in (('msrv','1.90.0'),('current','1.99.1')):
            check=checks['accelerated-x86-startup-'+endpoint]
            self.assertEqual(check['command'],['python3','scripts/aes/check-aes-accelerated-startup-x86.py','--toolchain',compiler])
            self.assertEqual(check['success']['unique_lines'],[f'AES_X86_STARTUP_LINKED_PASS: {compiler}; four static native consumers'])
            self.assertTrue({'aes-build','aes-accelerated-x86-startup','aes-accelerated-linked','aes-accelerated-campaigns','aes-packaged'}<=set(check['inputs']))
        self.assertEqual(set(registry['groups']['aes-accelerated-x86-startup']['paths']),{
            'assurance/aes-accelerated-campaigns/startup-x86.rs','assurance/aes-kernel-candidate/probe.rs',
            'scripts/aes/check-aes-accelerated-startup-x86.py','scripts/aes/aes_accelerated_startup_x86.py',
            'scripts/aes/startup-x86-review.json','scripts/aes/startup-arm-reference.json',
            'scripts/aes/aes_linked_mix.py','scripts/aes/test-aes-accelerated-startup-x86.py',
            'docs/assurance/aes-accelerated-x86-startup.md'})

    def test_host_probe_is_baseline_compiled_and_requires_exact_success(self):
        root=Path('/tmp/startup-probe-test');env={}
        for compiler in ('1.90.0','1.99.1'):
            result=SimpleNamespace(stdout='AES_STATIC_HOST_BUNDLE_PASS\n',stderr='')
            with patch.object(runner.packaged.archives,'run',return_value=result) as run:
                self.assertEqual(runner.probe_host(root,env,compiler),result.stdout)
                self.assertEqual(run.call_args_list[0].args[0],['rustc','+'+compiler,'--edition=2024',
                    str(runner.ROOT/'assurance/aes-kernel-candidate/probe.rs'),'--target',runner.TARGET,'-o',str(root/'probe')])
                self.assertEqual(run.call_args_list[1].args[0],[str(root/'probe')])
            for stdout,stderr in (('',''),('wrong',''),('AES_STATIC_HOST_BUNDLE_PASS\nextra',''),
                                  ('AES_STATIC_HOST_BUNDLE_PASS\n','warning')):
                with patch.object(runner.packaged.archives,'run',return_value=SimpleNamespace(stdout=stdout,stderr=stderr)):
                    with self.assertRaisesRegex(ValueError,'ISA probe failed'):runner.probe_host(root,env,compiler)


if __name__=='__main__':unittest.main()
