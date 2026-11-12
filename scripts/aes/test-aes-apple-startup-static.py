#!/usr/bin/env python3
"""Static startup controls use constructed Mach-O images, not native execution."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


f=module('startup_apple_fixture','test-aes-apple-unwind-import.py')
runner=module('startup_apple_runner','check-aes-apple-linked.py')
r=runner.startup_review
BASE=f.BASE


def fixture(compiler='1.99.1'):
    original,meta=f.fixture(b'_memcmp')
    code,functions,symbols=r.mapping.parse(original)
    image=bytearray(0x5000)
    image[:0x1000]=original[:0x1000]
    image[0x2000:0x3000]=original[0x1000:0x2000]
    image[0x3000:0x5000]=original[0x2000:0x4000]
    targets={b['role']+str(b['bits']):int(b['address'],16) for b in r.mapping.inspect(original)['bodies']}
    targets['memcmp']=BASE+0xe00
    addresses,positions={},{}
    pos=0x1100
    for role,data in r.REFERENCE.items():
        pos=(pos+15)&~15
        addresses[role]=BASE+pos;positions[role]=(pos,len(data))
        image[pos:pos+len(data)]=data
        pos+=len(data)
    start=functions[-1]
    raw,relocations=r.template(compiler,start,targets,addresses)
    bodypos=start-BASE
    image[bodypos:bodypos+len(raw)]=raw
    image[bodypos+len(raw):bodypos+len(raw)+4]=bytes.fromhex('c0035fd6')
    symbol=('__ZN30brynja_aes_accelerated_fixture7startup17h0000000000000000E' if compiler=='1.90.0' else
            '__RNvCtest_30brynja_aes_accelerated_fixture7startup')
    oldstrings=struct.unpack_from('<I',image,meta['symcmd']+20)[0]
    image[0x3100+oldstrings:0x3100+oldstrings+len(symbol)+1]=symbol.encode()+b'\0'
    image[0x3070:0x3080]=image[0x3060:0x3070]
    struct.pack_into('<IBBHQ',image,0x3060,oldstrings,0xe,1,0,start)
    # Expand immutable text, move writable import pointers and linkedit away.
    struct.pack_into('<Q',image,64,0x2000);struct.pack_into('<Q',image,80,0x2000)
    struct.pack_into('<Q',image,144,bodypos+len(raw)+4-0x400)
    cursor=32
    for _ in range(struct.unpack_from('<I',image,16)[0]):
        cmd,length=struct.unpack_from('<II',image,cursor)
        if cmd==0x19:
            label=image[cursor+8:cursor+24].split(b'\0')[0]
            if label in (b'__DATA',b'__LINKEDIT'):
                for off in (24,40):
                    struct.pack_into('<Q',image,cursor+off,struct.unpack_from('<Q',image,cursor+off)[0]+0x1000)
                if label==b'__DATA':
                    struct.pack_into('<Q',image,cursor+72+32,BASE+0x2000)
                    struct.pack_into('<I',image,cursor+72+48,0x2000)
        cursor+=length
    struct.pack_into('<6I',image,meta['symcmd'],2,24,0x3000,8,0x3100,oldstrings+len(symbol)+1)
    encoded=bytearray();previous=BASE
    for address in [*functions,start+len(raw)]:
        encoded.extend(f.fixture_module.uleb(address-previous));previous=address
    encoded.append(0)
    image[0x3800:0x3800+len(encoded)]=encoded
    struct.pack_into('<4I',image,meta['symcmd']+24,0x26,16,0x3800,len(encoded))
    struct.pack_into('<I',image,meta['dysymcmd']+12,7) # local count
    struct.pack_into('<I',image,meta['dysymcmd']+24,7) # first undefined
    struct.pack_into('<I',image,meta['dysymcmd']+56,0x3a00)
    struct.pack_into('<I',image,meta['dyldcmd']+32,0x3900)
    struct.pack_into('<2I',image,0x3a00,7,7)
    struct.pack_into('<I',image,0xe00,0xd0000010)
    return image,dict(start=start,offset=bodypos,size=len(raw),targets=targets,
                     addresses=addresses,positions=positions,relocations=relocations)


class AppleStaticStartupTests(unittest.TestCase):
    def test_both_compilers_profiles_and_fixed_population(self):
        for compiler,size in (('1.90.0',784),('1.99.1',772)):
            image,meta=fixture(compiler)
            for panic in ('abort','unwind'):
                result=r.inspect(image,compiler,panic)
                self.assertEqual(result['startup']['size'],size)
                self.assertEqual(len(result['kernels']['bodies']),6)
                self.assertEqual(result['comparison_import']['symbol'],'_memcmp')
                self.assertEqual({ref['role'] for ref in result['references']},set(r.REFERENCE))
                self.assertEqual(len(result['references']),10 if compiler=='1.90.0' else 11)
                self.assertEqual(sum(word>>26==0x25 for word in struct.unpack('<'+'I'*(size//4),
                    image[meta['offset']:meta['offset']+size])),12)

    def test_every_startup_byte_rejected(self):
        total=0
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            for offset in range(meta['offset'],meta['offset']+meta['size']):
                changed=bytearray(image);changed[offset]^=0xff
                with self.subTest(compiler=compiler,offset=offset),self.assertRaises(ValueError):
                    r.inspect(changed,compiler,'abort')
                total+=1
        self.assertEqual(total,1556)

    def test_equivalent_immutable_constant_relocation_is_allowed(self):
        # tail8 also occurs at schedule192+16. Changing only that address to
        # identical immutable bytes is valid relocation, not an instruction bug.
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            addresses={**meta['addresses'],'tail8':meta['addresses']['schedule192']+16}
            raw,_=r.template(compiler,meta['start'],meta['targets'],addresses)
            image[meta['offset']:meta['offset']+meta['size']]=raw
            r.inspect(image,compiler,'abort')

    def test_every_reference_byte_rejected(self):
        total=0
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            for role,(pos,size) in meta['positions'].items():
                for offset in range(pos,pos+size):
                    changed=bytearray(image);changed[offset]^=1
                    with self.subTest(role=role,offset=offset),self.assertRaisesRegex(ValueError,'reference changed'):
                        r.inspect(changed,compiler,'abort')
                    total+=1
        self.assertEqual(total,1456)

    def test_direction_lengths_health_and_wrong_architecture_branches(self):
        for compiler in ('1.90.0','1.99.1'):
            image,meta=fixture(compiler)
            words=list(struct.unpack('<'+'I'*(meta['size']//4),image[meta['offset']:meta['offset']+meta['size']]))
            # Zero/one direction, comparison lengths, generation and health
            # discriminate independently of template-vs-template construction.
            replacements={0x52800002:0x52800022,0x52800022:0x52800002,
                0x52801602:0x52801402,0x52801a02:0x52801802,0x52801e02:0x52801c02,
                0x7a400900:0x7100011f,0x52800049:0x52800029}
            counts={key:0 for key in replacements}
            for i,word in enumerate(words):
                if word in replacements:
                    counts[word]+=1; changed=bytearray(image)
                    struct.pack_into('<I',changed,meta['offset']+i*4,replacements[word])
                    with self.assertRaises(ValueError):r.inspect(changed,compiler,'abort')
            self.assertEqual(counts,{key:3 if key in (0x52800002,0x52800022) else 1 for key in replacements})
            for i in (9,):
                changed=bytearray(image);struct.pack_into('<I',changed,meta['offset']+i*4,0xd503201f)
                with self.assertRaises(ValueError):r.inspect(changed,compiler,'abort')

    def test_calls_constants_and_dependencies_cannot_be_substituted(self):
        image,meta=fixture()
        words=struct.unpack('<'+'I'*(meta['size']//4),image[meta['offset']:meta['offset']+meta['size']])
        for i,word in enumerate(words):
            if word>>26==0x25:
                for edited in (word+1,word^0x80000000):
                    changed=bytearray(image);struct.pack_into('<I',changed,meta['offset']+i*4,edited)
                    with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        for offset in (0x400,0xe00,0x2000,0x3904,meta['offset']+meta['size']-4):
            changed=bytearray(image);changed[offset]^=1
            with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        with patch.object(r.imports,'inspect',side_effect=ValueError('import rejected')):
            with self.assertRaisesRegex(ValueError,'import rejected'):r.inspect(image,'1.99.1','abort')
        changed=bytearray(image);struct.pack_into('<ii',changed,88,7,7)
        with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')

    def test_symbol_profile_and_extent_fail_closed(self):
        image,meta=fixture()
        for compiler,panic,admission in (('unknown','abort','static'),('1.99.1','other','static'),
                ('1.99.1','abort','hosted'),('1.90.0','abort','static')):
            with self.assertRaises(ValueError):r.inspect(image,compiler,panic,admission)
        for changed in (image.replace(b'fixture7startup',b'fixture7startuq'),image[:meta['offset']+4]):
            with self.assertRaises(ValueError):r.inspect(changed,'1.99.1','abort')
        targets=dict(meta['targets']);targets['expand128']+=2
        with self.assertRaises(ValueError):r.template('1.99.1',meta['start'],targets,meta['addresses'])

    def test_cli_hash_configuration_and_failure_output(self):
        image,_=fixture()
        with tempfile.TemporaryDirectory() as temporary:
            binary=Path(temporary)/'fixture.macho';binary.write_bytes(image)
            command=[sys.executable,str(Path(__file__).with_name('check-aes-apple-linked.py')),
                str(binary),'--sha256',r.hashlib.sha256(image).hexdigest(),
                '--review-static-startup','--compiler','1.99.1','--panic','abort','--admission','static']
            good=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertEqual(json.loads(good.stdout)['startup']['size'],772)
            badhash=command.copy();badhash[4]='0'*64
            for args in (command[:-2],command[:-1]+['hosted'],command+['--review-cleanup'],badhash):
                bad=subprocess.run(args,capture_output=True,text=True)
                self.assertEqual(bad.returncode,2,bad.stderr);self.assertEqual(bad.stdout,'')
            with self.assertRaises(ValueError):runner.check(binary,r.hashlib.sha256(image).hexdigest(),
                static_startup=('1.99.1','abort','static'),cleanup=('1.99.1','abort','static'))


if __name__=='__main__':unittest.main()
