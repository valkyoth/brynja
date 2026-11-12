#!/usr/bin/env python3
"""Native-control runner tests; mocked execution is never hardware evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


r=module('apple_native_controls','check-aes-apple-startup-controls.py')
f=module('apple_native_control_fixture','test-aes-apple-startup-static.py')
h=module('apple_hosted_native_control_fixture','test-aes-apple-startup-hosted.py')


def fixture(admission='static'):
    image,meta=(h if admission=='hosted' else f).fixture()
    count,length=struct.unpack_from('<II',image,16)
    struct.pack_into('<4I',image,32+length,0x1d,16,0x4800,0x800)
    struct.pack_into('<II',image,16,count+1,length+16)
    struct.pack_into('>III',image,0x4800,0xfade0cc0,0x800,0)
    return image,meta


class AppleStartupControlTests(unittest.TestCase):
    def test_signature_only_changes_are_allowed(self):
        image,_=fixture();self.assertEqual(r.signature(image),(0x4800,0x800))
        changed=bytearray(image);changed[0x4850]^=1
        r.signed_copy_matches(image,changed)
        for offset in (0x400,0x1100,0x3000,0x3800,0x3900):
            changed=bytearray(image);changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(ValueError):r.signed_copy_matches(image,changed)
        with self.assertRaises(ValueError):r.signed_copy_matches(image,image+b'\0')

    def test_signature_resize_only_changes_its_two_validated_sizes(self):
        image,_=fixture();cursor=32
        while image[cursor+8:cursor+24].rstrip(b'\0')!=b'__LINKEDIT':
            cursor+=struct.unpack_from('<I',image,cursor+4)[0]
        # Leave mapped padding for a larger terminal signature, without changing
        # VM size during signing. Growth beyond the mapping remains invalid.
        struct.pack_into('<Q',image,cursor+32,struct.unpack_from('<Q',image,cursor+32)[0]+0x1000)
        cmd=32+struct.unpack_from('<I',image,20)[0]-16
        for delta in (-0x400,0x400):
            changed=bytearray(image[:len(image)+delta] if delta<0 else image+b'\0'*delta)
            struct.pack_into('<Q',changed,cursor+48,struct.unpack_from('<Q',image,cursor+48)[0]+delta)
            struct.pack_into('<I',changed,cmd+12,0x800+delta)
            struct.pack_into('>I',changed,0x4804,0x800+delta)
            r.signed_copy_matches(image,changed)
            for field in (cursor+48,cmd+12,cursor+32,cursor+40,cmd+8,0x400,0x1100):
                invalid=bytearray(changed);invalid[field]^=1
                with self.subTest(delta=delta,field=field),self.assertRaises(ValueError):
                    r.signed_copy_matches(image,invalid)

    def test_signature_layout_and_table_overlap_fail_closed(self):
        image,_=fixture();cmd=32+struct.unpack_from('<I',image,20)[0]-16
        for offset,value in ((cmd,0x29),(cmd+4,8),(cmd+8,0x3000),(cmd+12,0x801),(0x4800,0)):
            changed=bytearray(image);struct.pack_into('<I',changed,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):r.signature(changed)
        cursor=32
        while struct.unpack_from('<I',image,cursor)[0]!=0x80000022:
            cursor+=struct.unpack_from('<I',image,cursor+4)[0]
        # Bind stream must not be hidden within the permitted signature region.
        struct.pack_into('<II',image,cursor+16,0x4800,16)
        with self.assertRaisesRegex(ValueError,'runtime linkedit tables'):r.signature(image)

    def test_exact_628_public_answer_mutations(self):
        image,_=fixture();report=r.review.inspect(image,'1.99.1','abort')
        cases=list(r.corruption_cases(image,report))
        self.assertEqual(len(cases),628);self.assertEqual(len({c[0] for c in cases}),628)
        counts={}
        for case,offset,changed in cases:
            counts[case.split(':')[0]]=counts.get(case.split(':')[0],0)+1
            self.assertEqual(changed,image[:offset]+bytes([image[offset]^1])+image[offset+1:])
            self.assertEqual(r.signature(changed),r.signature(image))
        self.assertEqual(counts,dict(schedule128=176,schedule192=208,schedule256=240,
                                     plain=1,cipher128=1,cipher192=1,cipher256=1))
        for refs in (report['references'][:-2], [{**x,'offset':-1} for x in report['references']],
                     report['references']+[{**next(x for x in report['references'] if x['role']=='schedule128'),'size':0}]):
            with self.assertRaises(ValueError):list(r.corruption_cases(image,{'references':refs}))

    def test_wrong_host_hash_environment_and_profile_reject_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            binary=Path(temp).resolve()/'input';binary.write_bytes(fixture()[0]);expected=r.digest(binary.read_bytes())
            for system,machine,sha,compiler,panic,environment in (
                ('Linux','aarch64',expected,'1.99.1','abort',{}),
                ('Darwin','x86_64',expected,'1.99.1','abort',{}),
                ('Darwin','arm64','0'*64,'1.99.1','abort',{}),
                ('Darwin','arm64',expected,'bad','abort',{}),
                ('Darwin','arm64',expected,'1.99.1','bad',{}),
                ('Darwin','arm64',expected,'1.99.1','abort',{'DYLD_INSERT_LIBRARIES':'bad'})):
                with patch.object(r.platform,'system',return_value=system), \
                     patch.object(r.platform,'machine',return_value=machine), \
                     patch.dict(r.os.environ,environment,clear=True),patch.object(r,'run') as run:
                    with self.assertRaises(ValueError):r.check(binary,sha,compiler,panic)
                    run.assert_not_called()
            link=binary.parent/'linked';link.symlink_to(binary)
            with patch.object(r.platform,'system',return_value='Darwin'), \
                 patch.object(r.platform,'machine',return_value='arm64'), \
                 patch.dict(r.os.environ,{},clear=True),patch.object(r,'run') as run:
                with self.assertRaisesRegex(ValueError,'symlinked'):
                    r.check(link,expected,'1.99.1','abort')
                run.assert_not_called()

    def test_execution_requires_success_exit_exact_marker_and_no_stderr(self):
        for result in (SimpleNamespace(returncode=1,stdout=r.QUARANTINED+'\n',stderr=''),
                       SimpleNamespace(returncode=0,stdout='',stderr=''),
                       SimpleNamespace(returncode=0,stdout=r.PASS+'\n',stderr=''),
                       SimpleNamespace(returncode=0,stdout=r.QUARANTINED+'\n',stderr='diagnostic'),
                       SimpleNamespace(returncode=0,stdout=r.QUARANTINED+'\nextra\n',stderr='')):
            with patch.object(r.subprocess,'run',return_value=result):
                with self.assertRaises(ValueError):r.execute(Path('/tmp/control'),Path('/tmp'),{},True)
        with patch.object(r.subprocess,'run',side_effect=subprocess.TimeoutExpired('control',30)):
            with self.assertRaises(subprocess.TimeoutExpired):r.execute(Path('/tmp/control'),Path('/tmp'),{},True)

    def test_native_workflow_preserves_original_and_retains_every_case(self):
        self.workflow('static')

    def test_hosted_workflow_retains_both_admission_controls_and_fails_closed(self):
        self.workflow('hosted')

    def test_hosted_output_markers_do_not_accept_static_or_wrong_state(self):
        for stdout in (r.QUARANTINED+'\n','AES_ARM_HOSTED_STARTUP_PASS\n','AES_ARM_HOSTED_STARTUP_QUARANTINED\n'):
            with patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=stdout,stderr='')):
                with self.assertRaises(ValueError):r.execute(Path('/tmp/control'),Path('/tmp'),{},False,'hosted',True)
        with patch.object(r,'run') as run:
            for admission,quarantined in (('static',False),('hosted',True),('bad',False)):
                with self.assertRaises(ValueError):r.execute(Path('/tmp/control'),Path('/tmp'),{},quarantined,admission,True)
            run.assert_not_called()

    def workflow(self,admission):
        failures=(None,'negative-output','signing-modifies-code')+ (('missing-feature-output',) if admission=='hosted' else ())
        prefix='AES_ARM_HOSTED_STARTUP' if admission=='hosted' else 'AES_ARM_STARTUP'
        for failure in failures:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temp:
                # macOS commonly spells its temp root through /var, a symlink.
                # Canonicalize our own fixture directory, not caller inputs.
                root=Path(temp).resolve();image,_=fixture(admission)
                binary=root/'original.macho';binary.write_bytes(image)
                tool=root/'codesign';tool.write_bytes(b'mocked tool')
                observed=[];output=io.StringIO()
                def process(argv,**kwargs):
                    observed.append(argv)
                    self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                    self.assertEqual(kwargs['timeout'],30)
                    stdout=''
                    if argv[0]==str(tool) and '--force' in argv:
                        path=Path(argv[-1]);data=bytearray(path.read_bytes())
                        data[0x400 if failure=='signing-modifies-code' else 0x4850]^=1
                        path.write_bytes(data)
                    elif argv[0]!=str(tool):
                        negative=argv[-1]=='expect-quarantined'
                        absent=argv[-1]=='expect-unavailable'
                        stdout=prefix+('_UNAVAILABLE' if absent and failure!='missing-feature-output' else
                                       '_QUARANTINED' if negative and failure!='negative-output' else '_PASS')+'\n'
                    return SimpleNamespace(returncode=0,stdout=stdout,stderr='')
                with patch.object(r,'ROOT',root),patch.object(r,'CODESIGN',tool), \
                     patch.object(r.platform,'system',return_value='Darwin'), \
                     patch.object(r.platform,'machine',return_value='arm64'), \
                     patch.dict(r.os.environ,{},clear=True),patch.object(r.subprocess,'run',side_effect=process), \
                     contextlib.redirect_stdout(output):
                    if failure:
                        with self.assertRaises(ValueError):r.check(binary,r.digest(image),'1.99.1','abort',admission)
                    else:result=r.check(binary,r.digest(image),'1.99.1','abort',admission)
                self.assertEqual(binary.read_bytes(),image)
                reports=list((root/'target').rglob('report.json'))
                if failure:
                    self.assertEqual(reports,[]);self.assertNotIn('CONTROLS_PASS',output.getvalue())
                else:
                    self.assertEqual(len(reports),1)
                    self.assertEqual(len(result['executed_quarantine_cases']),628)
                    lines=(reports[0].parent/'cases.jsonl').read_text().splitlines()
                    self.assertEqual(len(lines),628)
                    self.assertEqual([json.loads(line)['case'] for line in lines],result['executed_quarantine_cases'])
                    self.assertEqual(len([a for a in observed if a[-1]=='expect-quarantined']),628)
                    extra=4 if admission=='hosted' else 0
                    self.assertEqual(len([a for a in observed if '--force' in a]),629+extra)
                    self.assertEqual(len([a for a in observed if '--verify' in a]),629+extra)
                    self.assertEqual(len([a for a in observed if a[-1]=='expect-unavailable']),extra)
                    self.assertEqual(result['executed_admission_cases'],['warm-aes-absent','cold-aes-absent',
                                                                          'warm-pmull-absent','cold-pmull-absent'] if extra else [])
                    if extra:
                        log=reports[0].parent/'admission.jsonl'
                        self.assertEqual(r.digest(log.read_bytes()),result['admission_log_sha256'])
                        self.assertEqual([json.loads(line)['case'] for line in log.read_text().splitlines()],result['executed_admission_cases'])
                    self.assertFalse(list(reports[0].parent.glob('executables-*')))


if __name__=='__main__':unittest.main()
