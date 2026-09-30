#!/usr/bin/env python3
"""Real parser and trusted-policy boundary regressions, no platform claims."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import windows_enclave_admission as workflow
import windows_enclave_admission_native as native


class Tests(unittest.TestCase):
    def test_owner_policy_requires_review_and_never_overwrites(self):
        policy=dict(status='OWNER_REVIEWED',schema=1,profile='production',reviewer='test authority',
            source_commit='a'*40,sha256=[1]*32,family=[2]*16,image=[3]*16,version=1,security=1,
            policy=0,size=0x10000000,threads=1,minimum_import_security=[0,0])
        import json
        with tempfile.TemporaryDirectory(prefix='owner-policy-test-') as tmp:
            directory=Path(tmp); source=directory/'reviewed.json'; output=directory/'policy.rs'
            source.write_text(json.dumps(policy))
            with patch.object(workflow, 'inspect', return_value=policy):
                workflow.owner_policy(directory/'candidate.dll', source, output)
                original=output.read_bytes()
                with self.assertRaises(FileExistsError): workflow.owner_policy(directory/'candidate.dll', source, output)
                self.assertEqual(output.read_bytes(), original)
            with patch.object(workflow, 'inspect', return_value=dict(policy, security=2)):
                with self.assertRaises(ValueError): workflow.owner_policy(directory/'candidate.dll', source, directory/'mismatch.rs')
            source.write_text(json.dumps(policy).replace('"schema": 1', '"schema": 1, "schema": 1'))
            with self.assertRaises(ValueError): workflow.owner_policy(directory/'candidate.dll', source, directory/'duplicate.rs')

    def test_native_outcome_schema(self):
        for profile,stage in [('development',0),('production',2),('development',1)]:
            value=dict(profile=profile,stage=stage,trust_status=-1,os_error=0,
                loaded=int(stage==0),called=int(stage==0),cleanup=True)
            code=0 if stage==0 else 97
            native.validate(value,code,profile,stage)
            for field in ('stage','loaded','called','os_error'):
                with self.assertRaises(ValueError): native.validate(dict(value,**{field:999}),code,profile,stage)
            with self.assertRaises(ValueError): native.validate(dict(value,cleanup=False),code,profile,stage)
            with self.assertRaises(ValueError): native.validate(dict(value,loaded=True),code,profile,stage)
        value=dict(profile='production',stage=0,trust_status=-1,os_error=0,loaded=1,called=1,cleanup=True)
        with self.assertRaises(ValueError): native.validate(value,0,'production',0)
    def test_compiled_parser(self):
        target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
        with tempfile.TemporaryDirectory(prefix='image-admission-test-') as tmp:
            directory=Path(tmp); workflow.pin.dependencies(directory,target,testing=True)
            for level in ('0','2'):
                command=['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level='+level,
                    '-L','dependency='+str(directory),'--extern','brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
                    str(workflow.SOURCE/'image_admission_tests.rs'),'-o',str(directory/'tests')]
                result=subprocess.run(command,capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('4 passed',result.stdout)

    def test_compiled_security_mutants(self):
        target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
        source=(workflow.SOURCE/'image_admission.rs').read_text()
        mutants=[('hash.as_bytes() == &policy.digest','hash.as_bytes().len() == policy.digest.len()'),
            ('inspect(b)? == policy.identity','inspect(b)?.threads == policy.identity.threads'),
            ('u32_at(self.b, t)? == 2','u32_at(self.b, t)? <= 4'),
            ('bytes(self.b, t + 8, 64)?.iter().all(|x| *x == 0)','bytes(self.b, t + 8, 64)?.len() == 64'),
            ('matches!(identity.policy, 0 | 2)','identity.policy<=3'),
            ('flags & 0x41e0 == 0x41e0','flags <= u16::MAX')]
        with tempfile.TemporaryDirectory(prefix='image-admission-mutants-') as tmp:
            directory=Path(tmp); workflow.pin.dependencies(directory,target,testing=True)
            (directory/'image_admission_tests.rs').write_bytes((workflow.SOURCE/'image_admission_tests.rs').read_bytes())
            for old,new in mutants:
                self.assertEqual(source.count(old),1,old)
                (directory/'image_admission.rs').write_text(source.replace(old,new))
                command=['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level=2',
                    '-L','dependency='+str(directory),'--extern','brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'),
                    str(directory/'image_admission_tests.rs'),'-o',str(directory/'tests')]
                result=subprocess.run(command,capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=90)
                self.assertNotEqual(result.returncode,0,old)
                self.assertIn('FAILED',result.stdout)

    def test_policy_is_not_candidate_metadata(self):
        policy=dict(status='OWNER_REVIEWED',schema=1,profile='development',reviewer='test authority',
            source_commit='a'*40,sha256=[1]*32,family=[2]*16,image=[3]*16,version=1,security=1,
            policy=0,size=0x10000000,threads=1,minimum_import_security=[0,0])
        workflow.checked_policy(policy,'development')
        for key,value in [('status','UNTRUSTED_INSPECTION'),('schema',True),('profile','production'),
            ('source_commit','unknown'),('reviewer',''),('sha256',[0]*32),('sha256',[True]*32),
            ('family',[0]*16),('image',[1]*15),('version',0),('security',-1),('policy',1),
            ('threads',True),('threads',2),('size',1),('minimum_import_security',[0,2**32])]:
            changed=copy.deepcopy(policy); changed[key]=value
            with self.assertRaises(ValueError,msg=key): workflow.checked_policy(changed,'development')
        with self.assertRaises(ValueError): workflow.checked_policy(dict(policy,unknown=1),'development')
        with self.assertRaises(ValueError): workflow.checked_policy(policy,'production')
        text=workflow.policy_source(policy)
        changed=dict(policy,reviewer='"; arbitrary injected text; //')
        self.assertEqual(workflow.policy_source(changed),text)
        with self.assertRaises(ValueError): workflow.owner_policy_source(policy)
        production = dict(policy, profile='production')
        generated = workflow.owner_policy_source(production)
        self.assertIn('brynja_strict::enclave::ImagePolicy::reviewed_sha256(', generated)
        self.assertNotIn('test authority', generated)
        self.assertEqual(workflow.owner_policy_source(dict(production, reviewer='injected text')), generated)
        with self.assertRaises(ValueError): workflow.owner_policy_source(dict(production, policy=2))


if __name__=='__main__': unittest.main()
