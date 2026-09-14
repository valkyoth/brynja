"""Exact reviewed native ordinary MD5 captures, never timing/migration proof."""
import hashlib
import json
import re
import subprocess
import md5_execution_policy as policy

LANES={'amd-x86_64':'legacy-x86_64-avx2-md5','intel-x86_64':'legacy-x86_64-avx2-md5',
       'aws-aarch64':'legacy-aarch64-neon-md5','apple-m2-aarch64':'legacy-aarch64-neon-md5'}
INDEX='security/md5-execution-native.json'

def require(value,label):
    if not value: raise ValueError('MD5 native evidence: '+label)

def record_check(record,lane,commit,sources):
    require(set(record)=={'schema','version','lane','commit','compiler','cpu','system','features','source_sha256','results','native','profile','independent_review','fips_validated'},'record fields')
    require(type(record['schema']) is int and record['schema']==1 and record['version']=='0.24.44','schema/version')
    require(record['lane']==lane and record['commit']==commit,'lane/commit')
    require(record['source_sha256']==sources,'source closure')
    require(record['native']=='operator-self-attested' and record['profile']=='ordinary-public-only','classification')
    require(record['independent_review'] is False and record['fips_validated'] is False,'claims')
    require(isinstance(record['compiler'],str) and 'release: 1.98.1' in record['compiler'].splitlines(),'compiler')
    target='aarch64-apple-darwin' if lane=='apple-m2-aarch64' else ('x86_64-unknown-linux-gnu' if 'x86_64' in lane else 'aarch64-unknown-linux-gnu')
    require('host: '+target in record['compiler'].splitlines(),'compiler host')
    require(isinstance(record['cpu'],str) and 0<len(record['cpu'])<256,'CPU')
    cpu=record['cpu']
    require((lane=='amd-x86_64' and cpu=='AuthenticAMD') or
        (lane=='intel-x86_64' and cpu=='GenuineIntel') or
        (lane=='apple-m2-aarch64' and cpu.startswith('Apple M2')) or
        (lane=='aws-aarch64' and cpu=='operator-labelled AWS Arm; provider identity not authenticated'),'CPU lane identity')
    require(record['system']==('Darwin' if lane=='apple-m2-aarch64' else 'Linux'),'OS')
    require(record['features']==('+avx2' if 'x86_64' in lane else '+neon'),'features')
    results=record['results']
    require(set(results)=={'portable','hosted','static','packaged'},'all result commands')
    require(all(isinstance(v,str) and len(v)<2_000_000 for v in results.values()),'result bounds')
    require('MD5_OPERATIONAL: '+LANES[lane]+'; cases=2048; normal-build SIMD' in results['static'].splitlines(),'actual static SIMD')
    def complete(name, count):
        pattern=rf'test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s'
        return sum(re.fullmatch(pattern,line) is not None for line in results[name].splitlines())==1
    require(complete('static',3) and complete('portable',3),'complete execution tests')
    hosted='None' if 'x86_64' in lane else 'Some(Aarch64Neon)'
    require('MD5_HOSTED_OPERATIONAL: '+hosted in results['hosted'].splitlines(),'hosted route')
    require(complete('hosted',1),'hosted tests')
    require('Packaged MD5 operational: 13 ownership/classification negatives; 6 compiled output/report mutants rejected' in results['packaged'].splitlines(),'packaged mutations')
    require('mode=require; width='+('8' if 'x86_64' in lane else '4') in results['packaged'],'required independent oracle')

def validate():
    root=policy.ROOT
    index=json.loads(policy.read(root,INDEX))
    require(set(index)=={'schema','version','owner_review','lanes'} and type(index['schema']) is int and index['schema']==1 and index['version']=='0.24.44','index')
    require(index['owner_review']=='accepted-correctness-with-residuals','owner review pending')
    require(set(index['lanes'])==set(LANES),'four native lanes required')
    sources=policy.snapshot()
    for lane,row in index['lanes'].items():
        require(set(row)=={'artifact','sha256','commit'},'lane fields')
        require(re.fullmatch(r'assurance/md5-execution-observations/v0\.24\.43/[a-z0-9_-]+\.json',row['artifact']) is not None,'artifact path')
        require(re.fullmatch('[a-f0-9]{40}',row['commit']) is not None,'commit')
        subprocess.run(['git','merge-base','--is-ancestor',row['commit'],'HEAD'],cwd=root,check=True)
        raw=policy.read(root,row['artifact'])
        require(hashlib.sha256(raw).hexdigest()==row['sha256'],'artifact checksum')
        for name,digest in sources.items():
            old=subprocess.check_output(['git','show',row['commit']+':'+name],cwd=root)
            require(hashlib.sha256(old.replace(b'\r\n',b'\n')).hexdigest()==digest,'capture source differs')
        record_check(json.loads(raw),lane,row['commit'],sources)
    print('MD5 ordinary SIMD native qualification: reviewed correctness with residual limits')
