"""Exhaustive uses of one saved LLVM descriptor allocation, not general LLVM.

Only byte GEP aliases, bounded loads/stores and explicitly reviewed calls are
accepted. Loading a descriptor's pointer value does not alias the allocation
containing it. Consumers must separately establish that value's provenance.
"""
import re
import windows_enclave_kmac_shapes as s

SSA=r'%[\w.$-]+'


def function(ir,name):
    found=re.findall(r'^define [^\n]*@'+re.escape(name)+r'\([^\n]*\n.*?^}',ir,re.M|re.S)
    s.require(len(found)==1,'unique descriptor IR function')
    return [line.split(';',1)[0].split(', !',1)[0].strip()
            for line in found[0].splitlines() if line.split(';',1)[0].strip()]


def definitions(lines):
    result={}
    for line in lines:
        match=re.match('('+SSA+r') = (.*)',line)
        if match:
            s.require(match[1] not in result,'unique descriptor SSA definition')
            result[match[1]]=match[2]
    return result


def gep(value):
    return re.fullmatch(r'getelementptr inbounds nuw i8, ptr ('+SSA+r'), i64 ('+SSA+r'|-?\d+)',value)


def aliases(defs,root,size,dynamic):
    s.require(defs.get(root)==f'alloca [{size} x i8], align 8','exact descriptor allocation')
    result={root:(0,)}
    while True:
        changed=False
        for name,value in defs.items():
            match=gep(value)
            if not match or match[1] not in result or name in result: continue
            index=match[2]
            if index.startswith('%'):
                s.require(index in dynamic,'reviewed bounded descriptor index')
                offsets=dynamic[index]
            else: offsets=(int(index),)
            values=tuple(sorted({a+b for a in result[match[1]] for b in offsets}))
            s.require(values and min(values)>=0 and max(values)<size,'descriptor GEP bounds')
            result[name]=values;changed=True
        if not changed: return result


def call(line):
    match=re.search(r'\bcall [^@]*@([\w.$]+)\(',line)
    s.require(match is not None,'descriptor address escapes only to reviewed direct calls')
    start=match.end();depth=0;args=[];part=start
    for i in range(start,len(line)):
        char=line[i]
        if char==')' and depth==0:
            args.append(line[part:i].strip())
            return match[1],args,line[i+1:]
        if char=='(': depth+=1
        elif char==')': depth-=1
        elif char==',' and depth==0: args.append(line[part:i].strip());part=i+1
    raise ValueError('unterminated descriptor call')


def pointer(argument):
    match=re.fullmatch(r'ptr .*?('+SSA+r')',argument)
    s.require(match is not None,'typed descriptor call pointer')
    return match[1]


def scan(lines,root,size,dynamic,allow_call):
    defs=definitions(lines);known=aliases(defs,root,size,dynamic)
    reads=[];writes=[];calls=[]
    for number,line in enumerate(lines):
        used=set(re.findall(SSA,line)) & known.keys()
        if not used: continue
        match=re.fullmatch('('+SSA+r') = (.*)',line)
        if match and match[1] in known:
            s.require(match[1]==root or gep(match[2]) is not None,'descriptor alias definition')
            continue
        match=re.match('('+SSA+r') = load (ptr|i8|i16|i32|i64), ptr ('+SSA+r'), align \d+$',line)
        if match and match[3] in known:
            s.require(used=={match[3]},'descriptor read cannot hide another address')
            width=8 if match[2]=='ptr' else int(match[2][1:])//8
            s.require(max(known[match[3]])+width<=size,'descriptor read extent')
            reads.append(dict(line=number,name=match[1],offsets=list(known[match[3]]),type=match[2]));continue
        match=re.fullmatch(r'store (ptr|i8|i16|i32|i64) ([^,]+), ptr ('+SSA+r'), align \d+',line)
        if match and match[3] in known:
            s.require(used=={match[3]} and match[2] not in known,'descriptor address must not be stored')
            width=8 if match[1]=='ptr' else int(match[1][1:])//8
            offsets=known[match[3]]
            s.require(len(offsets)==1 and offsets[0]+width<=size,'constant descriptor write extent')
            writes.append(dict(line=number,offset=offsets[0],type=match[1],value=match[2]));continue
        name,args,tail=call(line)
        s.require(not used.intersection(re.findall(SSA,tail)),'no hidden descriptor call-tail use')
        calls.append(allow_call(name,args,tail,known,used)|dict(line=number))
    return dict(aliases=known,reads=reads,writes=writes,calls=calls)
