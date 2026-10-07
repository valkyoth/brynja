"""Closed saved-LLVM pointer-use and CFG inventory for SHA-2 metadata.

This is deliberately not a general LLVM interpreter. Unknown address operations,
escapes and control transfers reject. Object separation and the machine-level
index contracts must be supplied separately by the enclosing saved-image review.
"""
import re
import windows_enclave_sha2_descriptor_ir as ir
s=ir.s
SSA=ir.SSA


def cfg(lines):
    labels={line[:-1]:at for at,line in enumerate(lines) if line.endswith(':')}
    s.require(len(labels)==sum(line.endswith(':') for line in lines),'unique field CFG blocks')
    edges={};at=1
    while at<len(lines)-1:
        line=lines[at];last=at;targets=None
        if line.startswith('br '): targets=re.findall(r'label %([\w.$-]+)',line)
        elif line.startswith('switch '):
            while lines[last]!=']':
                last+=1;s.require(last<len(lines)-1,'closed field switch')
            targets=re.findall(r'label %([\w.$-]+)',' '.join(lines[at:last+1]))
        elif re.search(r'\binvoke ',line):
            last+=1
            s.require(re.fullmatch(r'to label %[\w.$-]+ unwind label %[\w.$-]+',lines[last]) is not None,
                      'complete field invoke destinations')
            targets=re.findall(r'label %([\w.$-]+)',lines[last])
        elif line.startswith('cleanupret '):
            targets=re.findall(r'unwind label %([\w.$-]+)',line)
            s.require(targets or line.endswith('unwind to caller'),'assigned field cleanup return')
        elif line.startswith('ret ') or line=='unreachable':targets=[]
        else:
            s.require(not re.search(r'\b(indirectbr|callbr|catchswitch|catchret|resume)\b',line),
                      'no unreviewed field control transfer')
        for position in range(at,last):edges[position]=[position+1]
        if targets is None:edges[last]=[last+1]
        else:
            s.require(all(t in labels for t in targets),'local field branch targets')
            edges[last]=[labels[t] for t in targets]
        at=last+1
    return edges


def lifetime(edges,reads,initializers,kills,initial=False):
    """Every path to a read must cross initialization since its latest kill."""
    pending=[(1,initial)];seen=set();used=set()
    while pending:
        at,valid=pending.pop()
        if (at,valid) in seen:continue
        s.require(at in edges,'closed field lifetime CFG')
        seen.add((at,valid));used.add(at)
        if at in initializers:valid=True
        if at in reads:s.require(valid,'metadata read before initialization or after invalidation')
        if at in kills:valid=False
        pending.extend((dest,valid) for dest in edges[at])
    s.require(set(reads)<=used and set(initializers)<=used and set(kills)<=used,
              'all field lifetime events reachable')
    return len(used)


def gep(expr):
    match=re.fullmatch(r'getelementptr(?: inbounds)?(?: nuw)? (.+), ptr ('+SSA+r'), i64 ('+SSA+r'|-?\d+)',expr)
    if not match:return None
    kind=match[1]
    if kind=='i8':stride=1
    elif re.fullmatch(r'\[\d+ x i8\]',kind):stride=int(kind.split()[0][1:])
    elif kind in ('{ [32 x i8], i8, [7 x i8] }','{ [16 x i16], i16, [3 x i16] }'):stride=40
    else:raise ValueError('unreviewed field GEP type: '+kind)
    return match[2],match[3],stride


def aliases(lines,seeds,bounds):
    defs=ir.definitions(lines);known=dict(seeds);alias_defs=set()
    while True:
        changed=False
        for name,expr in defs.items():
            if name in known:continue
            base=re.search(r', ptr ('+SSA+'), i64 ',expr)
            match=gep(expr) if base and base[1] in known else None
            if match and match[0] in known:
                base,index,stride=match
                if index.startswith('%'):
                    s.require(index in bounds,'assigned public field index: '+index)
                    low,high=bounds[index]
                else:low=high=int(index)
                known[name]=[(root,a+stride*low,b+stride*high) for root,a,b in known[base]]
            elif expr.startswith('phi ptr ') and set(re.findall(r'\[ ('+SSA+r'),',expr)) & known.keys():
                values=re.findall(r'\[ ('+SSA+r'|null), %[^ ]+ \]',expr)
                if not values or not all(v=='null' or v in known for v in values):continue
                known[name]=sorted({item for v in values if v!='null' for item in known[v]})
            else:continue
            alias_defs.add(name);changed=True
        if not changed:return known,alias_defs


def inventory(lines,seeds,bounds,special):
    known,derived=aliases(lines,seeds,bounds);records=[]
    for at,line in enumerate(lines):
        used=set(re.findall(SSA,line)) & known.keys()
        if not used:continue
        match=re.fullmatch('('+SSA+r') = (.*)',line)
        if match and match[1] in derived:continue
        if match:used.discard(match[1])
        if not used:continue
        if at==0:continue  # Argument roots are checked by their caller contracts.
        if special(at,line,used,known):continue
        read=re.fullmatch(SSA+r' = load (ptr|i\d+), ptr ('+SSA+r'), align \d+',line)
        write=re.fullmatch(r'store (ptr|i\d+) ([^,]+), ptr ('+SSA+r'), align \d+',line)
        if read or write:
            dest=read[2] if read else write[3]
            s.require(dest in known and used=={dest},'field address cannot escape as stored data')
            typ=read[1] if read else write[1];width=8 if typ=='ptr' else (int(typ[1:])+7)//8
            records.append(dict(line=at,kind='read' if read else 'write',address=dest,
                spans=[(root,low,high+width) for root,low,high in known[dest]],
                value=None if read else write[2],type=typ));continue
        if re.search(r'\b(call|invoke) ',line):
            target,args,tail=ir.call(line.replace('invoke ','call ',1))
            s.require(not set(re.findall(SSA,tail)) & known.keys(),'no hidden call-tail field address')
            pointers={i:ir.pointer(arg) for i,arg in enumerate(args) if arg.startswith('ptr ')}
            s.require(used==set(pointers.values()) & known.keys(),'no hidden non-pointer field call argument')
            records.append(dict(line=at,kind='call',target=target,args=args,pointers=pointers));continue
        raise ValueError('unreviewed field address use: '+line)
    return known,records
