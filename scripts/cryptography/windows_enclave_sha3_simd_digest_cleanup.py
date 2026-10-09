"""Resident digest FH3 state transitions and complete saved cleanup funclets."""
import re
import windows_enclave_sha3_simd_digest_shape as shape
life,s,L=shape.life,shape.s,shape.L


def shapes(bodies,n):
    found={};expected={}
    end=['addq $56, %rsp']+['popq %'+r for r in reversed(shape.SAVES)]+['retq']
    for number in (68,71,72,73,74):
        name=s.one(bodies,r'^\?dtor\$'+str(number)+r'@\?0\?'+re.escape(n['digest'])+r'@')
        found[number]=name
        code=[f'.B{number}:','movq %rdx, 16(%rsp)']+['pushq %'+r for r in shape.SAVES]+L(
            'subq $56, %rsp|leaq 128(%rdx), %rbp')
        if number==68:
            code+=L(f'''cmpb $0, 8974(%rbp)|je .B70|leaq 8784(%rbp), %rcx|
                callq {n['output_drop']}|nop''')+end+['.B70:']
        elif number==71:code+=shape.retire(n)+['nop']
        elif number in (72,73):code+=L('movq 8944(%rbp), %rax|movb $0, 16(%rax)')
        else:code+=L('testb $1, 8975(%rbp)|jne .B76|movq 8960(%rbp), %rsi')+shape.worker.owner.clear('rsi')+['.B76:']
        expected[name]=code+end
    return found,expected


def inspect(bodies,asm,n):
    found,expected=shapes(bodies,n)
    for name,want in expected.items():s.require(life.code(bodies[name])==want,'complete digest cleanup funclet')
    prefix={p:p+n['digest'] for p in ('$cppxdata$','$stateUnwindMap$','$ip2state$')}
    states=[(-1,74),(0,71),(1,68),(0,72),(0,73)]
    ips=[('.Lfunc_begin40',-1),('.Ltmp54',4),('.Ltmp56',3),('.Ltmp57',-1),
         ('.Ltmp58',1),('.Ltmp60',2),('.Ltmp63',-1)]
    tables={prefix['$cppxdata$']:['429065506','5',prefix['$stateUnwindMap$']+'@IMGREL',
        '0','0','7',prefix['$ip2state$']+'@IMGREL','9104','0','1'],
        prefix['$stateUnwindMap$']:[v for parent,h in states for v in (str(parent),'"'+found[h]+'"@IMGREL')],
        prefix['$ip2state$']:[v for label,state in ips for v in (label+'@IMGREL',str(state))]}
    for label,want in tables.items():
        rows=list(re.finditer(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M))
        s.require(len(rows)==1,'unique digest exception metadata')
        s.require([line.strip().split(None,1)[1] for line in rows[0][1].splitlines()]==want,
            'exact digest exception metadata')
    s.sequences(bodies[n['digest']],['|'.join(L(site)) for site in literal_sites(n)])
    chains={}
    for label,state in ips:
        chain=[]
        while state!=-1:
            state,h=states[state];chain.append(found[h])
        chains[label]=chain
    return dict(funclets=found,instruction_positions={k:len(v) for k,v in expected.items()},
        expected_tables=tables,ordered_cleanup_chains=chains,
        output_live_flag_offset=8974,operation_complete_flag_offset=8975,
        post_output_drop_revalidation_uses_disarmed_output_flag=True,
        os_dispatcher_and_fatal_abort_cleanup_qualified=False)


def literal_sites(n):
    return [
        '.Ltmp54:|movq %r8, 8944(%rbp)|vzeroupper|callq *8(%r8)|nop|.Ltmp55:',
        '.Ltmp56:|callq *8(%r8)|nop|.Ltmp57:',
        f'''.Ltmp58:|leaq 8752(%rbp), %rax|movq %rax, 48(%rsp)|movq %r15, 40(%rsp)|
            movq %r14, 32(%rsp)|leaq 8608(%rbp), %rcx|leaq 8888(%rbp), %rdx|
            leaq 8144(%rbp), %r8|leaq 8784(%rbp), %r9|callq {n['executor']}|nop|.Ltmp59:'''.replace('\n',''),
        f'.Ltmp60:|vzeroupper|callq {n["check"]}|nop|.Ltmp61:',
        f'.Ltmp62:|callq {n["check"]}|nop|.Ltmp63:']
