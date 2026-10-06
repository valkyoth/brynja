"""Distinct scalar KMAC reader paths in the saved Windows image."""
import re
import windows_enclave_kmac_shapes as s


def terminal_cleanup(body,name,wipe):
    # Only this explicitly named tail call is treated as a returning destructor.
    # Unknown tail targets and indirect branches still fail the CFG traversal.
    code=s.lines(body)
    s.require('retq' not in code and code.count('jmp '+wipe)==1,
              'one terminal destructor tail exit, no direct return')
    transformed='\n'.join(code).replace('jmp '+wipe,'callq '+wipe+'\nretq')
    return s.normal_returns(transformed,name,['callq '+wipe])


def same_reader_shape(bodies,role):
    a=s.one(bodies,rf'KmacXof128Reader\d+{role}$')
    b=s.one(bodies,rf'KmacXof256Reader\d+{role}$')
    def norm(body):
        lines=s.lines(body)
        # The two instantiated wrappers differ only in their own symbol,
        # labels and the exact strength-specific callee listed here.
        text='\n'.join(lines[2:])
        text=text.replace(a,b)
        text=re.sub(r'\.Lfunc_begin\d+', '.Lfunc_begin',text)
        if role=='squeeze_secret': text=text.replace('OwnerKja8_E','OwnerKj88_E')
        else:
            old=s.one(bodies,r'Cshake128Reader.*CshakeReader25squeeze_final_bits_secret$')
            new=s.one(bodies,r'Cshake256Reader.*CshakeReader25squeeze_final_bits_secret$')
            text=text.replace(old,new)
        return text
    s.require(norm(bodies[a])==norm(bodies[b]),'only enumerated reader strength substitutions')
    return a,b


def inspect(bodies):
    wipe=s.one(bodies,r'HardenedFips202OwnerKj88_E4wipe')
    result={}
    for strength,rate in ((128,168),(256,136)):
        name=s.one(bodies,rf'Cshake{strength}Reader.*CshakeReader25squeeze_final_bits_secret$')
        body=bodies[name]
        s.sequences(body,[
            'cmpb $1, (%rdx)|jne .B31|movb $2, (%rsi)|leaq 1(%rsi), %rdi',
            'movq %r15, %rcx|movq %r14, %rdx|callq '+s.ZERO,
            'addq %r15, %rax|setb %cl|addq 17(%rsi), %rax|adcq 25(%rsi), %rcx|movb $2, %al|jb .B17',
            f'cmpb ${rate-256}, %r14b|jbe .B10',
            'cmpq %r15, %r14|jne .B26|movq %rcx, 8(%rbx)|movq %r14, 16(%rbx)',
            'callq '+s.CORE+'13secret_memory22apply_secret_byte_mask',
            'movl $168, %edx|movq %r12, %rcx|callq '+s.ZERO+'|jmp .B22',
            'incq %rsi|movq %rsi, %rcx'])
        result[name]=dict(rate=rate,terminal_tail_exits=terminal_cleanup(body,name,wipe),
            consumed_before_output=True,output_count_checked=True,partial_staging_bytes_cleared=168)
    readers=same_reader_shape(bodies,'squeeze_secret')
    wrappers=same_reader_shape(bodies,'squeeze_final_bits_secret')
    for name in readers:
        s.sequences(bodies[name],[
            'cmpb $1, (%rdx)|jne .B1',
            'callq '+s.ZERO,
            'cmpq %rdx, %r8|je .B6|movq %rax, %rcx|callq '+s.ZERO])
    for name in wrappers:
        strength=128 if '128Reader' in name else 256
        target=s.one(bodies,rf'Cshake{strength}Reader.*CshakeReader25squeeze_final_bits_secret$')
        event=['leaq 32(%rsp), %rcx','movq %rbx, %rdx','movq %rdi, %r8','callq '+target]
        s.sequences(bodies[name],[
            'leaq 63(%rsp), %rbx|movl $1041, %r8d|movq %rbx, %rcx|callq memcpy',
            '|'.join(event)])
        s.normal_returns(bodies[name],name,event)
    return dict(terminal=result,nonterminal_readers=list(readers),terminal_wrappers=list(wrappers),
                moved_reader_bytes=1041,moved_reader_offset=63,
                moved_source_stack_cleanup_package=8,arbitrary_exception_cleanup_qualified=False)
