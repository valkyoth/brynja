0000000000010a10 <brynja_ghash_timing::timed>:
   10a10:      	pushq	%rbp
   10a11:      	pushq	%r15
   10a13:      	pushq	%r14
   10a15:      	pushq	%r13
   10a17:      	pushq	%r12
   10a19:      	pushq	%rbx
   10a1a:      	subq	$0xb8, %rsp
   10a21:      	movq	%rsi, %r14
   10a24:      	pxor	%xmm0, %xmm0
   10a28:      	movdqa	%xmm0, (%rsp)
   10a2d:      	movdqa	%xmm0, 0xa0(%rsp)
   10a36:      	movq	%rdi, 0x88(%rsp)
   10a3e:      	leaq	0x88(%rsp), %rax
   10a46:      	movq	0x88(%rsp), %rax
   10a4e:      	movq	%rax, 0x18(%rsp)
   10a53:      	movq	%rsp, %rdi
   10a56:      	movl	$0x10, %esi
   10a5b:      	callq	0x14930 <brynja_core::secret_memory_volatile::zeroize_region_volatile>
   10a60:      	movq	0x3f851(%rip), %rax     # 0x502b8 <std_detect::detect::cache::CACHE (.0)>
   10a67:      	testq	%rax, %rax
   10a6a:      	je	0x10a77 <brynja_ghash_timing::timed+0x67>
   10a6c:      	testb	$0x2, %al
   10a6e:      	jne	0x10a80 <brynja_ghash_timing::timed+0x70>
   10a70:      	xorl	%ebx, %ebx
   10a72:      	jmp	0x10aff <brynja_ghash_timing::timed+0xef>
   10a77:      	callq	0x4b540 <std_detect::detect::cache::detect_and_initialize>
   10a7c:      	testb	$0x2, %al
   10a7e:      	je	0x10a70 <brynja_ghash_timing::timed+0x60>
   10a80:      	movabsq	$0x388dace60b6a392, %rax # imm = 0x388DACE60B6A392
   10a8a:      	movq	%rax, 0x68(%rsp)
   10a8f:      	movabsq	$-0xcd73d468e4d0188, %rax # imm = 0xF328C2B971B2FE78
   10a99:      	movq	%rax, 0x60(%rsp)
   10a9e:      	leaq	0x60(%rsp), %rax
   10aa3:      	movabsq	$0x66e94bd4ef8a2c3b, %rax # imm = 0x66E94BD4EF8A2C3B
   10aad:      	movq	%rax, 0x28(%rsp)
   10ab2:      	movabsq	$-0x77b305a635cbd4d2, %rax # imm = 0x884CFA59CA342B2E
   10abc:      	movq	%rax, 0x20(%rsp)
   10ac1:      	leaq	0x20(%rsp), %rax
   10ac6:      	movq	0x60(%rsp), %rdi
   10acb:      	movq	0x68(%rsp), %rsi
   10ad0:      	movq	0x20(%rsp), %rdx
   10ad5:      	movq	0x28(%rsp), %rcx
   10ada:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   10adf:      	movabsq	$0x5e2ec74691706288, %rcx # imm = 0x5E2EC74691706288
   10ae9:      	xorq	%rdx, %rcx
   10aec:      	movabsq	$0x2c85b0685353deb7, %rdx # imm = 0x2C85B0685353DEB7
   10af6:      	xorq	%rax, %rdx
   10af9:      	orq	%rcx, %rdx
   10afc:      	sete	%bl
   10aff:      	callq	0x49040 <<std::sys::pal::unix::time::Timespec>::now>
   10b04:      	movq	%r14, 0x20(%rsp)
   10b09:      	movq	$0x10, 0x28(%rsp)
   10b12:      	leaq	0x20(%rsp), %rcx
   10b17:      	testb	%bl, %bl
   10b19:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   10b1f:      	movq	0x28(%rsp), %rbp
   10b24:      	movb	$0x5, %cl
   10b26:      	cmpq	$0x100, %rbp            # imm = 0x100
   10b2d:      	ja	0x123ec <brynja_ghash_timing::timed+0x19dc>
   10b33:      	movq	%r14, 0x58(%rsp)
   10b38:      	movl	%edx, 0x84(%rsp)
   10b3f:      	movq	%rax, 0x98(%rsp)
   10b47:      	testq	%rbp, %rbp
   10b4a:      	je	0x10cd3 <brynja_ghash_timing::timed+0x2c3>
   10b50:      	movq	0x20(%rsp), %rbx
   10b55:      	leaq	(%rbx,%rbp), %r14
   10b59:      	leaq	0x3(%rsp), %r12
   10b5e:      	xorl	%r13d, %r13d
   10b61:      	movl	$0x4, %r15d
   10b67:      	pcmpeqd	%xmm2, %xmm2
   10b6b:      	xorl	%eax, %eax
   10b6d:      	xorl	%ecx, %ecx
   10b6f:      	jmp	0x10bc9 <brynja_ghash_timing::timed+0x1b9>
   10b71:      	nopw	%cs:(%rax,%rax)
   10b80:      	movq	0x18(%rsp), %rax
   10b85:      	movq	(%rax), %rcx
   10b88:      	movq	0x8(%rax), %rdx
   10b8c:      	movq	0x8(%rsp), %rdi
   10b91:      	bswapq	%rdx
   10b94:      	bswapq	%rcx
   10b97:      	bswapq	%rdi
   10b9a:      	movq	(%rsp), %rsi
   10b9e:      	bswapq	%rsi
   10ba1:      	incq	%r13
   10ba4:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   10ba9:      	pcmpeqd	%xmm2, %xmm2
   10bad:      	bswapq	%rdx
   10bb0:      	bswapq	%rax
   10bb3:      	movq	%rax, 0x8(%rsp)
   10bb8:      	movq	%rdx, (%rsp)
   10bbc:      	xorl	%eax, %eax
   10bbe:      	xorl	%ecx, %ecx
   10bc0:      	cmpq	%rbx, %r14
   10bc3:      	je	0x10cd8 <brynja_ghash_timing::timed+0x2c8>
   10bc9:      	testq	%rcx, %rcx
   10bcc:      	jne	0x10cc7 <brynja_ghash_timing::timed+0x2b7>
   10bd2:      	cmpq	%r14, %rbx
   10bd5:      	je	0x10cd8 <brynja_ghash_timing::timed+0x2c8>
   10bdb:      	movzbl	(%rbx), %edx
   10bde:      	xorb	%dl, (%rsp,%rcx)
   10be1:      	movq	%rbx, %rdx
   10be4:      	notq	%rdx
   10be7:      	addq	%r14, %rdx
   10bea:      	movl	$0xf, %esi
   10bef:      	subq	%rcx, %rsi
   10bf2:      	cmpq	%rsi, %rdx
   10bf5:      	cmovbq	%rdx, %rsi
   10bf9:      	cmpq	$0x4, %rsi
   10bfd:      	jae	0x10c10 <brynja_ghash_timing::timed+0x200>
   10bff:      	movq	%rbx, %rdx
   10c02:      	jmp	0x10c7a <brynja_ghash_timing::timed+0x26a>
   10c04:      	nopw	%cs:(%rax,%rax)
   10c10:      	incq	%rsi
   10c13:      	movl	%esi, %edx
   10c15:      	andl	$0x3, %edx
   10c18:      	cmoveq	%r15, %rdx
   10c1c:      	subq	%rdx, %rsi
   10c1f:      	leaq	(%rbx,%rsi), %rdx
   10c23:      	movq	%rax, %xmm0
   10c28:      	leaq	(%r12,%rcx), %rax
   10c2c:      	addq	%rsi, %rcx
   10c2f:      	pxor	%xmm1, %xmm1
   10c33:      	xorl	%edi, %edi
   10c35:      	nopw	%cs:(%rax,%rax)
   10c40:      	movzwl	0x1(%rbx,%rdi), %r8d
   10c46:      	movzwl	0x3(%rbx,%rdi), %r9d
   10c4c:      	xorw	%r8w, -0x2(%rax,%rdi)
   10c52:      	xorw	%r9w, (%rax,%rdi)
   10c57:      	psubq	%xmm2, %xmm0
   10c5b:      	psubq	%xmm2, %xmm1
   10c5f:      	addq	$0x4, %rdi
   10c63:      	cmpq	%rdi, %rsi
   10c66:      	jne	0x10c40 <brynja_ghash_timing::timed+0x230>
   10c68:      	paddq	%xmm0, %xmm1
   10c6c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   10c71:      	paddq	%xmm1, %xmm0
   10c75:      	movq	%xmm0, %rax
   10c7a:      	incq	%rax
   10c7d:      	incq	%rdx
   10c80:      	movq	%rdx, %rbx
   10c83:      	cmpq	$0xf, %rcx
   10c87:      	je	0x10cab <brynja_ghash_timing::timed+0x29b>
   10c89:      	nopl	(%rax)
   10c90:      	cmpq	%r14, %rbx
   10c93:      	je	0x10cab <brynja_ghash_timing::timed+0x29b>
   10c95:      	movzbl	(%rbx), %edx
   10c98:      	xorb	%dl, 0x1(%rsp,%rcx)
   10c9c:      	incq	%rax
   10c9f:      	incq	%rbx
   10ca2:      	incq	%rcx
   10ca5:      	cmpq	$0xf, %rcx
   10ca9:      	jne	0x10c90 <brynja_ghash_timing::timed+0x280>
   10cab:      	movq	%rax, %rcx
   10cae:      	cmpq	$0x10, %rcx
   10cb2:      	jne	0x10bc0 <brynja_ghash_timing::timed+0x1b0>
   10cb8:      	cmpq	$-0x1, %r13
   10cbc:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   10cc2:      	jmp	0x10b80 <brynja_ghash_timing::timed+0x170>
   10cc7:      	cmpq	$0xf, %rcx
   10ccb:      	jbe	0x10bd2 <brynja_ghash_timing::timed+0x1c2>
   10cd1:      	jmp	0x10cae <brynja_ghash_timing::timed+0x29e>
   10cd3:      	xorl	%r13d, %r13d
   10cd6:      	xorl	%eax, %eax
   10cd8:      	movl	$0x100, %r14d           # imm = 0x100
   10cde:      	subq	%rbp, %r14
   10ce1:      	movq	0x58(%rsp), %rcx
   10ce6:      	movq	%rcx, 0x20(%rsp)
   10ceb:      	movq	$0x10, 0x28(%rsp)
   10cf4:      	leaq	0x20(%rsp), %rcx
   10cf9:      	movq	0x28(%rsp), %rbp
   10cfe:      	subq	%rbp, %r14
   10d01:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   10d07:      	testq	%rbp, %rbp
   10d0a:      	je	0x10e83 <brynja_ghash_timing::timed+0x473>
   10d10:      	movq	0x20(%rsp), %rbx
   10d15:      	addq	%rbx, %rbp
   10d18:      	leaq	0x3(%rsp), %r12
   10d1d:      	movl	$0x4, %r15d
   10d23:      	pcmpeqd	%xmm2, %xmm2
   10d27:      	movq	%rax, %rcx
   10d2a:      	jmp	0x10d39 <brynja_ghash_timing::timed+0x329>
   10d2c:      	nopl	(%rax)
   10d30:      	cmpq	%rbx, %rbp
   10d33:      	je	0x10e83 <brynja_ghash_timing::timed+0x473>
   10d39:      	testq	%rcx, %rcx
   10d3c:      	jne	0x10e77 <brynja_ghash_timing::timed+0x467>
   10d42:      	cmpq	%rbp, %rbx
   10d45:      	je	0x10e83 <brynja_ghash_timing::timed+0x473>
   10d4b:      	movzbl	(%rbx), %edx
   10d4e:      	xorb	%dl, (%rsp,%rcx)
   10d51:      	movq	%rbx, %rdx
   10d54:      	notq	%rdx
   10d57:      	addq	%rbp, %rdx
   10d5a:      	movl	$0xf, %esi
   10d5f:      	subq	%rcx, %rsi
   10d62:      	cmpq	%rsi, %rdx
   10d65:      	cmovbq	%rdx, %rsi
   10d69:      	incq	%rsi
   10d6c:      	cmpq	$0x5, %rsi
   10d70:      	jae	0x10d80 <brynja_ghash_timing::timed+0x370>
   10d72:      	movq	%rbx, %rdx
   10d75:      	jmp	0x10dea <brynja_ghash_timing::timed+0x3da>
   10d77:      	nopw	(%rax,%rax)
   10d80:      	movl	%esi, %edx
   10d82:      	andl	$0x3, %edx
   10d85:      	cmoveq	%r15, %rdx
   10d89:      	subq	%rdx, %rsi
   10d8c:      	leaq	(%rbx,%rsi), %rdx
   10d90:      	movq	%rax, %xmm0
   10d95:      	leaq	(%r12,%rcx), %rax
   10d99:      	addq	%rsi, %rcx
   10d9c:      	pxor	%xmm1, %xmm1
   10da0:      	xorl	%edi, %edi
   10da2:      	nopw	%cs:(%rax,%rax)
   10db0:      	movzwl	0x1(%rbx,%rdi), %r8d
   10db6:      	movzwl	0x3(%rbx,%rdi), %r9d
   10dbc:      	xorw	%r8w, -0x2(%rax,%rdi)
   10dc2:      	xorw	%r9w, (%rax,%rdi)
   10dc7:      	psubq	%xmm2, %xmm0
   10dcb:      	psubq	%xmm2, %xmm1
   10dcf:      	addq	$0x4, %rdi
   10dd3:      	cmpq	%rdi, %rsi
   10dd6:      	jne	0x10db0 <brynja_ghash_timing::timed+0x3a0>
   10dd8:      	paddq	%xmm0, %xmm1
   10ddc:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   10de1:      	paddq	%xmm1, %xmm0
   10de5:      	movq	%xmm0, %rax
   10dea:      	incq	%rax
   10ded:      	incq	%rdx
   10df0:      	movq	%rdx, %rbx
   10df3:      	cmpq	$0xf, %rcx
   10df7:      	je	0x10e1b <brynja_ghash_timing::timed+0x40b>
   10df9:      	nopl	(%rax)
   10e00:      	cmpq	%rbp, %rbx
   10e03:      	je	0x10e1b <brynja_ghash_timing::timed+0x40b>
   10e05:      	movzbl	(%rbx), %edx
   10e08:      	xorb	%dl, 0x1(%rsp,%rcx)
   10e0c:      	incq	%rax
   10e0f:      	incq	%rbx
   10e12:      	incq	%rcx
   10e15:      	cmpq	$0xf, %rcx
   10e19:      	jne	0x10e00 <brynja_ghash_timing::timed+0x3f0>
   10e1b:      	movq	%rax, %rcx
   10e1e:      	cmpq	$0x10, %rcx
   10e22:      	jne	0x10d30 <brynja_ghash_timing::timed+0x320>
   10e28:      	cmpq	$-0x1, %r13
   10e2c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   10e32:      	movq	0x18(%rsp), %rax
   10e37:      	movq	(%rax), %rcx
   10e3a:      	movq	0x8(%rax), %rdx
   10e3e:      	movq	0x8(%rsp), %rdi
   10e43:      	bswapq	%rdx
   10e46:      	bswapq	%rcx
   10e49:      	bswapq	%rdi
   10e4c:      	movq	(%rsp), %rsi
   10e50:      	bswapq	%rsi
   10e53:      	incq	%r13
   10e56:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   10e5b:      	pcmpeqd	%xmm2, %xmm2
   10e5f:      	bswapq	%rdx
   10e62:      	bswapq	%rax
   10e65:      	movq	%rax, 0x8(%rsp)
   10e6a:      	movq	%rdx, (%rsp)
   10e6e:      	xorl	%eax, %eax
   10e70:      	xorl	%ecx, %ecx
   10e72:      	jmp	0x10d30 <brynja_ghash_timing::timed+0x320>
   10e77:      	cmpq	$0xf, %rcx
   10e7b:      	jbe	0x10d42 <brynja_ghash_timing::timed+0x332>
   10e81:      	jmp	0x10e1e <brynja_ghash_timing::timed+0x40e>
   10e83:      	movq	0x58(%rsp), %rcx
   10e88:      	movq	%rcx, 0x20(%rsp)
   10e8d:      	movq	$0x10, 0x28(%rsp)
   10e96:      	leaq	0x20(%rsp), %rcx
   10e9b:      	movq	0x28(%rsp), %rbp
   10ea0:      	subq	%rbp, %r14
   10ea3:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   10ea9:      	testq	%rbp, %rbp
   10eac:      	je	0x11023 <brynja_ghash_timing::timed+0x613>
   10eb2:      	movq	0x20(%rsp), %rbx
   10eb7:      	addq	%rbx, %rbp
   10eba:      	leaq	0x3(%rsp), %r12
   10ebf:      	movl	$0x4, %r15d
   10ec5:      	pcmpeqd	%xmm2, %xmm2
   10ec9:      	movq	%rax, %rcx
   10ecc:      	jmp	0x10ed9 <brynja_ghash_timing::timed+0x4c9>
   10ece:      	nop
   10ed0:      	cmpq	%rbx, %rbp
   10ed3:      	je	0x11023 <brynja_ghash_timing::timed+0x613>
   10ed9:      	testq	%rcx, %rcx
   10edc:      	jne	0x11017 <brynja_ghash_timing::timed+0x607>
   10ee2:      	cmpq	%rbp, %rbx
   10ee5:      	je	0x11023 <brynja_ghash_timing::timed+0x613>
   10eeb:      	movzbl	(%rbx), %edx
   10eee:      	xorb	%dl, (%rsp,%rcx)
   10ef1:      	movq	%rbx, %rdx
   10ef4:      	notq	%rdx
   10ef7:      	addq	%rbp, %rdx
   10efa:      	movl	$0xf, %esi
   10eff:      	subq	%rcx, %rsi
   10f02:      	cmpq	%rsi, %rdx
   10f05:      	cmovbq	%rdx, %rsi
   10f09:      	incq	%rsi
   10f0c:      	cmpq	$0x5, %rsi
   10f10:      	jae	0x10f20 <brynja_ghash_timing::timed+0x510>
   10f12:      	movq	%rbx, %rdx
   10f15:      	jmp	0x10f8a <brynja_ghash_timing::timed+0x57a>
   10f17:      	nopw	(%rax,%rax)
   10f20:      	movl	%esi, %edx
   10f22:      	andl	$0x3, %edx
   10f25:      	cmoveq	%r15, %rdx
   10f29:      	subq	%rdx, %rsi
   10f2c:      	leaq	(%rbx,%rsi), %rdx
   10f30:      	movq	%rax, %xmm0
   10f35:      	leaq	(%r12,%rcx), %rax
   10f39:      	addq	%rsi, %rcx
   10f3c:      	pxor	%xmm1, %xmm1
   10f40:      	xorl	%edi, %edi
   10f42:      	nopw	%cs:(%rax,%rax)
   10f50:      	movzwl	0x1(%rbx,%rdi), %r8d
   10f56:      	movzwl	0x3(%rbx,%rdi), %r9d
   10f5c:      	xorw	%r8w, -0x2(%rax,%rdi)
   10f62:      	xorw	%r9w, (%rax,%rdi)
   10f67:      	psubq	%xmm2, %xmm0
   10f6b:      	psubq	%xmm2, %xmm1
   10f6f:      	addq	$0x4, %rdi
   10f73:      	cmpq	%rdi, %rsi
   10f76:      	jne	0x10f50 <brynja_ghash_timing::timed+0x540>
   10f78:      	paddq	%xmm0, %xmm1
   10f7c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   10f81:      	paddq	%xmm1, %xmm0
   10f85:      	movq	%xmm0, %rax
   10f8a:      	incq	%rax
   10f8d:      	incq	%rdx
   10f90:      	movq	%rdx, %rbx
   10f93:      	cmpq	$0xf, %rcx
   10f97:      	je	0x10fbb <brynja_ghash_timing::timed+0x5ab>
   10f99:      	nopl	(%rax)
   10fa0:      	cmpq	%rbp, %rbx
   10fa3:      	je	0x10fbb <brynja_ghash_timing::timed+0x5ab>
   10fa5:      	movzbl	(%rbx), %edx
   10fa8:      	xorb	%dl, 0x1(%rsp,%rcx)
   10fac:      	incq	%rax
   10faf:      	incq	%rbx
   10fb2:      	incq	%rcx
   10fb5:      	cmpq	$0xf, %rcx
   10fb9:      	jne	0x10fa0 <brynja_ghash_timing::timed+0x590>
   10fbb:      	movq	%rax, %rcx
   10fbe:      	cmpq	$0x10, %rcx
   10fc2:      	jne	0x10ed0 <brynja_ghash_timing::timed+0x4c0>
   10fc8:      	cmpq	$-0x1, %r13
   10fcc:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   10fd2:      	movq	0x18(%rsp), %rax
   10fd7:      	movq	(%rax), %rcx
   10fda:      	movq	0x8(%rax), %rdx
   10fde:      	movq	0x8(%rsp), %rdi
   10fe3:      	bswapq	%rdx
   10fe6:      	bswapq	%rcx
   10fe9:      	bswapq	%rdi
   10fec:      	movq	(%rsp), %rsi
   10ff0:      	bswapq	%rsi
   10ff3:      	incq	%r13
   10ff6:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   10ffb:      	pcmpeqd	%xmm2, %xmm2
   10fff:      	bswapq	%rdx
   11002:      	bswapq	%rax
   11005:      	movq	%rax, 0x8(%rsp)
   1100a:      	movq	%rdx, (%rsp)
   1100e:      	xorl	%eax, %eax
   11010:      	xorl	%ecx, %ecx
   11012:      	jmp	0x10ed0 <brynja_ghash_timing::timed+0x4c0>
   11017:      	cmpq	$0xf, %rcx
   1101b:      	jbe	0x10ee2 <brynja_ghash_timing::timed+0x4d2>
   11021:      	jmp	0x10fbe <brynja_ghash_timing::timed+0x5ae>
   11023:      	movq	0x58(%rsp), %rcx
   11028:      	movq	%rcx, 0x20(%rsp)
   1102d:      	movq	$0x10, 0x28(%rsp)
   11036:      	leaq	0x20(%rsp), %rcx
   1103b:      	movq	0x28(%rsp), %rbp
   11040:      	subq	%rbp, %r14
   11043:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11049:      	testq	%rbp, %rbp
   1104c:      	je	0x111b3 <brynja_ghash_timing::timed+0x7a3>
   11052:      	movq	0x20(%rsp), %rbx
   11057:      	addq	%rbx, %rbp
   1105a:      	leaq	0x3(%rsp), %r12
   1105f:      	movl	$0x4, %r15d
   11065:      	pcmpeqd	%xmm2, %xmm2
   11069:      	movq	%rax, %rcx
   1106c:      	jmp	0x11077 <brynja_ghash_timing::timed+0x667>
   1106e:      	cmpq	%rbx, %rbp
   11071:      	je	0x111b3 <brynja_ghash_timing::timed+0x7a3>
   11077:      	testq	%rcx, %rcx
   1107a:      	jne	0x111a7 <brynja_ghash_timing::timed+0x797>
   11080:      	cmpq	%rbp, %rbx
   11083:      	je	0x111b3 <brynja_ghash_timing::timed+0x7a3>
   11089:      	movzbl	(%rbx), %edx
   1108c:      	xorb	%dl, (%rsp,%rcx)
   1108f:      	movq	%rbx, %rdx
   11092:      	notq	%rdx
   11095:      	addq	%rbp, %rdx
   11098:      	movl	$0xf, %esi
   1109d:      	subq	%rcx, %rsi
   110a0:      	cmpq	%rsi, %rdx
   110a3:      	cmovbq	%rdx, %rsi
   110a7:      	incq	%rsi
   110aa:      	cmpq	$0x5, %rsi
   110ae:      	jae	0x110b5 <brynja_ghash_timing::timed+0x6a5>
   110b0:      	movq	%rbx, %rdx
   110b3:      	jmp	0x1111a <brynja_ghash_timing::timed+0x70a>
   110b5:      	movl	%esi, %edx
   110b7:      	andl	$0x3, %edx
   110ba:      	cmoveq	%r15, %rdx
   110be:      	subq	%rdx, %rsi
   110c1:      	leaq	(%rbx,%rsi), %rdx
   110c5:      	movq	%rax, %xmm0
   110ca:      	leaq	(%r12,%rcx), %rax
   110ce:      	addq	%rsi, %rcx
   110d1:      	pxor	%xmm1, %xmm1
   110d5:      	xorl	%edi, %edi
   110d7:      	nopw	(%rax,%rax)
   110e0:      	movzwl	0x1(%rbx,%rdi), %r8d
   110e6:      	movzwl	0x3(%rbx,%rdi), %r9d
   110ec:      	xorw	%r8w, -0x2(%rax,%rdi)
   110f2:      	xorw	%r9w, (%rax,%rdi)
   110f7:      	psubq	%xmm2, %xmm0
   110fb:      	psubq	%xmm2, %xmm1
   110ff:      	addq	$0x4, %rdi
   11103:      	cmpq	%rdi, %rsi
   11106:      	jne	0x110e0 <brynja_ghash_timing::timed+0x6d0>
   11108:      	paddq	%xmm0, %xmm1
   1110c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11111:      	paddq	%xmm1, %xmm0
   11115:      	movq	%xmm0, %rax
   1111a:      	incq	%rax
   1111d:      	incq	%rdx
   11120:      	movq	%rdx, %rbx
   11123:      	cmpq	$0xf, %rcx
   11127:      	je	0x1114b <brynja_ghash_timing::timed+0x73b>
   11129:      	nopl	(%rax)
   11130:      	cmpq	%rbp, %rbx
   11133:      	je	0x1114b <brynja_ghash_timing::timed+0x73b>
   11135:      	movzbl	(%rbx), %edx
   11138:      	xorb	%dl, 0x1(%rsp,%rcx)
   1113c:      	incq	%rax
   1113f:      	incq	%rbx
   11142:      	incq	%rcx
   11145:      	cmpq	$0xf, %rcx
   11149:      	jne	0x11130 <brynja_ghash_timing::timed+0x720>
   1114b:      	movq	%rax, %rcx
   1114e:      	cmpq	$0x10, %rcx
   11152:      	jne	0x1106e <brynja_ghash_timing::timed+0x65e>
   11158:      	cmpq	$-0x1, %r13
   1115c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11162:      	movq	0x18(%rsp), %rax
   11167:      	movq	(%rax), %rcx
   1116a:      	movq	0x8(%rax), %rdx
   1116e:      	movq	0x8(%rsp), %rdi
   11173:      	bswapq	%rdx
   11176:      	bswapq	%rcx
   11179:      	bswapq	%rdi
   1117c:      	movq	(%rsp), %rsi
   11180:      	bswapq	%rsi
   11183:      	incq	%r13
   11186:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   1118b:      	pcmpeqd	%xmm2, %xmm2
   1118f:      	bswapq	%rdx
   11192:      	bswapq	%rax
   11195:      	movq	%rax, 0x8(%rsp)
   1119a:      	movq	%rdx, (%rsp)
   1119e:      	xorl	%eax, %eax
   111a0:      	xorl	%ecx, %ecx
   111a2:      	jmp	0x1106e <brynja_ghash_timing::timed+0x65e>
   111a7:      	cmpq	$0xf, %rcx
   111ab:      	jbe	0x11080 <brynja_ghash_timing::timed+0x670>
   111b1:      	jmp	0x1114e <brynja_ghash_timing::timed+0x73e>
   111b3:      	movq	0x58(%rsp), %rcx
   111b8:      	movq	%rcx, 0x20(%rsp)
   111bd:      	movq	$0x10, 0x28(%rsp)
   111c6:      	leaq	0x20(%rsp), %rcx
   111cb:      	movq	0x28(%rsp), %rbp
   111d0:      	subq	%rbp, %r14
   111d3:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   111d9:      	testq	%rbp, %rbp
   111dc:      	je	0x11343 <brynja_ghash_timing::timed+0x933>
   111e2:      	movq	0x20(%rsp), %rbx
   111e7:      	addq	%rbx, %rbp
   111ea:      	leaq	0x3(%rsp), %r12
   111ef:      	movl	$0x4, %r15d
   111f5:      	pcmpeqd	%xmm2, %xmm2
   111f9:      	movq	%rax, %rcx
   111fc:      	jmp	0x11207 <brynja_ghash_timing::timed+0x7f7>
   111fe:      	cmpq	%rbx, %rbp
   11201:      	je	0x11343 <brynja_ghash_timing::timed+0x933>
   11207:      	testq	%rcx, %rcx
   1120a:      	jne	0x11337 <brynja_ghash_timing::timed+0x927>
   11210:      	cmpq	%rbp, %rbx
   11213:      	je	0x11343 <brynja_ghash_timing::timed+0x933>
   11219:      	movzbl	(%rbx), %edx
   1121c:      	xorb	%dl, (%rsp,%rcx)
   1121f:      	movq	%rbx, %rdx
   11222:      	notq	%rdx
   11225:      	addq	%rbp, %rdx
   11228:      	movl	$0xf, %esi
   1122d:      	subq	%rcx, %rsi
   11230:      	cmpq	%rsi, %rdx
   11233:      	cmovbq	%rdx, %rsi
   11237:      	incq	%rsi
   1123a:      	cmpq	$0x5, %rsi
   1123e:      	jae	0x11245 <brynja_ghash_timing::timed+0x835>
   11240:      	movq	%rbx, %rdx
   11243:      	jmp	0x112aa <brynja_ghash_timing::timed+0x89a>
   11245:      	movl	%esi, %edx
   11247:      	andl	$0x3, %edx
   1124a:      	cmoveq	%r15, %rdx
   1124e:      	subq	%rdx, %rsi
   11251:      	leaq	(%rbx,%rsi), %rdx
   11255:      	movq	%rax, %xmm0
   1125a:      	leaq	(%r12,%rcx), %rax
   1125e:      	addq	%rsi, %rcx
   11261:      	pxor	%xmm1, %xmm1
   11265:      	xorl	%edi, %edi
   11267:      	nopw	(%rax,%rax)
   11270:      	movzwl	0x1(%rbx,%rdi), %r8d
   11276:      	movzwl	0x3(%rbx,%rdi), %r9d
   1127c:      	xorw	%r8w, -0x2(%rax,%rdi)
   11282:      	xorw	%r9w, (%rax,%rdi)
   11287:      	psubq	%xmm2, %xmm0
   1128b:      	psubq	%xmm2, %xmm1
   1128f:      	addq	$0x4, %rdi
   11293:      	cmpq	%rdi, %rsi
   11296:      	jne	0x11270 <brynja_ghash_timing::timed+0x860>
   11298:      	paddq	%xmm0, %xmm1
   1129c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   112a1:      	paddq	%xmm1, %xmm0
   112a5:      	movq	%xmm0, %rax
   112aa:      	incq	%rax
   112ad:      	incq	%rdx
   112b0:      	movq	%rdx, %rbx
   112b3:      	cmpq	$0xf, %rcx
   112b7:      	je	0x112db <brynja_ghash_timing::timed+0x8cb>
   112b9:      	nopl	(%rax)
   112c0:      	cmpq	%rbp, %rbx
   112c3:      	je	0x112db <brynja_ghash_timing::timed+0x8cb>
   112c5:      	movzbl	(%rbx), %edx
   112c8:      	xorb	%dl, 0x1(%rsp,%rcx)
   112cc:      	incq	%rax
   112cf:      	incq	%rbx
   112d2:      	incq	%rcx
   112d5:      	cmpq	$0xf, %rcx
   112d9:      	jne	0x112c0 <brynja_ghash_timing::timed+0x8b0>
   112db:      	movq	%rax, %rcx
   112de:      	cmpq	$0x10, %rcx
   112e2:      	jne	0x111fe <brynja_ghash_timing::timed+0x7ee>
   112e8:      	cmpq	$-0x1, %r13
   112ec:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   112f2:      	movq	0x18(%rsp), %rax
   112f7:      	movq	(%rax), %rcx
   112fa:      	movq	0x8(%rax), %rdx
   112fe:      	movq	0x8(%rsp), %rdi
   11303:      	bswapq	%rdx
   11306:      	bswapq	%rcx
   11309:      	bswapq	%rdi
   1130c:      	movq	(%rsp), %rsi
   11310:      	bswapq	%rsi
   11313:      	incq	%r13
   11316:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   1131b:      	pcmpeqd	%xmm2, %xmm2
   1131f:      	bswapq	%rdx
   11322:      	bswapq	%rax
   11325:      	movq	%rax, 0x8(%rsp)
   1132a:      	movq	%rdx, (%rsp)
   1132e:      	xorl	%eax, %eax
   11330:      	xorl	%ecx, %ecx
   11332:      	jmp	0x111fe <brynja_ghash_timing::timed+0x7ee>
   11337:      	cmpq	$0xf, %rcx
   1133b:      	jbe	0x11210 <brynja_ghash_timing::timed+0x800>
   11341:      	jmp	0x112de <brynja_ghash_timing::timed+0x8ce>
   11343:      	movq	0x58(%rsp), %rcx
   11348:      	movq	%rcx, 0x20(%rsp)
   1134d:      	movq	$0x10, 0x28(%rsp)
   11356:      	leaq	0x20(%rsp), %rcx
   1135b:      	movq	0x28(%rsp), %rbp
   11360:      	subq	%rbp, %r14
   11363:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11369:      	testq	%rbp, %rbp
   1136c:      	je	0x114d3 <brynja_ghash_timing::timed+0xac3>
   11372:      	movq	0x20(%rsp), %rbx
   11377:      	addq	%rbx, %rbp
   1137a:      	leaq	0x3(%rsp), %r12
   1137f:      	movl	$0x4, %r15d
   11385:      	pcmpeqd	%xmm2, %xmm2
   11389:      	movq	%rax, %rcx
   1138c:      	jmp	0x113d7 <brynja_ghash_timing::timed+0x9c7>
   1138e:      	movq	0x18(%rsp), %rax
   11393:      	movq	(%rax), %rcx
   11396:      	movq	0x8(%rax), %rdx
   1139a:      	movq	0x8(%rsp), %rdi
   1139f:      	bswapq	%rdx
   113a2:      	bswapq	%rcx
   113a5:      	bswapq	%rdi
   113a8:      	movq	(%rsp), %rsi
   113ac:      	bswapq	%rsi
   113af:      	incq	%r13
   113b2:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   113b7:      	pcmpeqd	%xmm2, %xmm2
   113bb:      	bswapq	%rdx
   113be:      	bswapq	%rax
   113c1:      	movq	%rax, 0x8(%rsp)
   113c6:      	movq	%rdx, (%rsp)
   113ca:      	xorl	%eax, %eax
   113cc:      	xorl	%ecx, %ecx
   113ce:      	cmpq	%rbx, %rbp
   113d1:      	je	0x114d3 <brynja_ghash_timing::timed+0xac3>
   113d7:      	testq	%rcx, %rcx
   113da:      	jne	0x114c7 <brynja_ghash_timing::timed+0xab7>
   113e0:      	cmpq	%rbp, %rbx
   113e3:      	je	0x114d3 <brynja_ghash_timing::timed+0xac3>
   113e9:      	movzbl	(%rbx), %edx
   113ec:      	xorb	%dl, (%rsp,%rcx)
   113ef:      	movq	%rbx, %rdx
   113f2:      	notq	%rdx
   113f5:      	addq	%rbp, %rdx
   113f8:      	movl	$0xf, %esi
   113fd:      	subq	%rcx, %rsi
   11400:      	cmpq	%rsi, %rdx
   11403:      	cmovbq	%rdx, %rsi
   11407:      	incq	%rsi
   1140a:      	cmpq	$0x5, %rsi
   1140e:      	jae	0x11415 <brynja_ghash_timing::timed+0xa05>
   11410:      	movq	%rbx, %rdx
   11413:      	jmp	0x1147a <brynja_ghash_timing::timed+0xa6a>
   11415:      	movl	%esi, %edx
   11417:      	andl	$0x3, %edx
   1141a:      	cmoveq	%r15, %rdx
   1141e:      	subq	%rdx, %rsi
   11421:      	leaq	(%rbx,%rsi), %rdx
   11425:      	movq	%rax, %xmm0
   1142a:      	leaq	(%r12,%rcx), %rax
   1142e:      	addq	%rsi, %rcx
   11431:      	pxor	%xmm1, %xmm1
   11435:      	xorl	%edi, %edi
   11437:      	nopw	(%rax,%rax)
   11440:      	movzwl	0x1(%rbx,%rdi), %r8d
   11446:      	movzwl	0x3(%rbx,%rdi), %r9d
   1144c:      	xorw	%r8w, -0x2(%rax,%rdi)
   11452:      	xorw	%r9w, (%rax,%rdi)
   11457:      	psubq	%xmm2, %xmm0
   1145b:      	psubq	%xmm2, %xmm1
   1145f:      	addq	$0x4, %rdi
   11463:      	cmpq	%rdi, %rsi
   11466:      	jne	0x11440 <brynja_ghash_timing::timed+0xa30>
   11468:      	paddq	%xmm0, %xmm1
   1146c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11471:      	paddq	%xmm1, %xmm0
   11475:      	movq	%xmm0, %rax
   1147a:      	incq	%rax
   1147d:      	incq	%rdx
   11480:      	movq	%rdx, %rbx
   11483:      	cmpq	$0xf, %rcx
   11487:      	je	0x114ab <brynja_ghash_timing::timed+0xa9b>
   11489:      	nopl	(%rax)
   11490:      	cmpq	%rbp, %rbx
   11493:      	je	0x114ab <brynja_ghash_timing::timed+0xa9b>
   11495:      	movzbl	(%rbx), %edx
   11498:      	xorb	%dl, 0x1(%rsp,%rcx)
   1149c:      	incq	%rax
   1149f:      	incq	%rbx
   114a2:      	incq	%rcx
   114a5:      	cmpq	$0xf, %rcx
   114a9:      	jne	0x11490 <brynja_ghash_timing::timed+0xa80>
   114ab:      	movq	%rax, %rcx
   114ae:      	cmpq	$0x10, %rcx
   114b2:      	jne	0x113ce <brynja_ghash_timing::timed+0x9be>
   114b8:      	cmpq	$-0x1, %r13
   114bc:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   114c2:      	jmp	0x1138e <brynja_ghash_timing::timed+0x97e>
   114c7:      	cmpq	$0xf, %rcx
   114cb:      	jbe	0x113e0 <brynja_ghash_timing::timed+0x9d0>
   114d1:      	jmp	0x114ae <brynja_ghash_timing::timed+0xa9e>
   114d3:      	movq	0x58(%rsp), %rcx
   114d8:      	movq	%rcx, 0x20(%rsp)
   114dd:      	movq	$0x10, 0x28(%rsp)
   114e6:      	leaq	0x20(%rsp), %rcx
   114eb:      	movq	0x28(%rsp), %rbp
   114f0:      	subq	%rbp, %r14
   114f3:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   114f9:      	testq	%rbp, %rbp
   114fc:      	je	0x11663 <brynja_ghash_timing::timed+0xc53>
   11502:      	movq	0x20(%rsp), %rbx
   11507:      	addq	%rbx, %rbp
   1150a:      	leaq	0x3(%rsp), %r12
   1150f:      	movl	$0x4, %r15d
   11515:      	pcmpeqd	%xmm2, %xmm2
   11519:      	movq	%rax, %rcx
   1151c:      	jmp	0x11527 <brynja_ghash_timing::timed+0xb17>
   1151e:      	cmpq	%rbx, %rbp
   11521:      	je	0x11663 <brynja_ghash_timing::timed+0xc53>
   11527:      	testq	%rcx, %rcx
   1152a:      	jne	0x11657 <brynja_ghash_timing::timed+0xc47>
   11530:      	cmpq	%rbp, %rbx
   11533:      	je	0x11663 <brynja_ghash_timing::timed+0xc53>
   11539:      	movzbl	(%rbx), %edx
   1153c:      	xorb	%dl, (%rsp,%rcx)
   1153f:      	movq	%rbx, %rdx
   11542:      	notq	%rdx
   11545:      	addq	%rbp, %rdx
   11548:      	movl	$0xf, %esi
   1154d:      	subq	%rcx, %rsi
   11550:      	cmpq	%rsi, %rdx
   11553:      	cmovbq	%rdx, %rsi
   11557:      	incq	%rsi
   1155a:      	cmpq	$0x5, %rsi
   1155e:      	jae	0x11565 <brynja_ghash_timing::timed+0xb55>
   11560:      	movq	%rbx, %rdx
   11563:      	jmp	0x115ca <brynja_ghash_timing::timed+0xbba>
   11565:      	movl	%esi, %edx
   11567:      	andl	$0x3, %edx
   1156a:      	cmoveq	%r15, %rdx
   1156e:      	subq	%rdx, %rsi
   11571:      	leaq	(%rbx,%rsi), %rdx
   11575:      	movq	%rax, %xmm0
   1157a:      	leaq	(%r12,%rcx), %rax
   1157e:      	addq	%rsi, %rcx
   11581:      	pxor	%xmm1, %xmm1
   11585:      	xorl	%edi, %edi
   11587:      	nopw	(%rax,%rax)
   11590:      	movzwl	0x1(%rbx,%rdi), %r8d
   11596:      	movzwl	0x3(%rbx,%rdi), %r9d
   1159c:      	xorw	%r8w, -0x2(%rax,%rdi)
   115a2:      	xorw	%r9w, (%rax,%rdi)
   115a7:      	psubq	%xmm2, %xmm0
   115ab:      	psubq	%xmm2, %xmm1
   115af:      	addq	$0x4, %rdi
   115b3:      	cmpq	%rdi, %rsi
   115b6:      	jne	0x11590 <brynja_ghash_timing::timed+0xb80>
   115b8:      	paddq	%xmm0, %xmm1
   115bc:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   115c1:      	paddq	%xmm1, %xmm0
   115c5:      	movq	%xmm0, %rax
   115ca:      	incq	%rax
   115cd:      	incq	%rdx
   115d0:      	movq	%rdx, %rbx
   115d3:      	cmpq	$0xf, %rcx
   115d7:      	je	0x115fb <brynja_ghash_timing::timed+0xbeb>
   115d9:      	nopl	(%rax)
   115e0:      	cmpq	%rbp, %rbx
   115e3:      	je	0x115fb <brynja_ghash_timing::timed+0xbeb>
   115e5:      	movzbl	(%rbx), %edx
   115e8:      	xorb	%dl, 0x1(%rsp,%rcx)
   115ec:      	incq	%rax
   115ef:      	incq	%rbx
   115f2:      	incq	%rcx
   115f5:      	cmpq	$0xf, %rcx
   115f9:      	jne	0x115e0 <brynja_ghash_timing::timed+0xbd0>
   115fb:      	movq	%rax, %rcx
   115fe:      	cmpq	$0x10, %rcx
   11602:      	jne	0x1151e <brynja_ghash_timing::timed+0xb0e>
   11608:      	cmpq	$-0x1, %r13
   1160c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11612:      	movq	0x18(%rsp), %rax
   11617:      	movq	(%rax), %rcx
   1161a:      	movq	0x8(%rax), %rdx
   1161e:      	movq	0x8(%rsp), %rdi
   11623:      	bswapq	%rdx
   11626:      	bswapq	%rcx
   11629:      	bswapq	%rdi
   1162c:      	movq	(%rsp), %rsi
   11630:      	bswapq	%rsi
   11633:      	incq	%r13
   11636:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   1163b:      	pcmpeqd	%xmm2, %xmm2
   1163f:      	bswapq	%rdx
   11642:      	bswapq	%rax
   11645:      	movq	%rax, 0x8(%rsp)
   1164a:      	movq	%rdx, (%rsp)
   1164e:      	xorl	%eax, %eax
   11650:      	xorl	%ecx, %ecx
   11652:      	jmp	0x1151e <brynja_ghash_timing::timed+0xb0e>
   11657:      	cmpq	$0xf, %rcx
   1165b:      	jbe	0x11530 <brynja_ghash_timing::timed+0xb20>
   11661:      	jmp	0x115fe <brynja_ghash_timing::timed+0xbee>
   11663:      	movq	0x58(%rsp), %rcx
   11668:      	movq	%rcx, 0x20(%rsp)
   1166d:      	movq	$0x10, 0x28(%rsp)
   11676:      	leaq	0x20(%rsp), %rcx
   1167b:      	movq	0x28(%rsp), %rbp
   11680:      	subq	%rbp, %r14
   11683:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11689:      	testq	%rbp, %rbp
   1168c:      	je	0x117f3 <brynja_ghash_timing::timed+0xde3>
   11692:      	movq	0x20(%rsp), %rbx
   11697:      	addq	%rbx, %rbp
   1169a:      	leaq	0x3(%rsp), %r12
   1169f:      	movl	$0x4, %r15d
   116a5:      	pcmpeqd	%xmm2, %xmm2
   116a9:      	movq	%rax, %rcx
   116ac:      	jmp	0x116b7 <brynja_ghash_timing::timed+0xca7>
   116ae:      	cmpq	%rbx, %rbp
   116b1:      	je	0x117f3 <brynja_ghash_timing::timed+0xde3>
   116b7:      	testq	%rcx, %rcx
   116ba:      	jne	0x117e7 <brynja_ghash_timing::timed+0xdd7>
   116c0:      	cmpq	%rbp, %rbx
   116c3:      	je	0x117f3 <brynja_ghash_timing::timed+0xde3>
   116c9:      	movzbl	(%rbx), %edx
   116cc:      	xorb	%dl, (%rsp,%rcx)
   116cf:      	movq	%rbx, %rdx
   116d2:      	notq	%rdx
   116d5:      	addq	%rbp, %rdx
   116d8:      	movl	$0xf, %esi
   116dd:      	subq	%rcx, %rsi
   116e0:      	cmpq	%rsi, %rdx
   116e3:      	cmovbq	%rdx, %rsi
   116e7:      	incq	%rsi
   116ea:      	cmpq	$0x5, %rsi
   116ee:      	jae	0x116f5 <brynja_ghash_timing::timed+0xce5>
   116f0:      	movq	%rbx, %rdx
   116f3:      	jmp	0x1175a <brynja_ghash_timing::timed+0xd4a>
   116f5:      	movl	%esi, %edx
   116f7:      	andl	$0x3, %edx
   116fa:      	cmoveq	%r15, %rdx
   116fe:      	subq	%rdx, %rsi
   11701:      	leaq	(%rbx,%rsi), %rdx
   11705:      	movq	%rax, %xmm0
   1170a:      	leaq	(%r12,%rcx), %rax
   1170e:      	addq	%rsi, %rcx
   11711:      	pxor	%xmm1, %xmm1
   11715:      	xorl	%edi, %edi
   11717:      	nopw	(%rax,%rax)
   11720:      	movzwl	0x1(%rbx,%rdi), %r8d
   11726:      	movzwl	0x3(%rbx,%rdi), %r9d
   1172c:      	xorw	%r8w, -0x2(%rax,%rdi)
   11732:      	xorw	%r9w, (%rax,%rdi)
   11737:      	psubq	%xmm2, %xmm0
   1173b:      	psubq	%xmm2, %xmm1
   1173f:      	addq	$0x4, %rdi
   11743:      	cmpq	%rdi, %rsi
   11746:      	jne	0x11720 <brynja_ghash_timing::timed+0xd10>
   11748:      	paddq	%xmm0, %xmm1
   1174c:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11751:      	paddq	%xmm1, %xmm0
   11755:      	movq	%xmm0, %rax
   1175a:      	incq	%rax
   1175d:      	incq	%rdx
   11760:      	movq	%rdx, %rbx
   11763:      	cmpq	$0xf, %rcx
   11767:      	je	0x1178b <brynja_ghash_timing::timed+0xd7b>
   11769:      	nopl	(%rax)
   11770:      	cmpq	%rbp, %rbx
   11773:      	je	0x1178b <brynja_ghash_timing::timed+0xd7b>
   11775:      	movzbl	(%rbx), %edx
   11778:      	xorb	%dl, 0x1(%rsp,%rcx)
   1177c:      	incq	%rax
   1177f:      	incq	%rbx
   11782:      	incq	%rcx
   11785:      	cmpq	$0xf, %rcx
   11789:      	jne	0x11770 <brynja_ghash_timing::timed+0xd60>
   1178b:      	movq	%rax, %rcx
   1178e:      	cmpq	$0x10, %rcx
   11792:      	jne	0x116ae <brynja_ghash_timing::timed+0xc9e>
   11798:      	cmpq	$-0x1, %r13
   1179c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   117a2:      	movq	0x18(%rsp), %rax
   117a7:      	movq	(%rax), %rcx
   117aa:      	movq	0x8(%rax), %rdx
   117ae:      	movq	0x8(%rsp), %rdi
   117b3:      	bswapq	%rdx
   117b6:      	bswapq	%rcx
   117b9:      	bswapq	%rdi
   117bc:      	movq	(%rsp), %rsi
   117c0:      	bswapq	%rsi
   117c3:      	incq	%r13
   117c6:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   117cb:      	pcmpeqd	%xmm2, %xmm2
   117cf:      	bswapq	%rdx
   117d2:      	bswapq	%rax
   117d5:      	movq	%rax, 0x8(%rsp)
   117da:      	movq	%rdx, (%rsp)
   117de:      	xorl	%eax, %eax
   117e0:      	xorl	%ecx, %ecx
   117e2:      	jmp	0x116ae <brynja_ghash_timing::timed+0xc9e>
   117e7:      	cmpq	$0xf, %rcx
   117eb:      	jbe	0x116c0 <brynja_ghash_timing::timed+0xcb0>
   117f1:      	jmp	0x1178e <brynja_ghash_timing::timed+0xd7e>
   117f3:      	movq	0x58(%rsp), %rcx
   117f8:      	movq	%rcx, 0x20(%rsp)
   117fd:      	movq	$0x10, 0x28(%rsp)
   11806:      	leaq	0x20(%rsp), %rcx
   1180b:      	movq	0x28(%rsp), %rbp
   11810:      	subq	%rbp, %r14
   11813:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11819:      	testq	%rbp, %rbp
   1181c:      	je	0x11973 <brynja_ghash_timing::timed+0xf63>
   11822:      	movq	0x20(%rsp), %rbx
   11827:      	addq	%rbx, %rbp
   1182a:      	leaq	0x3(%rsp), %r12
   1182f:      	movl	$0x4, %r15d
   11835:      	pcmpeqd	%xmm2, %xmm2
   11839:      	movq	%rax, %rcx
   1183c:      	jmp	0x11847 <brynja_ghash_timing::timed+0xe37>
   1183e:      	cmpq	%rbx, %rbp
   11841:      	je	0x11973 <brynja_ghash_timing::timed+0xf63>
   11847:      	testq	%rcx, %rcx
   1184a:      	jne	0x11967 <brynja_ghash_timing::timed+0xf57>
   11850:      	cmpq	%rbp, %rbx
   11853:      	je	0x11973 <brynja_ghash_timing::timed+0xf63>
   11859:      	movzbl	(%rbx), %edx
   1185c:      	xorb	%dl, (%rsp,%rcx)
   1185f:      	movq	%rbx, %rdx
   11862:      	notq	%rdx
   11865:      	addq	%rbp, %rdx
   11868:      	movl	$0xf, %esi
   1186d:      	subq	%rcx, %rsi
   11870:      	cmpq	%rsi, %rdx
   11873:      	cmovbq	%rdx, %rsi
   11877:      	incq	%rsi
   1187a:      	cmpq	$0x5, %rsi
   1187e:      	jae	0x11885 <brynja_ghash_timing::timed+0xe75>
   11880:      	movq	%rbx, %rdx
   11883:      	jmp	0x118e1 <brynja_ghash_timing::timed+0xed1>
   11885:      	movl	%esi, %edx
   11887:      	andl	$0x3, %edx
   1188a:      	cmoveq	%r15, %rdx
   1188e:      	subq	%rdx, %rsi
   11891:      	leaq	(%rbx,%rsi), %rdx
   11895:      	movq	%rax, %xmm0
   1189a:      	leaq	(%r12,%rcx), %rax
   1189e:      	addq	%rsi, %rcx
   118a1:      	pxor	%xmm1, %xmm1
   118a5:      	xorl	%edi, %edi
   118a7:      	movzwl	0x1(%rbx,%rdi), %r8d
   118ad:      	movzwl	0x3(%rbx,%rdi), %r9d
   118b3:      	xorw	%r8w, -0x2(%rax,%rdi)
   118b9:      	xorw	%r9w, (%rax,%rdi)
   118be:      	psubq	%xmm2, %xmm0
   118c2:      	psubq	%xmm2, %xmm1
   118c6:      	addq	$0x4, %rdi
   118ca:      	cmpq	%rdi, %rsi
   118cd:      	jne	0x118a7 <brynja_ghash_timing::timed+0xe97>
   118cf:      	paddq	%xmm0, %xmm1
   118d3:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   118d8:      	paddq	%xmm1, %xmm0
   118dc:      	movq	%xmm0, %rax
   118e1:      	incq	%rax
   118e4:      	incq	%rdx
   118e7:      	movq	%rdx, %rbx
   118ea:      	cmpq	$0xf, %rcx
   118ee:      	je	0x1190b <brynja_ghash_timing::timed+0xefb>
   118f0:      	cmpq	%rbp, %rbx
   118f3:      	je	0x1190b <brynja_ghash_timing::timed+0xefb>
   118f5:      	movzbl	(%rbx), %edx
   118f8:      	xorb	%dl, 0x1(%rsp,%rcx)
   118fc:      	incq	%rax
   118ff:      	incq	%rbx
   11902:      	incq	%rcx
   11905:      	cmpq	$0xf, %rcx
   11909:      	jne	0x118f0 <brynja_ghash_timing::timed+0xee0>
   1190b:      	movq	%rax, %rcx
   1190e:      	cmpq	$0x10, %rcx
   11912:      	jne	0x1183e <brynja_ghash_timing::timed+0xe2e>
   11918:      	cmpq	$-0x1, %r13
   1191c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11922:      	movq	0x18(%rsp), %rax
   11927:      	movq	(%rax), %rcx
   1192a:      	movq	0x8(%rax), %rdx
   1192e:      	movq	0x8(%rsp), %rdi
   11933:      	bswapq	%rdx
   11936:      	bswapq	%rcx
   11939:      	bswapq	%rdi
   1193c:      	movq	(%rsp), %rsi
   11940:      	bswapq	%rsi
   11943:      	incq	%r13
   11946:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   1194b:      	pcmpeqd	%xmm2, %xmm2
   1194f:      	bswapq	%rdx
   11952:      	bswapq	%rax
   11955:      	movq	%rax, 0x8(%rsp)
   1195a:      	movq	%rdx, (%rsp)
   1195e:      	xorl	%eax, %eax
   11960:      	xorl	%ecx, %ecx
   11962:      	jmp	0x1183e <brynja_ghash_timing::timed+0xe2e>
   11967:      	cmpq	$0xf, %rcx
   1196b:      	jbe	0x11850 <brynja_ghash_timing::timed+0xe40>
   11971:      	jmp	0x1190e <brynja_ghash_timing::timed+0xefe>
   11973:      	movq	0x58(%rsp), %rcx
   11978:      	movq	%rcx, 0x20(%rsp)
   1197d:      	movq	$0x10, 0x28(%rsp)
   11986:      	leaq	0x20(%rsp), %rcx
   1198b:      	movq	0x28(%rsp), %rbp
   11990:      	subq	%rbp, %r14
   11993:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11999:      	testq	%rbp, %rbp
   1199c:      	je	0x11af3 <brynja_ghash_timing::timed+0x10e3>
   119a2:      	movq	0x20(%rsp), %rbx
   119a7:      	addq	%rbx, %rbp
   119aa:      	leaq	0x3(%rsp), %r12
   119af:      	movl	$0x4, %r15d
   119b5:      	pcmpeqd	%xmm2, %xmm2
   119b9:      	movq	%rax, %rcx
   119bc:      	jmp	0x119c7 <brynja_ghash_timing::timed+0xfb7>
   119be:      	cmpq	%rbx, %rbp
   119c1:      	je	0x11af3 <brynja_ghash_timing::timed+0x10e3>
   119c7:      	testq	%rcx, %rcx
   119ca:      	jne	0x11ae7 <brynja_ghash_timing::timed+0x10d7>
   119d0:      	cmpq	%rbp, %rbx
   119d3:      	je	0x11af3 <brynja_ghash_timing::timed+0x10e3>
   119d9:      	movzbl	(%rbx), %edx
   119dc:      	xorb	%dl, (%rsp,%rcx)
   119df:      	movq	%rbx, %rdx
   119e2:      	notq	%rdx
   119e5:      	addq	%rbp, %rdx
   119e8:      	movl	$0xf, %esi
   119ed:      	subq	%rcx, %rsi
   119f0:      	cmpq	%rsi, %rdx
   119f3:      	cmovbq	%rdx, %rsi
   119f7:      	incq	%rsi
   119fa:      	cmpq	$0x5, %rsi
   119fe:      	jae	0x11a05 <brynja_ghash_timing::timed+0xff5>
   11a00:      	movq	%rbx, %rdx
   11a03:      	jmp	0x11a61 <brynja_ghash_timing::timed+0x1051>
   11a05:      	movl	%esi, %edx
   11a07:      	andl	$0x3, %edx
   11a0a:      	cmoveq	%r15, %rdx
   11a0e:      	subq	%rdx, %rsi
   11a11:      	leaq	(%rbx,%rsi), %rdx
   11a15:      	movq	%rax, %xmm0
   11a1a:      	leaq	(%r12,%rcx), %rax
   11a1e:      	addq	%rsi, %rcx
   11a21:      	pxor	%xmm1, %xmm1
   11a25:      	xorl	%edi, %edi
   11a27:      	movzwl	0x1(%rbx,%rdi), %r8d
   11a2d:      	movzwl	0x3(%rbx,%rdi), %r9d
   11a33:      	xorw	%r8w, -0x2(%rax,%rdi)
   11a39:      	xorw	%r9w, (%rax,%rdi)
   11a3e:      	psubq	%xmm2, %xmm0
   11a42:      	psubq	%xmm2, %xmm1
   11a46:      	addq	$0x4, %rdi
   11a4a:      	cmpq	%rdi, %rsi
   11a4d:      	jne	0x11a27 <brynja_ghash_timing::timed+0x1017>
   11a4f:      	paddq	%xmm0, %xmm1
   11a53:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11a58:      	paddq	%xmm1, %xmm0
   11a5c:      	movq	%xmm0, %rax
   11a61:      	incq	%rax
   11a64:      	incq	%rdx
   11a67:      	movq	%rdx, %rbx
   11a6a:      	cmpq	$0xf, %rcx
   11a6e:      	je	0x11a8b <brynja_ghash_timing::timed+0x107b>
   11a70:      	cmpq	%rbp, %rbx
   11a73:      	je	0x11a8b <brynja_ghash_timing::timed+0x107b>
   11a75:      	movzbl	(%rbx), %edx
   11a78:      	xorb	%dl, 0x1(%rsp,%rcx)
   11a7c:      	incq	%rax
   11a7f:      	incq	%rbx
   11a82:      	incq	%rcx
   11a85:      	cmpq	$0xf, %rcx
   11a89:      	jne	0x11a70 <brynja_ghash_timing::timed+0x1060>
   11a8b:      	movq	%rax, %rcx
   11a8e:      	cmpq	$0x10, %rcx
   11a92:      	jne	0x119be <brynja_ghash_timing::timed+0xfae>
   11a98:      	cmpq	$-0x1, %r13
   11a9c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11aa2:      	movq	0x18(%rsp), %rax
   11aa7:      	movq	(%rax), %rcx
   11aaa:      	movq	0x8(%rax), %rdx
   11aae:      	movq	0x8(%rsp), %rdi
   11ab3:      	bswapq	%rdx
   11ab6:      	bswapq	%rcx
   11ab9:      	bswapq	%rdi
   11abc:      	movq	(%rsp), %rsi
   11ac0:      	bswapq	%rsi
   11ac3:      	incq	%r13
   11ac6:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   11acb:      	pcmpeqd	%xmm2, %xmm2
   11acf:      	bswapq	%rdx
   11ad2:      	bswapq	%rax
   11ad5:      	movq	%rax, 0x8(%rsp)
   11ada:      	movq	%rdx, (%rsp)
   11ade:      	xorl	%eax, %eax
   11ae0:      	xorl	%ecx, %ecx
   11ae2:      	jmp	0x119be <brynja_ghash_timing::timed+0xfae>
   11ae7:      	cmpq	$0xf, %rcx
   11aeb:      	jbe	0x119d0 <brynja_ghash_timing::timed+0xfc0>
   11af1:      	jmp	0x11a8e <brynja_ghash_timing::timed+0x107e>
   11af3:      	movq	0x58(%rsp), %rcx
   11af8:      	movq	%rcx, 0x20(%rsp)
   11afd:      	movq	$0x10, 0x28(%rsp)
   11b06:      	leaq	0x20(%rsp), %rcx
   11b0b:      	movq	0x28(%rsp), %rbp
   11b10:      	subq	%rbp, %r14
   11b13:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11b19:      	testq	%rbp, %rbp
   11b1c:      	je	0x11c73 <brynja_ghash_timing::timed+0x1263>
   11b22:      	movq	0x20(%rsp), %rbx
   11b27:      	addq	%rbx, %rbp
   11b2a:      	leaq	0x3(%rsp), %r12
   11b2f:      	movl	$0x4, %r15d
   11b35:      	pcmpeqd	%xmm2, %xmm2
   11b39:      	movq	%rax, %rcx
   11b3c:      	jmp	0x11b47 <brynja_ghash_timing::timed+0x1137>
   11b3e:      	cmpq	%rbx, %rbp
   11b41:      	je	0x11c73 <brynja_ghash_timing::timed+0x1263>
   11b47:      	testq	%rcx, %rcx
   11b4a:      	jne	0x11c67 <brynja_ghash_timing::timed+0x1257>
   11b50:      	cmpq	%rbp, %rbx
   11b53:      	je	0x11c73 <brynja_ghash_timing::timed+0x1263>
   11b59:      	movzbl	(%rbx), %edx
   11b5c:      	xorb	%dl, (%rsp,%rcx)
   11b5f:      	movq	%rbx, %rdx
   11b62:      	notq	%rdx
   11b65:      	addq	%rbp, %rdx
   11b68:      	movl	$0xf, %esi
   11b6d:      	subq	%rcx, %rsi
   11b70:      	cmpq	%rsi, %rdx
   11b73:      	cmovbq	%rdx, %rsi
   11b77:      	incq	%rsi
   11b7a:      	cmpq	$0x5, %rsi
   11b7e:      	jae	0x11b85 <brynja_ghash_timing::timed+0x1175>
   11b80:      	movq	%rbx, %rdx
   11b83:      	jmp	0x11be1 <brynja_ghash_timing::timed+0x11d1>
   11b85:      	movl	%esi, %edx
   11b87:      	andl	$0x3, %edx
   11b8a:      	cmoveq	%r15, %rdx
   11b8e:      	subq	%rdx, %rsi
   11b91:      	leaq	(%rbx,%rsi), %rdx
   11b95:      	movq	%rax, %xmm0
   11b9a:      	leaq	(%r12,%rcx), %rax
   11b9e:      	addq	%rsi, %rcx
   11ba1:      	pxor	%xmm1, %xmm1
   11ba5:      	xorl	%edi, %edi
   11ba7:      	movzwl	0x1(%rbx,%rdi), %r8d
   11bad:      	movzwl	0x3(%rbx,%rdi), %r9d
   11bb3:      	xorw	%r8w, -0x2(%rax,%rdi)
   11bb9:      	xorw	%r9w, (%rax,%rdi)
   11bbe:      	psubq	%xmm2, %xmm0
   11bc2:      	psubq	%xmm2, %xmm1
   11bc6:      	addq	$0x4, %rdi
   11bca:      	cmpq	%rdi, %rsi
   11bcd:      	jne	0x11ba7 <brynja_ghash_timing::timed+0x1197>
   11bcf:      	paddq	%xmm0, %xmm1
   11bd3:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11bd8:      	paddq	%xmm1, %xmm0
   11bdc:      	movq	%xmm0, %rax
   11be1:      	incq	%rax
   11be4:      	incq	%rdx
   11be7:      	movq	%rdx, %rbx
   11bea:      	cmpq	$0xf, %rcx
   11bee:      	je	0x11c0b <brynja_ghash_timing::timed+0x11fb>
   11bf0:      	cmpq	%rbp, %rbx
   11bf3:      	je	0x11c0b <brynja_ghash_timing::timed+0x11fb>
   11bf5:      	movzbl	(%rbx), %edx
   11bf8:      	xorb	%dl, 0x1(%rsp,%rcx)
   11bfc:      	incq	%rax
   11bff:      	incq	%rbx
   11c02:      	incq	%rcx
   11c05:      	cmpq	$0xf, %rcx
   11c09:      	jne	0x11bf0 <brynja_ghash_timing::timed+0x11e0>
   11c0b:      	movq	%rax, %rcx
   11c0e:      	cmpq	$0x10, %rcx
   11c12:      	jne	0x11b3e <brynja_ghash_timing::timed+0x112e>
   11c18:      	cmpq	$-0x1, %r13
   11c1c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11c22:      	movq	0x18(%rsp), %rax
   11c27:      	movq	(%rax), %rcx
   11c2a:      	movq	0x8(%rax), %rdx
   11c2e:      	movq	0x8(%rsp), %rdi
   11c33:      	bswapq	%rdx
   11c36:      	bswapq	%rcx
   11c39:      	bswapq	%rdi
   11c3c:      	movq	(%rsp), %rsi
   11c40:      	bswapq	%rsi
   11c43:      	incq	%r13
   11c46:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   11c4b:      	pcmpeqd	%xmm2, %xmm2
   11c4f:      	bswapq	%rdx
   11c52:      	bswapq	%rax
   11c55:      	movq	%rax, 0x8(%rsp)
   11c5a:      	movq	%rdx, (%rsp)
   11c5e:      	xorl	%eax, %eax
   11c60:      	xorl	%ecx, %ecx
   11c62:      	jmp	0x11b3e <brynja_ghash_timing::timed+0x112e>
   11c67:      	cmpq	$0xf, %rcx
   11c6b:      	jbe	0x11b50 <brynja_ghash_timing::timed+0x1140>
   11c71:      	jmp	0x11c0e <brynja_ghash_timing::timed+0x11fe>
   11c73:      	movq	0x58(%rsp), %rcx
   11c78:      	movq	%rcx, 0x20(%rsp)
   11c7d:      	movq	$0x10, 0x28(%rsp)
   11c86:      	leaq	0x20(%rsp), %rcx
   11c8b:      	movq	0x28(%rsp), %rbp
   11c90:      	subq	%rbp, %r14
   11c93:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11c99:      	testq	%rbp, %rbp
   11c9c:      	je	0x11df3 <brynja_ghash_timing::timed+0x13e3>
   11ca2:      	movq	0x20(%rsp), %rbx
   11ca7:      	addq	%rbx, %rbp
   11caa:      	leaq	0x3(%rsp), %r12
   11caf:      	movl	$0x4, %r15d
   11cb5:      	pcmpeqd	%xmm2, %xmm2
   11cb9:      	movq	%rax, %rcx
   11cbc:      	jmp	0x11cc7 <brynja_ghash_timing::timed+0x12b7>
   11cbe:      	cmpq	%rbx, %rbp
   11cc1:      	je	0x11df3 <brynja_ghash_timing::timed+0x13e3>
   11cc7:      	testq	%rcx, %rcx
   11cca:      	jne	0x11de7 <brynja_ghash_timing::timed+0x13d7>
   11cd0:      	cmpq	%rbp, %rbx
   11cd3:      	je	0x11df3 <brynja_ghash_timing::timed+0x13e3>
   11cd9:      	movzbl	(%rbx), %edx
   11cdc:      	xorb	%dl, (%rsp,%rcx)
   11cdf:      	movq	%rbx, %rdx
   11ce2:      	notq	%rdx
   11ce5:      	addq	%rbp, %rdx
   11ce8:      	movl	$0xf, %esi
   11ced:      	subq	%rcx, %rsi
   11cf0:      	cmpq	%rsi, %rdx
   11cf3:      	cmovbq	%rdx, %rsi
   11cf7:      	incq	%rsi
   11cfa:      	cmpq	$0x5, %rsi
   11cfe:      	jae	0x11d05 <brynja_ghash_timing::timed+0x12f5>
   11d00:      	movq	%rbx, %rdx
   11d03:      	jmp	0x11d61 <brynja_ghash_timing::timed+0x1351>
   11d05:      	movl	%esi, %edx
   11d07:      	andl	$0x3, %edx
   11d0a:      	cmoveq	%r15, %rdx
   11d0e:      	subq	%rdx, %rsi
   11d11:      	leaq	(%rbx,%rsi), %rdx
   11d15:      	movq	%rax, %xmm0
   11d1a:      	leaq	(%r12,%rcx), %rax
   11d1e:      	addq	%rsi, %rcx
   11d21:      	pxor	%xmm1, %xmm1
   11d25:      	xorl	%edi, %edi
   11d27:      	movzwl	0x1(%rbx,%rdi), %r8d
   11d2d:      	movzwl	0x3(%rbx,%rdi), %r9d
   11d33:      	xorw	%r8w, -0x2(%rax,%rdi)
   11d39:      	xorw	%r9w, (%rax,%rdi)
   11d3e:      	psubq	%xmm2, %xmm0
   11d42:      	psubq	%xmm2, %xmm1
   11d46:      	addq	$0x4, %rdi
   11d4a:      	cmpq	%rdi, %rsi
   11d4d:      	jne	0x11d27 <brynja_ghash_timing::timed+0x1317>
   11d4f:      	paddq	%xmm0, %xmm1
   11d53:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11d58:      	paddq	%xmm1, %xmm0
   11d5c:      	movq	%xmm0, %rax
   11d61:      	incq	%rax
   11d64:      	incq	%rdx
   11d67:      	movq	%rdx, %rbx
   11d6a:      	cmpq	$0xf, %rcx
   11d6e:      	je	0x11d8b <brynja_ghash_timing::timed+0x137b>
   11d70:      	cmpq	%rbp, %rbx
   11d73:      	je	0x11d8b <brynja_ghash_timing::timed+0x137b>
   11d75:      	movzbl	(%rbx), %edx
   11d78:      	xorb	%dl, 0x1(%rsp,%rcx)
   11d7c:      	incq	%rax
   11d7f:      	incq	%rbx
   11d82:      	incq	%rcx
   11d85:      	cmpq	$0xf, %rcx
   11d89:      	jne	0x11d70 <brynja_ghash_timing::timed+0x1360>
   11d8b:      	movq	%rax, %rcx
   11d8e:      	cmpq	$0x10, %rcx
   11d92:      	jne	0x11cbe <brynja_ghash_timing::timed+0x12ae>
   11d98:      	cmpq	$-0x1, %r13
   11d9c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11da2:      	movq	0x18(%rsp), %rax
   11da7:      	movq	(%rax), %rcx
   11daa:      	movq	0x8(%rax), %rdx
   11dae:      	movq	0x8(%rsp), %rdi
   11db3:      	bswapq	%rdx
   11db6:      	bswapq	%rcx
   11db9:      	bswapq	%rdi
   11dbc:      	movq	(%rsp), %rsi
   11dc0:      	bswapq	%rsi
   11dc3:      	incq	%r13
   11dc6:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   11dcb:      	pcmpeqd	%xmm2, %xmm2
   11dcf:      	bswapq	%rdx
   11dd2:      	bswapq	%rax
   11dd5:      	movq	%rax, 0x8(%rsp)
   11dda:      	movq	%rdx, (%rsp)
   11dde:      	xorl	%eax, %eax
   11de0:      	xorl	%ecx, %ecx
   11de2:      	jmp	0x11cbe <brynja_ghash_timing::timed+0x12ae>
   11de7:      	cmpq	$0xf, %rcx
   11deb:      	jbe	0x11cd0 <brynja_ghash_timing::timed+0x12c0>
   11df1:      	jmp	0x11d8e <brynja_ghash_timing::timed+0x137e>
   11df3:      	movq	0x58(%rsp), %rcx
   11df8:      	movq	%rcx, 0x20(%rsp)
   11dfd:      	movq	$0x10, 0x28(%rsp)
   11e06:      	leaq	0x20(%rsp), %rcx
   11e0b:      	movq	0x28(%rsp), %rbp
   11e10:      	subq	%rbp, %r14
   11e13:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11e19:      	testq	%rbp, %rbp
   11e1c:      	je	0x11f73 <brynja_ghash_timing::timed+0x1563>
   11e22:      	movq	0x20(%rsp), %rbx
   11e27:      	addq	%rbx, %rbp
   11e2a:      	leaq	0x3(%rsp), %r12
   11e2f:      	movl	$0x4, %r15d
   11e35:      	pcmpeqd	%xmm2, %xmm2
   11e39:      	movq	%rax, %rcx
   11e3c:      	jmp	0x11e87 <brynja_ghash_timing::timed+0x1477>
   11e3e:      	movq	0x18(%rsp), %rax
   11e43:      	movq	(%rax), %rcx
   11e46:      	movq	0x8(%rax), %rdx
   11e4a:      	movq	0x8(%rsp), %rdi
   11e4f:      	bswapq	%rdx
   11e52:      	bswapq	%rcx
   11e55:      	bswapq	%rdi
   11e58:      	movq	(%rsp), %rsi
   11e5c:      	bswapq	%rsi
   11e5f:      	incq	%r13
   11e62:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   11e67:      	bswapq	%rdx
   11e6a:      	bswapq	%rax
   11e6d:      	movq	%rax, 0x8(%rsp)
   11e72:      	movq	%rdx, (%rsp)
   11e76:      	xorl	%eax, %eax
   11e78:      	xorl	%ecx, %ecx
   11e7a:      	pcmpeqd	%xmm2, %xmm2
   11e7e:      	cmpq	%rbx, %rbp
   11e81:      	je	0x11f73 <brynja_ghash_timing::timed+0x1563>
   11e87:      	testq	%rcx, %rcx
   11e8a:      	jne	0x11f67 <brynja_ghash_timing::timed+0x1557>
   11e90:      	cmpq	%rbp, %rbx
   11e93:      	je	0x11f73 <brynja_ghash_timing::timed+0x1563>
   11e99:      	movzbl	(%rbx), %edx
   11e9c:      	xorb	%dl, (%rsp,%rcx)
   11e9f:      	movq	%rbx, %rdx
   11ea2:      	notq	%rdx
   11ea5:      	addq	%rbp, %rdx
   11ea8:      	movl	$0xf, %esi
   11ead:      	subq	%rcx, %rsi
   11eb0:      	cmpq	%rsi, %rdx
   11eb3:      	cmovbq	%rdx, %rsi
   11eb7:      	incq	%rsi
   11eba:      	cmpq	$0x5, %rsi
   11ebe:      	jae	0x11ec5 <brynja_ghash_timing::timed+0x14b5>
   11ec0:      	movq	%rbx, %rdx
   11ec3:      	jmp	0x11f21 <brynja_ghash_timing::timed+0x1511>
   11ec5:      	movl	%esi, %edx
   11ec7:      	andl	$0x3, %edx
   11eca:      	cmoveq	%r15, %rdx
   11ece:      	subq	%rdx, %rsi
   11ed1:      	leaq	(%rbx,%rsi), %rdx
   11ed5:      	movq	%rax, %xmm0
   11eda:      	leaq	(%r12,%rcx), %rax
   11ede:      	addq	%rsi, %rcx
   11ee1:      	pxor	%xmm1, %xmm1
   11ee5:      	xorl	%edi, %edi
   11ee7:      	movzwl	0x1(%rbx,%rdi), %r8d
   11eed:      	movzwl	0x3(%rbx,%rdi), %r9d
   11ef3:      	xorw	%r8w, -0x2(%rax,%rdi)
   11ef9:      	xorw	%r9w, (%rax,%rdi)
   11efe:      	psubq	%xmm2, %xmm0
   11f02:      	psubq	%xmm2, %xmm1
   11f06:      	addq	$0x4, %rdi
   11f0a:      	cmpq	%rdi, %rsi
   11f0d:      	jne	0x11ee7 <brynja_ghash_timing::timed+0x14d7>
   11f0f:      	paddq	%xmm0, %xmm1
   11f13:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   11f18:      	paddq	%xmm1, %xmm0
   11f1c:      	movq	%xmm0, %rax
   11f21:      	incq	%rax
   11f24:      	incq	%rdx
   11f27:      	movq	%rdx, %rbx
   11f2a:      	cmpq	$0xf, %rcx
   11f2e:      	je	0x11f4b <brynja_ghash_timing::timed+0x153b>
   11f30:      	cmpq	%rbp, %rbx
   11f33:      	je	0x11f4b <brynja_ghash_timing::timed+0x153b>
   11f35:      	movzbl	(%rbx), %edx
   11f38:      	xorb	%dl, 0x1(%rsp,%rcx)
   11f3c:      	incq	%rax
   11f3f:      	incq	%rbx
   11f42:      	incq	%rcx
   11f45:      	cmpq	$0xf, %rcx
   11f49:      	jne	0x11f30 <brynja_ghash_timing::timed+0x1520>
   11f4b:      	movq	%rax, %rcx
   11f4e:      	cmpq	$0x10, %rcx
   11f52:      	jne	0x11e7e <brynja_ghash_timing::timed+0x146e>
   11f58:      	cmpq	$-0x1, %r13
   11f5c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   11f62:      	jmp	0x11e3e <brynja_ghash_timing::timed+0x142e>
   11f67:      	cmpq	$0xf, %rcx
   11f6b:      	jbe	0x11e90 <brynja_ghash_timing::timed+0x1480>
   11f71:      	jmp	0x11f4e <brynja_ghash_timing::timed+0x153e>
   11f73:      	movq	0x58(%rsp), %rcx
   11f78:      	movq	%rcx, 0x20(%rsp)
   11f7d:      	movq	$0x10, 0x28(%rsp)
   11f86:      	leaq	0x20(%rsp), %rcx
   11f8b:      	movq	0x28(%rsp), %rbp
   11f90:      	subq	%rbp, %r14
   11f93:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   11f99:      	testq	%rbp, %rbp
   11f9c:      	je	0x120ef <brynja_ghash_timing::timed+0x16df>
   11fa2:      	movq	0x20(%rsp), %rbx
   11fa7:      	addq	%rbx, %rbp
   11faa:      	leaq	0x3(%rsp), %r12
   11faf:      	movl	$0x4, %r15d
   11fb5:      	movq	%rax, %rcx
   11fb8:      	jmp	0x11fc3 <brynja_ghash_timing::timed+0x15b3>
   11fba:      	cmpq	%rbx, %rbp
   11fbd:      	je	0x120ef <brynja_ghash_timing::timed+0x16df>
   11fc3:      	testq	%rcx, %rcx
   11fc6:      	jne	0x120e3 <brynja_ghash_timing::timed+0x16d3>
   11fcc:      	cmpq	%rbp, %rbx
   11fcf:      	je	0x120ef <brynja_ghash_timing::timed+0x16df>
   11fd5:      	movzbl	(%rbx), %edx
   11fd8:      	xorb	%dl, (%rsp,%rcx)
   11fdb:      	movq	%rbx, %rdx
   11fde:      	notq	%rdx
   11fe1:      	addq	%rbp, %rdx
   11fe4:      	movl	$0xf, %esi
   11fe9:      	subq	%rcx, %rsi
   11fec:      	cmpq	%rsi, %rdx
   11fef:      	cmovbq	%rdx, %rsi
   11ff3:      	incq	%rsi
   11ff6:      	cmpq	$0x5, %rsi
   11ffa:      	jae	0x12001 <brynja_ghash_timing::timed+0x15f1>
   11ffc:      	movq	%rbx, %rdx
   11fff:      	jmp	0x12061 <brynja_ghash_timing::timed+0x1651>
   12001:      	movl	%esi, %edx
   12003:      	andl	$0x3, %edx
   12006:      	cmoveq	%r15, %rdx
   1200a:      	subq	%rdx, %rsi
   1200d:      	leaq	(%rbx,%rsi), %rdx
   12011:      	movq	%rax, %xmm0
   12016:      	leaq	(%r12,%rcx), %rax
   1201a:      	addq	%rsi, %rcx
   1201d:      	pxor	%xmm1, %xmm1
   12021:      	xorl	%edi, %edi
   12023:      	pcmpeqd	%xmm2, %xmm2
   12027:      	movzwl	0x1(%rbx,%rdi), %r8d
   1202d:      	movzwl	0x3(%rbx,%rdi), %r9d
   12033:      	xorw	%r8w, -0x2(%rax,%rdi)
   12039:      	xorw	%r9w, (%rax,%rdi)
   1203e:      	psubq	%xmm2, %xmm0
   12042:      	psubq	%xmm2, %xmm1
   12046:      	addq	$0x4, %rdi
   1204a:      	cmpq	%rdi, %rsi
   1204d:      	jne	0x12027 <brynja_ghash_timing::timed+0x1617>
   1204f:      	paddq	%xmm0, %xmm1
   12053:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   12058:      	paddq	%xmm1, %xmm0
   1205c:      	movq	%xmm0, %rax
   12061:      	incq	%rax
   12064:      	incq	%rdx
   12067:      	movq	%rdx, %rbx
   1206a:      	cmpq	$0xf, %rcx
   1206e:      	je	0x1208b <brynja_ghash_timing::timed+0x167b>
   12070:      	cmpq	%rbp, %rbx
   12073:      	je	0x1208b <brynja_ghash_timing::timed+0x167b>
   12075:      	movzbl	(%rbx), %edx
   12078:      	xorb	%dl, 0x1(%rsp,%rcx)
   1207c:      	incq	%rax
   1207f:      	incq	%rbx
   12082:      	incq	%rcx
   12085:      	cmpq	$0xf, %rcx
   12089:      	jne	0x12070 <brynja_ghash_timing::timed+0x1660>
   1208b:      	movq	%rax, %rcx
   1208e:      	cmpq	$0x10, %rcx
   12092:      	jne	0x11fba <brynja_ghash_timing::timed+0x15aa>
   12098:      	cmpq	$-0x1, %r13
   1209c:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   120a2:      	movq	0x18(%rsp), %rax
   120a7:      	movq	(%rax), %rcx
   120aa:      	movq	0x8(%rax), %rdx
   120ae:      	movq	0x8(%rsp), %rdi
   120b3:      	bswapq	%rdx
   120b6:      	bswapq	%rcx
   120b9:      	bswapq	%rdi
   120bc:      	movq	(%rsp), %rsi
   120c0:      	bswapq	%rsi
   120c3:      	incq	%r13
   120c6:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   120cb:      	bswapq	%rdx
   120ce:      	bswapq	%rax
   120d1:      	movq	%rax, 0x8(%rsp)
   120d6:      	movq	%rdx, (%rsp)
   120da:      	xorl	%eax, %eax
   120dc:      	xorl	%ecx, %ecx
   120de:      	jmp	0x11fba <brynja_ghash_timing::timed+0x15aa>
   120e3:      	cmpq	$0xf, %rcx
   120e7:      	jbe	0x11fcc <brynja_ghash_timing::timed+0x15bc>
   120ed:      	jmp	0x1208e <brynja_ghash_timing::timed+0x167e>
   120ef:      	movq	0x58(%rsp), %rcx
   120f4:      	movq	%rcx, 0x20(%rsp)
   120f9:      	movq	$0x10, 0x28(%rsp)
   12102:      	leaq	0x20(%rsp), %rcx
   12107:      	movq	0x28(%rsp), %rbp
   1210c:      	subq	%rbp, %r14
   1210f:      	jb	0x12132 <brynja_ghash_timing::timed+0x1722>
   12111:      	testq	%rbp, %rbp
   12114:      	je	0x1226e <brynja_ghash_timing::timed+0x185e>
   1211a:      	movq	0x20(%rsp), %rbx
   1211f:      	addq	%rbx, %rbp
   12122:      	leaq	0x3(%rsp), %r12
   12127:      	movl	$0x4, %r15d
   1212d:      	movq	%rax, %rcx
   12130:      	jmp	0x12142 <brynja_ghash_timing::timed+0x1732>
   12132:      	movb	$0x5, %cl
   12134:      	jmp	0x123ec <brynja_ghash_timing::timed+0x19dc>
   12139:      	cmpq	%rbx, %rbp
   1213c:      	je	0x1226e <brynja_ghash_timing::timed+0x185e>
   12142:      	testq	%rcx, %rcx
   12145:      	jne	0x12262 <brynja_ghash_timing::timed+0x1852>
   1214b:      	cmpq	%rbp, %rbx
   1214e:      	je	0x1226e <brynja_ghash_timing::timed+0x185e>
   12154:      	movzbl	(%rbx), %edx
   12157:      	xorb	%dl, (%rsp,%rcx)
   1215a:      	movq	%rbx, %rdx
   1215d:      	notq	%rdx
   12160:      	addq	%rbp, %rdx
   12163:      	movl	$0xf, %esi
   12168:      	subq	%rcx, %rsi
   1216b:      	cmpq	%rsi, %rdx
   1216e:      	cmovbq	%rdx, %rsi
   12172:      	incq	%rsi
   12175:      	cmpq	$0x5, %rsi
   12179:      	jae	0x12180 <brynja_ghash_timing::timed+0x1770>
   1217b:      	movq	%rbx, %rdx
   1217e:      	jmp	0x121e0 <brynja_ghash_timing::timed+0x17d0>
   12180:      	movl	%esi, %edx
   12182:      	andl	$0x3, %edx
   12185:      	cmoveq	%r15, %rdx
   12189:      	subq	%rdx, %rsi
   1218c:      	leaq	(%rbx,%rsi), %rdx
   12190:      	movq	%rax, %xmm0
   12195:      	leaq	(%r12,%rcx), %rax
   12199:      	addq	%rsi, %rcx
   1219c:      	pxor	%xmm1, %xmm1
   121a0:      	xorl	%edi, %edi
   121a2:      	pcmpeqd	%xmm2, %xmm2
   121a6:      	movzwl	0x1(%rbx,%rdi), %r8d
   121ac:      	movzwl	0x3(%rbx,%rdi), %r9d
   121b2:      	xorw	%r8w, -0x2(%rax,%rdi)
   121b8:      	xorw	%r9w, (%rax,%rdi)
   121bd:      	psubq	%xmm2, %xmm0
   121c1:      	psubq	%xmm2, %xmm1
   121c5:      	addq	$0x4, %rdi
   121c9:      	cmpq	%rdi, %rsi
   121cc:      	jne	0x121a6 <brynja_ghash_timing::timed+0x1796>
   121ce:      	paddq	%xmm0, %xmm1
   121d2:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   121d7:      	paddq	%xmm1, %xmm0
   121db:      	movq	%xmm0, %rax
   121e0:      	incq	%rax
   121e3:      	incq	%rdx
   121e6:      	movq	%rdx, %rbx
   121e9:      	cmpq	$0xf, %rcx
   121ed:      	je	0x1220a <brynja_ghash_timing::timed+0x17fa>
   121ef:      	cmpq	%rbp, %rbx
   121f2:      	je	0x1220a <brynja_ghash_timing::timed+0x17fa>
   121f4:      	movzbl	(%rbx), %edx
   121f7:      	xorb	%dl, 0x1(%rsp,%rcx)
   121fb:      	incq	%rax
   121fe:      	incq	%rbx
   12201:      	incq	%rcx
   12204:      	cmpq	$0xf, %rcx
   12208:      	jne	0x121ef <brynja_ghash_timing::timed+0x17df>
   1220a:      	movq	%rax, %rcx
   1220d:      	cmpq	$0x10, %rcx
   12211:      	jne	0x12139 <brynja_ghash_timing::timed+0x1729>
   12217:      	cmpq	$-0x1, %r13
   1221b:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   12221:      	movq	0x18(%rsp), %rax
   12226:      	movq	(%rax), %rcx
   12229:      	movq	0x8(%rax), %rdx
   1222d:      	movq	0x8(%rsp), %rdi
   12232:      	bswapq	%rdx
   12235:      	bswapq	%rcx
   12238:      	bswapq	%rdi
   1223b:      	movq	(%rsp), %rsi
   1223f:      	bswapq	%rsi
   12242:      	incq	%r13
   12245:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   1224a:      	bswapq	%rdx
   1224d:      	bswapq	%rax
   12250:      	movq	%rax, 0x8(%rsp)
   12255:      	movq	%rdx, (%rsp)
   12259:      	xorl	%eax, %eax
   1225b:      	xorl	%ecx, %ecx
   1225d:      	jmp	0x12139 <brynja_ghash_timing::timed+0x1729>
   12262:      	cmpq	$0xf, %rcx
   12266:      	jbe	0x1214b <brynja_ghash_timing::timed+0x173b>
   1226c:      	jmp	0x1220d <brynja_ghash_timing::timed+0x17fd>
   1226e:      	movq	0x58(%rsp), %rcx
   12273:      	movq	%rcx, 0x20(%rsp)
   12278:      	movq	$0x10, 0x28(%rsp)
   12281:      	leaq	0x20(%rsp), %rcx
   12286:      	movq	0x28(%rsp), %r15
   1228b:      	subq	%r15, %r14
   1228e:      	movb	$0x5, %cl
   12290:      	jb	0x123ec <brynja_ghash_timing::timed+0x19dc>
   12296:      	testq	%r15, %r15
   12299:      	je	0x12414 <brynja_ghash_timing::timed+0x1a04>
   1229f:      	movq	0x20(%rsp), %rbp
   122a4:      	addq	%rbp, %r15
   122a7:      	leaq	0x3(%rsp), %rbx
   122ac:      	movl	$0x4, %r12d
   122b2:      	movq	%rax, %rcx
   122b5:      	jmp	0x122c0 <brynja_ghash_timing::timed+0x18b0>
   122b7:      	cmpq	%rbp, %r15
   122ba:      	je	0x12414 <brynja_ghash_timing::timed+0x1a04>
   122c0:      	testq	%rcx, %rcx
   122c3:      	jne	0x123de <brynja_ghash_timing::timed+0x19ce>
   122c9:      	cmpq	%r15, %rbp
   122cc:      	je	0x12414 <brynja_ghash_timing::timed+0x1a04>
   122d2:      	movzbl	(%rbp), %edx
   122d6:      	xorb	%dl, (%rsp,%rcx)
   122d9:      	movq	%rbp, %rdx
   122dc:      	notq	%rdx
   122df:      	addq	%r15, %rdx
   122e2:      	movl	$0xf, %esi
   122e7:      	subq	%rcx, %rsi
   122ea:      	cmpq	%rsi, %rdx
   122ed:      	cmovbq	%rdx, %rsi
   122f1:      	incq	%rsi
   122f4:      	cmpq	$0x5, %rsi
   122f8:      	jae	0x122ff <brynja_ghash_timing::timed+0x18ef>
   122fa:      	movq	%rbp, %rdx
   122fd:      	jmp	0x1235f <brynja_ghash_timing::timed+0x194f>
   122ff:      	movl	%esi, %edx
   12301:      	andl	$0x3, %edx
   12304:      	cmoveq	%r12, %rdx
   12308:      	subq	%rdx, %rsi
   1230b:      	leaq	(%rsi,%rbp), %rdx
   1230f:      	movq	%rax, %xmm0
   12314:      	leaq	(%rbx,%rcx), %rax
   12318:      	addq	%rsi, %rcx
   1231b:      	pxor	%xmm1, %xmm1
   1231f:      	xorl	%edi, %edi
   12321:      	pcmpeqd	%xmm2, %xmm2
   12325:      	movzwl	0x1(%rbp,%rdi), %r8d
   1232b:      	movzwl	0x3(%rbp,%rdi), %r9d
   12331:      	xorw	%r8w, -0x2(%rax,%rdi)
   12337:      	xorw	%r9w, (%rax,%rdi)
   1233c:      	psubq	%xmm2, %xmm0
   12340:      	psubq	%xmm2, %xmm1
   12344:      	addq	$0x4, %rdi
   12348:      	cmpq	%rdi, %rsi
   1234b:      	jne	0x12325 <brynja_ghash_timing::timed+0x1915>
   1234d:      	paddq	%xmm0, %xmm1
   12351:      	pshufd	$0xee, %xmm1, %xmm0     # xmm0 = xmm1[2,3,2,3]
   12356:      	paddq	%xmm1, %xmm0
   1235a:      	movq	%xmm0, %rax
   1235f:      	incq	%rax
   12362:      	incq	%rdx
   12365:      	movq	%rdx, %rbp
   12368:      	cmpq	$0xf, %rcx
   1236c:      	je	0x1238a <brynja_ghash_timing::timed+0x197a>
   1236e:      	cmpq	%r15, %rbp
   12371:      	je	0x1238a <brynja_ghash_timing::timed+0x197a>
   12373:      	movzbl	(%rbp), %edx
   12377:      	xorb	%dl, 0x1(%rsp,%rcx)
   1237b:      	incq	%rax
   1237e:      	incq	%rbp
   12381:      	incq	%rcx
   12384:      	cmpq	$0xf, %rcx
   12388:      	jne	0x1236e <brynja_ghash_timing::timed+0x195e>
   1238a:      	movq	%rax, %rcx
   1238d:      	cmpq	$0x10, %rcx
   12391:      	jne	0x122b7 <brynja_ghash_timing::timed+0x18a7>
   12397:      	cmpq	$-0x1, %r13
   1239b:      	je	0x123ea <brynja_ghash_timing::timed+0x19da>
   1239d:      	movq	0x18(%rsp), %rax
   123a2:      	movq	(%rax), %rcx
   123a5:      	movq	0x8(%rax), %rdx
   123a9:      	movq	0x8(%rsp), %rdi
   123ae:      	bswapq	%rdx
   123b1:      	bswapq	%rcx
   123b4:      	bswapq	%rdi
   123b7:      	movq	(%rsp), %rsi
   123bb:      	bswapq	%rsi
   123be:      	incq	%r13
   123c1:      	callq	0x14a60 <brynja_crypto_cpu::ghash_pclmul::multiply>
   123c6:      	bswapq	%rdx
   123c9:      	bswapq	%rax
   123cc:      	movq	%rax, 0x8(%rsp)
   123d1:      	movq	%rdx, (%rsp)
   123d5:      	xorl	%eax, %eax
   123d7:      	xorl	%ecx, %ecx
   123d9:      	jmp	0x122b7 <brynja_ghash_timing::timed+0x18a7>
   123de:      	cmpq	$0xf, %rcx
   123e2:      	jbe	0x122c9 <brynja_ghash_timing::timed+0x18b9>
   123e8:      	jmp	0x1238d <brynja_ghash_timing::timed+0x197d>
   123ea:      	movb	$0x4, %cl
   123ec:      	movb	%cl, 0x60(%rsp)
   123f0:      	leaq	-0xa56c(%rip), %rdi     # 0x7e8b <core::unicode::unicode_data::cf::SHORT_OFFSET_RUNS+0xa4b>
   123f7:      	leaq	0x3a97a(%rip), %rcx     # 0x4cd78 <write+0x4cd78>
   123fe:      	leaq	0x3a95b(%rip), %r8      # 0x4cd60 <write+0x4cd60>
   12405:      	leaq	0x60(%rsp), %rdx
   1240a:      	movl	$0x2b, %esi
   1240f:      	callq	0x17970 <core::result::unwrap_failed>
   12414:      	movq	%rax, 0x20(%rsp)
   12419:      	movq	%r14, 0x28(%rsp)
   1241e:      	movq	0x18(%rsp), %rax
   12423:      	movq	%rax, 0x30(%rsp)
   12428:      	movq	%rsp, %rax
   1242b:      	movq	%rax, 0x38(%rsp)
   12430:      	movq	%r13, 0x40(%rsp)
   12435:      	movb	$0x2, 0x48(%rsp)
   1243a:      	leaq	0x60(%rsp), %rdi
   1243f:      	leaq	0x20(%rsp), %rsi
   12444:      	leaq	0xa0(%rsp), %rdx
   1244c:      	callq	0x149f0 <<brynja_crypto::ghash::Ghash>::finish>
   12451:      	cmpb	$0x0, 0x60(%rsp)
   12456:      	jne	0x12508 <brynja_ghash_timing::timed+0x1af8>
   1245c:      	movq	0x68(%rsp), %rdi
   12461:      	testq	%rdi, %rdi
   12464:      	movl	$0x1, %eax
   12469:      	cmovneq	%rdi, %rax
   1246d:      	movq	0x70(%rsp), %rsi
   12472:      	movq	%rsi, %rcx
   12475:      	cmoveq	%rdi, %rcx
   12479:      	movq	%rax, 0x20(%rsp)
   1247e:      	movq	%rcx, 0x28(%rsp)
   12483:      	leaq	0x20(%rsp), %rax
   12488:      	je	0x1248f <brynja_ghash_timing::timed+0x1a7f>
   1248a:      	callq	0x14930 <brynja_core::secret_memory_volatile::zeroize_region_volatile>
   1248f:      	callq	0x49040 <<std::sys::pal::unix::time::Timespec>::now>
   12494:      	movq	%rax, 0x88(%rsp)
   1249c:      	movl	%edx, 0x90(%rsp)
   124a3:      	movq	0x98(%rsp), %rax
   124ab:      	movq	%rax, 0x60(%rsp)
   124b0:      	movl	0x84(%rsp), %eax
   124b7:      	movl	%eax, 0x68(%rsp)
   124bb:      	leaq	0x20(%rsp), %rdi
   124c0:      	leaq	0x88(%rsp), %rsi
   124c8:      	leaq	0x60(%rsp), %rdx
   124cd:      	callq	0x48f80 <<std::sys::pal::unix::time::Timespec>::sub_timespec>
   124d2:      	movl	$0x3b9aca00, %eax       # imm = 0x3B9ACA00
   124d7:      	mulq	0x28(%rsp)
   124dc:      	movl	0x30(%rsp), %ecx
   124e0:      	addq	%rcx, %rax
   124e3:      	adcq	$0x0, %rdx
   124e7:      	xorl	%ecx, %ecx
   124e9:      	cmpb	$0x0, 0x20(%rsp)
   124ee:      	cmovneq	%rcx, %rax
   124f2:      	cmovneq	%rcx, %rdx
   124f6:      	addq	$0xb8, %rsp
   124fd:      	popq	%rbx
   124fe:      	popq	%r12
   12500:      	popq	%r13
   12502:      	popq	%r14
   12504:      	popq	%r15
   12506:      	popq	%rbp
   12507:      	retq
   12508:      	movzbl	0x61(%rsp), %eax
   1250d:      	movb	%al, 0x20(%rsp)
   12511:      	leaq	-0xa68d(%rip), %rdi     # 0x7e8b <core::unicode::unicode_data::cf::SHORT_OFFSET_RUNS+0xa4b>
   12518:      	leaq	0x3a859(%rip), %rcx     # 0x4cd78 <write+0x4cd78>
   1251f:      	leaq	0x3a822(%rip), %r8      # 0x4cd48 <write+0x4cd48>
   12526:      	leaq	0x20(%rsp), %rdx
   1252b:      	movl	$0x2b, %esi
   12530:      	callq	0x17970 <core::result::unwrap_failed>
   12535:      	int3
   12536:      	int3
   12537:      	int3
   12538:      	int3
   12539:      	int3
   1253a:      	int3
   1253b:      	int3
   1253c:      	int3
   1253d:      	int3
   1253e:      	int3
   1253f:      	int3
0000000000014a60 <brynja_crypto_cpu::ghash_pclmul::multiply>:
   14a60:      	pushq	%r14
   14a62:      	pushq	%rbx
   14a63:      	bswapq	%rsi
   14a66:      	movq	%rsi, %rax
   14a69:      	shrq	$0x4, %rax
   14a6d:      	movabsq	$0xf0f0f0f0f0f0f0f, %r9 # imm = 0xF0F0F0F0F0F0F0F
   14a77:      	andq	%r9, %rax
   14a7a:      	andq	%r9, %rsi
   14a7d:      	shlq	$0x4, %rsi
   14a81:      	orq	%rax, %rsi
   14a84:      	movabsq	$0x3333333333333333, %r8 # imm = 0x3333333333333333
   14a8e:      	movq	%rsi, %rax
   14a91:      	andq	%r8, %rax
   14a94:      	shrq	$0x2, %rsi
   14a98:      	andq	%r8, %rsi
   14a9b:      	leaq	(%rsi,%rax,4), %rax
   14a9f:      	movabsq	$0x5555555555555555, %rsi # imm = 0x5555555555555555
   14aa9:      	movq	%rax, %r10
   14aac:      	andq	%rsi, %r10
   14aaf:      	shrq	%rax
   14ab2:      	andq	%rsi, %rax
   14ab5:      	leaq	(%rax,%r10,2), %rax
   14ab9:      	bswapq	%rdi
   14abc:      	movq	%rdi, %r10
   14abf:      	shrq	$0x4, %r10
   14ac3:      	andq	%r9, %r10
   14ac6:      	andq	%r9, %rdi
   14ac9:      	shlq	$0x4, %rdi
   14acd:      	orq	%r10, %rdi
   14ad0:      	movq	%rdi, %r10
   14ad3:      	andq	%r8, %r10
   14ad6:      	shrq	$0x2, %rdi
   14ada:      	andq	%r8, %rdi
   14add:      	leaq	(%rdi,%r10,4), %rdi
   14ae1:      	movq	%rdi, %r10
   14ae4:      	andq	%rsi, %r10
   14ae7:      	shrq	%rdi
   14aea:      	andq	%rsi, %rdi
   14aed:      	leaq	(%rdi,%r10,2), %rdi
   14af1:      	movq	%rdi, %xmm2
   14af6:      	movq	%rax, %xmm1
   14afb:      	movdqa	%xmm1, %xmm0
   14aff:      	bswapq	%rcx
   14b02:      	punpcklqdq	%xmm2, %xmm0    # xmm0 = xmm0[0],xmm2[0]
   14b06:      	movq	%rcx, %rax
   14b09:      	shrq	$0x4, %rax
   14b0d:      	andq	%r9, %rax
   14b10:      	andq	%r9, %rcx
   14b13:      	shlq	$0x4, %rcx
   14b17:      	orq	%rax, %rcx
   14b1a:      	movq	%rcx, %rax
   14b1d:      	andq	%r8, %rax
   14b20:      	shrq	$0x2, %rcx
   14b24:      	andq	%r8, %rcx
   14b27:      	leaq	(%rcx,%rax,4), %rax
   14b2b:      	movq	%rax, %rcx
   14b2e:      	andq	%rsi, %rcx
   14b31:      	shrq	%rax
   14b34:      	andq	%rsi, %rax
   14b37:      	leaq	(%rax,%rcx,2), %rax
   14b3b:      	bswapq	%rdx
   14b3e:      	movq	%rdx, %rcx
   14b41:      	shrq	$0x4, %rcx
   14b45:      	andq	%r9, %rcx
   14b48:      	andq	%r9, %rdx
   14b4b:      	shlq	$0x4, %rdx
   14b4f:      	orq	%rcx, %rdx
   14b52:      	movq	%rdx, %rcx
   14b55:      	andq	%r8, %rcx
   14b58:      	shrq	$0x2, %rdx
   14b5c:      	andq	%r8, %rdx
   14b5f:      	leaq	(%rdx,%rcx,4), %rcx
   14b63:      	movq	%rcx, %rdx
   14b66:      	andq	%rsi, %rdx
   14b69:      	shrq	%rcx
   14b6c:      	andq	%rsi, %rcx
   14b6f:      	leaq	(%rcx,%rdx,2), %rcx
   14b73:      	movq	%rcx, %xmm2
   14b78:      	movq	%rax, %xmm3
   14b7d:      	movdqa	%xmm1, %xmm4
   14b81:      	pclmulqdq	$0x0, %xmm3, %xmm4
   14b87:      	movdqa	%xmm0, %xmm5
   14b8b:      	pclmulqdq	$0x1, %xmm3, %xmm0
   14b91:      	punpcklqdq	%xmm2, %xmm3    # xmm3 = xmm3[0],xmm2[0]
   14b95:      	pclmulqdq	$0x11, %xmm3, %xmm5
   14b9b:      	pclmulqdq	$0x1, %xmm1, %xmm3
   14ba1:      	pxor	%xmm0, %xmm3
   14ba5:      	movq	%xmm4, %rax
   14baa:      	pshufd	$0xee, %xmm4, %xmm0     # xmm0 = xmm4[2,3,2,3]
   14baf:      	movq	%xmm0, %rcx
   14bb4:      	pshufd	$0xee, %xmm5, %xmm0     # xmm0 = xmm5[2,3,2,3]
   14bb9:      	movq	%xmm0, %rdi
   14bbe:      	movq	%xmm5, %rdx
   14bc3:      	movq	%xmm3, %r11
   14bc8:      	xorq	%rcx, %r11
   14bcb:      	pshufd	$0xee, %xmm3, %xmm0     # xmm0 = xmm3[2,3,2,3]
   14bd0:      	movq	%xmm0, %rcx
   14bd5:      	xorq	%rdx, %rcx
   14bd8:      	movq	%rdi, %rbx
   14bdb:      	shldq	$0x1, %rcx, %rbx
   14be0:      	movq	%rdi, %r10
   14be3:      	movq	%rdi, %r14
   14be6:      	shldq	$0x2, %rcx, %r14
   14beb:      	xorq	%r11, %rbx
   14bee:      	movq	%rdi, %rdx
   14bf1:      	shldq	$0x7, %rcx, %rdx
   14bf6:      	movq	%rdi, %r11
   14bf9:      	xorq	%r14, %rdx
   14bfc:      	xorq	%rbx, %rdx
   14bff:      	xorq	%rdi, %rdx
   14c02:      	shrq	$0x3f, %rdi
   14c06:      	shrq	$0x3e, %r10
   14c0a:      	xorq	%rdi, %r10
   14c0d:      	shrq	$0x39, %r11
   14c11:      	xorq	%r10, %r11
   14c14:      	leaq	(%rcx,%rcx), %rdi
   14c18:      	leaq	(,%rcx,4), %r10
   14c20:      	xorq	%rdi, %r10
   14c23:      	movq	%rcx, %rdi
   14c26:      	shlq	$0x7, %rdi
   14c2a:      	xorq	%r10, %rdi
   14c2d:      	leal	(%r11,%r11), %r10d
   14c31:      	xorq	%rax, %r10
   14c34:      	leal	(,%r11,4), %eax
   14c3c:      	xorq	%r11, %rdi
   14c3f:      	shll	$0x7, %r11d
   14c43:      	xorq	%rax, %r11
   14c46:      	xorq	%r10, %r11
   14c49:      	xorq	%r11, %rdi
   14c4c:      	xorq	%rcx, %rdi
   14c4f:      	bswapq	%rdx
   14c52:      	movq	%rdx, %rax
   14c55:      	shrq	$0x4, %rax
   14c59:      	andq	%r9, %rax
   14c5c:      	andq	%r9, %rdx
   14c5f:      	shlq	$0x4, %rdx
   14c63:      	orq	%rax, %rdx
   14c66:      	movq	%rdx, %rax
   14c69:      	andq	%r8, %rax
   14c6c:      	shrq	$0x2, %rdx
   14c70:      	andq	%r8, %rdx
   14c73:      	leaq	(%rdx,%rax,4), %rax
   14c77:      	movq	%rax, %rcx
   14c7a:      	andq	%rsi, %rcx
   14c7d:      	shrq	%rax
   14c80:      	andq	%rsi, %rax
   14c83:      	leaq	(%rax,%rcx,2), %rax
   14c87:      	bswapq	%rdi
   14c8a:      	movq	%rdi, %rcx
   14c8d:      	shrq	$0x4, %rcx
   14c91:      	andq	%r9, %rcx
   14c94:      	andq	%r9, %rdi
   14c97:      	shlq	$0x4, %rdi
   14c9b:      	orq	%rcx, %rdi
   14c9e:      	movq	%rdi, %rcx
   14ca1:      	andq	%r8, %rcx
   14ca4:      	shrq	$0x2, %rdi
   14ca8:      	andq	%r8, %rdi
   14cab:      	leaq	(%rdi,%rcx,4), %rcx
   14caf:      	movq	%rcx, %rdx
   14cb2:      	andq	%rsi, %rdx
   14cb5:      	shrq	%rcx
   14cb8:      	andq	%rsi, %rcx
   14cbb:      	leaq	(%rcx,%rdx,2), %rdx
   14cbf:      	popq	%rbx
   14cc0:      	popq	%r14
   14cc2:      	retq
   14cc3:      	int3
