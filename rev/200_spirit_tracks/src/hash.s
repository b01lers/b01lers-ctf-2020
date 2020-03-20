.intel_syntax noprefix
.section .text

// hash(char c, index idx);
.global hash
hash:
	push r10
	push r9
	push r8
	// Push a constant val
	pushq 0x002493ca
	popq rbx 		
	mov r10, rsi
	pushq r10 		
	popq rcx 		
	mov r9, 0x0 	
	or r9, rcx 		
	mov r8, 0x0 	
fill:
	shl rcx, 0x8 	
	or r9, rcx 		
	add r8, 0x1 	
	cmp r8, 0x3 	
	jle fill 	
	mov rcx, r9 	
	xor rbx, rcx 	
	xorps xmm2, xmm2
	movq xmm2, rcx	
	movq xmm3, rcx 	
	xor r8, r8 		
xmmfill:
	pslldq xmm3, 0x10
	orps xmm2, xmm3
	add r8, 0x1 
	cmp r8, 0x8 
	jle xmmfill
	mov r10, rdi
	pushq r10 
	popq rax 
	shl rax, 0x18 
	movq xmm1, rax
	xor r8, r8 
aes:
	aesenc xmm1, xmm2 
	add r8, 0x1 	
	cmp r8, 0x20 	
	jle aes
	movq rcx, xmm1
	psrldq xmm1, 0x40 
	movq rbx, xmm1 
	xor rcx, rbx 
	mov rax, rcx
	pop r8
	pop r9
	pop r10
	ret
