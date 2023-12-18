start:
	mov	r8, 1
L1:
	cmp	r8, rsi
	jge	L2
	mov	r10, [rdi+r8*8]
	mov	rax, r8
	sub	rax, 1
	mov	r9, rax
L4:
	cmp	r9, 0
	jl	L3	
	cmp	[rdi+r9*8], r10
	jle	L3
	mov	r11, [rdi+r9*8]
	mov	[rdi+r9*8+8], r11
	sub	r9, 1	
	jmp	L4		
L3:
	mov	[rdi+r9*8+8], r10
	inc	r8
	jmp	L1
L2:

	mov	rax, 60
	xor	rdi, rdi
	syscall
