.section .data
str_ptrfmt: .asciz "%lx\n"

.intel_syntax noprefix
.section .text


.global init_shadow
.global populate_shadow
.global test_shadow
init_shadow:
	mov r11, rdi # pseudostack
	mov r10, rsi # argv[2]

	mov DWORD PTR [r11], 0x0
	mov DWORD PTR [r11 + 0x8], 0x0
	mov DWORD PTR [r11 + 0x10], 0x0
	mov r9b, [r10]
	mov [r11 + 0x18], r9b
	xor rdi, rdi
	xor rsi, rsi
	mov dil, [r10]
	mov rsi, 0x1
	
	call hash

	mov [r11 + 0x20], rax
	movq [r11 + 0x18], 0x69696969
	ret

populate_shadow:
	mov r11, rdi # store the root node in r11

	mov r10, 0x1 # store the counter in r10
	xor r9, r9
	mov r9b, [rsi+r10] # store the current character in r9b

	mov r8, rdi
	add r8, 0x28 # store pointer to the new node location in r8

create_nodes:
	cmpb r9b, 0x0
	je create_nodes_finish # if we've created all the nodes
	# if we have NOT created all the nodes
	mov [r8 + 0x18], r9

	push rsi
	push rdi
	xor rdi, rdi
	xor rsi, rsi
	mov dil, r9b
	mov rsi, r10

	call hash

	mov [r8 + 0x20], rax
	movq [r8 + 0x18], 0x69696969

	mov rsi, r8 # pass current node in rsi
	mov rdi, r11 # pass root node in rdi
	call add_node
	pop rdi
	pop rsi

	add r10, 0x1
	xor r9, r9
	mov r9b, [rsi+r10]

	add r8, 0x28 # advance to the next node
	jmp create_nodes

create_nodes_finish:
	ret
	
add_node:
	mov rcx, [rdi + 0x20] # pointer to root hash
	mov rbx, [rsi + 0x20] # pointer to node hash
	rol rcx, 0x20
	rol rbx, 0x20
	cmp rcx, rbx
	jl left
	jg right
	mov rdi, 0
	call exit
left:
	cmpq [rdi + 0x8], 0x0 # check if root left is null
	jne prep_add_left
	mov [rsi], rdi
	mov [rdi + 0x8], rsi
	ret
prep_add_left:
	mov rdi, [rdi + 0x8]
	mov rsi, rsi
	jmp add_node
right:
	cmpq [rdi + 0x10], 0x0 # check if root right is null
	jne prep_add_right
	mov [rsi], rdi
	mov [rdi + 0x10], rsi
	ret
prep_add_right:
	mov rdi, [rdi + 0x10]
	mov rsi, rsi
	jmp add_node

test_shadow:
	mov r11, rdi # grab the pseudostack
	
