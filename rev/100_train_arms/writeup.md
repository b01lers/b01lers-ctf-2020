# Train ARMS

```asm
.cpu cortex-m0
.thumb
.syntax unified
.fpu softvfp


.data 
    flag: .string "REDACTED" //len = 28

.text
.global main
main:
    ldr r0,=flag
    eors r1,r1
    eors r2,r2
    movs r7,#1
    movs r6,#42
loop:
    ldrb r2,[r0,r1]
    cmp r2,#0
    beq exit
    lsls r3,r1,#0
    ands r3,r7
    cmp r3,#0
    bne f1//if odd
    strb r2,[r0,r1]
    adds r1,#1
    b loop
f1:
    eors r2,r6
    strb r2,[r0,r1]
    adds r1,#1
    b loop

exit:
    wfi
```

# Breakdown of program
From the main to loop label we are loading the address of the flag from the .data section into the r0 register. The registers being eors (xor) with themselves are being 0'd and then I'm moving constants into r7 and r6. Within the loop label section we are loading one byte which is one character at a time and then checking if it is '\x00' if not we compare the index if odd we xor the character with 42 and store otherwise we keep the same character.

To solve this you can use the given string in result and at every odd indice xor with 42 to retrieve the flag back. If that's not clear check my solve.py file to confirm your understanding.


