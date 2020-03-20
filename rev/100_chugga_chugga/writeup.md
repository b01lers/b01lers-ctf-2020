# RE 100 - chugga 

| Author | novafacing |
| --- | --- |
| Point Value | 100 |
| Description | Simple input checker with constraint solve |

A couple things up front:

1. I solved this completely using gdb and z3, but you should note that I use the gef (https://github.com/hugsy/gef) extension for gdb to make things look nice.

2. My gdbinit looks like this in order to support Go debugging (if you don't do this, you'll have a bad time :):

```
	set disassembly-flavor intel
	#source /usr/share/pwndbg/gdbinit.py
	#source /usr/share/peda/peda.py
	source /usr/share/gef/gef.py
	add-auto-load-safe-path /usr/lib/go/src/runtime/runtime-gdb.py # This last line is the important bit for Go
```


3. This isn't the only way to solve this challenge! As with most things there are a lot of ways you could go about this, this is just the ah "intended solution".

This is a reasonably easy constraint solving problem, with the only real catch being that it's written in Go. This doesn't change the way it works, though, so we can figure out what we need by disassembling first.

So, yeah. This is a 100 point challenge but Go is gross to disassemble if you aren't used to it. You get a lot of stuff like this:

```
gef> info function
...
File /usr/lib/go/src/runtime/mcache.go:
        void runtime.(*mcache).prepareForSweep;
        void runtime.(*mcache).refill;
        void runtime.(*mcache).releaseAll;
        void runtime.allocmcache(runtime.mcache *);
        void runtime.allocmcache.func1(void);
        void runtime.freemcache(runtime.mcache *);
        void runtime.freemcache.func1(void);
...
```

That's because Go has a runtime that enables all its nice features unlike, say, something like Java that runs on a virtual machine that has all this stuff inside it, Go just shoves it all into your program. Neat!

The side effect for us hackers is that it makes it a little harder to find stuff though, so let's look for main.main, the "real" main function of this program:

```
File /[REDACTED]/100_chugga_chugga/chugga.go:
        void main.main(void);
        void main.win(void);

```

Luckily we don't have to scroll through all the library and runtime stuff, we can just focus on the two functions actually defined by yours truly.

```
gef> disas main.win
   0x00000000004995e0 <+0>:     mov    rcx,QWORD PTR fs:0xfffffffffffffff8
   0x00000000004995e9 <+9>:     cmp    rsp,QWORD PTR [rcx+0x10]
   0x00000000004995ed <+13>:    jbe    0x49966c <main.win+140>
   0x00000000004995ef <+15>:    sub    rsp,0x58
   0x00000000004995f3 <+19>:    mov    QWORD PTR [rsp+0x50],rbp
   0x00000000004995f8 <+24>:    lea    rbp,[rsp+0x50]
   0x00000000004995fd <+29>:    xorps  xmm0,xmm0
   0x0000000000499600 <+32>:    movups XMMWORD PTR [rsp+0x40],xmm0
   0x0000000000499605 <+37>:    lea    rax,[rip+0x12434]        # 0x4aba40
   0x000000000049960c <+44>:    mov    QWORD PTR [rsp+0x40],rax
   0x0000000000499611 <+49>:    lea    rax,[rip+0x4fdb8]        # 0x4e93d0
   0x0000000000499618 <+56>:    mov    QWORD PTR [rsp+0x48],rax
   0x000000000049961d <+61>:    mov    rax,QWORD PTR [rip+0xdbecc]        # 0x5754f0 <os.Stdout>
   0x0000000000499624 <+68>:    lea    rcx,[rip+0x51615]        # 0x4eac40 <go.itab.*os.File,io.Writer>
   0x000000000049962b <+75>:    mov    QWORD PTR [rsp],rcx
   0x000000000049962f <+79>:    mov    QWORD PTR [rsp+0x8],rax
   0x0000000000499634 <+84>:    lea    rax,[rsp+0x40]
   0x0000000000499639 <+89>:    mov    QWORD PTR [rsp+0x10],rax
   0x000000000049963e <+94>:    mov    QWORD PTR [rsp+0x18],0x1
   0x0000000000499647 <+103>:   mov    QWORD PTR [rsp+0x20],0x1
   0x0000000000499650 <+112>:   call   0x48d450 <fmt.Fprintln>
   0x0000000000499655 <+117>:   mov    QWORD PTR [rsp],0x1
   0x000000000049965d <+125>:   call   0x489ff0 <os.Exit>
   0x0000000000499662 <+130>:   mov    rbp,QWORD PTR [rsp+0x50]
   0x0000000000499667 <+135>:   add    rsp,0x58
   0x000000000049966b <+139>:   ret
   0x000000000049966c <+140>:   call   0x4518e0 <runtime.morestack_noctxt>
   0x0000000000499671 <+145>:   jmp    0x4995e0 <main.win>
```

The important bits are the call to fmt.Println() and os.Exit().

Since this function is called win and it prints something and exits we can *probably* assume this is gonna get called when we correctly meet whatever the requirements for the challenge are. So, let's look at that shall we?

```
gef> disas main.main
...
   0x0000000000499a2f <+943>:   jne    0x499833 <main.main+435>
   0x0000000000499a35 <+949>:   shl    ebx,0x2
   0x0000000000499a38 <+952>:   cmp    sil,bl
   0x0000000000499a3b <+955>:   jne    0x499833 <main.main+435>
   0x0000000000499a41 <+961>:   cmp    r14b,r8b
   0x0000000000499a44 <+964>:   jne    0x499833 <main.main+435>
   0x0000000000499a4a <+970>:   call   0x4995e0 <main.win>
...
```

So we have a lot of code, after which main.win is called. If we take a look at the preceeding code, we see that it follows a pretty simple pattern, do something, check comparison, jump. As usual in CTF if we have a bunch of comparisons that only after meeting all the conditions we get a win, we're almost definitely looking at constraints on the input. Even more confirmation is the fact that every single comparison jumps to <main.main+435> if it fails. +435 is the block:

```
   0x0000000000499833 <+435>:   nop
   0x0000000000499834 <+436>:   xorps  xmm0,xmm0
   0x0000000000499837 <+439>:   movups XMMWORD PTR [rsp+0x50],xmm0
   0x000000000049983c <+444>:   lea    rax,[rip+0x121fd]        # 0x4aba40
   0x0000000000499843 <+451>:   mov    QWORD PTR [rsp+0x50],rax
   0x0000000000499848 <+456>:   lea    rcx,[rip+0x4fbb1]        # 0x4e9400
   0x000000000049984f <+463>:   mov    QWORD PTR [rsp+0x58],rcx
   0x0000000000499854 <+468>:   mov    rdx,QWORD PTR [rip+0xdbc95]        # 0x5754f0 <os.Stdout>
   0x000000000049985b <+475>:   lea    rbx,[rip+0x513de]        # 0x4eac40 <go.itab.*os.File,io.Writer>
   0x0000000000499862 <+482>:   mov    QWORD PTR [rsp],rbx
   0x0000000000499866 <+486>:   mov    QWORD PTR [rsp+0x8],rdx
   0x000000000049986b <+491>:   lea    rdx,[rsp+0x50]
   0x0000000000499870 <+496>:   mov    QWORD PTR [rsp+0x10],rdx
   0x0000000000499875 <+501>:   mov    QWORD PTR [rsp+0x18],0x1
   0x000000000049987e <+510>:   mov    QWORD PTR [rsp+0x20],0x1
   0x0000000000499887 <+519>:   call   0x48d450 <fmt.Fprintln>
   0x000000000049988c <+524>:   mov    rax,QWORD PTR [rsp+0x40]
   0x0000000000499891 <+529>:   inc    rax
   0x0000000000499894 <+532>:   jmp    0x4996cd <main.main+77>
```

Basically: print something, increment a counter, and loop back to near the beginning of main. We can see this in action if we run the program:

```
	We're in train car:  0
	The door is locked, but luckily, you're the conductor! Input your code:
	6969420
	Boom! You are dead. You come back to life in the next car.
	We're in train car:  1
	The door is locked, but luckily, you're the conductor! Input your code:
	6969420
	Boom! You are dead. You come back to life in the next car.
	We're in train car:  2
	The door is locked, but luckily, you're the conductor! Input your code:
	6969420
	Boom! You are dead. You come back to life in the next car.
	We're in train car:  3
	The door is locked, but luckily, you're the conductor! Input your code:
```


So nice, we know what we need to do somewhat! Let's figure out how to do that. If we break the disassembly down into sections we can get a list of conditions. I'm not going to go *too* much into each one because there are a lot, and I've left out a couple places where you'll need to either make a breakpoint and print a variable or go hunt it down yourself somewhere other than the small basic block, but I'll put each basic block and the equivalent Golang code below:

```
movzx   ebx, byte [rdx+0x2]
cmp     bl, 0x74
je      0x499899

```
buf[0x2] == 't'

```
movzx   esi, byte [rdx+0x9]
cmp     sil, 0x63
jne     0x499833
```
buf[0x9] == 'c'

```
movzx   edi, byte [rdx+0x10]
cmp     dil, 0x6e
jne     0x499833
```
buf[0x10] == 'n'

```
movzx   r8d, byte [rdx+0x15]
cmp     r8b, 0x7a
jne     0x499833
```
buf[0x15] == 'z'

```
movzx   ecx, byte [rdx+0x16]
cmp     cl, 0x7d
jne     0x499833
```
buf[0x16] == 'z'

```
movzx   r9d, byte [rdx+0x5]
lea     r10d, [rbx-0x1]
cmp     r10b, r9b
jne     0x499833
```
buf[0x5] == buf[0x2] - 0x1


```
movzx   r10d, byte [rdx+0x3]
xor     r10d, ebx
cmp     r10b, 0x12
jne     0x499833
```
buf[0x2] ^ buf[0x3] == 0x12

```
movzx   ebx, byte [rdx+0x1]
cmp     bl, sil
jne     0x499833
```
buf[0x1] == buf[0x9]

```
movzx   esi, byte [rdx+0x7]
lea     r10d, [rsi-0x1]
cmp     r10b, bl
jne     0x499833
```
buf[0x1] == buf[0x7] - 1

```
movzx   r10d, byte [rdx+0xd]
cmp     byte [rdx+0xc], r10b
jne     0x499833
```
buf[0xc] == buf[0xd]

```
movzx   r11d, byte [rdx+0x13]
xor     r11d, r8d
test    r11b, r11b
jne     0x499833
```
buf[0x13] ^ buf[0x15] == 0

```
movzx   r8d, byte [rdx+0xe]
movzx   r11d, byte [rdx+0x6]
lea     r12d, [r11+r8]
cmp     r12b, 0x68
jne     0x499833
```
buf[0xe] - 0x30 + buf[0x6] - 0x30 == 0x8 (This can be simplified but I'm lazy so whatever)

```
movzx   r12d, byte [rdx+0x4]
lea     r13d, [rcx-0x2]
cmp     r13b, r12b
jne     0x499833
```
buf[0x4] == buf[0x16] - 2

```
movzx   r13d, byte [rdx+0x8]
cmp     byte [rdx+0xf], r13b
jne     0x499833
```
buf[0x8] == buf[0xf]

```
add     r13d, 0x4
cmp     r13b, bl
jne     0x499833
```
buf[0x8] + 0x4 == buf[0x1]

```
movzx   r13d, byte [rdx+0x11]
sub     ecx, r13d
movzx   r14d, byte [rdx+0xb]
add     ecx, 0x28
cmp     cl, r14b
jne     0x499833
```
buf[0x16] - buf[0x11] + 0x28 == buf[11]

```
sub     r14d, r9d
movzx   ecx, byte [rdx+0x12]
sub     r14d, ecx
add     r14d, r13d
sub     ecx, r13d
cmp     r14b, cl
jne     0x499833
```
buf[0xb] - buf[0x5] - buf[0x12] + buf[0x11] == buf[12] - buf[11]

```
mov     r14d, r11d
sub     r11d, r13d
mov     r13d, r11d
shr     r11b, 0x1
imul    r11d, ecx
add     r11d, edi
cmp     byte [rdx], r11b
jne     0x499833
```
buf[0x0] == buf[0x10] + ((buf[0x12] - buf[0x11]) * ((buf[0x6] - buf[0x11]) / 2))
(The divide by 2 here is compiler optimized to >> 0x1 but that's a pretty common paradigm)

```
movzx   r11d, byte [rdx+0xa]
inc     r10d
cmp     r10b, r11b
jne     0x499833
```
buf[0xa] == buf[0xd] + 0x1

```
sub     r12d, esi
mov     esi, r13d
shl     r13d, 0x1
lea     r10d, [r13+r12*4]
add     r10d, esi
cmp     r10b, r11b
jne     0x499833
```
Yeah, yeah, don't throw your tomatoes at me I know this one's annoying.
buf[0xa] == (((buf[0x4] - buf[0x7]) * 0x4) + (0x2 * (buf[0x6] - buf[0x11]))) + ((buf[0x6] - buf[0x11]))
(Again, we have a shift instead of 2*n)

```
movzx   edx, byte [rdx+0x14]
sub     edx, ebx
mov     ebx, ecx
shl     ecx, 0x1
cmp     dl, cl
jne     0x499833
```
(buf[0x12] - buf[0x11]) * 2 == buf[0x14] - buf[0x1]

```
xor     r9d, edi
cmp     r9b, 0x1d
jne     0x499833
```
buf[0x5] ^ buf[0x10] == 29

```
shl     ebx, 0x2
cmp     sil, bl
jne     0x499833
```
buf[0x6] - buf[0x11] == (buf[0x12] - buf[0x11]) * 4

```
cmp     r14b, r8b
jne     0x499833
```
buf[0x6] == buf[0xe]

That's it! Finally! My hands hurt from copy and pasting stuff.

So now that we have all the equations how do we solve this quickly and painlessly? One way is with z3, a theorem proving tool from Microsoft. I'll just put my commented script below instead of going into painful detail:

```
import z3

# Create a solver object
s = z3.Solver()

# Create 8-bit bitvectors for each of the 21 chars in the string. There's actually no check on this in the program but the last one is given and it's a '}' so I'm gonna go ahead and hope people take the hint.
chrlist = z3.BitVecs('c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12 c13 c14 c15 c16 c17 c18 c19 c20 c21 c22', 8)

# Do a preliminary constraint that all characters must be printable ascii. This isn't super intensive but for harder challenges this could be a reasonable and cheap speedup.
for char in chrlist:
    s.add(z3.And(0x20 < char, char < 0x7f))

# This is the function that'll check each possible solution to see if it satisfies the constraints and return the solution
def get_models(s):
	# While the current solution satisfies:
    while s.check() == z3.sat:
		# Get the current solution
        m = s.model()
		# Yield it (this is a generator for ez)
        yield m
		# Get the next possibility
        s.add(z3.Or([sym() != m[sym] for sym in m.decls()]))


# add constraints from program:
# given values
s.add(chrlist[2] == ord('t'))
s.add(chrlist[9] == ord('c'))
s.add(chrlist[16] == ord('n'))
s.add(chrlist[21] == ord('z'))
s.add(chrlist[22] == ord('}'))

# equalities
s.add(chrlist[5] == chrlist[2] - 1)
s.add(chrlist[2] ^ chrlist[3] == 18)
s.add(chrlist[1] == chrlist[9])
s.add(chrlist[1] == chrlist[7] - 1)
s.add(chrlist[12] == chrlist[13])
s.add(chrlist[19] ^ chrlist[21] == 0)
s.add(chrlist[14] - ord('0') + chrlist[6] - ord('0') == 8)
#
s.add(chrlist[4] == chrlist[22] - 2)
s.add(chrlist[8] == chrlist[15])
s.add(chrlist[8] + 4 == chrlist[1])
s.add(chrlist[22] - chrlist[17] + 40 == chrlist[11])
s.add(chrlist[11] - chrlist[5] - chrlist[18] + chrlist[17] == chrlist[18] - chrlist[17])
s.add(chrlist[0] == chrlist[16] + ((chrlist[18] - chrlist[17]) * ((chrlist[6] - chrlist[17])  / 2)))
s.add(chrlist[10] == chrlist[13] + 1)
s.add(chrlist[10] == (((chrlist[4] - chrlist[7]) * 4) + (2 * (chrlist[6] - chrlist[17]))) + ((chrlist[6] - chrlist[17])))
s.add(2 * (chrlist[18] - chrlist[17]) == chrlist[20] - chrlist[1])
s.add(chrlist[5] ^ chrlist[16] == 29)
s.add(chrlist[6] - chrlist[17] == (chrlist[18] - chrlist[17]) * 4)
s.add(chrlist[6] == chrlist[14])

# Once we've added all the constraints, we check all our solutions
for m in get_models(s):
    print("".join([chr(m[char].as_long()) for char in chrlist]))
```

Run that and it spits out the answer!
```
python solve.py
pctf{s4d_chugg4_n01zez}
```

-novafacing




