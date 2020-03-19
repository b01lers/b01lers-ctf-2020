# Rev 200 - Spirit Tracks 

| Author | novafacing |
| --- | --- |
| Point Value | 200 |
| Description | Hashmap input transformation and tree data structure input checker |

So we're finally moving up in the world! This challenge is significantly more involved than the 100-point reversing challenges but is still very doable. To make sure the code didn't get too arcane, I hand-wrote most of this challenge in assembly. You're welcome ;)

Anyway, now that we're looking at some more involved stuff, having a decompiler will come in handy. I'm using Ghidra for this, but R2/Angr/Ghidra/IDA should all do fine. It's also totally doable without one, but efficiency is efficiency.

So when we run the program, if we just give no inputs we get a usage message:

```
> ./spirit_tracks      
Well you gotta give me something!
Usage: ./spirit_tracks <input>
```

So we give it an input:
```
> ./spirit_tracks hello
Welcome to Zoulda's Spirit Train Station! We've taken your ticket (id: hello)
 and we'll board you shortly! But first, here's a map. Use it go get to the platform!
zsh: segmentation fault (core dumped)  ./spirit_tracks hello
```

Whoops. First order of business is to figure out why that's happening. Let's look at the disassembly/decomp of main. Keep in mind that I'll be putting this below with my own annotated variable names, YMMV as far as what your disassembler gives you in terms of types/names.

```
int FUN_00400977:
  if (argc < 2) {
    puts("Well you gotta give me something!");
    puts("Usage: ./spirit_tracks <input>");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf(
         "Welcome to Zoulda\'s Spirit Train Station! We\'ve taken your ticket (id: %s)\n and we\'llboard you shortly! But first, here\'s a map. Use it go get to the platform!\n"
         ,argv[1]);
  input_0 = argv[1];
```

None of this looks particularly suspicious, a check for argc size gives us the usage message from earlier, and we're printing out argv[1] as we saw. The next bit makes it pretty easy to see our segfault:

```
  do_something_a(memory_block,argv[2],argv[2]);
  do_something_b(memory_block,argv[2],argv[2])
```

Aha! We've got the code using argv[2] even though it doesn't really make that clear. Fair enough, lets try running with two arguments:

```
./spirit_tracks hello hello
Welcome to Zoulda's Spirit Train Station! We've taken your ticket (id: hello)
 and we'll board you shortly! But first, here's a map. Use it go get to the platform!
Oh no! our map broke...I'll try to get it working, sit tight!
```

The program hangs (but doesn't segfault this time!), we're making progress. If we keep looking we can see why it's hanging. Our symbol tree includes `sleep()`, so if we look at xrefs to that function we can see that we're calling sleep in a function:

```
void FUN_00400829 :
  puts("Oh no! our map broke...I\'ll try to get it working, sit tight!");
  sleep((uint)*(undefined8 *)(param_1 + 0x20));
  ...
```

Okay so the author is just being a dirtbag (sorry!), just gotta patch that line out real quick Ghidra is garbage for patching so I'm going to do it using r2. Just open the binary like so:

`r2 -w ./spirit_tracks`
```
> v # Go to visual Mode
> c # View the cursor
> # Use the H/J/K/L keys to go the the address of the bytes we need to patch (in this case we want to convert e830feffff to 9090909090) and press i to enter insert mode and patch the bytes
> q
```

Now reopen the binary in ghidra. We can run it now too, if we run with the "hello hello" we used earlier we get:

```
/spirit_tracks_patched hello hello
Welcome to Zoulda's Spirit Train Station! We've taken your ticket (id: hello)
 and we'll board you shortly! But first, here's a map. Use it go get to the platform!
Oh no! our map broke...I'll try to get it working, sit tight!
Oh no! our map broke...I'll try to get it working, sit tight!
Oh no! our map broke...I'll try to get it working, sit tight!
Here's a map fragment: o a7da51c621e7758b
Oh no! our map broke...I'll try to get it working, sit tight!
Here's a map fragment: l 319cea7dc989f3fd
Here's a map fragment: e c7449d7a464dc255
Oh no! our map broke...I'll try to get it working, sit tight!
Here's a map fragment: l 7824ac0fb3ab8834
Here's a map fragment: h 76dcf89510c18813
Oh honey, I'm sorry. Looks like your ticket has changed!
...
<Some sweet ascii art of Ganondorf (tm) here>
```

Now that we can run our stuff....let's get to the real reversing part. The program gives us a hint as to what's going on pretty early on with the following block. Astute reverse engineers will recognize this is probably a struct initialization, and that this is the author being nice and giving the definition. If you don't recognize that, not a big deal, but this is the code in question:

```
  struct_instance_0 = (undefined8 *)calloc(1,0x28);
  *struct_instance_0 = 0;
  struct_instance_0[1] = 0;
  struct_instance_0[2] = 0;
  *(char *)(struct_instance_0 + 3) = *argv[1];
  uVar1 = FUN_004011df((ulong)(uint)(int)*(char *)(struct_instance_0 + 3),1);
  struct_instance_0[4] = uVar1;
```

Something to note here is that ghidra is pretty bad about types, but we luckily know already that this struct has a size of 0x28 because of the calloc call, and we know it has 5 elements. We'll define what those 5 elements are when we see something that's not a dummy struct (this one is all zeroes so it's not unreasonable to assume this is a placeholder). After creating that one struct, we loop through our input with the following:

```
   loop_counter = 1;
   while( true ) {
    len = strlen(input_0);
    if (len <= (ulong)(long)(int)loop_counter) break;
    struct_ptr = calloc(1,0x28);
    *(char *)((long)struct_ptr + 0x18) = argv[1][(int)loop_counter];
    uVar1 = FUN_004011df((ulong)(uint)(int)*(char *)((long)struct_ptr + 0x18),
                         (ulong)((int)loop_counter + 1U),(ulong)((int)loop_counter + 1U));
    *(undefined8 *)((long)struct_ptr + 0x20) = uVar1;
    FUN_00400772(struct_instance_0,struct_ptr,struct_ptr);
    loop_counter._0_4_ = (int)loop_counter + 1;
  }
```

So, pretty simple. For each character in our input, make a new struct like the one we saw previously and do the following:
- Assign struct offset 0x18 to the character value.
- Assign the output of some function call to struct offset 0x20
- Call some function with our first struct and our new struct as arguments)
- Increment our loop counter

So lets go reverse those two functions, shall we?

The first function FUN_004011df, is actually a lot easier to reverse from asm. Why? Because that's how I wrote it. If you want to struggle through the pseudocode, then be my guest. The easiest way to reverse this function will be to just annotate the assembly, which I've done below:

```
        004011df 41 52           PUSH       R10 		# Setup stuff
        004011e1 41 51           PUSH       R9 			# |
        004011e3 41 50           PUSH       R8 			# |
        004011e5 68 ca 93        PUSH       0x2493ca 	# v
                 24 00
        004011ea 5b              POP        RBX 		# Pop that 0x2493ca constant into RBX
        004011eb 49 89 f2        MOV        R10,index 	# Put the index we're at in argv[1] into R10
        004011ee 41 52           PUSH       R10
        004011f0 59              POP        RCX 		# And then pop it out into RCX
        004011f1 49 c7 c1        MOV        R9,0x0 		#
                 00 00 00 00
        004011f8 49 09 c9        OR         R9,RCX 		# Copy rcx (index in argv [1]) into r9's lowest byte
        004011fb 49 c7 c0        MOV        R8,0x0 		# Set up a counter in r8
                 00 00 00 00
                             LAB_00401202          		# 
        00401202 48 c1 e1 08     SHL        RCX,0x8 	# Shift rcx 8 left (clear a byte of rcx)
        00401206 49 09 c9        OR         R9,RCX 		# Copy rcx into r9's next byte
        00401209 49 83 c0 01     ADD        R8,0x1 		# add to our counter
        0040120d 49 83 f8 03     CMP        R8,0x3 		# check if we've done this 4 times
        00401211 7e ef           JLE        LAB_00401202 # continue to fill all the bytes in r9 with the value in rcx
        00401213 4c 89 c9        MOV        RCX,R9 		 
        00401216 48 31 cb        XOR        RBX,RCX 	# xor our constant by our filled value
        00401219 0f 57 d2        XORPS      XMM2,XMM2 	# Clear XMM2
        0040121c 66 48 0f        MOVQ       XMM2,RCX 	# Copy our filled and xor'ed value into xmm2
                 6e d1
        00401221 66 48 0f        MOVQ       XMM3,RCX 	# copy our filled and xor'ed value into xmm3 as well
                 6e d9
        00401226 4d 31 c0        XOR        R8,R8 		# clear r8, setting up a counter
                             LAB_00401229          
        00401229 66 0f 73        PSLLDQ     XMM3,0x10
                 fb 10
        0040122e 0f 56 d3        ORPS       XMM2,XMM3
        00401231 49 83 c0 01     ADD        R8,0x1
        00401235 49 83 f8 08     CMP        R8,0x8
        00401239 7e ee           JLE        LAB_00401229 # Once again, we're filling the whole register's bytes with the value in rcx
        0040123b 49 89 fa        MOV        R10,param_1  # Now we copy our character into r10
        0040123e 41 52           PUSH       R10 		
        00401240 58              POP        RAX 		 # and move it into rax
        00401241 48 c1 e0 18     SHL        RAX,0x18 	 # And then shift it left 0x18 (24) so the character value will now be in the leftmost byte of this (presumably) integer
        00401245 66 48 0f        MOVQ       XMM1,RAX 	# We then copy that shifted value into xmm1
                 6e c8
        0040124a 4d 31 c0        XOR        R8,R8 		# and set up another counter 
                             LAB_0040124d          
        0040124d 66 0f 38        AESENC     XMM1,XMM2 	# We then use the aesenc instruction to perform one round of AES encryption on XMM1 using XMM2 as the round key
                 dc ca
        00401252 49 83 c0 01     ADD        R8,0x1 		
        00401256 49 83 f8 20     CMP        R8,0x20 	# We do this 32 times
        0040125a 7e f1           JLE        LAB_0040124d
        0040125c 66 48 0f        MOVQ       RCX,XMM1
                 7e c9
        00401261 66 0f 73        PSRLDQ     XMM1,0x40
                 d9 40
        00401266 66 48 0f        MOVQ       RBX,XMM1
                 7e cb
        0040126b 48 31 d9        XOR        RCX,RBX
        0040126e 48 89 c8        MOV        RAX,RCX
        00401271 41 58           POP        R8
        00401273 41 59           POP        R9
        00401275 41 5a           POP        R10
        00401277 c3              RET 					# This is all teardown stuff, we return the result of the 32 rounds of aes encryption
```

So a few things here. 1) This is a deterministic function with a prototype of something like badhash(char c, int position); 2) We *could* go backwards because we know the key for each round, but it'd probably be easier just to pull this function out and use it ourselves to build a lookup table. What are we looking up, you ask? We'll have to keep going to figure that out. The next function, which takes two of our structs, is pretty simple, especially if we define a type for our struct. Let's do that now based on what we've seen prior. We have 3 address fields, which are 64 bits each, a char field, which is one byte but is aligned to be 8 bytes because our last field is also a 64 bit field that holds our hash from the above function.

Let's make a structure in Ghidra using the Data Type manager. We'll make it size 0x28 and have the following elements:

| Offset | Length | Mnemonic | datatype | name |
| --- | --- | --- | --- | --- |
| 0 | 8 | struct * | struct * | parent |
| 8 | 8 | struct * | struct * | left |
| 16 | 8 | struct * | struct * | right |
| 24 | 1 | char | char | character |
| 32 | 8 | int64_t | int64_t | hash |

You might not get that exactly on your own, I'm just including the full correct structure because this is a writeup after all. I'd like it to be reasonably clear.

Once we add a structure and change our inputs we'll be able to tell what the function is much more easily.
```
void tree_add(struct *root,struct *node)

{
  if (root->hash < node->hash) {
    if (root->right == (struct *)0x0) {
      root->right = node;
      node->parent = root;
    }
    else {
      tree_add(root->right,node);
    }
  }
  else {
    if (node->hash < root->hash) {
      if (root->left == (struct *)0x0) {
        root->left = node;
        node->parent = root;
      }
      tree_add(root->left,node);
    }
  }
  return;
```

So, if our hash is larger we connect our node with the current character to the right of the tree recursively, if it's less we go left. So...a binary search tree. Easy!

This explains the order of the printout. The printer function then becomes:

```
void tree_add(struct *root,struct *node)

{
  if (root->hash < node->hash) {
    if (root->right == (struct *)0x0) {
      root->right = node;
      node->parent = root;
    }
    else {
      tree_add(root->right,node);
    }
  }
  else {
    if (node->hash < root->hash) {
      if (root->left == (struct *)0x0) {
        root->left = node;
        node->parent = root;
      }
      tree_add(root->left,node);
    }
  }
  return;


```
So again we recurse down into the tree and print out the char / hash pairs. This is all great! We have uncovered almost all the functionality here but we really have yet to find anything that seems like it might get us a flag.

We skipped over two functions earlier that'll give us more info, but `main()` has a pretty good indication. The check that led to the ganondorf face earlier can also lead to a success state. If we check how that loop works, we basically just iterate from 0 to 1000 over the "memdump" file and check it against a region of memory. So we need our memory region to be the same as the memdump (or just reverse engineer the memdump and get the input, but probably this'll be easier for most people). We're checking against the memory region allocated at:

```
memory_region = calloc(1,0x1000);
```

That region is then passed into two functions, the first of which:

```
void FUN_00401278(undefined4 *param_1,char *param_2)

{
        00401278 49 89 fb        MOV        R11,RDI
        0040127b 49 89 f2        MOV        R10,RSI
        0040127e 41 c7 03        MOV        dword ptr [R11],0x0 			# Set our first element to 0
                 00 00 00 00
        00401285 41 c7 43        MOV        dword ptr [R11 + 0x8],0x0 		# Set our second element to 0
                 08 00 00 
                 00 00
        0040128d 41 c7 43        MOV        dword ptr [R11 + 0x10],0x0 		# Set our third element to 0
                 10 00 00 
                 00 00
        00401295 45 8a 0a        MOV        R9B,byte ptr [R10] 				
        00401298 45 88 4b 18     MOV        byte ptr [R11 + 0x18],R9B 		# Set our fourth element to the character passed in
        0040129c 48 31 ff        XOR        RDI,RDI
        0040129f 48 31 f6        XOR        RSI,RSI
        004012a2 41 8a 3a        MOV        DIL,byte ptr [R10]
        004012a5 48 c7 c6        MOV        RSI,0x1
                 01 00 00 00
        004012ac e8 2e ff        CALL       hash
                 ff ff
        004012b1 49 89 43 20     MOV        qword ptr [R11 + 0x20],RAX 		# Set our fifth element to the hash of the character/index
        004012b5 49 c7 43        MOV        qword ptr [R11 + 0x18],0x69696969  # Overwrite the fourth element with 0x69696969. Nice.
                 18 69 69 
                 69 69
        004012bd c3              RET 										# Return void
}
```

Looks awful familiar, huh? And if we look at our memdump we have 0x69696969 galore. Likely came from here. Remember when we realized we need to supply two arguments? It looks like the program uses the first one with the relatively transparent methods that show up in main and the second with this code (slightly harder to parse). 

Next, we get the longer function:

```
void populate_shadow(struct *memory_area,char *argv2)

{
 byte cur_char;
 int64_t hashval;
 struct *node;
 long index;

 index = 1;
 cur_char = argv2[1];
 node = memory_area + 1;
 while (cur_char != 0) {
  *(ulong *)&node->data = (ulong)cur_char;
  hashval = hash((ulong)cur_char,index);
  node->hash = hashval;
  *(undefined8 *)&node->data = 0x69696969;
  FUN_0040131e(memory_area,node);
  index = index + 1;
  cur_char = argv2[index];
  node = node + 1;
 }
 return;
}
```

With the earlier type annotations we made this is pretty easy to read and does a very similar thing to before. However, instead of allocating on the heap each new node we create, we are just iterating along the large contiguous memory area we had before. Interesting. Now, let's take a look at that final function we have yet to reverse. Again, I wrote this out in assembly so we'll look at it that way instead of the monstrosity of shifts Ghidra tries to show us.

```
FUN_0040131e: # a recursive function. Where have we seen that before in this program....
0040131e 48 8b 4f 20     MOV        RCX,qword ptr [RDI + 0x20]
00401322 48 8b 5e 20     MOV        RBX,qword ptr [RSI + 0x20]
00401326 48 c1 c1 20     ROL        RCX,0x20
0040132a 48 c1 c3 20     ROL        RBX,0x20
0040132e 48 39 d9        CMP        RCX,RBX # Check to see if our hashes of our two inputs are the same
00401331 7c 0e           JL         LAB_00401341 # If arg2 > arg1
00401333 7f 24           JG         LAB_00401359 # if arg1 > arg2
00401335 48 c7 c7        MOV        RDI,0x0 	 # Else error
		 00 00 00 00
0040133c e8 2f f3        CALL       exit             
		 ff ff
					 LAB_00401341      # we check the left pointer 
00401341 48 83 7f        CMP        qword ptr [RDI + 0x8],0x0
		 08 00
00401346 75 08           JNZ        LAB_00401350 # if pointer not null, this isn't a leaf. Otherwise:
00401348 48 89 3e        MOV        qword ptr [RSI],RDI #make the parent node address known to the new child
0040134b 48 89 77 08     MOV        qword ptr [RDI + 0x8],RSI #copy child address into parent->left
0040134f c3              RET
					 LAB_00401350     
00401350 48 8b 7f 08     MOV        RDI,qword ptr [RDI + 0x8]
00401354 48 89 f6        MOV        RSI,RSI
00401357 eb c5           JMP        FUN_0040131e      
					 -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
					 LAB_00401359    # we check the right pointer
00401359 48 83 7f        CMP        qword ptr [RDI + 0x10],0x0
		 10 00
0040135e 75 08           JNZ        LAB_00401368 # if the pointer is not null, this isn't a leaf
00401360 48 89 3e        MOV        qword ptr [RSI],RDI # copy parent address into pointer
00401363 48 89 77 10     MOV        qword ptr [RDI + 0x10],RSI #Copy child address into parent->right
00401367 c3              RET
					 LAB_00401368     
00401368 48 8b 7f 10     MOV        RDI,qword ptr [RDI + 0x10] # move the right pointer's value into rdi and recurse with the node we want to add as the second argument still
0040136c 48 89 f6        MOV        RSI,RSI
0040136f eb ad           JMP        FUN_0040131e      
```

So, we're doing essentially the same thing we did before. We're creating a tree, just in a slightly different manner. Luckily for us, this means we can abuse the fact that despite it usually being hard to see how a tree is organized in memory, this one is ordered in input order in memory (even if it isn't linked that way). And we have the correct memory image. So next step, let's create a lookup table. We know the range of characters is going to be 0x20-0x7f (printable ascii), and we can get the length of the input by looking at the memdump file. If we count them all up, we get 76. Yikes, but not unreasonable to do on a laptop at all. Lets use python to go through the memdump and just print out all the hashes:

```
import struct
with open("memdump", "rb") as f:
	# Start at offset 0x20 (first hash)
    bytevals = f.read()[0x20:]
	# Increment index by 0x28 (struct size)
    for i in range(0, len(bytevals), 0x28):
		# Unpack as little endian quad word and print just hex
        print(hex(struct.unpack("<Q", bytevals[i:i+8])[0])[2:])
```



Next, lets rip out the hash function and compile our table generator against it.

```

#include <stdint.h>
#include <stdio.h>

extern int64_t hash(char c, int pos);

int main() {
        for (char c = 0x20; c < 0x7f; c++) {
                for (int pos = 0; pos < 76; pos++) {
                        printf("%c:%lx,\n", c, pos, hash(c, pos));
                }
        }
}

```

Then compile with `gcc -o solve solve.c hash.s`

Now we can modify our python script and map each hash to its input value and reconstruct the flag!



