# REV 300 - Railed

| Author | novafacing |
| --- | --- |
| Point Value | 300 |
| Description | Custom ISA CPU emulator reverse engineering |

Whooo baby. This one was really fun to make until I realized what the second step was. 

So, we get a binary and...a binary and....another binary. Yay!

If you haven't yet, go read my writeup for 300_prerailed. This challenge is a little more complicated in a couple areas and I'll cover those, but I won't cover the lexer (because it's exactly the same) or the parser (because it's exactly the same save for a couple differences). This writeup will be focused on reversing the object oriented C++ code that forms the processor emulator. Spoiler: it's not great code.

So we have a shitload of objects, but the base classes are:

```
Context
Instruction
Register
```

Our parser unlike prerailed doesn't create nameless structs, we're creating Instruction objects from the assembly code and adding them to our context (case 0x1-0xd simply add the passed-up pointer to an Instruction()) to the context. It's actually nice in this case they all inherit the Instruction base class, because they can be treated exactly the same way. So in this program, the parser parses an assembly file and creates the correct instruction for each line, and adds it to the CPU. 

When Context::run() is called, we very simply iterate through the instructions and call execute on each instruction.

Context::execute() is just a table that checks the type of the input (a derived Instruction) and calls the right function.

For example, if we get ENQInstruction, we call Context::enq() with the instruction as an argument, and so forth. 

The instruction names might give some indication of what the instruction will do, but in several cases (mooq, allrmrpcivrii) they are pretty arcanely named and not obvious. There are a couple ways to go about figuring out what they do, the easiest of which is probably to compile in your own code that will print out the current CPU state. We know we have 5 registers, so we'll want to know what the contents of those are. If we look at the constructor of context, we'll see those 5 vectors are added to a class variable vector. We also have a vector of queues containing a queue and a pointer to that single queue. Finally we have a vector of instructions and a pointer to the first register that is stored separately.

So, what can we do to see the code in progress? If we run it, we get a nice printout of garbage, do obviously something flaggy happens during execution. Now that we understand the processor is pretty simple, basically just a bunch of queues and five registers, we can just print each of those values every time execute is called. I did that by compiling in some code with binary ninja, but it could be done just as easily with a GDB script. Last option is to manually reverse the instructions. I don't really recommend that, I wrote about 1000 by hand and there are 4000 fake instructions that are skipped over with MPC (make program counter) to trip up people who want to do that, I wanted to railroad players towards doing it with some level of automation.


Whatever you choose, the flag will be placed 4 characters at a time into the first four queues in the queue pointer towards the end of execution and can be read from there. 
