# REV 300 - derailed

| Author | novafacing |
| --- | --- |
| Point Value | 300 |
| Description | GUI Application with trace; figure out what the input was |

Alrighty! We made it to the hards! This is definitely the easiest hard challenge. Because of unforseen issues with GTK, I wasn't able to get mozilla RR working on the binary, which was my first choice, so I used a custom GDB tracer. 

This challenge was heavily inspired by this thread from /r/programmerhumor: https://imgur.com/a/4f3XB

I didn't do anything *that* horrible, but opening up the GUI will show you several columns of different input types, some combo boxes, on/off switches, numeric sliders, and buttons that randomize the displayed character. Fun!

Of course we don't have anything as abstract as a video of using the program, but the trace is perfectly good enough to recover the inputs. Let's start with the obvious setup stuff though. We have a call to srand() very early in the program, and we'll need to record the time we seed with before anything. It's also a good example of how we can quickly process the trace to find a value using a lil bit of python.

```python
import ast
with open("./dist/trace.log", "r") as f:
    trace = f.read().splitlines()[1:] # discard the first line, that just tells us what order stuff goes in
trace[0] = trace[0][2:] # trim off the front "{"
trace[-1] = trace[-1][:-2]  + "," # trim off the end "}" and make it look like all the other lines

class Instr():
    def __init__(self, instr, regs):
        self.instr = " ".join(instr)
        self.rax = regs[0]
        self.rbx = regs[1]
        self.rcx = regs[2]
        self.rdx = regs[3]
        self.rsp = regs[4]
        self.rbp = regs[5]
        self.rsi = regs[6]
        self.rdi = regs[7]
        self.rip = regs[8]
        self.r8 = regs[8]
        self.r9 = regs[9]
        self.r10 = regs[10]
        self.r11 = regs[11]
        self.r12 = regs[12]
        self.r13 = regs[13]
        self.r14 = regs[14]
        self.r15 = regs[15]

def initialize_instrs():
    instrs = []
    for instr in trace:
        tup = ast.literal_eval(instr[:-1])
        instrs.append(Instr(tup[0], tup[1]))
    return instrs

if __name__ == "__main__":
    instrs = initialize_instrs()
```

So let's find the time. We'll need to process gdb's function offsets pretty often in reversing this execution, so I'll add some logic to do that. We could check out the time call and try and grab the return value but it's both easier and probably more accurate to just grab rsi at the call to srand. By the way, since this is a hard I'm glossing over some of the more nitty gritty reading decomp/disas part of the challenge and focusing on the solve itself.

```python
def find_time(instrs):
    insiter = iter(instrs)
    for instr in insiter:
        if "call" in instr.instr and "srand" in instr.instr:
            return instr.rsi
```

We could examine register values at different points for the random callbacks (go reverse it!) to figure out what values we randomized to, OR we could use a nice feature of python and just call srand() and rand() from python!

The next step is to figure out how many randomizations (note that I'm focusing on the random buttons first. This is for no reason except that I want to) we performed and for which buttons. To do this, we can find calls to random that are made from random_callback in our trace. 

I implemented a couple more functions in my Instr representation class:

```python
def fn_name(self):
        try:
            return self.instr.split("+")[0].split("<")[1]
        except:
            return None
    def text(self):
        try:
            return " ".join(self.instr.split(": ")[1].split(" ")[1:])
        except:
            return None

    def mnem(self):
        try:
            return self.instr.split(": ")[1].split(" ")[0]
        except:
            return None
	def fn_offset(self):
        try:
            return int(self.instr.split("+")[1].split(">")[0])
        except:
            return None
```

And then found both the number of randoms and what those values are:

```
def rand_count(instrs, fname):
    count = 0
    for instr in instrs:
        if fname == instr.fn_name() and "call" == instr.mnem() and "rand" in instr.text() and not "srand" in instr.text():
            count += 1
    return count

if __name__ == "__main__":
    instrs = initialize_instrs()
    print("time seed: ", find_time(instrs))
    libc.srand(find_time(instrs))
    for i in range(rand_count(instrs, "random_callback")):
        print(chr(libc.rand() % 0xff))
```

It was here that I realized that glib calls random pretty often and since the trace stops at library boundaries I can't figure out how many. So, back to the drawing board, and actually this ended up being easier: just check out eax here:

`0010189b 83 c0 20        ADD        EAX,0x20`

And we'll get the character selected on that callback. Now, let's grab that character as well as the address of the buffer we're putting the selected character into. From looking at the data structure a bit we'd be able to tell that there's a list of mappings from the widget name to a character, which defines how we're storing our inputs. Now, we only have registers otherwise we'd be able to just print out that structure and be done, but since we're clever we'll get it anyway. Since that target won't change and will be unique for each input, we can use it to index our flag. 

So we make a quick function:
```
def get_rand_chars(instrs):

    rcs = {}
    lch = None
    instriter = iter(instrs)
    for instr in instriter:
        if instr.fn_name() == "random_callback" and instr.fn_offset() == 79:
            ch = (chr(instr.rax))
            while instr.fn_offset() != 149:
                instr = next(instriter)
            rcs[instr.rax] = ch
    return rcs
```

And we get the dict:
```
{93824999901312: 'e', 93824999901760: 'v', 93824999900864: 'I', 93824999900416: 'o', 93824999899968: 's'}
```

The addresses are in reverse order, plus it loosely spells out "soIve", so it's pretty obvious that this is right but backward. The "I" is just because GTK has bad font and I thought it was an "l". Oops. Either flag will be accepted. Womp Womp.


Now, we've done with the randoms, so on to the next thing! Let's do something similar for each of the callbacks. We know that the first argument to any callback in Gtk is the widget the callback was generated from, so we can grab that value at any point and index our characters by that widget's address. That won't *necessarily* tell us the ordering, but if it's wrong at all (hint: it won't be too off, but it'll be a little off). 

So, we add some functions to grab the characters we landed on for each type of box:

```python
def get_rand_chars(instrs):

    rcs = {}
    instriter = iter(instrs)
    for instr in instriter:
        if instr.fn_name() == "random_callback" and instr.fn_offset() == 79:
            ch = (chr(instr.rax))
            while instr.fn_offset() != 149:
                instr = next(instriter)
            rcs[instr.rax] = ch
    return rcs

def get_combo_chars(instrs):
    ccs = {}
    instriter = iter(instrs)
    for instr in instriter:
        if instr.fn_name() == "combo_callback" and instr.fn_offset() == 9:
            addr = instr.rdi
            while instr.fn_offset() != 119:
               instr  = next(instriter)
            ccs[addr] = chr(instr.rdx)
    return ccs

def get_a_chars(instrs):
    acs = {}
    instriter = iter(instrs)
    for instr in instriter:
        if instr.fn_name() == "a_callback" and instr.fn_offset() == 8:
            addr = instr.rdi
            while instr.fn_offset() != 142 and instr.fn_offset() != 239:
                instr = next(instriter)
            acs[addr] = instr.rdx
    return acs

def get_slider_chars(instrs):
    scs = {}
    instriter = iter(instrs)
    for instr in instriter:
        if instr.fn_name() == "slider_callback" and instr.fn_offset() == 9:
            addr = instr.rdi
            while instr.fn_offset() != 153:
                instr = next(instriter)
            scs[addr] = instr.rdx
    return scs

if __name__ == "__main__":
    instrs = initialize_instrs()
    rcs = get_rand_chars(instrs)
    ccs = get_combo_chars(instrs)
    acs = get_a_chars(instrs)
    scs = get_slider_chars(instrs)
    flag = {}
    flag.update(rcs)
    flag.update(ccs)
    flag.update(acs)
    flag.update(scs)
    for key, value in sorted(flag.items(), key=lambda x: x[0]):
        print(value, end="")
```

We'll get something that's almost the flag: correct characters, but wrong ordering. So the addresses of the widgets isn't the right way to order this because they aren't in the same order as the flag. Luckily, we already know what order the widget addresses are if we look at https://github.com/GNOME/gtk/blob/mainline/gtk/gtkbuilder.c. We know that gtk is simple and easy, so it adds widgets to a container in a particular order. We can get the ordering by address with:

```python
def get_ordering(instrs):
    for instr in instrs:
        if instr.fn_name() == "populate_passcode_maps" and instr.fn_offset() == 8:
            yield instr.rdi
```

And get the following:
```
('0x555555a42270', 'p')
('0x555555a424a0', 'c')
('0x555555a426d0', 't')
('0x555555a42900', 'f')
('0x555555a42b30', '{')
('0x555555a42d60', 'a')
('0x555555a42f90', 'l')
('0x555555a431c0', 'l')
('0x555555a433f0', '_')
('0x555555a43620', 'a')
('0x555555a43850', 'h')
('0x555555a43a80', 'e')
('0x555555a43cb0', 'a')
('0x555555b54700', 1)
('0x555555b548b0', 1)
('0x555555b54a60', 0)
('0x555555b54c10', 0)
('0x555555b54dc0', 1)
('0x555555b54f70', 0)
('0x555555b5d1c0', 0)
('0x555555b5d370', 1)
('0x555555b5d520', 0)
('0x555555b5d6d0', 0)
('0x555555b5d880', 0)
('0x555555b5da30', 0)
('0x555555b5dbe0', 1)
('0x555555a43ef0', 115)
('0x555555b40310', 109)
('0x555555b40540', 111)
('0x555555b40770', 112)
('0x555555b409a0', 114)
('0x555555b40bd0', 111)
('0x555555b40df0', 'w')
('0x555555b41020', 'b')
('0x555555b41250', 'l')
('0x555555b41480', 'e')
('0x555555b416b0', 'm')
('0x555555b418e0', '_')
('0x555555b41b10', 'i')
('0x555555b41d40', 's')
('0x555555b41f70', '_')
('0x555555c7a200', '}')
('0x555555ca4340', 's')
('0x555555ca4500', 'o')
('0x555555ca46c0', 'I')
('0x555555ca4880', 'e')
('0x555555ca4a40', 'v')
```

Now we could be smart about this and extend our solver to do it 100% correctly, but that's a pain. Instead, we can just glance at the gui and realize there's a combobox in the middle of the sliders, move a value up (if we convert to ascii, it'll spell a real word instead of a misspelled one as well), and then move the "soIev" inside the closing brace. And we're done!

`pctf{all_ahea110100100001115109111w112114111blem_is_soIev}`

Note that since this *did* spell out valid ascii we also accepted:

`pctf{all_ahead_slow_problem_is_soIev}`

Double note that since people might not realize "soIev" should be switched to be "soIve", we also accepted "soIve" there.


