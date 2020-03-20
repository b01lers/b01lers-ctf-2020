import gdb
import re

# This is the script I used to generate trace.log. To Run it, simply
# > gdb -q
# > source trace.py

addr_re = "0x[a-fA-F0-9]{16}"

gdb.execute("file rr_crossing")
gdb.execute("handle SIGSEGV nostop noprint pass")
gdb.execute("handle SIGILL nostop noprint pass")
gdb.execute("gef config context.layout \"\"")
gdb.execute("b main")
bps = ["a_callback", "combo_callback", "slider_callback", "random_callback", "submit_callback", "destroy_callback", "set_mapval_b", "set_mapval_c", "set_mapval_i", "init_valmap", "map_hasname", "map_add", "populate_passcode_maps"]
breakpoints = [gdb.Breakpoint(bp) for bp in bps]
gdb.execute("r")

mappings = gdb.execute("info proc mappings", True, True).split("\n")
mappings = [(int(mp.split()[0], 16), int(mp.split()[1], 16)) for mp in mappings if "rr_crossing" in mp]

def get_start_end(fname):
    disassembly = gdb.execute("disas {}".format(fname), True, True).split("\n")
    insns = []
    for insn in disassembly:
        insn_addr = re.findall(addr_re, insn)
        if len(insn_addr) > 0:
            insns.append(insn_addr[0])
    return (int(insns[0], 16), int(insns[-1], 16))

def in_prog(rip):
    for start, end in mappings:
        if start <= rip <= end:
            return True
    return False

def ctx():
    regnames = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    regs = [int(gdb.execute("p/d ${}".format(reg), True, True).split(" ")[-1]) for reg in regnames]
    instr = gdb.execute("x/i $rip", True, True).split()[2:]
    return (instr, regs)


start, end = get_start_end("main")
rip = int(gdb.execute("p/d $rip", True, True).split(" ")[-1])
with open("trace.log", "w") as f:
    while(rip != end):
        print(list(bp.hit_count for bp in breakpoints))
        rip = int(gdb.execute("p/d $rip", True, True).split(" ")[-1])
        if in_prog(rip):
            gdb.execute("si")
            f.write(str(ctx()))
            f.write("\n")
        else:
            gdb.execute("n")
