import ast
from ctypes import *
import xml.etree.ElementTree as ET

with open("./dist/trace.log", "r") as f:
    trace = f.read().splitlines()[1:] # discard the first line, that just tells us what order stuff goes in
trace[0] = trace[0][2:] # trim off the front "{"
trace[-1] = trace[-1][:-2]  + "," # trim off the end "}" and make it look like all the other lines
order = [
    "combo_a1",
    "combo_a2",
    "combo_a3",
    "combo_a4",
    "combo_a5",
    "combo_a6",
    "combo_a7",
    "combo_a8",
    "combo_a9",
    "combo_a10",
    "combo_a11",
    "combo_a12",
    "combo_a13",
    "switch_a",
    "switch_a1",
    "switch_a2",
    "switch_a3",
    "switch_a4",
    "switch_a5",
    "switch_a6",
    "switch_a7",
    "switch_a8",
    "switch_a9",
    "switch_a10",
    "switch_a11",
    "switch_a12",
    "scale_a",
    "scale_a1",
    "scale_a2",
    "scale_a3",
    "combo_a14",
    "scale_a4",
    "scale_a5",
    "combo_a15",
    "combo_a16",
    "combo_a17",
    "combo_a18",
    "combo_a19",
    "combo_a20",
    "combo_a21",
    "combo_a22",
    "randbutton_a",
    "randbutton_a1",
    "randbutton_a2",
    "randbutton_a4",
    "randbutton_a3",
    "combo_a23",
]

badorder = [
    "combo_a1",
    "combo_a2",
    "combo_a3",
    "combo_a4",
    "combo_a5",
    "combo_a6",
    "combo_a7",
    "combo_a8",
    "combo_a9",
    "combo_a10",
    "combo_a11",
    "combo_a12",
    "combo_a13",
    "switch_a",
    "switch_a1",
    "switch_a2",
    "switch_a3",
    "switch_a4",
    "switch_a5",
    "switch_a6",
    "switch_a7",
    "switch_a8",
    "switch_a9",
    "switch_a10",
    "switch_a11",
    "switch_a12",
    "scale_a",
    "scale_a1",
    "scale_a2",
    "scale_a3",
    "scale_a4",
    "scale_a5",
    "combo_a14",
    "combo_a15",
    "combo_a16",
    "combo_a17",
    "combo_a18",
    "combo_a19",
    "combo_a20",
    "combo_a21",
    "combo_a22",
    "combo_a23",
    "randbutton_a",
    "randbutton_a1",
    "randbutton_a2",
    "randbutton_a4",
    "randbutton_a3",
]

class Instr():
    def __init__(self, instr, regs):
        self.instr = " ".join(instr)
        self.rax = int(regs[0])
        self.rbx = int(regs[1])
        self.rcx = int(regs[2])
        self.rdx = int(regs[3])
        self.rsp = int(regs[4])
        self.rbp = int(regs[5])
        self.rsi = int(regs[6])
        self.rdi = int(regs[7])
        self.rip = int(regs[8])
        self.r8  = int(regs[8])
        self.r9  = int(regs[9])
        self.r10 = int(regs[10])
        self.r11 = int(regs[11])
        self.r12 = int(regs[12])
        self.r13 = int(regs[13])
        self.r14 = int(regs[14])
        self.r15 = int(regs[15])
    def fn_offset(self):
        try:
            return int(self.instr.split("+")[1].split(">")[0])
        except:
            return None
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

def initialize_instrs():
    instrs = []
    for instr in trace:
        tup = ast.literal_eval(instr[:-1])
        instrs.append(Instr(tup[0], tup[1]))
    return instrs

def find_time(instrs):
    insiter = iter(instrs)
    for instr in insiter:
        if "call" in instr.instr and "srand" in instr.instr:
            return instr.rsi

def rand_count(instrs, fname):
    count = 0
    for instr in instrs:
        if fname == instr.fn_name() and "call" == instr.mnem() and "rand" in instr.text() and not "srand" in instr.text():
            count += 1
    return count

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

def get_ordering(instrs):
    for instr in instrs:
        if instr.fn_name() == "populate_passcode_maps" and instr.fn_offset() == 8:
            yield instr.rdi

def get_xml_ordering(xmlfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    window = [obj for obj in root.findall("object") if obj.attrib['class'] == "GtkWindow"][0]
    grid = [obj for obj in window.findall('child') if obj.findall("object")][0].getchildren()[0]
    children = grid.findall('child')
    for child in children:
        innerobj = child.findall("object")
        if innerobj and 'id' in innerobj[0].attrib:
            yield innerobj[0].attrib['id']
        else:
            yield "ignore"

def fix_order(flag):
    borderflag = {}
    for idx, pair in enumerate(sorted(flag.items(), key=lambda x: x[0])):
        key, value = pair[0], pair[1]
        borderflag[badorder[idx]] = value
    for item in order:
        print(borderflag[item], end="")



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
        print(hex(key), value)

    print("---")
    flg = []
    for box in get_ordering(instrs):
        if box in flag:
            flg.append((hex(box), flag[box]))
    for f in reversed(flg):
        print(f)
