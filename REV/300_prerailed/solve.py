import sys
import struct
import binascii
from pwn import *

# opcode / number of args / number of register args

ops = {
    0x7c:("mpc", 2, 1),
    0x7d:("mpc", 1, 1),
    0x7e:("hcf", 2, 2),
    0x7f:("enq", 1, 1),
    0x80:("enq", 2, 1),
    0x81:("deq", 2, 1),
    0x82:("deq", 1, 1),
    0x83:("deq", 0, 0),
    0x84:("jsz", 3, 3),
    0x85:("allrmprcivri", 3, 1),
    0x86:("allrmprcivri", 3, 3),
    0x87:("mooq", 0, 0),
    0x88:("rv", 2, 2),
    0x89:("rv", 3, 2),
    0x8a:("lar", 2, 1),
    0x8b:("aml", 0, 0),
    0x8c:("aml", 1, 1),
    0x8d:("aml", 1, 0),
    0x8e:("gml", 1, 1),
    0x8f:("gml", 1, 0),
    0x90:("sq", 1, 0),
    0x91:("sq", 1, 1),
    0x92:("emp", 3, 2)
}

regs = {
    0x10:"ra",
    0x11:"rb",
    0x12:"rc",
    0x13:"rd",
    0x14:"re"
}

def get_regs(f, op):
    reg_ct = op[2]
    reglist = []
    if reg_ct > 0:
        for i in range(reg_ct):
            reglist.append(regs[struct.unpack("<Q", f.read(8))[0]])
        return " " + " ".join(reglist)
    else:
        return ""

def get_imms(f, op):
    imm_ct = op[1] - op[2]
    immlist = []
    if imm_ct > 0:
        for i in range(imm_ct):
            immlist.append('0x{:016x}'.format(struct.unpack("<Q", f.read(8))[0]))
        return " #" + " #".join(immlist)
    else:
        return ""


lines = []
with open(sys.argv[1], "rb") as f:
    c = struct.unpack("<Q", f.read(8))[0]
    while True:
        mnem = ops[c][0]
        rgs = get_regs(f, ops[c])
        imms = get_imms(f, ops[c])
        lines.append(mnem + rgs + imms + ";")
        nc = f.read(8)
        if not nc:
            break
        c = struct.unpack("<Q", nc)[0]

with open(sys.argv[1] + "dis", "w") as f:
    for line in lines:
        f.write(line + "\n")



p = process(['./railed', sys.argv[1] + 'dis'])
flag = p.recv(timeout=1)
flag = flag.split(b'\n')
flag = [f[2:] for f in flag]
for f in flag:
    print(binascii.unhexlify(f))