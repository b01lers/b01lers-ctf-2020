import random
regs = ['ra', 'rb', 'rc', 'rd', 're']
def generate_imm():
    return hex(random.randint(0, 0xffffffffffffffff))

def generate_mpc():
    if random.randint(0, 1) == 0:
        return 'mpc {}'.format(random.choice(regs))
    else:
        return 'mpc {} #{}'.format(random.choice(regs), generate_imm())



def generate_enq():
    if random.randint(0, 1) == 0:
        return 'enq {}'.format(random.choice(regs))
    else:
        return 'enq {} #{}'.format(random.choice(regs), generate_imm())


def generate_deq():
    ch = random.randint(0, 2)
    if ch == 0:
        return 'deq'
    elif ch == 1:
        return 'deq {}'.format(random.choice(regs))
    else:
        return 'deq {} #{}'.format(random.choice(regs), generate_imm())

def generate_jsz():
    return 'jsz {} {} {}'.format(random.choice(regs), random.choice(regs), random.choice(regs))

def generate_allrmprcivri():
    if random.randint(0, 1) == 0:
        return 'allrmprcivri {} {} {}'.format(random.choice(regs), random.choice(regs), random.choice(regs))
    else:
        return 'allrmprcivri {} #{} #{}'.format(random.choice(regs), generate_imm(), generate_imm())

def generate_mooq():
    return 'mooq'

def generate_rv():
    if random.randint(0, 1) == 0:
        return 'rv {} {}'.format(random.choice(regs), random.choice(regs))
    else:
        return 'rv {} {} #{}'.format(random.choice(regs), random.choice(regs), generate_imm())

def generate_lar():
    return 'lar {} #{}'.format(random.choice(regs), generate_imm())

def generate_aml():
    ch = random.randint(0, 2)
    if ch == 0:
        return 'aml'
    elif ch == 1:
        return 'aml {}'.format(random.choice(regs))
    else:
        return 'aml #{}'.format(generate_imm())

def generate_gml():
    if random.randint(0, 1) == 0:
        return 'gml {}'.format(random.choice(regs))
    else:
        return 'gml #{}'.format(generate_imm())

def generate_sq():
    if random.randint(0, 1) == 0:
        return 'sq {}'.format(random.choice(regs))
    else:
        return 'sq #{}'.format(generate_imm())


funcs = [generate_mpc, generate_enq, generate_deq, generate_jsz, generate_allrmprcivri, generate_mooq, generate_rv, generate_lar, generate_aml, generate_gml, generate_sq]
for i in range(0x1337):
    print(random.choice(funcs)() + ";")