# The challenge simulates a 2D binary (0/1) Turing machine (it operates on a 2D sheet instead of a 1D tape).
# [There is a "Two D baby" reference in the problem description.]
#
# The input is converted to code that is then run on the machine.
#
# To get the flag, the code needs to implement the integer manipulation v -> v + 1337, which is then tested 
# against 100 randomly generated 17-bit 'v' values. If the math checks out in all cases, the flag is printed.
#


import sys
from pwn import *


# 17-bit "add 1337" code for binary 2D Turing machine
# expands to 18 bits on overflow => 100% reliable    (if you miss the overflow, you could still win stochastically...)
#
# the input is given in the top left corner of the TM sheet as:
#
#  111111111111111110   <-baseline (1 for each digit, 0 terminator after last digit)
#  010111000...  ...    <-digit values (0/1), left to right from lowest to highest digit
#
# upon program start, the tape head is at the top left corner
#
# algorithm: go through digits of input and branch on carry C, adding 0/1 (when corresponding digit in 1337 is 0)
# or 1/2 (when digit in 1337 is 1). Note, 1337 = 100111001010... in low to high bit order.
#
# code line 'i' is tuple of two: (action on 0, action on 1) when in state 'i'
# where action is a tuple of three: (symbol to write, direction to move in, new state)
#
#
# the code is simple to generate algorithmically but let me just spell it out for you below
#
# (BTW, it is cooler to write a general Turing adder, transcribe 1337 and use it - try it :)
#

STAY, UP, RIGHT, DOWN, LEFT = 0, 1, 2, 3, 4    # direction codes

code = (
       ((1, DOWN,   1),   (1, DOWN,   1)),   #0 D           move from baseline to digit line
       ((1, RIGHT,  2),   (0, RIGHT,  3)),   #1: +1, R      bit 0*  (for bit 0 always add 1 with C = 0)

       ((0, RIGHT,  4),   (1, RIGHT,  4)),   #2: +0, R      bit 1   add 0 with C=0
       ((1, RIGHT,  4),   (0, RIGHT,  5)),   #3: +1, R              add 0 with C=1

       ((0, RIGHT,  6),   (1, RIGHT,  6)),   #4: +0, R      bit 2   add 0 with C=0
       ((1, RIGHT,  6),   (0, RIGHT,  7)),   #5: +1, R              add 0 with C=1

       ((1, RIGHT,  8),   (0, RIGHT,  9)),   #6: +1, R      bit 3*  add 1 with C=0
       ((0, RIGHT,  9),   (1, RIGHT,  9)),   #7: +2, R              add 1 with C=1

       ((1, RIGHT, 10),   (0, RIGHT, 11)),   #8: +1, R      bit 4*  ...
       ((0, RIGHT, 11),   (1, RIGHT, 11)),   #9: +2, R

       ((1, RIGHT, 12),   (0, RIGHT, 13)),   #10: +1, R     bit 5*
       ((0, RIGHT, 13),   (1, RIGHT, 13)),   #11: +2, R

       ((0, RIGHT, 14),   (1, RIGHT, 14)),   #12: +0, R     bit 6
       ((1, RIGHT, 14),   (0, RIGHT, 15)),   #13: +1, R

       ((0, RIGHT, 16),   (1, RIGHT, 16)),   #14: +0, R     bit 7
       ((1, RIGHT, 16),   (0, RIGHT, 17)),   #15: +1, R

       ((1, RIGHT, 18),   (0, RIGHT, 19)),   #16: +1, R     bit 8*
       ((0, RIGHT, 19),   (1, RIGHT, 19)),   #17: +2, R
    
       ((0, RIGHT, 20),   (1, RIGHT, 20)),   #18: +0, R     bit 9
       ((1, RIGHT, 20),   (0, RIGHT, 21)),   #19: +1, R
 
       ((1, RIGHT, 22),   (0, RIGHT, 23)),   #20: +1, R     bit 10*
       ((0, RIGHT, 23),   (1, RIGHT, 23)),   #21: +2, R

       ((0, RIGHT, 24),   (1, RIGHT, 24)),   #22: +0, R     bit 11
       ((1, RIGHT, 24),   (0, RIGHT, 25)),   #23: +1, R

       ((0, RIGHT, 26),   (1, RIGHT, 26)),   #24: +0, R     bit 12
       ((1, RIGHT, 26),   (0, RIGHT, 27)),   #25: +1, R
 
       ((0, RIGHT, 28),   (1, RIGHT, 28)),   #26: +0, R     bit 13
       ((1, RIGHT, 28),   (0, RIGHT, 29)),   #27: +1, R
 
       ((0, RIGHT, 30),   (1, RIGHT, 30)),   #28: +0, R     bit 14
       ((1, RIGHT, 30),   (0, RIGHT, 31)),   #29: +1, R
 
       ((0, RIGHT, 32),   (1, RIGHT, 32)),   #30: +0, R     bit 15
       ((1, RIGHT, 32),   (0, RIGHT, 33)),   #31: +1, R
 
       ((0, RIGHT, -1),   (1, RIGHT, -1)),   #32: +0, R     bit 16
       ((1, RIGHT, -1),   (0, RIGHT, 34)),   #33: +1, R
 
       ((1, UP,    34),   (1, UP,    34)),   #34: write, U     on overflow to bit 17, write bit 17
       ((1, RIGHT, 35),   (1, RIGHT, 35)),   #35: write, R     create baseline for bit 17
       ((0, RIGHT, -1),   (0, RIGHT, -1))    #36: erase, TERM  end baseline and terminate
 
    )



# convert Turing code to string

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encode64(b):
   return alphabet[b]   # let us rely on Python range checks

def action2str(a):
   (sym, move, state) = a
   if state == -1:  state = 63   # map -1 to 63 for state
   return encode64(sym * 8 + move) + encode64(state)

def code2str(code):
   return "".join( [action2str(a0) + action2str(a1)  for (a0, a1) in code] )
   

payload = code2str(code)


# connect to challenge, send code, get result

r = remote("localhost", 13371)

in1 = r.recvuntil("code")
print(in1)

r.send(payload + "\n")

print(r.recvall())





