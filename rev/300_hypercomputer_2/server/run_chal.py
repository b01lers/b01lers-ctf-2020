import sys, time, subprocess
from datetime import datetime


def slowPrint(msg):
   for b in msg.upper():
       sys.stdout.buffer.write(bytes([b]))
       sys.stdout.flush()
       time.sleep(0.010)


         
t0 = datetime.now()
date = bytearray(t0.strftime("%Y-%m-%d %H:%M:%S"), "ascii")
# send story string
slowPrint(b"\n")
slowPrint(b"Captain's log entry " + date + b"\n")
slowPrint(b"=======================================\n")
slowPrint(b"\n")
time.sleep(0.6)
slowPrint(b"The droids sealed off the bridge. An emergency shutdown of the ship AI may be our only hope... ")
slowPrint(b"but the virus prompts for a code whenever we try to access any of the systems.")
time.sleep(1.5)
slowPrint(b" Gosh, here we go aga\n")
time.sleep(0.3)
# impose a timeout (also needed for catching nonhalting Turing code)
try:
   subprocess.run("./hypercomputer2", timeout = 10)
except:
   print("Timeout...")
