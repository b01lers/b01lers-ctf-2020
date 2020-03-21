import subprocess, time, sys

# 5-sec wait to discourage bruteforcing
sys.stdout.buffer.write(b"Connecting...\n")
sys.stdout.flush()
time.sleep(5)

# run challenge - impose a timeout (in case they hang too long at input)
try:
   subprocess.run(["./hypercomputer-server", "1000000"], timeout = 20)
except:
   print("Timeout...")
