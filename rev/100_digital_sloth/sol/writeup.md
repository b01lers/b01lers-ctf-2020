Author: dm
Category: REV
Point Value: 100

In this challenge there is a bunch of random looking data loaded onto the stack. Then, in main() there is a 
function which does a very slow unscrambling of the flag. If you run the binary you see that it prints pct and 
then hangs because the descramble takes so long. The solution is to rewrite the binary such that it uses a much 
faster unscramble (i.e., more efficient modular exponentiation). An example of a faster unscramble is shown in 
digitalsloth.c
