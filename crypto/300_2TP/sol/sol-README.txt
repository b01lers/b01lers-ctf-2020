The Easter egg made cribbing pretty viable, so that was one way to solve the challenge. We had something
more sophisticated in mind (see below).

----

2TP can be solved in a largely automated way by assuming that the plaintexts are n-character 
English-language Markov chains (see, e.g., "A Natural Language Approach to Automated Cryptanalysis 
of Two-time Pads" by Mason, Watkins, Eisner, and Stubblefield, presented at CCS2006). That way the 
problem is equivalent to finding the most probable plaintext pair (ptxt1, ptx2) for which xor(ptxt1, 
ptxt2) = xor(ctxt1, ctxt2). The most frequent error is reconstructed plaintext segments getting 
swapped between the two messages. Those can be fixed by hand, then one reruns the solver, fixes the 
next error, and hence succeeds by induction.

In a couple hours one can whip up a simple solver that uses n-character frequencies (probabilities) 
for n=1,2,3,4 stored in arrays. You do need at least n=4 or more for reasonable accuracy, so this 
was within reach. Frequencies can be determined by analyzing a reasonably large body of text. 
English books in ASCII format can be obtained, for example, from the Gutenberg project. The 
Hitchhikers' Guide to The Galaxy book is also freely available in text format. Domain-specific text 
is, of course, generally better but 19th- and 20th-century literature still works rather well. The 
enclosed Python 3 code ngrams-np.py creates smoothed log-likelihood arrays and writes them to disk 
(~300 MB of compressed data).

Given the frequency arrays, sol-np.py finds the most likely solutions. As progress indicator, after 
each 10th recovered character the solver prints the top Nbest (100 by default) overall solutions at 
the end. One can restrict it to specific plaintexts passed in external files (the character # serves 
as a wildcard in these, and any character beyond the end of the files is also considered to be #). 
When solutions go astray (they noticeably do, for n<=4), it is good practice to rerun with an ending 
position that is 3-5 characters beyond the problematic character position, check whether there is a 
feasible variation among to top Nbest solutions, and update the solution files to impose that 
particular continuation.

Of course, once you discover the Easter egg you can just use that as a crib to quickly finish things 
off.

I am including the unguided (first-run) output from n=3, n=4 and n=5 Markov chain analyses. Clearly, 
the method has too many errors for n<=3, but with 4-gram data included it is workable and can be 
used to decipher the challenge (with some nudging). Going beyond n > 4 requires more sophisticated 
data structures than simple arrays (to save on memory) - it should be straighforward for you to 
re-implement the technique with tries, for example.


===
