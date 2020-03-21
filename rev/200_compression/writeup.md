# Compression

Points: 200

Description: We've written a compression algorithim special for our favorite train video! It's not exactly the most optimal, however. Write the decompression algorithim.

Creator: nsnc

# Solving

In this challenge, a binary is given with a "compression" algorithim implemented. The task is to reverse engineer the encoding, and write a tool to reverse it. Sucessfully decoding the given file will reveal a video, with the flag in it.

The simple description of the algorithim is that it keeps track of the index of each byte, then can use those indexes to recreate the original file. (Look at decompress.c for the decompression algorithim.)

The source code for the compression algorithim is in `compression.c`
