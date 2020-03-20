#CRYPTO 100 - Armstrong

| Author | novafacing |
| --- | --- |
| Point Value | 100 |
| Description | Book cipher |

So at first glance this challenge looks slightly arcane. We have a binary and a book. If we run the binary, we receive an image from a challenge site. If you run the binary several times, you'll get a different image each time. What gives!?

Well, the astute CTF players will recognize that A) we're provided a book B) the program output claims the captain is going to write a book of 140 lines per page. Book ciphers are often noted as page/line/character triples. Images are...RGB colors, which are triples. We can use the RGB values in the image to construct a sequence from the book. 

We can make a solver using PIL like so:

```
from PIL import Image

PAGE_LENGTH = 140

book = open("book.txt", "r").read().split('\n')
pages = [book[x:x+PAGE_LENGTH] for x in range(0, len(book), PAGE_LENGTH)]

im = Image.open("chal.png", 'r')
pix_val = list(im.getdata())

for tup in pix_val:
    #print(pages[tup[0]], pages[tup[0]][tup[1]], pages[tup[0]][tup[1]][tup[2]])
     print(pages[tup[0]][tup[1]][tup[2]], end="")
```
