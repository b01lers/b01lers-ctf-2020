from PIL import Image

PAGE_LENGTH = 140

book = open("book.txt", "r").read().split('\n')
pages = [book[x:x+PAGE_LENGTH] for x in range(0, len(book), PAGE_LENGTH)]


# print(list(enumerate(pages)))

im = Image.open("chal.png", 'r')
pix_val = list(im.getdata())
for tup in pix_val:
    print(tup[0], tup[1], tup[2])

for tup in pix_val:
    #print(pages[tup[0]], pages[tup[0]][tup[1]], pages[tup[0]][tup[1]][tup[2]])
     print(pages[tup[0]][tup[1]][tup[2]], end="")