with open("book.txt", "rb") as f:
    with open("book.txt.fix", "wb") as o:
        for byt in f.read():
            if byt > 127:
                o.write(b" ")
            else:
                o.write(bytes(chr(byt), "ascii"))