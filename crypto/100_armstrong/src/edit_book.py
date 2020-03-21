with open("book_split.txt", "w") as o:
    with open("book.txt", "r") as f:
        for line in f.read().split("\n"):
            print(line)
            if len(line) > 255:
                lines = [line[x:x+255] for x in range(0, len(line), 255)]
                for l in lines:
                    o.write(l)
                    o.write("\n")
            else:
                o.write(line)
                o.write("\n")
