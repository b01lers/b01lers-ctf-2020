import segno, os


# do regular PNG QR codes (1 square = 1 pixel)

def writePNG(datfile, pngfile):
   with open(datfile, "rb") as f:
      content = f.read()
   print(len(content))
   qr = segno.make(content, encoding = None, eci = True)
   print(qr)
   qr.save(pngfile)


#
# convert to QR codes in funny formats for challenge
#

from PIL import Image


def tilePNG(tile0, tile1, imgfile):
   img = Image.open(imgfile)
   img0 = Image.open(tile0)
   img1 = Image.open(tile1)

   (dx,dy) = img0.size
   (x,y) = img.size
   print(x,y)
   result = Image.new('RGB', (x * dx, y*dy), (0,0,0))

   p0 = img.getpixel((0,0))
   for i in range(x):
      for j in range(y):
         p = img.getpixel((i,j))
         pos = (i * dx, j * dy)
         if p == p0:
            result.paste(img0, pos)
         else:
            result.paste(img1, pos)

   return result


def invertPNG(imgfile):
   img = Image.open(imgfile)
   (x,y) = img.size
   print(x,y)
   for i in range(x):
      for j in range(y):
         p = img.getpixel((i,j))
         img.putpixel((i,j), 255 - p)
   img.convert("1")
   return img


def asciiPNG(c0, c1, imgfile):
   img = Image.open(imgfile)
   (x,y) = img.size
   print(x,y)
   ret = ""
   for j in range(y):
      for i in range(x):
         p = img.getpixel((i,j))
         if p == 0:
            ret += c0
         else:
            ret += c1
      ret += "\n"
   return ret



# compress/"encrypt" flag    - THE RESULT IS VARIABLE DUE TO TIMESTAMPS
os.system("7za a flag.7z -p1234 flag")

# convert to inverted PNG   - 57x57
writePNG("flag.7z", "doll1-tmp.png")
img = invertPNG("doll1-tmp.png")   
img.save("doll1.png", "PNG", compress_level = 9)    # Note: the PNG writer seems to be a bit stochastic...

# convert to ASCII encoded PNG   - 85x85
writePNG("doll1.png", "doll2.png")
txt2 = asciiPNG("1", "l", "doll2.png") 
with open("doll2.txt", "w") as f:
   f.write(txt2)
os.system("cat doll2.txt | gzip -c > doll2.txt.gz")

# convert to tiled PNG  - 121 x 121
writePNG("doll2.txt.gz", "doll3.png")

tilePNG("left2-50.png", "right2-50.png", "doll3.png").save("matryoshka.png", "PNG")
         

