# the image is a 121x121 pattern of two kinds of 50x50 tiles...
# => suspect QR code (version #26)
#
# most QR readers, such as qrtools, cannot reliably decode QR images of binary data... because they 
# automatically do byte->string conversion at the very end (e.g., via UTF-8)
#
# so take raw data from ZXing Decoder (e.g., zxing.org/w/decode.jspx)
# 
# or for better automation, adapt the zxing-cpp code on Github, in particular, examples/scan_image.cpp to print 
# raw hex data extracted from images
#


# STEP 1: read original PNG, convert to normal black & white QR image (PNG)
#

from PIL import Image


img = Image.open("matryoshka.png")
print(img.size)

img2 = Image.new("1", (121,121))
(dx,dy) = (20,5)

p0 = img.getpixel((dx,dy))  # top left corner color

for i in range(121):
   for j in range(121):
      (x,y) = (i * 50 + dx,  j * 50 + dy)
      p = img.getpixel((x,y))

      if p == p0:
         img2.putpixel((i,j), 255)
      else:
         img2.putpixel((i,j), 0)

img2.save("img2.png", "PNG", compress_level = 9)


# STEP2: get the binary data in img2.png -> extract to img2.dat
#
# convert QR code to raw hex data with ZXing, cut and paste
# result to file img2.raw.hex
#
# NOTE, this is NOT simply the byte stream because ZXing gives
# us the encoding data as well. Thus:
#
# 40 48 d1 f8 b0 80 ... actually means 4|048d|1f|8b|08|..
#
# where the first nibble is the encoding (4 = byte), the next two
# bytes are the data length (0x048d), then come the data bytes
# 1f, 8b, 08, ... etc. So one needs to assemble the binary data
# correctly from nibbles


def extractQRData(fn, lengthBytes):
   # convert to one long hex stream
   s = ""
   with open(fn, "r") as f:
      for l in f:
         l = l.strip().replace(" ", "")
         s += l
   # extract mode and data length in bytes
   mode = int(s[0], 16)
   if mode != 4:
      print("expecting binary mode QRcode (%d!=4)" % mode)
      exit(1)
   offset = 1 + lengthBytes * 2
   length = int(s[1:offset], 16)
   # convert data nibbles to bytes
   ret = bytearray()
   for i in range(length):
      b = int( s[(offset + 2 * i):(offset + 2 * i + 2)], 16 )
      ret += bytes( [b] )
   return ret


# get data, write to file
img2data = extractQRData("img2.raw.hex", 2)
with open("img2.dat", "wb") as f:
   f.write(img2data)


# STEP 3: check what kind of data we got
#

import os

os.system("file img2.dat")

# -> GZIP compressed, so ungzip it

os.system("gunzip -c img2.dat > img2.unzipped")
os.system("file img2.unzipped")

# -> ASCII text
# upon further inspection, it is an 85x85 grid of 1s and l-s (lower case L)
# 
# another QR code? (version 17 now)
#


# STEP 4: write the grid into a black and white PNG image, decode with ZXing
#         top left char is 'l', so guess l = white, 1 = black

img = Image.new("1", (85,85))

with open("img2.unzipped", "r") as f:
   for y in range(85):
      l = f.readline()
      for x in range(85):
         if l[x] == '1':
            img.putpixel((x,y), 0)
         else:
            img.putpixel((x,y), 255)

img.save("img3.png", "PNG")


# STEP 5: get the data from the QR code, analogously to steps 2 & 3
#       
# ZXing -> raw hex data in img3.raw.hex


img3data = extractQRData("img3.raw.hex", 2)
with open("img3.dat", "wb") as f:
   f.write(img3data)

os.system("file img3.dat")

# -> 57x57 PNG image data, but if you check it, it is inverted
#    so ZXing cannot(!) decode it
#

os.system("cp img3.dat img4-inv.png")


# STEP 6: invert and decode image with ZXing -> img4.raw.hex -> img4.dat
#         check data type
#
# [ofc, there are a zillion other ways to invert an image]


img = Image.open("img4-inv.png")
(x,y) = img.size

for i in range(x):
   for j in range(y):
      p = img.getpixel((i,j))
      img.putpixel((i,j), 255 - p)

img.save("img4.png", "PNG")

# ZXing -> img4.raw.hex
# this is a small QR code now, so data length is only 1 byte

img4data = extractQRData("img4.raw.hex", 1)
with open("img4.dat", "wb") as f:
   f.write(img4data)


os.system("file img4.dat")
# -> 7zip file!   AES encrypted
os.system("cp img4.dat img4.7z")


# STEP 7: unpack the file
#

os.system("7z x img4.7z")
# password is 1234  (hint was 1 2 ... ...) => gives the flag
