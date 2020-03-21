#!/usr/bin/env python3

from PIL import Image
from random import randint
import sys

f = './image_original.png'

img = Image.open(f)

print('Width: {}\n'.format(img.size[0]))
print('Height: {}\n'.format(img.size[1]))

pixels = img.load()
for r in range(img.size[0]):
    for c in range(img.size[1]):
        print('{}: {}'.format(c, pixels[r, c]))

    backup_row = []
    for c in range(img.size[1]):
        backup_row += [pixels[r,c]]

    start = randint(0, img.size[1])
    for c in range(img.size[1]):
        pixels[r, (c + start) % img.size[1]] = backup_row[c]

img.save('./image_edited.png')
img.show()
