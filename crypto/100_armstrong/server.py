#!/usr/bin/env python3

import socket
import logging
from threading import Thread
from socketserver import ThreadingMixIn
from PIL import Image, PngImagePlugin
import random
import io
import sys

CFLAG = "pctf{_th1nk_n31l_armstr0ng_ev3r_r0de_4_b1cycl3_4r0und_4nd_h4d_1t_st0len_and_put_1t_up_in_the_tr33s_1wood_h4ve_t0ssed_it_4ll_th3_w4y_to_th3_m00n}"
BOOK = "/home/armstrong/book.txt"
# BOOK="book.txt"
BOOK_TEXT = open(BOOK, "r").read().split('\n')
PAGE_LENGTH = 140

def get_img():
    colors = []
    for ch in CFLAG:
        try:
            locs = {}
            pages = [BOOK_TEXT[x:x+PAGE_LENGTH] for x in range(0, len(BOOK_TEXT), PAGE_LENGTH)]
            for idx, page in enumerate(pages):
                for ldx, line in enumerate(page):
                    for cdx, char in enumerate(line[:255]):
                        if char == ch:
                            locs[(idx, ldx, cdx)] = ch
            chs = random.choice(list(locs))
            colors.append(chs)
        except Exception as e:
            logging.error("[!] Error: could not find: {} please let @novafacing on discord know!".format(ch))
    try:
        img = Image.new('RGB', (12,12))
        meta = PngImagePlugin.PngInfo()
        metadata = {"Page Length": "140 Lines"}
        for k, v in metadata.items():
            meta.add_text(k, v, 0)
        img.putdata(colors)
        imgbytearr = io.BytesIO()
        img.save(imgbytearr, format='PNG', pnginfo=meta)
        img_data = imgbytearr.getvalue()
        return img_data
    except:
        logging.error("[!] Error: could not create image please let @novafacing on discord know!")
        return None

if __name__ == "__main__":
    sys.stdout.buffer.write(b"Hold on, I'm grabbing you a photo from our gallery.\n")
    sys.stdout.buffer.flush()
    sys.stdout.buffer.write(get_img())
