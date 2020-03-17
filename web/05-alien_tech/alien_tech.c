#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len) {
  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char)i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = malloc(olen);
  if (out == NULL)
    return NULL;

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
        if (pad == 1)
          pos--;
        else if (pad == 2)
          pos -= 2;
        else {
          /* Invalid padding */
          free(out);
          return NULL;
        }
        break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}

char username[11] = {'\x90', '\x69', '\x42', '\x37', '\x13', '\x08',
                     '\x10', '\x09', '\x08', '\x07', '\x00'};

void init() {
  // N Gonzalez
  // 4e 20 47 6f 6e 7a 61 6c 65 7a
  username[0] ^= 0xde;
  username[1] ^= 0x49;
  username[2] ^= 0x5;
  username[3] ^= 0x58;
  username[4] ^= 0x7d;
  username[5] ^= 0x72;
  username[6] ^= 0x71;
  username[7] ^= 0x65;
  username[8] ^= 0x6d;
  username[9] ^= 0x7d;
}

int auth(char *f, char *a) {
  // f is b64(username:password:flag)
  // Base64 decode the whole thing
  // base64_decode(const unsigned char *src, size_t len, size_t *out_len)
  size_t out_len = 0xff;
  // df is username:password:flag
  char *df =
      (char *)base64_decode((const unsigned char *)f, strlen(f), &out_len);

  // a is authorization request
  // da is base64decoded authorization request
  char *da =
      (char *)base64_decode((const unsigned char *)a, strlen(a), &out_len);

  int res = strncmp(da, username, 10);
  // Return -2 if username isn't correct username
  if (res != 0)
    return -2;

  // Compares the two and returns index it failed at or 0 for success
  int return_val = 1;
  int current = 10;
  size_t len_df = strlen(df);
  size_t len_da = strlen(da);

  while (current < len_df && current < len_da) {
    if (df[current] != da[current])
      break;
    current++;
    return_val++;
  }

  // Return -1 if match
  if (current == len_df)
    return -1;
  return return_val;
}

int main(int argc, char **argv) {
  if (argc < 3)
    return 1;
  // Initialize username
  init();
  // Call auth
  int auth_ret = auth(argv[1], argv[2]);
  // Print ret
  printf("%d\n", auth_ret);
  return auth_ret;
}
