#!/usr/bin/env python3

import requests
import urllib

# Assume flag is less than 100 characters
array = [''] * 100

# Requests session
session = requests.Session()

# Initial cookie
cookie = {'transmissions': '0'}
num_requests = 0


# Requests the page n times
def req(n):
    # n requests
    for i in range(0, n):
        global num_requests
        # Get webpage with cookie
        session.get('http://web.ctf.b01lers.com:1002/', cookies=cookie)
        num_requests += 1

        # Get value of cookie from response
        string = session.cookies.get_dict().get('transmissions')
        # Remove junk from the cookie
        flagChars = string.replace('kxkxkxkxsh', '')
        length = len(flagChars)
        # Url decode string
        flagChars = urllib.parse.unquote(flagChars)

        # If index is 1 digit get index
        if(length == 3):
            index = flagChars[2:3]
        # If index is 2 digits get index
        else:
            index = flagChars[2:4]
        flag1 = flagChars[0:1]
        flag2 = flagChars[1:2]

        # Add characters to the array at index
        array[int(index)] = flag1
        array[int(index)+1] = flag2
        print('\r' + ''.join(array), end='')


# Check if flag is complete
done = False
while not done:
    # Check to see if flag is complete by searching for '}' at the end
    for character in array:
        # If there is a blank, request more
        if(character == ''):
            # Print part of flag
            print('\r' + ''.join(array), end='')
            req(50)
            break
        # If end of flag, exit loop
        elif(str(character) == '}'):
            done = True
            break

print('\r' + ''.join(array))  # print flag
print('In ' + str(num_requests) + ' requests')
