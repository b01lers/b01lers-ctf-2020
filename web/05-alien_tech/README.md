# 05-alien\_tech
- This chall opens with a basic http authorization prompt.
- You can type in a username and password, but then you get the invalid username and password page.

## alien\_tech.wasm
- Using wasm2c from wabt we get an 11,779 line c file
- At least it's C right...?


### Resource
- [https://www.pnfsoftware.com/reversing-wasm.pdf](https://www.pnfsoftware.com/reversing-wasm.pdf) This helped a little bit.


### Memory
- Let's start looking at functions

#### f8 on line 1220
- There's some xoring `i0 ^= i1`
- Tracing back to where i0 is, loaded it's `i0 (0) + 1648`
```c
// 11683:
memcpy(&((*Z_envZ_memory).data[1648u]), data_segment_data_1, 396);
data_segment_data_1
static const u8 data_segment_data_1[] = {
  0x90, 0x69, 0x42, 0x37, 0x13, 0x08, 0x10, 0x09, 0x08, 0x07, 0x00, 0x00, 
  ...
}
```

- f8 goes from 1648-1657 and does some xors
- looks like it's loading in as an immediate

```c
// 1248:
  i0 = 222u;
```

```
1648: 0x90 ^ 222  = 'N'
1649: 0x69 ^ 73   = ' '
1650: 0x42 ^ 5    = 'G'
1651: 0x37 ^ 88   = 'o'
1652: 0x13 ^ 125  = 'n'
1653: 0x08 ^ 114  = 'z'
1654: 0x10 ^ 113  = 'a'
1655: 0x09 ^ 101  = 'l'
1656: 0x08 ^ 109  = 'e'
1657: 0x07 ^ 125  = 'z'
```


### Running
- Let's try running it because I'm tired of looking at c
- We can run this webassembly file with the js file `$ node alien_tech.js`
- No output, let's try running it with args
- `$ node alien_tech.js 1`
    - Still no output
- `$ node alien_tech.js 1 2`
    - Output: -2
    - Nice, real helpful please don't make me look at the webassembly again


## Let's check out the website
- Just gives a basic http authorization response
- Quick note from [https://en.wikipedia.org/wiki/Basic_access_authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
- Header is sent in the form:
    - Authorization: Basic base64encoded(username:password)
- With this let's go back to the webassembly


## Webassembly... Again
- So we know it takes 2 inputs and we know that the authorization is base64encoded(username:password)
    - Let's try username password

```bash
$ node alien_tech.js "N gonzales" pass
-2
```
- Nope
- Is it passing in the flag & input as a check?

```bash
$ node alien_tech.js $(echo -n "N Gonzalez" | base64) $(echo -n "N Gonzalez" | base64)
-1
```
- No longer -2, it's -1
- Let's send this to the server


## Starting with authentication
```bash
$ curl -H "Authorization: Basic $(echo -n 'N Gonzalez' | base64)" -v web.ctf.b01lers.com:1005
*   Trying 35.211.156.94:1005...
* TCP_NODELAY set
* Connected to web.ctf.b01lers.com (35.211.156.94) port 1005 (#0)
> GET / HTTP/1.1
> Host: web.ctf.b01lers.com:1005
> User-Agent: curl/7.66.0
> Accept: */*
> Authorization: Basic TiBHb256YWxleg==
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< X-Powered-By: Express
< Progress: 1
< WWW-Authenticate: Basic realm="Welcome to index"
< Content-Type: text/html; charset=utf-8
< Content-Length: 210
< ETag: W/"d2-r5QCx2BGKcUdID5RjdeiCx3nEfw"
< Date: Sun, 15 Mar 2020 17:12:20 GMT
< Connection: keep-alive
<
<!DOCTYPE html>
<html>
  <head>
    <title>
      Alien Tech
    </title>
  </head>
  <body>
    <p>Invalid username or password, please try again.</p>
    <a href="/src">Here's source :)</a>
  </body>
</html>
* Connection #0 to host web.ctf.b01lers.com left intact
```
- What's this Progress header??
- Let's see if we get it with a regular request

```bash
➜ curl -I web.ctf.b01lers.com:1005
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
WWW-Authenticate: Basic realm="Welcome to index"
Content-Type: text/html; charset=utf-8
Content-Length: 210
ETag: W/"d2-r5QCx2BGKcUdID5RjdeiCx3nEfw"
Date: Sun, 15 Mar 2020 17:13:50 GMT
Connection: keep-alive
```
- Nope

- If we have the username correct, let's try sending "N Gonzalez:"
```bash
$ curl -H "Authorization: Basic $(echo -n 'N Gonzalez:' | base64)" -I web.ctf.b01lers.com:1005
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Progress: 2
WWW-Authenticate: Basic realm="Welcome to index"
Content-Type: text/html; charset=utf-8
Content-Length: 210
ETag: W/"d2-r5QCx2BGKcUdID5RjdeiCx3nEfw"
Date: Sun, 15 Mar 2020 17:15:36 GMT
Connection: keep-alive
```
- Progress went up!


### Getting the password
- Maybe we can brute force the password using the progress header.
- It works!
- Thankfully the flag is relatively short at 30 characters so it's only 2308 requests (for just printable characters). See [solve.py](solve.py) for the python solve which takes about 9 minutes in 2308 requests.


# Flag
- pctf{but_does_it_run_doom_yet}
