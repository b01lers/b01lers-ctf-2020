# 03-space_noodles

## /
```bash
$ curl -X post web.ctf.b01lers.com:1003
  <html>
  </body>
      <body>
        <text><p></text>text ? pleas test teh follwing five roots<p>,</p>
  <list>
    <one>

circle</one>
    <enter>
    <enter>
    <sendkey(enter)>

two
  I'm am making an a pea eye and its grate

         PHP is the best
      <php?> printf(hello world) </php>
square<?/p>two


  :pleasequithelpwww.google.
com/seaerch

    how to exit
vim/quit
  :wqwhy isnt it working:wq:wq:wq:qw?

      </body>
                                                                                                                                </html>
```
- The 'roots' aka routes are the 5 unindented lines

## /circle/one/
- `$ curl -X OPTIONS web.ctf.b01lers.com:1003/circle/one/ --output out`
- You get a pdf file that has `pctf{ketch` in it.
- This can be seen on the far left of the bowl in light text.


## /two/
```bash
$ curl -X PUT web.ctf.b01lers.com:1003/two/
Put the dots???
```
- This was a hint to use the `CONNECT` HTTP method since there is a thing called `connect the dots`
- `curl -X CONNECT web.ctf.b01lers.com:1003/two/ --output out`
- Look at the dots to find part of the flag
- `up_on_noodles_`


## /square/
- `$ curl -X DELETE localhost:4203/square/ --output out`
- It's a crossword puzzle with row 2 being the flag part
- Answers:
    - t
        - Which extra terrestrial just wants to 'phone home'?
        - ET
    - a
        - Which planet got blown up in the Death Star test?
        - Alderaan
    - s
        - The _____ core from Portal 2 is famous for saying this: "Oh oh oh. This is _____! I'm in ____!".
        - Space
    - t
        - Which Warhammer 40k species' motto is 'For the Greater Good!'?
        - Tau
    - e
        - Star trek something
        - Enterprise
    - s
        - What is the name of the ship in *Aliens*?
        - Sulaco

- `tastes`


## /com/seaerch/
```bash
$ curl web.ctf.b01lers.com:1003/com/seaerch/
<htlm>

,,,,,,,,,<search> <-- comment for search --!>:

  ERROR </> search=null</end>

</html>
```
- Just set search=null in the querystring

```bash
$ curl -X GET "web.ctf.b01lers.com:1003/com/seaerch/?search=null"
<htlm>

,,,,,,,,,<search> <-- comment for search --!>:

  ERROR </> search=null</end>

</html>
```
- Nope didn't work, lets try in the body

```bash
$ curl -X GET -d search=null web.ctf.b01lers.com:1003/com/seaerch/
<htlm>

,,,,,,,,,<search> <-- comment for search --!>:

  <query> null is not a good search, please use this one instead: 'flag' <try>

</html>%
```

```bash
$ curl -X GET -d search=flag web.ctf.b01lers.com:1003/com/seaerch/
<htlm>

,,,,,,,,,<search> <-- comment for search --!>:

  <query> good search</query>
  results: <p>_good_in_s</p>:w


</html>%
```
- Read the page and use a request body with a GET request to get the flag
- `_good_in_s`

## /vim/quit/
```bash
curl -X TRACE web.ctf.b01lers.com:1003/vim/quit/
   <hteeemel<body>>

                    <wrong>uh oh
                  ?exit=null
            </wrong>

</>
```
- This one's gotta be a query string

```bash
$ curl -X TRACE "web.ctf.b01lers.com:1003/vim/quit/?exit=flag"
   <hteeemel<body>>

       <erroror><p>E492: Not an editor command: flag</p>
 </errorror>
 </flag>


</>
```
- It's about quitting vim, so lets just send `:wq`

```bash
$ curl -X TRACE "web.ctf.b01lers.com:1003/vim/quit/?exit=:wq"
   <hteeemel<body>>

      <flag> well done wait </flag>
<text> this one/> <flag>pace_too}</flag>

</>%
```
- Use a query string with TRACE
- `pace_too}`
