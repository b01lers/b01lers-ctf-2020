# 02-scrambled
- This challenge is a single page with a youtube video and a reload button

## Cookies
- Looking around, there are two cookies:
    - frequency
    - transmissions

### Frequency
- The frequency cookie increments by 1 each request, setting it to a high number doesn't do anything.


### Transmissions
- The trasmissions cookie changes each time the page is refreshed.
- An example transmissions cookie is: `kxkxkxkxshiv30kxkxkxkxsh`
- We have 4 parts:
    1. `kxkxkxkxsh`
    1. `iv`
    1. `30`
    1. `kxkxkxkxsh`
- Doing a couple more requests we get `kxkxkxkxshvo31kxkxkxkxsh`
- 4 parts:
    1. `kxkxkxkxsh`
    1. `vo`
    1. `31`
    1. `kxkxkxkxsh`
- There's a v in both, so the number could be an index.
- The solution is to create a script to continually request the page and get each part.
- [solve.py](solve.py)
